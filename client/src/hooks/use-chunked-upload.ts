import { useState, useCallback, useRef } from "react";

interface UploadSession {
  sessionId: string;
  chunkSize: number;
  totalChunks: number;
  expiresAt: string;
}

interface UploadProgress {
  uploadedChunks: number;
  totalChunks: number;
  percentage: number;
  bytesUploaded: number;
  totalBytes: number;
}

interface ChunkedUploadState {
  isUploading: boolean;
  progress: UploadProgress | null;
  error: string | null;
  objectPath: string | null;
  sessionId: string | null;
}

interface ChunkedUploadOptions {
  maxRetries?: number;
  concurrency?: number;
  onProgress?: (progress: UploadProgress) => void;
  onComplete?: (objectPath: string) => void;
  onError?: (error: string) => void;
}

const STORAGE_KEY_PREFIX = "chunked_upload_session_";

function getStoredSession(filename: string, fileSize: number): string | null {
  const key = `${STORAGE_KEY_PREFIX}${filename}_${fileSize}`;
  const stored = localStorage.getItem(key);
  if (stored) {
    try {
      const parsed = JSON.parse(stored);
      if (new Date(parsed.expiresAt) > new Date()) {
        return parsed.sessionId;
      }
      localStorage.removeItem(key);
    } catch {
      localStorage.removeItem(key);
    }
  }
  return null;
}

function storeSession(filename: string, fileSize: number, session: UploadSession): void {
  const key = `${STORAGE_KEY_PREFIX}${filename}_${fileSize}`;
  localStorage.setItem(key, JSON.stringify({
    sessionId: session.sessionId,
    expiresAt: session.expiresAt,
  }));
}

function clearStoredSession(filename: string, fileSize: number): void {
  const key = `${STORAGE_KEY_PREFIX}${filename}_${fileSize}`;
  localStorage.removeItem(key);
}

export function useChunkedUpload(options: ChunkedUploadOptions = {}) {
  const { maxRetries = 3, concurrency = 3, onProgress, onComplete, onError } = options;
  
  const [state, setState] = useState<ChunkedUploadState>({
    isUploading: false,
    progress: null,
    error: null,
    objectPath: null,
    sessionId: null,
  });
  
  const abortRef = useRef(false);
  const authTokenRef = useRef<string | null>(null);
  
  const getAuthToken = useCallback(() => {
    if (!authTokenRef.current) {
      authTokenRef.current = localStorage.getItem("auth_token");
    }
    return authTokenRef.current;
  }, []);

  const initSession = useCallback(async (
    file: File,
    category?: "avatars" | "images" | "videos" | "voice" | "files"
  ): Promise<UploadSession> => {
    const token = getAuthToken();
    if (!token) throw new Error("Не авторизован");
    
    const response = await fetch("/api/upload/init", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify({
        filename: file.name,
        fileSize: file.size,
        mimeType: file.type || "application/octet-stream",
        category,
      }),
    });
    
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || "Ошибка инициализации загрузки");
    }
    
    return data.data;
  }, [getAuthToken]);
  
  const getSessionStatus = useCallback(async (sessionId: string): Promise<{
    status: string;
    uploadedChunks: number[];
    totalChunks: number;
    objectPath?: string;
  }> => {
    const token = getAuthToken();
    if (!token) throw new Error("Не авторизован");
    
    const response = await fetch(`/api/upload/status/${sessionId}`, {
      headers: { "Authorization": `Bearer ${token}` },
    });
    
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || "Ошибка получения статуса");
    }
    
    return data.data;
  }, [getAuthToken]);
  
  const uploadChunk = useCallback(async (
    sessionId: string,
    chunkIndex: number,
    chunkData: Blob,
    retryCount = 0
  ): Promise<void> => {
    const token = getAuthToken();
    if (!token) throw new Error("Не авторизован");
    
    try {
      const response = await fetch(`/api/upload/chunk/${sessionId}/${chunkIndex}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "Authorization": `Bearer ${token}`,
        },
        body: chunkData,
      });
      
      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || "Ошибка загрузки части");
      }
    } catch (error) {
      if (retryCount < maxRetries && !abortRef.current) {
        await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
        return uploadChunk(sessionId, chunkIndex, chunkData, retryCount + 1);
      }
      throw error;
    }
  }, [getAuthToken, maxRetries]);
  
  const completeUpload = useCallback(async (sessionId: string): Promise<string> => {
    const token = getAuthToken();
    if (!token) throw new Error("Не авторизован");
    
    const response = await fetch(`/api/upload/complete/${sessionId}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}` },
    });
    
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.error || "Ошибка завершения загрузки");
    }
    
    return data.data.objectPath;
  }, [getAuthToken]);
  
  const uploadFile = useCallback(async (
    file: File,
    category?: "avatars" | "images" | "videos" | "voice" | "files"
  ): Promise<string> => {
    abortRef.current = false;
    authTokenRef.current = null;
    
    setState({
      isUploading: true,
      progress: null,
      error: null,
      objectPath: null,
      sessionId: null,
    });
    
    try {
      let session: UploadSession;
      let uploadedChunks: number[] = [];
      
      const existingSessionId = getStoredSession(file.name, file.size);
      
      if (existingSessionId) {
        try {
          const status = await getSessionStatus(existingSessionId);
          
          if (status.status === "completed" && status.objectPath) {
            clearStoredSession(file.name, file.size);
            setState({
              isUploading: false,
              progress: { uploadedChunks: status.totalChunks, totalChunks: status.totalChunks, percentage: 100, bytesUploaded: file.size, totalBytes: file.size },
              error: null,
              objectPath: status.objectPath,
              sessionId: existingSessionId,
            });
            onComplete?.(status.objectPath);
            return status.objectPath;
          }
          
          if (status.status === "uploading" || status.status === "pending") {
            uploadedChunks = status.uploadedChunks;
            const chunkSize = Math.ceil(file.size / status.totalChunks);
            session = {
              sessionId: existingSessionId,
              chunkSize,
              totalChunks: status.totalChunks,
              expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            };
          } else {
            clearStoredSession(file.name, file.size);
            session = await initSession(file, category);
            storeSession(file.name, file.size, session);
          }
        } catch {
          clearStoredSession(file.name, file.size);
          session = await initSession(file, category);
          storeSession(file.name, file.size, session);
        }
      } else {
        session = await initSession(file, category);
        storeSession(file.name, file.size, session);
      }
      
      setState(prev => ({ ...prev, sessionId: session.sessionId }));
      
      const chunksToUpload = [];
      for (let i = 0; i < session.totalChunks; i++) {
        if (!uploadedChunks.includes(i)) {
          chunksToUpload.push(i);
        }
      }
      
      let completedChunks = uploadedChunks.length;
      
      const updateProgress = () => {
        const progress: UploadProgress = {
          uploadedChunks: completedChunks,
          totalChunks: session.totalChunks,
          percentage: Math.round((completedChunks / session.totalChunks) * 100),
          bytesUploaded: completedChunks * session.chunkSize,
          totalBytes: file.size,
        };
        setState(prev => ({ ...prev, progress }));
        onProgress?.(progress);
      };
      
      updateProgress();
      
      for (let i = 0; i < chunksToUpload.length; i += concurrency) {
        if (abortRef.current) {
          throw new Error("Загрузка отменена");
        }
        
        const batch = chunksToUpload.slice(i, i + concurrency);
        
        await Promise.all(batch.map(async (chunkIndex) => {
          const start = chunkIndex * session.chunkSize;
          const end = Math.min(start + session.chunkSize, file.size);
          const chunkData = file.slice(start, end);
          
          await uploadChunk(session.sessionId, chunkIndex, chunkData);
          completedChunks++;
          updateProgress();
        }));
      }
      
      const objectPath = await completeUpload(session.sessionId);
      clearStoredSession(file.name, file.size);
      
      setState({
        isUploading: false,
        progress: { uploadedChunks: session.totalChunks, totalChunks: session.totalChunks, percentage: 100, bytesUploaded: file.size, totalBytes: file.size },
        error: null,
        objectPath,
        sessionId: session.sessionId,
      });
      
      onComplete?.(objectPath);
      return objectPath;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Ошибка загрузки";
      setState(prev => ({
        ...prev,
        isUploading: false,
        error: errorMessage,
      }));
      onError?.(errorMessage);
      throw error;
    }
  }, [initSession, getSessionStatus, uploadChunk, completeUpload, concurrency, onProgress, onComplete, onError]);
  
  const abort = useCallback(() => {
    abortRef.current = true;
    setState(prev => ({
      ...prev,
      isUploading: false,
      error: "Загрузка отменена",
    }));
  }, []);
  
  const reset = useCallback(() => {
    abortRef.current = false;
    setState({
      isUploading: false,
      progress: null,
      error: null,
      objectPath: null,
      sessionId: null,
    });
  }, []);
  
  return {
    ...state,
    uploadFile,
    abort,
    reset,
  };
}

export async function uploadFileChunked(
  file: File,
  token: string,
  category?: "avatars" | "images" | "videos" | "voice" | "files",
  onProgress?: (progress: UploadProgress) => void
): Promise<string> {
  const initResponse = await fetch("/api/upload/init", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({
      filename: file.name,
      fileSize: file.size,
      mimeType: file.type || "application/octet-stream",
      category,
    }),
  });
  
  const initData = await initResponse.json();
  if (!initData.success) {
    throw new Error(initData.error || "Ошибка инициализации");
  }
  
  const session: UploadSession = initData.data;
  
  for (let i = 0; i < session.totalChunks; i++) {
    const start = i * session.chunkSize;
    const end = Math.min(start + session.chunkSize, file.size);
    const chunkData = file.slice(start, end);
    
    const chunkResponse = await fetch(`/api/upload/chunk/${session.sessionId}/${i}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "Authorization": `Bearer ${token}`,
      },
      body: chunkData,
    });
    
    const chunkResult = await chunkResponse.json();
    if (!chunkResult.success) {
      throw new Error(chunkResult.error || "Ошибка загрузки части");
    }
    
    onProgress?.({
      uploadedChunks: i + 1,
      totalChunks: session.totalChunks,
      percentage: Math.round(((i + 1) / session.totalChunks) * 100),
      bytesUploaded: end,
      totalBytes: file.size,
    });
  }
  
  const completeResponse = await fetch(`/api/upload/complete/${session.sessionId}`, {
    method: "POST",
    headers: { "Authorization": `Bearer ${token}` },
  });
  
  const completeData = await completeResponse.json();
  if (!completeData.success) {
    throw new Error(completeData.error || "Ошибка завершения");
  }
  
  return completeData.data.objectPath;
}
