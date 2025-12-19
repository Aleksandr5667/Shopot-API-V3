import { Router, Request, Response } from "express";
import { z } from "zod";
import { storage } from "../storage/index";
import { authenticateToken } from "../auth";
import { ObjectStorageService, ObjectNotFoundError } from "../objectStorage";
import { sendSuccess, sendError } from "./utils";

export const mediaRouter = Router();

const objectStorageService = new ObjectStorageService();

mediaRouter.post("/upload", authenticateToken, async (req: Request, res: Response) => {
  try {
    const filename = req.body.filename as string;
    const category = req.body.category as "avatars" | "images" | "videos" | "voice" | undefined;
    
    const validCategories = ["avatars", "images", "videos", "voice"];
    if (category && !validCategories.includes(category)) {
      return sendError(res, "Некорректная категория файла");
    }
    
    const user = await storage.getUserById(req.user!.userId);
    const userEmail = user?.email;
    
    const { uploadURL, objectPath } = await objectStorageService.getObjectEntityUploadURL(
      filename,
      userEmail,
      category
    );
    
    return sendSuccess(res, { uploadURL, objectPath });
  } catch (error) {
    console.error("Upload URL error:", error);
    return sendError(res, "Ошибка получения URL для загрузки", 500);
  }
});

mediaRouter.put("/media/finalize", authenticateToken, async (req: Request, res: Response) => {
  try {
    const { uploadedUrl } = req.body;
    if (!uploadedUrl) {
      return sendError(res, "uploadedUrl обязателен");
    }

    const objectPath = await objectStorageService.trySetObjectEntityAclPolicy(
      uploadedUrl,
      {
        owner: String(req.user!.userId),
        visibility: "public",
      }
    );

    return sendSuccess(res, { objectPath });
  } catch (error) {
    console.error("Finalize media error:", error);
    return sendError(res, "Ошибка финализации медиа", 500);
  }
});

const MAX_FILE_SIZE = 150 * 1024 * 1024; // 150 MB
const MIN_VOICE_FILE_SIZE = 1024; // 1 KB - минимальный размер голосового сообщения
const MIN_IMAGE_FILE_SIZE = 100; // 100 bytes - минимальный размер изображения
const MIN_VIDEO_FILE_SIZE = 1024; // 1 KB - минимальный размер видео

const initUploadSchemaWithValidation = z.object({
  filename: z.string().min(1, "Имя файла обязательно"),
  fileSize: z.number().int().positive().max(MAX_FILE_SIZE, "Максимальный размер файла 150 МБ"),
  mimeType: z.string().min(1, "MIME тип обязателен"),
  category: z.enum(["avatars", "images", "videos", "voice", "files"]).optional(),
});

mediaRouter.post("/upload/init", authenticateToken, async (req: Request, res: Response) => {
  try {
    const validation = initUploadSchemaWithValidation.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    const { fileSize, category } = validation.data;

    // Проверка минимального размера для медиа-файлов
    if (category === "voice" && fileSize < MIN_VOICE_FILE_SIZE) {
      return sendError(res, `Голосовое сообщение слишком короткое (минимум ${MIN_VOICE_FILE_SIZE} байт)`);
    }
    if (category === "images" && fileSize < MIN_IMAGE_FILE_SIZE) {
      return sendError(res, "Изображение повреждено или слишком маленькое");
    }
    if (category === "videos" && fileSize < MIN_VIDEO_FILE_SIZE) {
      return sendError(res, "Видео повреждено или слишком маленькое");
    }

    const session = await storage.createUploadSession(req.user!.userId, validation.data);
    
    return sendSuccess(res, {
      sessionId: session.id,
      chunkSize: session.chunkSize,
      totalChunks: session.totalChunks,
      expiresAt: session.expiresAt,
    }, 201);
  } catch (error) {
    console.error("Init upload error:", error);
    return sendError(res, "Ошибка инициализации загрузки", 500);
  }
});

mediaRouter.get("/upload/status/:sessionId", authenticateToken, async (req: Request, res: Response) => {
  try {
    const { sessionId } = req.params;
    
    const session = await storage.getUploadSession(sessionId);
    if (!session) {
      return sendError(res, "Сессия загрузки не найдена", 404);
    }

    if (session.userId !== req.user!.userId) {
      return sendError(res, "Доступ запрещён", 403);
    }

    return sendSuccess(res, {
      sessionId: session.id,
      status: session.status,
      uploadedChunks: session.uploadedChunks,
      totalChunks: session.totalChunks,
      objectPath: session.objectPath,
      expiresAt: session.expiresAt,
    });
  } catch (error) {
    console.error("Get upload status error:", error);
    return sendError(res, "Ошибка получения статуса", 500);
  }
});

mediaRouter.post("/upload/chunk/:sessionId/:chunkIndex", authenticateToken, async (req: Request, res: Response) => {
  try {
    const { sessionId, chunkIndex } = req.params;
    const chunkIdx = parseInt(chunkIndex);
    
    if (isNaN(chunkIdx) || chunkIdx < 0) {
      return sendError(res, "Некорректный индекс части");
    }

    const session = await storage.getUploadSession(sessionId);
    if (!session) {
      return sendError(res, "Сессия загрузки не найдена", 404);
    }

    if (session.userId !== req.user!.userId) {
      return sendError(res, "Доступ запрещён", 403);
    }

    if (session.status === "completed") {
      return sendError(res, "Загрузка уже завершена");
    }

    if (session.status === "expired" || session.expiresAt < new Date()) {
      return sendError(res, "Сессия загрузки истекла");
    }

    if (chunkIdx >= session.totalChunks) {
      return sendError(res, `Индекс части ${chunkIdx} выходит за пределы (всего ${session.totalChunks})`);
    }
    
    if (session.uploadedChunks.includes(chunkIdx)) {
      return sendSuccess(res, {
        chunkIndex: chunkIdx,
        uploadedChunks: session.uploadedChunks,
        totalChunks: session.totalChunks,
        progress: Math.round((session.uploadedChunks.length / session.totalChunks) * 100),
        message: "Часть уже загружена",
      });
    }

    const { chunkData: base64Data } = req.body;
    if (!base64Data || typeof base64Data !== 'string') {
      return sendError(res, "Отсутствует chunkData в теле запроса");
    }

    const chunkData = Buffer.from(base64Data, 'base64');

    if (chunkData.length === 0) {
      return sendError(res, "Пустая часть файла");
    }
    
    const isLastChunk = chunkIdx === session.totalChunks - 1;
    const expectedLastChunkSize = session.fileSize % session.chunkSize || session.chunkSize;
    const expectedSize = isLastChunk ? expectedLastChunkSize : session.chunkSize;
    
    if (!isLastChunk && chunkData.length !== session.chunkSize) {
      return sendError(res, `Неверный размер части: ожидалось ${session.chunkSize}, получено ${chunkData.length}`);
    }
    
    if (isLastChunk && chunkData.length > session.chunkSize) {
      return sendError(res, `Последняя часть слишком большая: ${chunkData.length} > ${session.chunkSize}`);
    }

    const fs = await import("fs/promises");
    const path = await import("path");
    const os = await import("os");
    
    const tempDir = path.join(os.tmpdir(), "uploads", sessionId);
    await fs.mkdir(tempDir, { recursive: true });
    
    const chunkPath = path.join(tempDir, `chunk_${chunkIdx}`);
    await fs.writeFile(chunkPath, chunkData);

    const updated = await storage.markChunkUploaded(sessionId, chunkIdx);
    if (!updated) {
      return sendError(res, "Ошибка обновления статуса", 500);
    }

    return sendSuccess(res, {
      chunkIndex: chunkIdx,
      uploadedChunks: updated.uploadedChunks,
      totalChunks: updated.totalChunks,
      progress: Math.round((updated.uploadedChunks.length / updated.totalChunks) * 100),
    });
  } catch (error) {
    console.error("Upload chunk error:", error);
    return sendError(res, "Ошибка загрузки части", 500);
  }
});

mediaRouter.post("/upload/complete/:sessionId", authenticateToken, async (req: Request, res: Response) => {
  const fs = await import("fs/promises");
  const path = await import("path");
  const os = await import("os");
  
  const { sessionId } = req.params;
  const tempDir = path.join(os.tmpdir(), "uploads", sessionId);
  
  const cleanupTempDir = async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch (cleanupError) {
      console.error(`[upload/complete] Error cleaning up temp files:`, cleanupError);
    }
  };
  
  try {
    const session = await storage.getUploadSession(sessionId);
    if (!session) {
      return sendError(res, "Сессия загрузки не найдена", 404);
    }

    if (session.userId !== req.user!.userId) {
      return sendError(res, "Доступ запрещён", 403);
    }

    if (session.status === "completed") {
      return sendSuccess(res, { objectPath: session.objectPath });
    }
    
    if (session.status === "failed") {
      return sendError(res, "Загрузка не удалась, начните заново", 400);
    }

    if (session.status === "expired" || session.expiresAt < new Date()) {
      return sendError(res, "Сессия загрузки истекла", 400);
    }

    const missingChunks: number[] = [];
    for (let i = 0; i < session.totalChunks; i++) {
      if (!session.uploadedChunks.includes(i)) {
        missingChunks.push(i);
      }
    }
    
    if (missingChunks.length > 0) {
      return sendError(res, `Не загружены части: ${missingChunks.join(", ")}`);
    }
    
    const chunks: Buffer[] = [];
    
    for (let i = 0; i < session.totalChunks; i++) {
      const chunkPath = path.join(tempDir, `chunk_${i}`);
      try {
        const chunkData = await fs.readFile(chunkPath);
        chunks.push(chunkData);
      } catch (err) {
        await storage.markUploadSessionFailed(sessionId);
        await cleanupTempDir();
        return sendError(res, `Часть ${i} не найдена на диске`, 500);
      }
    }
    
    const fileBuffer = Buffer.concat(chunks);

    // Валидация итогового размера файла
    if (fileBuffer.length !== session.fileSize) {
      console.error(`[upload/complete] File size mismatch: expected ${session.fileSize}, got ${fileBuffer.length}`);
      await storage.markUploadSessionFailed(sessionId);
      await cleanupTempDir();
      return sendError(res, `Размер файла не совпадает: ожидалось ${session.fileSize} байт, получено ${fileBuffer.length}`, 400);
    }

    // Дополнительная валидация для медиа-файлов
    const category = session.category;
    if (category === "voice" && fileBuffer.length < MIN_VOICE_FILE_SIZE) {
      console.error(`[upload/complete] Voice file too small: ${fileBuffer.length} bytes`);
      await storage.markUploadSessionFailed(sessionId);
      await cleanupTempDir();
      return sendError(res, "Голосовое сообщение повреждено или слишком короткое", 400);
    }

    // Проверка что аудио-файл содержит больше чем только заголовок (ftyp box = ~28-32 байт)
    if (category === "voice" && fileBuffer.length < 100) {
      console.error(`[upload/complete] Voice file appears truncated: ${fileBuffer.length} bytes (only header)`);
      await storage.markUploadSessionFailed(sessionId);
      await cleanupTempDir();
      return sendError(res, "Голосовое сообщение повреждено (файл обрезан)", 400);
    }

    const user = await storage.getUserById(req.user!.userId);
    const userEmail = user?.email;

    let objectPath: string;
    try {
      objectPath = await objectStorageService.uploadBuffer(
        fileBuffer,
        session.filename,
        session.mimeType,
        userEmail,
        session.category as "avatars" | "images" | "videos" | "voice" | undefined
      );
    } catch (uploadError) {
      console.error("[upload/complete] Object storage upload failed:", uploadError);
      await storage.markUploadSessionFailed(sessionId);
      await cleanupTempDir();
      return sendError(res, "Ошибка загрузки в хранилище", 500);
    }

    await storage.completeUploadSession(sessionId, objectPath);
    await cleanupTempDir();

    return sendSuccess(res, { objectPath });
  } catch (error) {
    console.error("Complete upload error:", error);
    await storage.markUploadSessionFailed(sessionId);
    await cleanupTempDir();
    return sendError(res, "Ошибка завершения загрузки", 500);
  }
});

export function registerObjectRoutes(app: any) {
  app.get("/objects/:objectPath(*)", async (req: Request, res: Response) => {
    try {
      const objectPath = `/objects/${req.params.objectPath}`;
      const objectFile = await objectStorageService.getObjectEntityFile(objectPath);
      await objectStorageService.streamMedia(objectFile, req, res);
    } catch (error) {
      console.error("Get object error:", error);
      if (error instanceof ObjectNotFoundError) {
        return res.sendStatus(404);
      }
      return res.sendStatus(500);
    }
  });

  app.get("/public-objects/:filePath(*)", async (req: Request, res: Response) => {
    const filePath = req.params.filePath;
    try {
      const file = await objectStorageService.searchPublicObject(filePath);
      if (!file) {
        return res.status(404).json({ success: false, error: "Файл не найден" });
      }
      await objectStorageService.downloadObject(file, res);
    } catch (error) {
      console.error("Error searching for public object:", error);
      return res.status(500).json({ success: false, error: "Ошибка сервера" });
    }
  });
}
