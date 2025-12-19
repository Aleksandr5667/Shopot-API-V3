import { Storage, File } from "@google-cloud/storage";
import { Request, Response } from "express";
import { randomUUID } from "crypto";
import {
  ObjectAclPolicy,
  ObjectPermission,
  canAccessObject,
  getObjectAclPolicy,
  setObjectAclPolicy,
} from "./objectAcl";

const REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";

export const objectStorageClient = new Storage({
  credentials: {
    audience: "replit",
    subject_token_type: "access_token",
    token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
    type: "external_account",
    credential_source: {
      url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
      format: {
        type: "json",
        subject_token_field_name: "access_token",
      },
    },
    universe_domain: "googleapis.com",
  },
  projectId: "",
});

export class ObjectNotFoundError extends Error {
  constructor() {
    super("Object not found");
    this.name = "ObjectNotFoundError";
    Object.setPrototypeOf(this, ObjectNotFoundError.prototype);
  }
}

export class ObjectStorageService {
  constructor() {}

  getPublicObjectSearchPaths(): Array<string> {
    const pathsStr = process.env.PUBLIC_OBJECT_SEARCH_PATHS || "";
    const paths = Array.from(
      new Set(
        pathsStr
          .split(",")
          .map((path) => path.trim())
          .filter((path) => path.length > 0)
      )
    );
    if (paths.length === 0) {
      throw new Error(
        "PUBLIC_OBJECT_SEARCH_PATHS not set. Create a bucket in 'Object Storage' " +
          "tool and set PUBLIC_OBJECT_SEARCH_PATHS env var (comma-separated paths)."
      );
    }
    return paths;
  }

  getPrivateObjectDir(): string {
    const dir = process.env.PRIVATE_OBJECT_DIR || "";
    if (!dir) {
      throw new Error(
        "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' " +
          "tool and set PRIVATE_OBJECT_DIR env var."
      );
    }
    return dir;
  }

  async searchPublicObject(filePath: string): Promise<File | null> {
    for (const searchPath of this.getPublicObjectSearchPaths()) {
      const fullPath = `${searchPath}/${filePath}`;

      const { bucketName, objectName } = parseObjectPath(fullPath);
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectName);

      const [exists] = await file.exists();
      if (exists) {
        return file;
      }
    }

    return null;
  }

  async downloadObject(file: File, res: Response, cacheTtlSec: number = 3600) {
    try {
      const [metadata] = await file.getMetadata();
      const aclPolicy = await getObjectAclPolicy(file);
      const isPublic = aclPolicy?.visibility === "public";
      res.set({
        "Content-Type": metadata.contentType || "application/octet-stream",
        "Content-Length": metadata.size,
        "Cache-Control": `${
          isPublic ? "public" : "private"
        }, max-age=${cacheTtlSec}`,
      });

      const stream = file.createReadStream();

      stream.on("error", (err) => {
        console.error("Stream error:", err);
        if (!res.headersSent) {
          res.status(500).json({ success: false, error: "Ошибка загрузки файла" });
        }
      });

      stream.pipe(res);
    } catch (error) {
      console.error("Error downloading file:", error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: "Ошибка загрузки файла" });
      }
    }
  }

  /**
   * Stream media file with Range request support for iOS AVPlayer
   * Supports partial content (206) responses for audio/video streaming
   */
  async streamMedia(file: File, req: Request, res: Response, cacheTtlSec: number = 3600) {
    try {
      const [metadata] = await file.getMetadata();
      const fileSize = parseInt(metadata.size as string, 10);
      const fileName = file.name;
      
      // Determine content type based on file extension
      let contentType = metadata.contentType || "application/octet-stream";
      const ext = fileName.split('.').pop()?.toLowerCase();
      
      // Override content type for common media formats
      const mimeTypes: Record<string, string> = {
        'm4a': 'audio/mp4',
        'mp3': 'audio/mpeg',
        'mp4': 'video/mp4',
        'mov': 'video/quicktime',
        'aac': 'audio/aac',
        'wav': 'audio/wav',
        'webm': 'video/webm',
        'ogg': 'audio/ogg',
        '3gp': 'video/3gpp',
      };
      
      if (ext && mimeTypes[ext]) {
        contentType = mimeTypes[ext];
      }

      const aclPolicy = await getObjectAclPolicy(file);
      const isPublic = aclPolicy?.visibility === "public";
      const cacheControl = `${isPublic ? "public" : "private"}, max-age=${cacheTtlSec}`;

      const rangeHeader = req.headers.range;

      if (rangeHeader) {
        // Parse Range header (e.g., "bytes=0-1023")
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

        // Validate range
        if (start >= fileSize || end >= fileSize || start > end) {
          res.status(416).set({
            "Content-Range": `bytes */${fileSize}`,
          }).end();
          return;
        }

        const chunkSize = end - start + 1;

        res.status(206).set({
          "Content-Type": contentType,
          "Content-Length": chunkSize,
          "Content-Range": `bytes ${start}-${end}/${fileSize}`,
          "Accept-Ranges": "bytes",
          "Cache-Control": cacheControl,
        });

        const stream = file.createReadStream({ start, end });

        // Обработка ошибок стриминга
        stream.on("error", (err) => {
          console.error(`[streamMedia] Stream error (range ${start}-${end}):`, err);
          // После начала стриминга нельзя отправить JSON - просто закрываем соединение
          if (!res.headersSent) {
            res.status(500).json({ success: false, error: "Ошибка загрузки файла" });
          } else {
            // Заголовки уже отправлены - уничтожаем соединение
            res.destroy();
          }
        });

        // Обработка разрыва соединения клиентом
        req.on("close", () => {
          if (!stream.destroyed) {
            console.log(`[streamMedia] Client disconnected, destroying stream for range ${start}-${end}`);
            stream.destroy();
          }
        });

        // Таймаут для предотвращения зависания (5 минут для больших файлов)
        const timeout = setTimeout(() => {
          if (!stream.destroyed) {
            const sizeMB = (fileSize / 1024 / 1024).toFixed(2);
            console.error(`[streamMedia] Timeout streaming file ${fileName} (${sizeMB} MB, range ${start}-${end})`);
            stream.destroy();
            res.destroy();
          }
        }, 300000); // 5 минут

        // Очистка таймаута при завершении
        stream.on("end", () => {
          clearTimeout(timeout);
        });

        stream.pipe(res);
      } else {
        // No Range header - send full file with Accept-Ranges header
        res.status(200).set({
          "Content-Type": contentType,
          "Content-Length": fileSize,
          "Accept-Ranges": "bytes",
          "Cache-Control": cacheControl,
        });

        const stream = file.createReadStream();

        // Обработка ошибок стриминга
        stream.on("error", (err) => {
          console.error(`[streamMedia] Stream error (full file ${fileSize} bytes):`, err);
          // После начала стриминга нельзя отправить JSON - просто закрываем соединение
          if (!res.headersSent) {
            res.status(500).json({ success: false, error: "Ошибка загрузки файла" });
          } else {
            // Заголовки уже отправлены - уничтожаем соединение
            res.destroy();
          }
        });

        // Обработка разрыва соединения клиентом
        req.on("close", () => {
          if (!stream.destroyed) {
            console.log(`[streamMedia] Client disconnected, destroying stream for full file`);
            stream.destroy();
          }
        });

        // Таймаут для предотвращения зависания (5 минут для больших файлов)
        const timeout = setTimeout(() => {
          if (!stream.destroyed) {
            const sizeMB = (fileSize / 1024 / 1024).toFixed(2);
            console.error(`[streamMedia] Timeout streaming file ${fileName} (${sizeMB} MB)`);
            stream.destroy();
            res.destroy();
          }
        }, 300000); // 5 минут

        // Очистка таймаута при завершении
        stream.on("end", () => {
          clearTimeout(timeout);
        });

        stream.pipe(res);
      }
    } catch (error) {
      console.error("[streamMedia] Error streaming media file:", error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, error: "Ошибка загрузки файла" });
      } else {
        res.destroy();
      }
    }
  }

  /**
   * Sanitize email for use as folder name
   * Replaces @ with _at_ and . with _
   * Example: user@example.com -> user_at_example_com
   */
  private sanitizeEmailForFolder(email: string): string {
    return email
      .toLowerCase()
      .replace(/@/g, '_at_')
      .replace(/\./g, '_')
      .replace(/[^a-z0-9_-]/g, '_');
  }

  /**
   * Get upload URL organized by user email folders
   * Structure: /users/{email}/{category}/{uuid}.{ext}
   * Categories: avatars, images, videos, voice, files (default)
   * 
   * Example: /users/ivan_at_mail_ru/images/abc123.jpg
   */
  async getObjectEntityUploadURL(
    filename?: string,
    userEmail?: string,
    category?: "avatars" | "images" | "videos" | "voice"
  ): Promise<{ uploadURL: string; objectPath: string }> {
    const privateObjectDir = this.getPrivateObjectDir();
    if (!privateObjectDir) {
      throw new Error(
        "PRIVATE_OBJECT_DIR not set. Create a bucket in 'Object Storage' " +
          "tool and set PRIVATE_OBJECT_DIR env var."
      );
    }

    const objectId = randomUUID();
    const extension = filename ? filename.split('.').pop() : '';
    const objectName = extension ? `${objectId}.${extension}` : objectId;
    
    // Always organize by user email folders if email provided
    // Use category if provided, otherwise use "files" as default
    let folderPath: string;
    if (userEmail) {
      const sanitizedEmail = this.sanitizeEmailForFolder(userEmail);
      const folderCategory = category || "files";
      folderPath = `users/${sanitizedEmail}/${folderCategory}`;
    } else {
      folderPath = "uploads";
    }
    
    const objectPath = `${folderPath}/${objectName}`;
    const fullPath = `${privateObjectDir}/${objectPath}`;

    const { bucketName, objectName: objName } = parseObjectPath(fullPath);

    const uploadURL = await signObjectURL({
      bucketName,
      objectName: objName,
      method: "PUT",
      ttlSec: 900,
    });

    return { uploadURL, objectPath };
  }

  async getObjectEntityFile(objectPath: string): Promise<File> {
    if (!objectPath.startsWith("/objects/")) {
      throw new ObjectNotFoundError();
    }

    const parts = objectPath.slice(1).split("/");
    if (parts.length < 2) {
      throw new ObjectNotFoundError();
    }

    const entityId = parts.slice(1).join("/");
    let entityDir = this.getPrivateObjectDir();
    if (!entityDir.endsWith("/")) {
      entityDir = `${entityDir}/`;
    }
    const objectEntityPath = `${entityDir}${entityId}`;
    const { bucketName, objectName } = parseObjectPath(objectEntityPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const objectFile = bucket.file(objectName);
    const [exists] = await objectFile.exists();
    if (!exists) {
      throw new ObjectNotFoundError();
    }
    return objectFile;
  }

  normalizeObjectEntityPath(rawPath: string): string {
    if (!rawPath.startsWith("https://storage.googleapis.com/")) {
      return rawPath;
    }

    const url = new URL(rawPath);
    const rawObjectPath = url.pathname;

    let objectEntityDir = this.getPrivateObjectDir();
    if (!objectEntityDir.endsWith("/")) {
      objectEntityDir = `${objectEntityDir}/`;
    }

    if (!rawObjectPath.startsWith(objectEntityDir)) {
      return rawObjectPath;
    }

    const entityId = rawObjectPath.slice(objectEntityDir.length);
    return `/objects/${entityId}`;
  }

  async trySetObjectEntityAclPolicy(
    rawPath: string,
    aclPolicy: ObjectAclPolicy
  ): Promise<string> {
    const normalizedPath = this.normalizeObjectEntityPath(rawPath);
    if (!normalizedPath.startsWith("/")) {
      return normalizedPath;
    }

    const objectFile = await this.getObjectEntityFile(normalizedPath);
    await setObjectAclPolicy(objectFile, aclPolicy);
    return normalizedPath;
  }

  async canAccessObjectEntity({
    userId,
    objectFile,
    requestedPermission,
  }: {
    userId?: string;
    objectFile: File;
    requestedPermission?: ObjectPermission;
  }): Promise<boolean> {
    return canAccessObject({
      userId,
      objectFile,
      requestedPermission: requestedPermission ?? ObjectPermission.READ,
    });
  }

  /**
   * Normalize media URL to relative path
   * Converts absolute URLs to relative paths for storage
   * - Absolute URL: https://server.repl.co/objects/uploads/filename -> /objects/uploads/filename
   * - Relative path: /objects/uploads/filename -> /objects/uploads/filename (unchanged)
   * - Other URLs: returned as-is
   */
  normalizeMediaUrl(mediaUrl: string): string {
    if (!mediaUrl) return mediaUrl;
    
    // Already a relative path - return as-is
    if (mediaUrl.startsWith('/objects/')) {
      return mediaUrl;
    }
    
    try {
      const url = new URL(mediaUrl);
      const pathMatch = url.pathname.match(/(\/objects\/.+)$/);
      if (pathMatch && pathMatch[1]) {
        return pathMatch[1];
      }
    } catch {
      // Not a valid URL, return as-is
    }
    
    return mediaUrl;
  }

  /**
   * Extract object key from media URL or path
   * Supports both absolute URLs and relative paths:
   * - Absolute URL: https://server.repl.co/objects/uploads/filename
   * - Relative path: /objects/uploads/filename
   * Returns: uploads/filename
   */
  extractObjectKeyFromUrl(mediaUrl: string): string | null {
    try {
      // Handle relative paths (e.g., /objects/uploads/filename)
      if (mediaUrl.startsWith('/objects/')) {
        const key = mediaUrl.slice('/objects/'.length);
        return key || null;
      }
      
      // Handle absolute URLs (e.g., https://server.repl.co/objects/uploads/filename)
      const url = new URL(mediaUrl);
      const pathMatch = url.pathname.match(/\/objects\/(.+)$/);
      if (pathMatch && pathMatch[1]) {
        return pathMatch[1];
      }
      return null;
    } catch (error) {
      console.error("[objectStorage] Error parsing media URL:", error);
      return null;
    }
  }

  /**
   * Delete an object from storage by its key
   * @param objectKey - The object key (e.g., "uploads/filename.jpg")
   * @returns true if deleted successfully, false if not found or error
   */
  async deleteObject(objectKey: string): Promise<boolean> {
    try {
      const privateObjectDir = this.getPrivateObjectDir();
      const fullPath = `${privateObjectDir}/${objectKey}`;
      
      const { bucketName, objectName } = parseObjectPath(fullPath);
      const bucket = objectStorageClient.bucket(bucketName);
      const file = bucket.file(objectName);
      
      const [exists] = await file.exists();
      if (!exists) {
        console.log(`[objectStorage] Object not found for deletion: ${objectKey}`);
        return false;
      }
      
      await file.delete();
      console.log(`[objectStorage] Successfully deleted object: ${objectKey}`);
      return true;
    } catch (error) {
      console.error(`[objectStorage] Error deleting object ${objectKey}:`, error);
      return false;
    }
  }

  /**
   * Delete object by its media URL
   * @param mediaUrl - The full media URL
   * @returns true if deleted successfully, false otherwise
   */
  async deleteObjectByUrl(mediaUrl: string): Promise<boolean> {
    const objectKey = this.extractObjectKeyFromUrl(mediaUrl);
    if (!objectKey) {
      console.log(`[objectStorage] Could not extract object key from URL: ${mediaUrl}`);
      return false;
    }
    return this.deleteObject(objectKey);
  }

  /**
   * Upload a buffer directly to object storage
   * @param buffer - The file buffer to upload
   * @param filename - Original filename
   * @param mimeType - MIME type of the file
   * @param userEmail - Optional user email for folder organization
   * @param category - Optional category for folder organization
   * @returns The object path that can be used to access the file
   */
  async uploadBuffer(
    buffer: Buffer,
    filename: string,
    mimeType: string,
    userEmail?: string,
    category?: "avatars" | "images" | "videos" | "voice"
  ): Promise<string> {
    const privateObjectDir = this.getPrivateObjectDir();
    const userFolder = userEmail ? userEmail.replace(/@/g, "_at_").replace(/\./g, "_") : "anonymous";
    const categoryFolder = category || "files";
    
    const ext = filename.substring(filename.lastIndexOf(".")) || "";
    const uniqueFilename = `${crypto.randomUUID()}${ext}`;
    
    const objectName = `users/${userFolder}/${categoryFolder}/${uniqueFilename}`;
    const fullPath = `${privateObjectDir}/${objectName}`;
    
    const { bucketName, objectName: gcsObjectName } = parseObjectPath(fullPath);
    const bucket = objectStorageClient.bucket(bucketName);
    const file = bucket.file(gcsObjectName);
    
    await file.save(buffer, {
      contentType: mimeType,
      resumable: false,
    });
    
    console.log(`[objectStorage] Successfully uploaded buffer to: ${objectName}`);
    return `/objects/${objectName}`;
  }
}

function parseObjectPath(path: string): {
  bucketName: string;
  objectName: string;
} {
  if (!path.startsWith("/")) {
    path = `/${path}`;
  }
  const pathParts = path.split("/");
  if (pathParts.length < 3) {
    throw new Error("Invalid path: must contain at least a bucket name");
  }

  const bucketName = pathParts[1];
  const objectName = pathParts.slice(2).join("/");

  return {
    bucketName,
    objectName,
  };
}

async function signObjectURL({
  bucketName,
  objectName,
  method,
  ttlSec,
}: {
  bucketName: string;
  objectName: string;
  method: "GET" | "PUT" | "DELETE" | "HEAD";
  ttlSec: number;
}): Promise<string> {
  const request = {
    bucket_name: bucketName,
    object_name: objectName,
    method,
    expires_at: new Date(Date.now() + ttlSec * 1000).toISOString(),
  };
  const response = await fetch(
    `${REPLIT_SIDECAR_ENDPOINT}/object-storage/signed-object-url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    throw new Error(
      `Failed to sign object URL, errorcode: ${response.status}, ` +
        `make sure you're running on Replit`
    );
  }

  const { signed_url: signedURL } = await response.json();
  return signedURL;
}
