import { uploadSessions, type UploadSession, type InitUploadInput } from "@shared/schema";
import { db } from "../db";
import { eq, and, lt, not } from "drizzle-orm";

export async function createUploadSession(userId: number, data: InitUploadInput): Promise<UploadSession> {
  const sessionId = crypto.randomUUID();
  const chunkSize = 1048576; // 1 MB
  const totalChunks = Math.ceil(data.fileSize / chunkSize);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  
  const [session] = await db
    .insert(uploadSessions)
    .values({
      id: sessionId,
      userId,
      filename: data.filename,
      fileSize: data.fileSize,
      mimeType: data.mimeType,
      chunkSize,
      totalChunks,
      category: data.category || "files",
      expiresAt,
    })
    .returning();
  
  return session;
}

export async function getUploadSession(sessionId: string): Promise<UploadSession | undefined> {
  const [session] = await db
    .select()
    .from(uploadSessions)
    .where(eq(uploadSessions.id, sessionId));
  return session || undefined;
}

export async function markChunkUploaded(sessionId: string, chunkIndex: number): Promise<UploadSession | undefined> {
  const session = await getUploadSession(sessionId);
  if (!session) return undefined;
  
  const uploadedChunks = session.uploadedChunks || [];
  if (uploadedChunks.includes(chunkIndex)) {
    return session;
  }
  
  const newUploadedChunks = [...uploadedChunks, chunkIndex].sort((a, b) => a - b);
  const newStatus = newUploadedChunks.length === session.totalChunks ? "uploading" : "uploading";
  
  const [updated] = await db
    .update(uploadSessions)
    .set({
      uploadedChunks: newUploadedChunks,
      status: newStatus,
    })
    .where(eq(uploadSessions.id, sessionId))
    .returning();
  
  return updated || undefined;
}

export async function completeUploadSession(sessionId: string, objectPath: string): Promise<UploadSession | undefined> {
  const [updated] = await db
    .update(uploadSessions)
    .set({
      status: "completed",
      objectPath,
      completedAt: new Date(),
    })
    .where(eq(uploadSessions.id, sessionId))
    .returning();
  
  return updated || undefined;
}

export async function markUploadSessionFailed(sessionId: string): Promise<UploadSession | undefined> {
  const [updated] = await db
    .update(uploadSessions)
    .set({
      status: "failed",
    })
    .where(eq(uploadSessions.id, sessionId))
    .returning();
  
  return updated || undefined;
}

export async function getExpiredSessions(): Promise<UploadSession[]> {
  return await db
    .select()
    .from(uploadSessions)
    .where(
      and(
        lt(uploadSessions.expiresAt, new Date()),
        not(eq(uploadSessions.status, "completed"))
      )
    );
}

export async function deleteUploadSession(sessionId: string): Promise<boolean> {
  const result = await db
    .delete(uploadSessions)
    .where(eq(uploadSessions.id, sessionId))
    .returning();
  return result.length > 0;
}
