import type { Response } from "express";
import { z } from "zod";

export function sendSuccess(res: Response, data: any, status: number = 200) {
  return res.status(status).json({ success: true, data });
}

export function sendError(res: Response, error: string, status: number = 400) {
  return res.status(status).json({ success: false, error });
}

export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 100;

export function parseLimit(limitParam: unknown): number {
  if (!limitParam) return DEFAULT_PAGE_LIMIT;
  const parsed = parseInt(limitParam as string);
  if (isNaN(parsed) || parsed < 1) return DEFAULT_PAGE_LIMIT;
  return Math.min(parsed, MAX_PAGE_LIMIT);
}

export const chatsCursorSchema = z.object({
  updatedAt: z.string(),
  id: z.number()
});

export const contactsCursorSchema = z.object({
  createdAt: z.string(),
  id: z.number()
});

export const messagesCursorSchema = z.object({
  createdAt: z.string(),
  id: z.number()
});

export function parseCursor<T>(cursorParam: unknown, schema: z.ZodSchema<T>): { cursor?: T; error?: string } {
  if (!cursorParam || typeof cursorParam !== 'string') return {};
  try {
    const decoded = Buffer.from(cursorParam, 'base64').toString('utf-8');
    const parsed = JSON.parse(decoded);
    const result = schema.safeParse(parsed);
    if (!result.success) {
      return { error: "Invalid cursor format" };
    }
    return { cursor: result.data };
  } catch {
    return { error: "Invalid cursor encoding" };
  }
}
