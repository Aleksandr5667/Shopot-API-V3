import type { Response, Request } from "express";
import { z } from "zod";
import { objectStorageService } from "../objectStorage";

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

/**
 * Get the base URL for absolute URL conversion
 * Uses request host in development, deployment URL in production
 */
export function getBaseUrl(req: Request): string {
  // In production, use the deployment URL
  if (process.env.REPLIT_DEPLOYMENT_URL) {
    const url = process.env.REPLIT_DEPLOYMENT_URL;
    return url.startsWith('http') ? url : `https://${url}`;
  }
  // In development, use request host
  const protocol = req.headers['x-forwarded-proto'] || 'https';
  const host = req.headers.host || req.hostname;
  return `${protocol}://${host}`;
}

/**
 * Convert all media URLs in an object to absolute URLs
 * Recursively processes objects and arrays
 */
export function withAbsoluteUrls<T>(data: T, baseUrl: string): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => withAbsoluteUrls(item, baseUrl)) as T;
  }

  if (typeof data === 'object') {
    const result: any = {};
    for (const [key, value] of Object.entries(data as object)) {
      // Convert URL fields
      if ((key === 'mediaUrl' || key === 'thumbnailUrl' || key === 'avatarUrl') && typeof value === 'string') {
        result[key] = objectStorageService.toAbsoluteUrl(value, baseUrl);
      } else if (typeof value === 'object') {
        result[key] = withAbsoluteUrls(value, baseUrl);
      } else {
        result[key] = value;
      }
    }
    return result as T;
  }

  return data;
}
