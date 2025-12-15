import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

// Security: Require SESSION_SECRET in production, use default only in development
const JWT_SECRET = (() => {
  const secret = process.env.SESSION_SECRET;
  const isProduction = process.env.NODE_ENV === "production";
  
  if (!secret && isProduction) {
    throw new Error("CRITICAL: SESSION_SECRET environment variable is required in production");
  }
  
  if (!secret) {
    console.warn("[security] WARNING: Using default JWT secret. Set SESSION_SECRET in production!");
    return "dev-only-secret-do-not-use-in-production";
  }
  
  if (secret.length < 32) {
    console.warn("[security] WARNING: SESSION_SECRET should be at least 32 characters for security");
  }
  
  return secret;
})();

const JWT_EXPIRES_IN = "7d";

export interface JwtPayload {
  userId: number;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

export function generateToken(payload: JwtPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyToken(token: string): JwtPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as JwtPayload;
  } catch {
    return null;
  }
}

export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ success: false, error: "Токен не предоставлен" });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ success: false, error: "Недействительный токен" });
  }

  req.user = payload;
  next();
}
