import type { Express } from "express";
import type { Server } from "http";
import cors from "cors";

import { authRouter } from "./auth.routes";
import { usersRouter } from "./users.routes";
import { contactsRouter } from "./contacts.routes";
import { chatsRouter } from "./chats.routes";
import { messagesRouter } from "./messages.routes";
import { mediaRouter, registerObjectRoutes } from "./media.routes";
import { debugRouter } from "./debug.routes";
import { generalLimiter, mediaLimiter, authLimiter } from "./limiters";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  const allowedOriginsEnv = process.env.ALLOWED_ORIGINS?.trim();
  const allowedOrigins = allowedOriginsEnv ? allowedOriginsEnv.split(",").map(o => o.trim()) : [];
  const isProduction = process.env.NODE_ENV === "production";
  
  app.use(cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      
      if (!isProduction) return callback(null, true);
      
      if (allowedOrigins.length === 0) return callback(null, true);
      
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      return callback(new Error("CORS not allowed"), false);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }));

  app.use("/api/", generalLimiter);

  app.use("/api/upload", mediaLimiter);
  app.use("/api/media", mediaLimiter);

  app.use("/api/auth/login", authLimiter);
  app.use("/api/auth/register", authLimiter);
  app.use("/api/auth/check-email", authLimiter);

  app.use("/api/auth", authRouter);
  app.use("/api/users", usersRouter);
  app.use("/api/contacts", contactsRouter);
  app.use("/api/chats", chatsRouter);
  app.use("/api/messages", messagesRouter);
  app.use("/api", mediaRouter);
  app.use("/api/debug", debugRouter);

  registerObjectRoutes(app);

  return httpServer;
}
