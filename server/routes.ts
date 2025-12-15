import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { authenticateToken, generateToken, JwtPayload } from "./auth";
import { ObjectStorageService, ObjectNotFoundError } from "./objectStorage";
import { getWebSocketService } from "./websocket";
import bcrypt from "bcrypt";
import { z } from "zod";
import {
  insertUserSchema,
  loginSchema,
  updateProfileSchema,
  insertContactSchema,
  insertChatSchema,
  insertMessageSchema,
  type ChatsCursor,
  type ContactsCursor,
  type MessagesCursor,
} from "@shared/schema";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { generateVerificationCode, sendVerificationEmail, sendPasswordResetEmail } from "./emailService";

function sendSuccess(res: Response, data: any, status: number = 200) {
  return res.status(status).json({ success: true, data });
}

function sendError(res: Response, error: string, status: number = 400) {
  return res.status(status).json({ success: false, error });
}

// Pagination constants
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 100;

function parseLimit(limitParam: unknown): number {
  if (!limitParam) return DEFAULT_PAGE_LIMIT;
  const parsed = parseInt(limitParam as string);
  if (isNaN(parsed) || parsed < 1) return DEFAULT_PAGE_LIMIT;
  return Math.min(parsed, MAX_PAGE_LIMIT);
}

const chatsCursorSchema = z.object({
  updatedAt: z.string(),
  id: z.number()
});

const contactsCursorSchema = z.object({
  createdAt: z.string(),
  id: z.number()
});

const messagesCursorSchema = z.object({
  createdAt: z.string(),
  id: z.number()
});

function parseCursor<T>(cursorParam: unknown, schema: z.ZodSchema<T>): { cursor?: T; error?: string } {
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

// Rate limiters for security
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window for auth endpoints
  message: { success: false, error: "Слишком много попыток. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { success: false, error: "Слишком много запросов. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip general limiter for media endpoints (they have their own limiter)
    return req.path.startsWith('/api/upload') || req.path.startsWith('/api/media');
  },
});

const emailLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1, // 1 email per minute per IP
  message: { success: false, error: "Подождите минуту перед повторной отправкой кода." },
  standardHeaders: true,
  legacyHeaders: false,
});

const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute for search
  message: { success: false, error: "Слишком много поисковых запросов. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Separate rate limiter for media upload endpoints (more permissive)
const mediaLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 50, // 50 requests per minute for media operations
  message: { success: false, error: "Слишком много запросов загрузки. Попробуйте позже." },
  standardHeaders: true,
  legacyHeaders: false,
});

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // Security: Configure CORS with allowed origins from environment
  const allowedOriginsEnv = process.env.ALLOWED_ORIGINS?.trim();
  const allowedOrigins = allowedOriginsEnv ? allowedOriginsEnv.split(",").map(o => o.trim()) : [];
  const isProduction = process.env.NODE_ENV === "production";
  
  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);
      
      // In development, allow all origins
      if (!isProduction) return callback(null, true);
      
      // In production, if ALLOWED_ORIGINS is not configured, allow all origins
      // This is useful for public APIs accessed by various clients
      if (allowedOrigins.length === 0) return callback(null, true);
      
      // In production with ALLOWED_ORIGINS set, check against the list
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      // Reject unknown origins in production when ALLOWED_ORIGINS is configured
      return callback(new Error("CORS not allowed"), false);
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }));

  // Apply general rate limiting to all API routes
  app.use("/api/", generalLimiter);

  // Apply separate rate limiting for media endpoints (more permissive)
  app.use("/api/upload", mediaLimiter);
  app.use("/api/media", mediaLimiter);

  // Apply stricter rate limiting to auth endpoints (brute-force protection)
  app.use("/api/auth/login", authLimiter);
  app.use("/api/auth/register", authLimiter);
  app.use("/api/auth/check-email", authLimiter);

  app.post("/api/auth/register", async (req: Request, res: Response) => {
    try {
      const validation = insertUserSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const existingUser = await storage.getUserByEmail(validation.data.email);
      if (existingUser) {
        return sendError(res, "Email уже зарегистрирован");
      }

      const user = await storage.createUser(validation.data);
      const token = generateToken({ userId: user.id, email: user.email });

      return sendSuccess(res, { user, token }, 201);
    } catch (error) {
      console.error("Register error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Check email availability (public endpoint for registration screen)
  const checkEmailSchema = z.object({
    email: z.string().email("Некорректный email"),
  });

  app.post("/api/auth/check-email", async (req: Request, res: Response) => {
    try {
      const validation = checkEmailSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const existingUser = await storage.getUserByEmail(validation.data.email);
      return sendSuccess(res, { available: !existingUser });
    } catch (error) {
      console.error("Check email error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.post("/api/auth/login", async (req: Request, res: Response) => {
    try {
      const validation = loginSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { email, password } = validation.data;

      // Check if account is locked
      const lockStatus = await storage.isAccountLocked(email);
      if (lockStatus.locked) {
        const minutesLeft = lockStatus.lockedUntil 
          ? Math.ceil((lockStatus.lockedUntil.getTime() - Date.now()) / 60000)
          : 15;
        return sendError(res, `Слишком много попыток. Попробуйте через ${minutesLeft} минут.`, 429);
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return sendError(res, "Пользователь не найден", 404);
      }

      const isValidPassword = await bcrypt.compare(password, user.passwordHash);
      if (!isValidPassword) {
        // Increment failed attempts
        const result = await storage.incrementFailedLoginAttempts(email);
        const attemptsLeft = 5 - result.attempts;
        
        if (result.lockedUntil) {
          return sendError(res, "Слишком много попыток. Попробуйте через 15 минут.", 429);
        }
        
        return sendError(res, `Неверный пароль. Осталось попыток: ${attemptsLeft}`, 401);
      }

      // Reset failed attempts on successful login
      await storage.resetFailedLoginAttempts(email);
      await storage.updateLastSeen(user.id);
      const token = generateToken({ userId: user.id, email: user.email });
      const { passwordHash, ...publicUser } = user;

      return sendSuccess(res, { user: publicUser, token });
    } catch (error) {
      console.error("Login error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.get("/api/auth/me", authenticateToken, async (req: Request, res: Response) => {
    try {
      const user = await storage.getUserById(req.user!.userId);
      if (!user) {
        return sendError(res, "Пользователь не найден", 404);
      }

      await storage.updateLastSeen(req.user!.userId);
      return sendSuccess(res, { user });
    } catch (error) {
      console.error("Get me error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  const sendVerificationSchema = z.object({
    email: z.string().email("Некорректный email"),
  });

  app.post("/api/auth/send-verification", emailLimiter, async (req: Request, res: Response) => {
    try {
      const validation = sendVerificationSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { email } = validation.data;

      const lastCodeTime = await storage.getLastVerificationCodeTime(email, "email_verification");
      if (lastCodeTime) {
        const timeSinceLastCode = Date.now() - lastCodeTime.getTime();
        if (timeSinceLastCode < 60000) {
          const secondsLeft = Math.ceil((60000 - timeSinceLastCode) / 1000);
          return sendError(res, `Подождите ${secondsLeft} секунд перед повторной отправкой`);
        }
      }

      const code = generateVerificationCode();
      await storage.createVerificationCode(email, code, "email_verification");

      const sent = await sendVerificationEmail(email, code);
      if (!sent) {
        return sendError(res, "Ошибка отправки email", 500);
      }

      return sendSuccess(res, { message: "Код отправлен на email" });
    } catch (error) {
      console.error("Send verification error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  const verifyEmailSchema = z.object({
    email: z.string().email("Некорректный email"),
    code: z.string().length(6, "Код должен содержать 6 цифр"),
  });

  app.post("/api/auth/verify-email", authLimiter, async (req: Request, res: Response) => {
    try {
      const validation = verifyEmailSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { email, code } = validation.data;

      const verificationCode = await storage.getValidVerificationCode(email, code, "email_verification");
      if (!verificationCode) {
        return sendError(res, "Неверный или истёкший код");
      }

      await storage.markVerificationCodeUsed(verificationCode.id);

      const user = await storage.getUserByEmail(email);
      if (user) {
        await storage.markEmailVerified(user.id);
      }

      return sendSuccess(res, { verified: true, message: "Email успешно подтверждён" });
    } catch (error) {
      console.error("Verify email error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.post("/api/auth/password-reset/request", emailLimiter, async (req: Request, res: Response) => {
    try {
      const validation = sendVerificationSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { email } = validation.data;

      const lastCodeTime = await storage.getLastVerificationCodeTime(email, "password_reset");
      if (lastCodeTime) {
        const timeSinceLastCode = Date.now() - lastCodeTime.getTime();
        if (timeSinceLastCode < 60000) {
          return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
        }
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
      }

      const code = generateVerificationCode();
      await storage.createVerificationCode(email, code, "password_reset");

      const sent = await sendPasswordResetEmail(email, code);
      if (!sent) {
        console.error("[password-reset] Failed to send email to:", email);
        return sendError(res, "Ошибка отправки email", 500);
      }

      return sendSuccess(res, { message: "Если email зарегистрирован, код будет отправлен" });
    } catch (error) {
      console.error("Password reset request error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  const passwordResetConfirmSchema = z.object({
    email: z.string().email("Некорректный email"),
    code: z.string().length(6, "Код должен содержать 6 цифр"),
    newPassword: z.string().min(8, "Пароль должен быть не менее 8 символов"),
  });

  app.post("/api/auth/password-reset/confirm", authLimiter, async (req: Request, res: Response) => {
    try {
      const validation = passwordResetConfirmSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { email, code, newPassword } = validation.data;

      const verificationCode = await storage.getValidVerificationCode(email, code, "password_reset");
      if (!verificationCode) {
        return sendError(res, "Неверный или истёкший код");
      }

      const user = await storage.getUserByEmail(email);
      if (!user) {
        return sendError(res, "Пользователь не найден", 404);
      }

      const newPasswordHash = await bcrypt.hash(newPassword, 10);
      const updated = await storage.updateUserPassword(email, newPasswordHash);

      if (!updated) {
        return sendError(res, "Ошибка обновления пароля", 500);
      }

      await storage.markVerificationCodeUsed(verificationCode.id);

      return sendSuccess(res, { message: "Пароль успешно изменён" });
    } catch (error) {
      console.error("Password reset confirm error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.get("/api/users/search", authenticateToken, searchLimiter, async (req: Request, res: Response) => {
    try {
      const emailParam = req.query.email as string;
      const term = emailParam?.trim().toLowerCase() || "";
      
      if (term.length < 3) {
        return sendSuccess(res, { users: [] });
      }

      const limit = Math.min(parseInt(req.query.limit as string) || 20, 50);
      const users = await storage.searchUsersByEmail(term, req.user!.userId, limit);
      return sendSuccess(res, { users });
    } catch (error) {
      console.error("Search users error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.put("/api/users/profile", authenticateToken, async (req: Request, res: Response) => {
    try {
      const validation = updateProfileSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const user = await storage.updateProfile(req.user!.userId, validation.data);
      if (!user) {
        return sendError(res, "Пользователь не найден", 404);
      }

      return sendSuccess(res, { user });
    } catch (error) {
      console.error("Update profile error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.get("/api/contacts", authenticateToken, async (req: Request, res: Response) => {
    try {
      const limit = parseLimit(req.query.limit);
      const { cursor, error } = parseCursor(req.query.cursor, contactsCursorSchema);
      if (error) {
        return sendError(res, error);
      }
      
      const result = await storage.getContactsPaginated(req.user!.userId, limit, cursor);
      return sendSuccess(res, { 
        contacts: result.contacts,
        pageInfo: result.pageInfo
      });
    } catch (error) {
      console.error("Get contacts error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.post("/api/contacts", authenticateToken, async (req: Request, res: Response) => {
    try {
      const validation = insertContactSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const contactUser = await storage.getUserById(validation.data.contactUserId);
      if (!contactUser) {
        return sendError(res, "Пользователь не найден", 404);
      }

      if (validation.data.contactUserId === req.user!.userId) {
        return sendError(res, "Нельзя добавить себя в контакты");
      }

      const existingContacts = await storage.getContacts(req.user!.userId);
      const alreadyExists = existingContacts.some(
        (c) => c.contactUserId === validation.data.contactUserId
      );
      if (alreadyExists) {
        return sendError(res, "Контакт уже добавлен");
      }

      const contact = await storage.addContact(req.user!.userId, validation.data.contactUserId);
      return sendSuccess(res, { contact, contactUser }, 201);
    } catch (error) {
      console.error("Add contact error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.delete("/api/contacts/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const contactId = parseInt(req.params.id);
      if (isNaN(contactId)) {
        return sendError(res, "Некорректный ID контакта");
      }

      const deleted = await storage.removeContact(contactId, req.user!.userId);
      if (!deleted) {
        return sendError(res, "Контакт не найден", 404);
      }

      return sendSuccess(res, { deleted: true });
    } catch (error) {
      console.error("Delete contact error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.get("/api/chats", authenticateToken, async (req: Request, res: Response) => {
    try {
      const limit = parseLimit(req.query.limit);
      const { cursor, error } = parseCursor(req.query.cursor, chatsCursorSchema);
      if (error) {
        return sendError(res, error);
      }
      
      const result = await storage.getChatsForUserPaginated(req.user!.userId, limit, cursor);
      return sendSuccess(res, { 
        chats: result.chats,
        pageInfo: result.pageInfo
      });
    } catch (error) {
      console.error("Get chats error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.post("/api/chats", authenticateToken, async (req: Request, res: Response) => {
    try {
      const validation = insertChatSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { type, name, avatarColor, memberIds } = validation.data;

      if (type === "private" && memberIds.length !== 1) {
        return sendError(res, "Для приватного чата нужен ровно один участник");
      }

      if (type === "private") {
        const existingChat = await storage.findPrivateChat(req.user!.userId, memberIds[0]);
        if (existingChat) {
          return sendSuccess(res, { chat: existingChat, existing: true });
        }
      }

      for (const memberId of memberIds) {
        const user = await storage.getUserById(memberId);
        if (!user) {
          return sendError(res, `Пользователь с ID ${memberId} не найден`, 404);
        }
      }

      const chat = await storage.createChat(
        type || "private",
        name || null,
        avatarColor || "#3B82F6",
        req.user!.userId,
        memberIds,
        req.body.description || null
      );

      return sendSuccess(res, { chat }, 201);
    } catch (error) {
      console.error("Create chat error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.get("/api/chats/:id/messages", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
      const beforeParam = req.query.before as string;
      const before = beforeParam ? new Date(beforeParam) : undefined;

      // Validate before date if provided
      if (beforeParam && isNaN(before!.getTime())) {
        return sendError(res, "Некорректный формат даты before");
      }

      const messages = await storage.getChatMessages(chatId, limit, before);
      return sendSuccess(res, { messages });
    } catch (error) {
      console.error("Get messages error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.delete("/api/chats/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const { deleted, mediaUrls, memberIds } = await storage.deleteChat(chatId, req.user!.userId);

      if (!deleted) {
        return sendError(res, "Чат не найден", 404);
      }

      // Delete all media files from Object Storage
      for (const mediaUrl of mediaUrls) {
        try {
          const objectKey = objectStorageService.extractObjectKeyFromUrl(mediaUrl);
          if (objectKey) {
            const deleteResult = await objectStorageService.deleteObject(objectKey);
            if (deleteResult) {
              console.log(`[deleteChat] Deleted media file: ${objectKey}`);
            } else {
              console.log(`[deleteChat] Media file not found: ${objectKey}`);
            }
          }
        } catch (mediaError) {
          console.error(`[deleteChat] Error deleting media file ${mediaUrl}:`, mediaError);
        }
      }

      // Notify all chat members via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        wsService.notifyChatDeleted(chatId, memberIds);
      }

      return sendSuccess(res, {});
    } catch (error) {
      console.error("Delete chat error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Get chat with members (for group info)
  app.get("/api/chats/:id/details", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chatWithMembers = await storage.getChatWithMembers(chatId, req.user!.userId);
      if (!chatWithMembers) {
        return sendError(res, "Чат не найден", 404);
      }

      return sendSuccess(res, { chat: chatWithMembers });
    } catch (error) {
      console.error("Get chat details error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Update group chat (name, description) - creator only
  app.patch("/api/chats/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Редактировать можно только групповые чаты", 400);
      }

      // Only creator can edit group settings
      if (chat.createdBy !== req.user!.userId) {
        return sendError(res, "Только создатель может редактировать чат", 403);
      }

      const { name, description } = req.body;
      const updateData: { name?: string; description?: string } = {};
      if (name !== undefined) updateData.name = name;
      if (description !== undefined) updateData.description = description;

      const updated = await storage.updateChat(chatId, updateData);
      if (!updated) {
        return sendError(res, "Ошибка обновления", 500);
      }

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        const memberIds = await storage.getChatMemberIds(chatId);
        wsService.notifyChatUpdated(chatId, updated, memberIds);
      }

      return sendSuccess(res, { chat: updated });
    } catch (error) {
      console.error("Update chat error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Add members to group - creator or admin
  app.post("/api/chats/:id/members", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Добавлять участников можно только в групповые чаты", 400);
      }

      // Creator or admin can add members
      const isCreator = chat.createdBy === req.user!.userId;
      const isAdmin = await storage.isUserChatAdmin(chatId, req.user!.userId);
      if (!isCreator && !isAdmin) {
        return sendError(res, "Только создатель или администратор может добавлять участников", 403);
      }

      const { userIds } = req.body;
      if (!Array.isArray(userIds) || userIds.length === 0) {
        return sendError(res, "userIds должен быть непустым массивом");
      }

      // Validate all users exist
      for (const userId of userIds) {
        const user = await storage.getUserById(userId);
        if (!user) {
          return sendError(res, `Пользователь с ID ${userId} не найден`, 404);
        }
      }

      const result = await storage.addChatMembers(chatId, userIds, req.user!.userId);

      if (result.error) {
        return sendError(res, result.error, 400);
      }

      // Create system messages for each added member
      const addedByUser = await storage.getUserById(req.user!.userId);
      for (const member of result.added) {
        const systemContent = `${addedByUser?.displayName || 'Администратор'} добавил(а) ${member.user.displayName}`;
        const systemMsg = await storage.createSystemMessage(chatId, systemContent);
        
        const wsService = getWebSocketService();
        if (wsService) {
          wsService.broadcastToChat(chatId, {
            type: "new_message",
            payload: { message: systemMsg },
          });
        }
      }

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService && result.added.length > 0) {
        const memberIds = await storage.getChatMemberIds(chatId);
        wsService.notifyMembersAdded(chatId, result.added, req.user!.userId, memberIds);
      }

      return sendSuccess(res, { addedMembers: result.added });
    } catch (error) {
      console.error("Add members error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Remove member from group - creator only
  app.delete("/api/chats/:id/members/:userId", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      const userId = parseInt(req.params.userId);
      if (isNaN(chatId) || isNaN(userId)) {
        return sendError(res, "Некорректные ID");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Удалять участников можно только из групповых чатов", 400);
      }

      // Only creator can remove members
      if (chat.createdBy !== req.user!.userId) {
        return sendError(res, "Only the group creator can remove members", 403);
      }

      if (userId === req.user!.userId) {
        return sendError(res, "Нельзя удалить самого себя, используйте выход из группы", 400);
      }

      // Cannot remove the creator
      if (userId === chat.createdBy) {
        return sendError(res, "Cannot remove the group creator", 403);
      }

      const memberIdsBefore = await storage.getChatMemberIds(chatId);
      const removedUser = await storage.getUserById(userId);
      const removed = await storage.removeChatMember(chatId, userId);
      if (!removed) {
        return sendError(res, "Участник не найден", 404);
      }

      // Create system message
      const adminUser = await storage.getUserById(req.user!.userId);
      const systemContent = `${adminUser?.displayName || 'Администратор'} удалил(а) ${removedUser?.displayName || 'пользователя'}`;
      const systemMsg = await storage.createSystemMessage(chatId, systemContent);

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        wsService.notifyMemberRemoved(chatId, userId, req.user!.userId, memberIdsBefore);
        wsService.broadcastToChat(chatId, {
          type: "new_message",
          payload: { message: systemMsg },
        });
      }

      return sendSuccess(res, {});
    } catch (error) {
      console.error("Remove member error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Change member role - creator only
  app.put("/api/chats/:chatId/members/:userId/role", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.chatId);
      const userId = parseInt(req.params.userId);
      if (isNaN(chatId) || isNaN(userId)) {
        return sendError(res, "Некорректные ID");
      }

      const { role } = req.body;
      if (!role || !["admin", "member"].includes(role)) {
        return sendError(res, "Некорректная роль. Допустимые значения: admin, member");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Chat not found", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Изменять роли можно только в групповых чатах", 400);
      }

      // Only creator can change roles
      if (chat.createdBy !== req.user!.userId) {
        return sendError(res, "Only the group creator can change member roles", 403);
      }

      // Check if target user is a member
      const targetRole = await storage.getChatMemberRole(chatId, userId);
      if (!targetRole) {
        return sendError(res, "Member not found", 404);
      }

      // Cannot change creator's role
      if (chat.createdBy === userId) {
        return sendError(res, "Cannot change the creator's role", 403);
      }

      // Update the role
      const updated = await storage.updateMemberRole(chatId, userId, role);
      if (!updated) {
        return sendError(res, "Не удалось обновить роль", 500);
      }

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        const memberIds = await storage.getChatMemberIds(chatId);
        wsService.notifyGroupRoleChanged(chatId, userId, role, req.user!.userId, memberIds);
      }

      return sendSuccess(res, { updated: true });
    } catch (error) {
      console.error("Change member role error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Leave group
  app.post("/api/chats/:id/leave", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Покинуть можно только групповой чат", 400);
      }

      const memberIdsBefore = await storage.getChatMemberIds(chatId);
      const result = await storage.leaveChat(chatId, req.user!.userId);
      
      if (!result.left) {
        return sendError(res, "Не удалось покинуть чат", 500);
      }

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        if (result.chatDeleted) {
          wsService.notifyChatDeleted(chatId, memberIdsBefore);
        } else {
          wsService.notifyMemberLeft(chatId, req.user!.userId, result.newAdminId, memberIdsBefore);
          
          // If ownership was transferred, notify about it
          if (result.newOwnerId && result.previousOwnerId) {
            wsService.notifyGroupOwnerChanged(chatId, result.previousOwnerId, result.newOwnerId, memberIdsBefore);
          }
        }
      }

      // Create system message if chat not deleted
      if (!result.chatDeleted) {
        const leavingUser = await storage.getUserById(req.user!.userId);
        const systemContent = `${leavingUser?.displayName || 'Пользователь'} покинул(а) группу`;
        const systemMsg = await storage.createSystemMessage(chatId, systemContent);
        
        if (wsService) {
          wsService.broadcastToChat(chatId, {
            type: "new_message",
            payload: { message: systemMsg },
          });
        }

        // If ownership was transferred, create system message about new owner
        if (result.newOwnerId) {
          const newOwner = await storage.getUserById(result.newOwnerId);
          const ownerContent = `${newOwner?.displayName || 'Пользователь'} теперь владелец группы`;
          const ownerMsg = await storage.createSystemMessage(chatId, ownerContent);
          
          if (wsService) {
            wsService.broadcastToChat(chatId, {
              type: "new_message",
              payload: { message: ownerMsg },
            });
          }
        } else if (result.newAdminId) {
          // Only show admin message if there was no ownership transfer
          const newAdmin = await storage.getUserById(result.newAdminId);
          const adminContent = `${newAdmin?.displayName || 'Пользователь'} теперь администратор`;
          const adminMsg = await storage.createSystemMessage(chatId, adminContent);
          
          if (wsService) {
            wsService.broadcastToChat(chatId, {
              type: "new_message",
              payload: { message: adminMsg },
            });
          }
        }
      }

      return sendSuccess(res, { chatDeleted: result.chatDeleted, newAdminId: result.newAdminId, newOwnerId: result.newOwnerId });
    } catch (error) {
      console.error("Leave chat error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Upload group avatar - creator only
  app.post("/api/chats/:id/avatar", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (chat.type !== "group") {
        return sendError(res, "Аватар можно установить только для группового чата", 400);
      }

      // Only creator can change avatar
      if (chat.createdBy !== req.user!.userId) {
        return sendError(res, "Только создатель может изменить аватар", 403);
      }

      const { avatarUrl } = req.body;
      if (!avatarUrl) {
        return sendError(res, "avatarUrl обязателен");
      }

      const updated = await storage.updateChatAvatar(chatId, avatarUrl);
      if (!updated) {
        return sendError(res, "Ошибка обновления", 500);
      }

      // Create system message
      const user = await storage.getUserById(req.user!.userId);
      const systemContent = `${user?.displayName || 'Администратор'} обновил(а) фото группы`;
      const systemMsg = await storage.createSystemMessage(chatId, systemContent);

      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        const memberIds = await storage.getChatMemberIds(chatId);
        wsService.notifyChatUpdated(chatId, updated, memberIds);
        wsService.broadcastToChat(chatId, {
          type: "new_message",
          payload: { message: systemMsg },
        });
      }

      return sendSuccess(res, { chat: updated });
    } catch (error) {
      console.error("Update chat avatar error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.post("/api/messages", authenticateToken, async (req: Request, res: Response) => {
    try {
      const validation = insertMessageSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
      }

      const { chatId, content, type, mediaUrl } = validation.data;

      if (!chatId) {
        return sendError(res, "chatId обязателен");
      }

      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }

      if (type === "text" && (!content || content.trim().length === 0)) {
        return sendError(res, "Текст сообщения обязателен");
      }

      if ((type === "image" || type === "video" || type === "voice") && !mediaUrl) {
        return sendError(res, "URL медиафайла обязателен");
      }

      const message = await storage.createMessage(chatId, req.user!.userId, validation.data);
      
      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService) {
        wsService.notifyNewMessage(message);
      }
      
      return sendSuccess(res, { message }, 201);
    } catch (error) {
      console.error("Send message error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  app.put("/api/messages/:id/delivered", authenticateToken, async (req: Request, res: Response) => {
    try {
      const messageId = parseInt(req.params.id);
      if (isNaN(messageId)) {
        return sendError(res, "Некорректный ID сообщения");
      }

      // Get message info for verification
      const existingMessage = await storage.getMessageById(messageId);
      if (!existingMessage) {
        return sendError(res, "Сообщение не найдено", 404);
      }

      // Verify user is a member of the chat
      const chat = await storage.getChatById(existingMessage.chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Сообщение не найдено", 404);
      }

      // Mark as delivered
      const marked = await storage.markMessageDelivered(messageId, req.user!.userId);

      if (marked) {
        // Notify sender via WebSocket
        const wsService = getWebSocketService();
        if (wsService) {
          wsService.sendToUser(existingMessage.senderId, {
            type: 'message:delivered',
            payload: {
              messageId: messageId,
              chatId: existingMessage.chatId,
              deliveredByUserId: req.user!.userId,
              deliveredAt: new Date().toISOString()
            }
          });
        }
      }

      return sendSuccess(res, { delivered: marked });
    } catch (error) {
      console.error("Mark delivered error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Edit message
  app.put("/api/messages/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const messageId = parseInt(req.params.id);
      if (isNaN(messageId)) {
        return sendError(res, "Некорректный ID сообщения");
      }

      const { content } = req.body;
      if (!content || content.trim().length === 0) {
        return sendError(res, "Текст сообщения обязателен");
      }

      const existingMessage = await storage.getMessageById(messageId);
      if (!existingMessage) {
        return sendError(res, "Сообщение не найдено", 404);
      }

      if (existingMessage.senderId !== req.user!.userId) {
        return sendError(res, "Нельзя редактировать чужое сообщение", 403);
      }

      const message = await storage.updateMessage(messageId, content);
      
      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService && message) {
        wsService.notifyMessageUpdate(existingMessage.chatId, messageId, { content, edited: true });
      }
      
      return sendSuccess(res, { message });
    } catch (error) {
      console.error("Edit message error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Delete message
  app.delete("/api/messages/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const messageId = parseInt(req.params.id);
      if (isNaN(messageId)) {
        return sendError(res, "Некорректный ID сообщения");
      }

      const existingMessage = await storage.getMessageById(messageId);
      if (!existingMessage) {
        return sendError(res, "Сообщение не найдено", 404);
      }

      // Check if user is a member of the chat (any member can delete any message)
      const chat = await storage.getChatById(existingMessage.chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Сообщение не найдено", 404);
      }

      // Delete media file from Object Storage if exists
      if (existingMessage.mediaUrl) {
        try {
          const mediaDeleted = await objectStorageService.deleteObjectByUrl(existingMessage.mediaUrl);
          if (mediaDeleted) {
            console.log(`[messages] Deleted media file for message ${messageId}`);
          } else {
            console.log(`[messages] Media file not found or already deleted for message ${messageId}`);
          }
        } catch (mediaError) {
          // Log error but continue with message deletion
          console.error(`[messages] Error deleting media file for message ${messageId}:`, mediaError);
        }
      }

      const deleted = await storage.deleteMessage(messageId);
      
      // Notify via WebSocket
      const wsService = getWebSocketService();
      if (wsService && deleted) {
        wsService.notifyMessageDeleted(existingMessage.chatId, messageId);
      }
      
      return sendSuccess(res, { deleted });
    } catch (error) {
      console.error("Delete message error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Search messages
  app.get("/api/messages/search", authenticateToken, async (req: Request, res: Response) => {
    try {
      const query = req.query.q as string;
      if (!query || query.length < 2) {
        return sendError(res, "Запрос должен содержать минимум 2 символа");
      }

      const limit = parseLimit(req.query.limit);
      const { cursor, error } = parseCursor(req.query.cursor, messagesCursorSchema);
      if (error) {
        return sendError(res, error);
      }

      const result = await storage.searchMessagesPaginated(req.user!.userId, query, limit, cursor);
      return sendSuccess(res, { 
        messages: result.messages,
        pageInfo: result.pageInfo
      });
    } catch (error) {
      console.error("Search messages error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Get online users
  app.get("/api/users/online", authenticateToken, async (req: Request, res: Response) => {
    try {
      const wsService = getWebSocketService();
      const onlineUserIds = wsService ? wsService.getOnlineUsers() : [];
      return sendSuccess(res, { userIds: onlineUserIds });
    } catch (error) {
      console.error("Get online users error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Check if specific user is online
  app.get("/api/users/:id/online", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = parseInt(req.params.id);
      if (isNaN(userId)) {
        return sendError(res, "Некорректный ID пользователя");
      }

      const wsService = getWebSocketService();
      const isOnline = wsService ? wsService.isUserOnline(userId) : false;
      
      const user = await storage.getUserById(userId);
      return sendSuccess(res, { 
        userId, 
        isOnline,
        lastSeen: user?.lastSeen 
      });
    } catch (error) {
      console.error("Check user online error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  const objectStorageService = new ObjectStorageService();

  app.post("/api/upload", authenticateToken, async (req: Request, res: Response) => {
    try {
      const filename = req.body.filename as string;
      const category = req.body.category as "avatars" | "images" | "videos" | "voice" | undefined;
      
      // Validate category if provided
      const validCategories = ["avatars", "images", "videos", "voice"];
      if (category && !validCategories.includes(category)) {
        return sendError(res, "Некорректная категория файла");
      }
      
      // Get user email for folder organization
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

  app.put("/api/media/finalize", authenticateToken, async (req: Request, res: Response) => {
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

  app.get("/objects/:objectPath(*)", async (req: Request, res: Response) => {
    try {
      const objectPath = `/objects/${req.params.objectPath}`;
      const objectFile = await objectStorageService.getObjectEntityFile(objectPath);
      // Use streamMedia for Range request support (iOS AVPlayer compatibility)
      await objectStorageService.streamMedia(objectFile, req, res);
    } catch (error) {
      console.error("Get object error:", error);
      if (error instanceof ObjectNotFoundError) {
        return res.sendStatus(404);
      }
      return res.sendStatus(500);
    }
  });

  app.get("/public-objects/:filePath(*)", async (req, res) => {
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

  // Chunked Upload API Endpoints
  const initUploadSchemaWithValidation = z.object({
    filename: z.string().min(1, "Имя файла обязательно"),
    fileSize: z.number().int().positive().max(500 * 1024 * 1024, "Максимальный размер файла 500 МБ"),
    mimeType: z.string().min(1, "MIME тип обязателен"),
    category: z.enum(["avatars", "images", "videos", "voice", "files"]).optional(),
  });

  app.post("/api/upload/init", authenticateToken, async (req: Request, res: Response) => {
    try {
      const validation = initUploadSchemaWithValidation.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
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

  app.get("/api/upload/status/:sessionId", authenticateToken, async (req: Request, res: Response) => {
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

  app.post("/api/upload/chunk/:sessionId/:chunkIndex", authenticateToken, async (req: Request, res: Response) => {
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

  app.post("/api/upload/complete/:sessionId", authenticateToken, async (req: Request, res: Response) => {
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
        return sendError(res, "Загрузка завершилась с ошибкой");
      }

      if (session.uploadedChunks.length !== session.totalChunks) {
        return sendError(res, `Загружено ${session.uploadedChunks.length} из ${session.totalChunks} частей`);
      }
      
      // Verify all chunk indices are present (0 to totalChunks-1)
      const sortedChunks = [...session.uploadedChunks].sort((a, b) => a - b);
      for (let i = 0; i < session.totalChunks; i++) {
        if (sortedChunks[i] !== i) {
          await storage.markUploadSessionFailed(sessionId);
          await cleanupTempDir();
          return sendError(res, `Отсутствует часть ${i}`, 500);
        }
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

  // Mark message as read
  app.put("/api/messages/:id/read", authenticateToken, async (req: Request, res: Response) => {
    try {
      const messageId = parseInt(req.params.id);
      if (isNaN(messageId)) {
        return sendError(res, "Некорректный ID сообщения");
      }
      const message = await storage.getMessageById(messageId);
      if (!message) {
        return sendError(res, "Сообщение не найдено", 404);
      }
      const chat = await storage.getChatById(message.chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Сообщение не найдено", 404);
      }
      await storage.markMessageRead(messageId, req.user!.userId);
      const wsService = getWebSocketService();
      if (wsService && message.senderId !== req.user!.userId) {
        wsService.sendToUser(message.senderId, {
          type: 'message:read',
          payload: {
            messageId,
            chatId: message.chatId,
            readByUserId: req.user!.userId,
            readAt: new Date().toISOString()
          }
        });
      }
      return sendSuccess(res, { read: true });
    } catch (error) {
      console.error("Mark message read error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Mark chat as read (all messages)
  app.put("/api/chats/:id/read", authenticateToken, async (req: Request, res: Response) => {
    try {
      const chatId = parseInt(req.params.id);
      if (isNaN(chatId)) {
        return sendError(res, "Некорректный ID чата");
      }
      const chat = await storage.getChatById(chatId, req.user!.userId);
      if (!chat) {
        return sendError(res, "Чат не найден", 404);
      }
      await storage.markChatRead(chatId, req.user!.userId);
      const wsService = getWebSocketService();
      if (wsService) {
        const memberIds = await storage.getChatMemberIds(chatId);
        for (const memberId of memberIds) {
          if (memberId !== req.user!.userId) {
            wsService.sendToUser(memberId, {
              type: 'chat:read',
              payload: {
                chatId,
                readByUserId: req.user!.userId,
                readAt: new Date().toISOString()
              }
            });
          }
        }
      }
      return sendSuccess(res, { read: true });
    } catch (error) {
      console.error("Mark chat read error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Register push token
  app.post("/api/users/push-token", authenticateToken, async (req: Request, res: Response) => {
    try {
      const { pushToken } = req.body;
      if (!pushToken || typeof pushToken !== 'string') {
        return sendError(res, "pushToken обязателен");
      }
      await storage.savePushToken(req.user!.userId, pushToken);
      return sendSuccess(res, { registered: true });
    } catch (error) {
      console.error("Register push token error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Remove push token
  app.delete("/api/users/push-token", authenticateToken, async (req: Request, res: Response) => {
    try {
      await storage.removePushToken(req.user!.userId);
      return sendSuccess(res, { removed: true });
    } catch (error) {
      console.error("Remove push token error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Delete user account
  app.delete("/api/users/account", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = req.user!.userId;

      // Get all private chat partner IDs BEFORE deleting the account
      const partnerIds = await storage.getPrivateChatPartnerIds(userId);

      // Delete the user account and get media URLs to clean up
      const { deleted, mediaUrls } = await storage.deleteUserAccount(userId);

      if (!deleted) {
        return sendError(res, "Пользователь не найден", 404);
      }

      // Delete all media files from Object Storage
      for (const mediaUrl of mediaUrls) {
        try {
          const objectKey = objectStorageService.extractObjectKeyFromUrl(mediaUrl);
          if (objectKey) {
            const deleteResult = await objectStorageService.deleteObject(objectKey);
            if (deleteResult) {
              console.log(`[deleteAccount] Deleted media file: ${objectKey}`);
            }
          }
        } catch (mediaError) {
          console.error(`[deleteAccount] Error deleting media file ${mediaUrl}:`, mediaError);
        }
      }

      // Notify all conversation partners via WebSocket
      const wsService = getWebSocketService();
      if (wsService && partnerIds.length > 0) {
        wsService.notifyUserDeleted(userId, partnerIds);
      }

      console.log(`[deleteAccount] User ${userId} account deleted successfully`);
      return sendSuccess(res, { deleted: true });
    } catch (error) {
      console.error("Delete account error:", error);
      return sendError(res, "Ошибка сервера", 500);
    }
  });

  // Memory monitoring endpoint (for debugging memory leaks)
  app.get("/api/debug/memory", async (_req: Request, res: Response) => {
    const memUsage = process.memoryUsage();
    const wsService = getWebSocketService();
    
    return sendSuccess(res, {
      memory: {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)} MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)} MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)} MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)} MB`,
      },
      websocket: {
        connectedUsers: wsService?.getOnlineUsers().length || 0,
      },
      uptime: `${Math.round(process.uptime())} seconds`,
    });
  });

  return httpServer;
}
