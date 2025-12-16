import { Router, Request, Response } from "express";
import { storage } from "../storage/index";
import { authenticateToken } from "../auth";
import { getWebSocketService } from "../websocket";
import { ObjectStorageService } from "../objectStorage";
import { insertMessageSchema } from "@shared/schema";
import { sendSuccess, sendError, parseLimit, parseCursor, messagesCursorSchema } from "./utils";

export const messagesRouter = Router();

const objectStorageService = new ObjectStorageService();

messagesRouter.post("/", authenticateToken, async (req: Request, res: Response) => {
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

messagesRouter.put("/:id/delivered", authenticateToken, async (req: Request, res: Response) => {
  try {
    const messageId = parseInt(req.params.id);
    if (isNaN(messageId)) {
      return sendError(res, "Некорректный ID сообщения");
    }

    const existingMessage = await storage.getMessageById(messageId);
    if (!existingMessage) {
      return sendError(res, "Сообщение не найдено", 404);
    }

    const chat = await storage.getChatById(existingMessage.chatId, req.user!.userId);
    if (!chat) {
      return sendError(res, "Сообщение не найдено", 404);
    }

    const marked = await storage.markMessageDelivered(messageId, req.user!.userId);

    if (marked) {
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

messagesRouter.put("/:id", authenticateToken, async (req: Request, res: Response) => {
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

messagesRouter.delete("/:id", authenticateToken, async (req: Request, res: Response) => {
  try {
    const messageId = parseInt(req.params.id);
    if (isNaN(messageId)) {
      return sendError(res, "Некорректный ID сообщения");
    }

    const existingMessage = await storage.getMessageById(messageId);
    if (!existingMessage) {
      return sendError(res, "Сообщение не найдено", 404);
    }

    const chat = await storage.getChatById(existingMessage.chatId, req.user!.userId);
    if (!chat) {
      return sendError(res, "Сообщение не найдено", 404);
    }

    if (existingMessage.mediaUrl) {
      try {
        const mediaDeleted = await objectStorageService.deleteObjectByUrl(existingMessage.mediaUrl);
        if (mediaDeleted) {
          console.log(`[messages] Deleted media file for message ${messageId}`);
        } else {
          console.log(`[messages] Media file not found or already deleted for message ${messageId}`);
        }
      } catch (mediaError) {
        console.error(`[messages] Error deleting media file for message ${messageId}:`, mediaError);
      }
    }

    const deleted = await storage.deleteMessage(messageId);
    
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

messagesRouter.get("/search", authenticateToken, async (req: Request, res: Response) => {
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

messagesRouter.put("/:id/read", authenticateToken, async (req: Request, res: Response) => {
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
