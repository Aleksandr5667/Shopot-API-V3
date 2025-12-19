import { Router, Request, Response } from "express";
import { storage } from "../storage/index";
import { authenticateToken } from "../auth";
import { getWebSocketService } from "../websocket/index";
import { ObjectStorageService } from "../objectStorage";
import { updateProfileSchema } from "@shared/schema";
import { sendSuccess, sendError } from "./utils";
import { searchLimiter } from "./limiters";

export const usersRouter = Router();

const objectStorageService = new ObjectStorageService();

usersRouter.get("/search", authenticateToken, searchLimiter, async (req: Request, res: Response) => {
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

usersRouter.put("/profile", authenticateToken, async (req: Request, res: Response) => {
  try {
    const validation = updateProfileSchema.safeParse(req.body);
    if (!validation.success) {
      return sendError(res, validation.error.errors[0]?.message || "Ошибка валидации");
    }

    // Normalize avatar URL to relative path
    const profileData = {
      ...validation.data,
      avatarUrl: validation.data.avatarUrl 
        ? objectStorageService.normalizeMediaUrl(validation.data.avatarUrl) 
        : validation.data.avatarUrl,
    };

    const user = await storage.updateProfile(req.user!.userId, profileData);
    if (!user) {
      return sendError(res, "Пользователь не найден", 404);
    }

    return sendSuccess(res, { user });
  } catch (error) {
    console.error("Update profile error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

usersRouter.get("/online", authenticateToken, async (req: Request, res: Response) => {
  try {
    const wsService = getWebSocketService();
    const onlineUserIds = wsService ? wsService.getOnlineUsers() : [];
    return sendSuccess(res, { userIds: onlineUserIds });
  } catch (error) {
    console.error("Get online users error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

usersRouter.get("/:id/online", authenticateToken, async (req: Request, res: Response) => {
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

usersRouter.post("/push-token", authenticateToken, async (req: Request, res: Response) => {
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

usersRouter.delete("/push-token", authenticateToken, async (req: Request, res: Response) => {
  try {
    await storage.removePushToken(req.user!.userId);
    return sendSuccess(res, { removed: true });
  } catch (error) {
    console.error("Remove push token error:", error);
    return sendError(res, "Ошибка сервера", 500);
  }
});

usersRouter.delete("/account", authenticateToken, async (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;

    const partnerIds = await storage.getPrivateChatPartnerIds(userId);

    const { deleted, mediaUrls } = await storage.deleteUserAccount(userId);

    if (!deleted) {
      return sendError(res, "Пользователь не найден", 404);
    }

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
