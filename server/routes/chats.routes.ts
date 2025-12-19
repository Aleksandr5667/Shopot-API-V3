import { Router, Request, Response } from "express";
import { storage } from "../storage/index";
import { authenticateToken } from "../auth";
import { getWebSocketService } from "../websocket/index";
import { ObjectStorageService } from "../objectStorage";
import { insertChatSchema } from "@shared/schema";
import { sendSuccess, sendError, parseLimit, parseCursor, chatsCursorSchema } from "./utils";

export const chatsRouter = Router();

const objectStorageService = new ObjectStorageService();

chatsRouter.get("/", authenticateToken, async (req: Request, res: Response) => {
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

chatsRouter.post("/", authenticateToken, async (req: Request, res: Response) => {
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

chatsRouter.get("/:id/messages", authenticateToken, async (req: Request, res: Response) => {
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

chatsRouter.delete("/:id", authenticateToken, async (req: Request, res: Response) => {
  try {
    const chatId = parseInt(req.params.id);
    if (isNaN(chatId)) {
      return sendError(res, "Некорректный ID чата");
    }

    const { deleted, mediaUrls, memberIds } = await storage.deleteChat(chatId, req.user!.userId);

    if (!deleted) {
      return sendError(res, "Чат не найден", 404);
    }

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

chatsRouter.get("/:id/details", authenticateToken, async (req: Request, res: Response) => {
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

chatsRouter.patch("/:id", authenticateToken, async (req: Request, res: Response) => {
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

chatsRouter.post("/:id/members", authenticateToken, async (req: Request, res: Response) => {
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

    const isCreator = chat.createdBy === req.user!.userId;
    const isAdmin = await storage.isUserChatAdmin(chatId, req.user!.userId);
    if (!isCreator && !isAdmin) {
      return sendError(res, "Только создатель или администратор может добавлять участников", 403);
    }

    const { userIds } = req.body;
    if (!Array.isArray(userIds) || userIds.length === 0) {
      return sendError(res, "userIds должен быть непустым массивом");
    }

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

chatsRouter.delete("/:id/members/:userId", authenticateToken, async (req: Request, res: Response) => {
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

    if (chat.createdBy !== req.user!.userId) {
      return sendError(res, "Only the group creator can remove members", 403);
    }

    if (userId === req.user!.userId) {
      return sendError(res, "Нельзя удалить самого себя, используйте выход из группы", 400);
    }

    if (userId === chat.createdBy) {
      return sendError(res, "Cannot remove the group creator", 403);
    }

    const memberIdsBefore = await storage.getChatMemberIds(chatId);
    const removedUser = await storage.getUserById(userId);
    const removed = await storage.removeChatMember(chatId, userId);
    if (!removed) {
      return sendError(res, "Участник не найден", 404);
    }

    const adminUser = await storage.getUserById(req.user!.userId);
    const systemContent = `${adminUser?.displayName || 'Администратор'} удалил(а) ${removedUser?.displayName || 'пользователя'}`;
    const systemMsg = await storage.createSystemMessage(chatId, systemContent);

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

chatsRouter.put("/:chatId/members/:userId/role", authenticateToken, async (req: Request, res: Response) => {
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

    if (chat.createdBy !== req.user!.userId) {
      return sendError(res, "Only the group creator can change member roles", 403);
    }

    const targetRole = await storage.getChatMemberRole(chatId, userId);
    if (!targetRole) {
      return sendError(res, "Member not found", 404);
    }

    if (chat.createdBy === userId) {
      return sendError(res, "Cannot change the creator's role", 403);
    }

    const updated = await storage.updateMemberRole(chatId, userId, role);
    if (!updated) {
      return sendError(res, "Не удалось обновить роль", 500);
    }

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

chatsRouter.post("/:id/leave", authenticateToken, async (req: Request, res: Response) => {
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

    const wsService = getWebSocketService();
    if (wsService) {
      if (result.chatDeleted) {
        wsService.notifyChatDeleted(chatId, memberIdsBefore);
      } else {
        wsService.notifyMemberLeft(chatId, req.user!.userId, result.newAdminId, memberIdsBefore);
        
        if (result.newOwnerId && result.previousOwnerId) {
          wsService.notifyGroupOwnerChanged(chatId, result.previousOwnerId, result.newOwnerId, memberIdsBefore);
        }
      }
    }

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

chatsRouter.post("/:id/avatar", authenticateToken, async (req: Request, res: Response) => {
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

    const user = await storage.getUserById(req.user!.userId);
    const systemContent = `${user?.displayName || 'Администратор'} обновил(а) фото группы`;
    const systemMsg = await storage.createSystemMessage(chatId, systemContent);

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

chatsRouter.put("/:id/read", authenticateToken, async (req: Request, res: Response) => {
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
