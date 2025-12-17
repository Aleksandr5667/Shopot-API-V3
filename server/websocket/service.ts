import { WebSocketServer, WebSocket } from "ws";
import { Server } from "http";
import { verifyToken } from "../auth";
import { storage } from "../storage/index";
import type { MessageWithReply } from "@shared/schema";
import type { AuthenticatedWebSocket, WSMessage } from "./types";
import { cleanupUserTypingStatus, verifyMembership } from "./handlers";
import { pushNotificationService } from "../pushNotificationService";

export class WebSocketService {
  private wss: WebSocketServer;
  private clients: Map<number, Set<AuthenticatedWebSocket>> = new Map();
  private typingUsers: Map<number, Set<number>> = new Map();

  constructor(server: Server) {
    this.wss = new WebSocketServer({ server, path: "/ws" });
    this.setupConnectionHandler();
    this.setupHeartbeat();
  }

  private setupConnectionHandler() {
    this.wss.on("connection", async (ws: AuthenticatedWebSocket, req) => {
      const url = new URL(req.url || "", `http://${req.headers.host}`);
      const token = url.searchParams.get("token");

      if (!token) {
        ws.close(4001, "Токен не предоставлен");
        return;
      }

      const payload = verifyToken(token);
      if (!payload) {
        ws.close(4002, "Недействительный токен");
        return;
      }

      ws.userId = payload.userId;
      ws.isAlive = true;

      if (!this.clients.has(payload.userId)) {
        this.clients.set(payload.userId, new Set());
      }
      this.clients.get(payload.userId)!.add(ws);

      await storage.updateLastSeen(payload.userId);
      this.broadcastPresence(payload.userId, true);
      await this.markMessagesAsDelivered(payload.userId);

      console.log(`[websocket] User ${payload.userId} connected`);

      ws.on("pong", () => {
        ws.isAlive = true;
      });

      ws.on("message", async (data) => {
        try {
          const message: WSMessage = JSON.parse(data.toString());
          await this.handleMessage(ws, message);
        } catch (error) {
          console.error("[websocket] Error parsing message:", error);
        }
      });

      ws.on("close", async () => {
        if (ws.userId) {
          if (ws.typingTimeouts) {
            ws.typingTimeouts.forEach((timeout) => clearTimeout(timeout));
            ws.typingTimeouts.clear();
          }
          
          cleanupUserTypingStatus(ws.userId, this.typingUsers, this.broadcastToChat.bind(this));
          
          const userSockets = this.clients.get(ws.userId);
          if (userSockets) {
            userSockets.delete(ws);
            if (userSockets.size === 0) {
              this.clients.delete(ws.userId);
              await storage.updateLastSeen(ws.userId);
              this.broadcastPresence(ws.userId, false);
            }
          }
          console.log(`[websocket] User ${ws.userId} disconnected`);
        }
      });

      ws.on("error", (error) => {
        console.error("[websocket] Connection error:", error);
      });

      this.sendToClient(ws, {
        type: "connected",
        payload: { userId: payload.userId },
      });
    });
  }

  private setupHeartbeat() {
    setInterval(() => {
      this.wss.clients.forEach((ws: AuthenticatedWebSocket) => {
        if (ws.isAlive === false) {
          return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
  }

  private async handleMessage(ws: AuthenticatedWebSocket, message: WSMessage) {
    if (!ws.userId) return;

    switch (message.type) {
      case "typing_start":
        await this.handleTypingStart(ws, ws.userId, message.payload.chatId);
        break;
      case "typing_stop":
        await this.handleTypingStop(ws, ws.userId, message.payload.chatId);
        break;
      case "ping":
        this.sendToClient(ws, { type: "pong", payload: {} });
        break;
    }
  }

  private async handleTypingStart(ws: AuthenticatedWebSocket, userId: number, chatId: number) {
    if (!await verifyMembership(userId, chatId)) {
      console.warn(`[websocket] Security: User ${userId} attempted typing in chat ${chatId} without membership`);
      return;
    }

    if (!this.typingUsers.has(chatId)) {
      this.typingUsers.set(chatId, new Set());
    }
    this.typingUsers.get(chatId)!.add(userId);

    this.broadcastToChat(chatId, {
      type: "typing",
      payload: { chatId, userId, isTyping: true },
    }, userId);

    if (!ws.typingTimeouts) {
      ws.typingTimeouts = new Map();
    }

    const existingTimeout = ws.typingTimeouts.get(chatId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    const timeout = setTimeout(() => {
      ws.typingTimeouts?.delete(chatId);
      void this.handleTypingStop(ws, userId, chatId).catch((error) => {
        console.error(`[websocket] Error in auto typing stop:`, error);
      });
    }, 5000);

    ws.typingTimeouts.set(chatId, timeout);
  }

  private async handleTypingStop(ws: AuthenticatedWebSocket, userId: number, chatId: number) {
    if (!await verifyMembership(userId, chatId)) {
      return;
    }

    if (ws.typingTimeouts) {
      const timeout = ws.typingTimeouts.get(chatId);
      if (timeout) {
        clearTimeout(timeout);
        ws.typingTimeouts.delete(chatId);
      }
    }

    const chatTyping = this.typingUsers.get(chatId);
    if (chatTyping) {
      chatTyping.delete(userId);
      if (chatTyping.size === 0) {
        this.typingUsers.delete(chatId);
      }
    }

    this.broadcastToChat(chatId, {
      type: "typing",
      payload: { chatId, userId, isTyping: false },
    }, userId);
  }

  private sendToClient(ws: WebSocket, message: WSMessage) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  sendToUser(userId: number, message: WSMessage) {
    const userSockets = this.clients.get(userId);
    if (userSockets) {
      userSockets.forEach((ws) => {
        this.sendToClient(ws, message);
      });
    }
  }

  async broadcastToChat(chatId: number, message: WSMessage, excludeUserId?: number) {
    try {
      const chatMembers = await storage.getChatMemberIds(chatId);
      chatMembers.forEach((memberId) => {
        if (memberId !== excludeUserId) {
          this.sendToUser(memberId, message);
        }
      });
    } catch (error) {
      console.error("[websocket] Error broadcasting to chat:", error);
    }
  }

  async broadcastPresence(userId: number, isOnline: boolean) {
    try {
      const relatedUserIds = await storage.getRelatedUserIds(userId);
      relatedUserIds.forEach((relatedUserId) => {
        const sockets = this.clients.get(relatedUserId);
        if (sockets) {
          sockets.forEach((ws) => {
            this.sendToClient(ws, {
              type: "presence",
              payload: {
                userId,
                isOnline,
                lastSeen: new Date().toISOString(),
              },
            });
          });
        }
      });
    } catch (error) {
      console.error("[websocket] Error broadcasting presence:", error);
    }
  }

  private async markMessagesAsDelivered(userId: number) {
    try {
      const deliveredMessages = await storage.markUserMessagesAsDelivered(userId);
      
      for (const msg of deliveredMessages) {
        this.sendToUser(msg.senderId, {
          type: "message_delivered",
          payload: {
            chatId: msg.chatId,
            messageId: msg.messageId,
            deliveredTo: msg.deliveredTo,
          },
        });
      }
      
      if (deliveredMessages.length > 0) {
        console.log(`[websocket] Marked ${deliveredMessages.length} messages as delivered for user ${userId}`);
      }
    } catch (error) {
      console.error("[websocket] Error marking messages as delivered:", error);
    }
  }

  async notifyNewMessage(message: MessageWithReply) {
    try {
      const chatMembers = await storage.getChatMemberIds(message.chatId);
      const onlineRecipients: number[] = [];
      const offlineRecipients: number[] = [];
      
      for (const memberId of chatMembers) {
        if (memberId !== message.senderId) {
          const isOnline = this.isUserOnline(memberId);
          if (isOnline) {
            onlineRecipients.push(memberId);
          } else {
            offlineRecipients.push(memberId);
          }
          this.sendToUser(memberId, {
            type: "new_message",
            payload: message,
          });
        }
      }
      
      if (onlineRecipients.length > 0) {
        for (const recipientId of onlineRecipients) {
          await storage.markMessageDelivered(message.id, recipientId);
        }
        
        const deliveredTo = await storage.getMessageDeliveredTo(message.id);
        this.sendToUser(message.senderId, {
          type: "message_delivered",
          payload: {
            chatId: message.chatId,
            messageId: message.id,
            deliveredTo,
          },
        });
      }
      
      if (offlineRecipients.length > 0) {
        const sender = await storage.getUserById(message.senderId);
        const senderName = sender?.displayName || 'Новое сообщение';
        const messageText = message.type === 'text' 
          ? (message.content || '') 
          : message.type === 'image' 
            ? 'Изображение' 
            : message.type === 'video'
              ? 'Видео'
              : message.type === 'voice'
                ? 'Голосовое сообщение'
                : 'Сообщение';
        
        for (const recipientId of offlineRecipients) {
          pushNotificationService.sendNewMessageNotification(
            recipientId,
            message.senderId,
            senderName,
            messageText,
            message.chatId
          ).catch(err => {
            console.error(`[websocket] Failed to send push to user ${recipientId}:`, err);
          });
        }
      }
    } catch (error) {
      console.error("[websocket] Error in notifyNewMessage:", error);
    }
  }

  async notifyMessageUpdate(chatId: number, messageId: number, update: any) {
    this.broadcastToChat(chatId, {
      type: "message_updated",
      payload: { messageId, chatId, ...update },
    });
  }

  async notifyMessageDeleted(chatId: number, messageId: number) {
    this.broadcastToChat(chatId, {
      type: "message_deleted",
      payload: { messageId, chatId },
    });
  }

  notifyChatDeleted(chatId: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "chat_deleted",
        payload: { chatId },
      });
    });
    console.log(`[websocket] Notified ${memberIds.length} users about chat ${chatId} deletion`);
  }

  notifyChatUpdated(chatId: number, chat: any, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "chat_updated",
        payload: { chatId, chat },
      });
    });
    console.log(`[websocket] Notified ${memberIds.length} users about chat ${chatId} update`);
  }

  notifyMembersAdded(chatId: number, addedMembers: any[], addedBy: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "members_added",
        payload: { chatId, addedMembers, addedBy },
      });
    });
    console.log(`[websocket] Notified about ${addedMembers.length} members added to chat ${chatId}`);
  }

  notifyMemberRemoved(chatId: number, userId: number, removedBy: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "member_removed",
        payload: { chatId, userId, removedBy },
      });
    });
    this.sendToUser(userId, {
      type: "removed_from_chat",
      payload: { chatId, removedBy },
    });
    console.log(`[websocket] Notified about member ${userId} removed from chat ${chatId}`);
  }

  notifyMemberLeft(chatId: number, userId: number, newAdminId: number | undefined, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "member_left",
        payload: { chatId, userId, newAdminId },
      });
    });
    console.log(`[websocket] Notified about member ${userId} left chat ${chatId}`);
  }

  notifyGroupRoleChanged(chatId: number, userId: number, role: "admin" | "member", changedBy: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "group_role_changed",
        payload: { chatId, userId, role, changedBy },
      });
    });
    console.log(`[websocket] Notified about role change for user ${userId} in chat ${chatId} to ${role}`);
  }

  notifyGroupOwnerChanged(chatId: number, previousOwnerId: number, newOwnerId: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "group_owner_changed",
        payload: { chatId, previousOwnerId, newOwnerId },
      });
    });
    this.sendToUser(previousOwnerId, {
      type: "group_owner_changed",
      payload: { chatId, previousOwnerId, newOwnerId },
    });
    console.log(`[websocket] Notified about ownership transfer in chat ${chatId} from user ${previousOwnerId} to user ${newOwnerId}`);
  }

  notifyUserDeleted(userId: number, conversationPartnerIds: number[]) {
    conversationPartnerIds.forEach((partnerId) => {
      this.sendToUser(partnerId, {
        type: "user_deleted",
        payload: { userId },
      });
    });
    console.log(`[websocket] Notified ${conversationPartnerIds.length} users about user ${userId} deletion`);
  }

  getOnlineUsers(): number[] {
    return Array.from(this.clients.keys());
  }

  isUserOnline(userId: number): boolean {
    return this.clients.has(userId) && this.clients.get(userId)!.size > 0;
  }
}
