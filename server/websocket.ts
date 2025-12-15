import { WebSocketServer, WebSocket } from "ws";
import { Server } from "http";
import { verifyToken, JwtPayload } from "./auth";
import { storage } from "./storage";
import type { MessageWithReply } from "@shared/schema";

interface AuthenticatedWebSocket extends WebSocket {
  userId?: number;
  isAlive?: boolean;
  typingTimeouts?: Map<number, NodeJS.Timeout>; // chatId -> timeout for auto-stop typing
}

interface WSMessage {
  type: string;
  payload: any;
}

class WebSocketService {
  private wss: WebSocketServer;
  private clients: Map<number, Set<AuthenticatedWebSocket>> = new Map();
  private typingUsers: Map<number, Set<number>> = new Map(); // chatId -> Set<userId>

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

      // Add to clients map
      if (!this.clients.has(payload.userId)) {
        this.clients.set(payload.userId, new Set());
      }
      this.clients.get(payload.userId)!.add(ws);

      // Update last seen and notify presence
      await storage.updateLastSeen(payload.userId);
      this.broadcastPresence(payload.userId, true);

      // Mark undelivered messages as delivered and notify senders
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
          // Cleanup typing timeouts to prevent memory leaks
          if (ws.typingTimeouts) {
            ws.typingTimeouts.forEach((timeout) => clearTimeout(timeout));
            ws.typingTimeouts.clear();
          }
          
          // Cleanup typing status from all chats
          this.cleanupUserTypingStatus(ws.userId);
          
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

      // Send connected confirmation
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

  // Security: Verify user is a member of the chat
  private async verifyMembership(userId: number, chatId: number): Promise<boolean> {
    try {
      const memberIds = await storage.getChatMemberIds(chatId);
      return memberIds.includes(userId);
    } catch {
      return false;
    }
  }

  private async handleTypingStart(ws: AuthenticatedWebSocket, userId: number, chatId: number) {
    // Security: Verify user is a member of the chat
    if (!await this.verifyMembership(userId, chatId)) {
      console.warn(`[websocket] Security: User ${userId} attempted typing in chat ${chatId} without membership`);
      return;
    }

    if (!this.typingUsers.has(chatId)) {
      this.typingUsers.set(chatId, new Set());
    }
    this.typingUsers.get(chatId)!.add(userId);

    this.broadcastToChat(chatId, {
      type: "typing",
      payload: {
        chatId,
        userId,
        isTyping: true,
      },
    }, userId);

    // Initialize typing timeouts map if needed
    if (!ws.typingTimeouts) {
      ws.typingTimeouts = new Map();
    }

    // Clear existing timeout for this chat if any
    const existingTimeout = ws.typingTimeouts.get(chatId);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    // Auto-stop typing after 5 seconds with proper cleanup
    const timeout = setTimeout(() => {
      ws.typingTimeouts?.delete(chatId);
      void this.handleTypingStop(ws, userId, chatId).catch((error) => {
        console.error(`[websocket] Error in auto typing stop:`, error);
      });
    }, 5000);

    ws.typingTimeouts.set(chatId, timeout);
  }

  private async handleTypingStop(ws: AuthenticatedWebSocket, userId: number, chatId: number) {
    // Security: Verify user is a member of the chat
    if (!await this.verifyMembership(userId, chatId)) {
      return;
    }

    // Clear timeout if manually stopped
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
      // Cleanup empty chat entries to prevent memory buildup
      if (chatTyping.size === 0) {
        this.typingUsers.delete(chatId);
      }
    }

    this.broadcastToChat(chatId, {
      type: "typing",
      payload: {
        chatId,
        userId,
        isTyping: false,
      },
    }, userId);
  }

  // Cleanup user typing status from all chats (called on disconnect)
  private cleanupUserTypingStatus(userId: number) {
    this.typingUsers.forEach((typingSet, chatId) => {
      if (typingSet.has(userId)) {
        typingSet.delete(userId);
        // Notify other users that this user stopped typing
        this.broadcastToChat(chatId, {
          type: "typing",
          payload: {
            chatId,
            userId,
            isTyping: false,
          },
        }, userId);
        
        // Remove empty entries
        if (typingSet.size === 0) {
          this.typingUsers.delete(chatId);
        }
      }
    });
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
    // Only broadcast presence to users who share at least one chat with this user
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
        // Notify sender about delivery
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

  // Public method to notify about new messages
  async notifyNewMessage(message: MessageWithReply) {
    try {
      const chatMembers = await storage.getChatMemberIds(message.chatId);
      const onlineRecipients: number[] = [];
      
      // Send message to all chat members (except sender) and track who's online
      for (const memberId of chatMembers) {
        if (memberId !== message.senderId) {
          const isOnline = this.isUserOnline(memberId);
          if (isOnline) {
            onlineRecipients.push(memberId);
          }
          this.sendToUser(memberId, {
            type: "new_message",
            payload: message,
          });
        }
      }
      
      // Mark message as delivered for online recipients and notify sender
      if (onlineRecipients.length > 0) {
        for (const recipientId of onlineRecipients) {
          await storage.markMessageDelivered(message.id, recipientId);
        }
        
        // Get updated deliveredTo list and notify sender
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
    } catch (error) {
      console.error("[websocket] Error in notifyNewMessage:", error);
    }
  }

  // Public method to notify about message updates (edit/delete)
  async notifyMessageUpdate(chatId: number, messageId: number, update: any) {
    this.broadcastToChat(chatId, {
      type: "message_updated",
      payload: {
        messageId,
        chatId,
        ...update,
      },
    });
  }

  // Public method to notify about message deletion
  async notifyMessageDeleted(chatId: number, messageId: number) {
    this.broadcastToChat(chatId, {
      type: "message_deleted",
      payload: {
        messageId,
        chatId,
      },
    });
  }

  // Public method to notify about chat deletion
  notifyChatDeleted(chatId: number, memberIds: number[]) {
    memberIds.forEach((memberId) => {
      this.sendToUser(memberId, {
        type: "chat_deleted",
        payload: {
          chatId,
        },
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
    // Also notify the removed user
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
    // Also notify the previous owner who just left
    this.sendToUser(previousOwnerId, {
      type: "group_owner_changed",
      payload: { chatId, previousOwnerId, newOwnerId },
    });
    console.log(`[websocket] Notified about ownership transfer in chat ${chatId} from user ${previousOwnerId} to user ${newOwnerId}`);
  }

  // Notify all conversation partners when a user deletes their account
  notifyUserDeleted(userId: number, conversationPartnerIds: number[]) {
    conversationPartnerIds.forEach((partnerId) => {
      this.sendToUser(partnerId, {
        type: "user_deleted",
        payload: { userId },
      });
    });
    console.log(`[websocket] Notified ${conversationPartnerIds.length} users about user ${userId} deletion`);
  }

  // Get online users
  getOnlineUsers(): number[] {
    return Array.from(this.clients.keys());
  }

  isUserOnline(userId: number): boolean {
    return this.clients.has(userId) && this.clients.get(userId)!.size > 0;
  }
}

let wsService: WebSocketService | null = null;

export function initWebSocket(server: Server): WebSocketService {
  wsService = new WebSocketService(server);
  return wsService;
}

export function getWebSocketService(): WebSocketService | null {
  return wsService;
}
