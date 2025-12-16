import { storage } from "../storage/index";
import type { AuthenticatedWebSocket, WSMessage } from "./types";

export async function verifyMembership(userId: number, chatId: number): Promise<boolean> {
  try {
    const memberIds = await storage.getChatMemberIds(chatId);
    return memberIds.includes(userId);
  } catch {
    return false;
  }
}

export async function handleTypingStart(
  ws: AuthenticatedWebSocket,
  userId: number,
  chatId: number,
  typingUsers: Map<number, Set<number>>,
  broadcastToChat: (chatId: number, message: WSMessage, excludeUserId?: number) => Promise<void>,
  handleTypingStop: (ws: AuthenticatedWebSocket, userId: number, chatId: number) => Promise<void>
) {
  if (!await verifyMembership(userId, chatId)) {
    console.warn(`[websocket] Security: User ${userId} attempted typing in chat ${chatId} without membership`);
    return;
  }

  if (!typingUsers.has(chatId)) {
    typingUsers.set(chatId, new Set());
  }
  typingUsers.get(chatId)!.add(userId);

  broadcastToChat(chatId, {
    type: "typing",
    payload: {
      chatId,
      userId,
      isTyping: true,
    },
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
    void handleTypingStop(ws, userId, chatId).catch((error) => {
      console.error(`[websocket] Error in auto typing stop:`, error);
    });
  }, 5000);

  ws.typingTimeouts.set(chatId, timeout);
}

export async function handleTypingStop(
  ws: AuthenticatedWebSocket,
  userId: number,
  chatId: number,
  typingUsers: Map<number, Set<number>>,
  broadcastToChat: (chatId: number, message: WSMessage, excludeUserId?: number) => Promise<void>
) {
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

  const chatTyping = typingUsers.get(chatId);
  if (chatTyping) {
    chatTyping.delete(userId);
    if (chatTyping.size === 0) {
      typingUsers.delete(chatId);
    }
  }

  broadcastToChat(chatId, {
    type: "typing",
    payload: {
      chatId,
      userId,
      isTyping: false,
    },
  }, userId);
}

export function cleanupUserTypingStatus(
  userId: number,
  typingUsers: Map<number, Set<number>>,
  broadcastToChat: (chatId: number, message: WSMessage, excludeUserId?: number) => Promise<void>
) {
  typingUsers.forEach((typingSet, chatId) => {
    if (typingSet.has(userId)) {
      typingSet.delete(userId);
      broadcastToChat(chatId, {
        type: "typing",
        payload: {
          chatId,
          userId,
          isTyping: false,
        },
      }, userId);
      
      if (typingSet.size === 0) {
        typingUsers.delete(chatId);
      }
    }
  });
}
