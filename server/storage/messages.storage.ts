import {
  messages, messageReceipts, chats, chatMembers,
  type Message, type UserPublic, type InsertMessage, type MessagesCursor, type PageInfo,
  type ReplyToMessage, type MessageWithReply
} from "@shared/schema";
import { db } from "../db";
import { eq, and, or, desc, lt, ilike, inArray, not, sql } from "drizzle-orm";
import { getUserById } from "./users.storage";

export async function getReplyToMessage(messageId: number, chatId: number): Promise<ReplyToMessage | null> {
  const [message] = await db.select().from(messages).where(eq(messages.id, messageId));
  if (!message) return null;

  if (message.chatId !== chatId) {
    return null;
  }

  const sender = await getUserById(message.senderId);
  if (!sender) return null;

  return {
    id: message.id,
    senderId: message.senderId,
    senderName: sender.displayName,
    content: message.content,
    type: message.type,
  };
}

export async function getMessageDeliveredTo(messageId: number): Promise<number[]> {
  const [message] = await db.select().from(messages).where(eq(messages.id, messageId));
  if (!message) return [];

  const receipts = await db
    .select({ userId: messageReceipts.userId })
    .from(messageReceipts)
    .where(
      and(
        eq(messageReceipts.messageId, messageId),
        sql`${messageReceipts.deliveredAt} IS NOT NULL`
      )
    );
  
  const deliveredUserIds = new Set([message.senderId, ...receipts.map(r => r.userId)]);
  return Array.from(deliveredUserIds);
}

export async function createMessageReceipts(messageId: number, userIds: number[]): Promise<void> {
  if (userIds.length === 0) return;
  
  const receipts = userIds.map(userId => ({
    messageId,
    userId,
  }));
  
  await db.insert(messageReceipts).values(receipts);
}

export async function getChatMemberIds(chatId: number): Promise<number[]> {
  const members = await db
    .select({ userId: chatMembers.userId })
    .from(chatMembers)
    .where(eq(chatMembers.chatId, chatId));
  return members.map((m) => m.userId);
}

export async function createMessage(chatId: number, senderId: number, data: InsertMessage): Promise<MessageWithReply> {
  let validatedReplyToId: number | null = null;
  if (data.replyToId) {
    const replyMessage = await getReplyToMessage(data.replyToId, chatId);
    if (replyMessage) {
      validatedReplyToId = data.replyToId;
    }
  }

  const [message] = await db
    .insert(messages)
    .values({
      chatId,
      senderId,
      content: data.content,
      type: data.type || "text",
      mediaUrl: data.mediaUrl,
      thumbnailUrl: data.thumbnailUrl,
      replyToId: validatedReplyToId,
      readBy: [senderId],
    })
    .returning();

  const memberIds = await getChatMemberIds(chatId);
  const recipientIds = memberIds.filter(id => id !== senderId);
  await createMessageReceipts(message.id, recipientIds);

  const sender = await getUserById(senderId);
  let replyToMessage: ReplyToMessage | null = null;
  
  if (message.replyToId) {
    replyToMessage = await getReplyToMessage(message.replyToId, chatId);
  }

  return { ...message, sender: sender!, replyToMessage, deliveredTo: [senderId] };
}

export async function createSystemMessage(chatId: number, content: string): Promise<Message> {
  const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
  if (!chat) throw new Error("Chat not found");
  
  let senderId = chat.createdBy;
  if (!senderId) {
    const [firstAdmin] = await db
      .select()
      .from(chatMembers)
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.role, "admin")))
      .limit(1);
    
    if (firstAdmin) {
      senderId = firstAdmin.userId;
    } else {
      const [firstMember] = await db
        .select()
        .from(chatMembers)
        .where(eq(chatMembers.chatId, chatId))
        .limit(1);
      if (firstMember) {
        senderId = firstMember.userId;
      }
    }
  }
  
  if (!senderId) throw new Error("No members in chat");

  const [message] = await db
    .insert(messages)
    .values({
      chatId,
      senderId,
      content,
      type: "system",
      readBy: [],
    })
    .returning();

  return message;
}

export async function getChatMessages(chatId: number, limit: number = 50, before?: Date): Promise<MessageWithReply[]> {
  const conditions = [eq(messages.chatId, chatId)];
  
  if (before) {
    conditions.push(lt(messages.createdAt, before));
  }

  const messageList = await db
    .select()
    .from(messages)
    .where(and(...conditions))
    .orderBy(desc(messages.createdAt))
    .limit(limit);

  const result: MessageWithReply[] = [];
  for (const message of messageList) {
    const sender = await getUserById(message.senderId);
    if (sender) {
      let replyToMessage: ReplyToMessage | null = null;
      if (message.replyToId) {
        replyToMessage = await getReplyToMessage(message.replyToId, chatId);
      }
      const deliveredTo = await getMessageDeliveredTo(message.id);
      result.push({ ...message, sender, replyToMessage, deliveredTo });
    }
  }

  return result.reverse();
}

export async function getMessageById(messageId: number): Promise<Message | undefined> {
  const [message] = await db.select().from(messages).where(eq(messages.id, messageId));
  return message || undefined;
}

export async function updateMessage(messageId: number, content: string): Promise<Message | undefined> {
  const [updated] = await db
    .update(messages)
    .set({ 
      content,
      edited: new Date()
    })
    .where(eq(messages.id, messageId))
    .returning();
  return updated || undefined;
}

export async function deleteMessage(messageId: number): Promise<boolean> {
  const result = await db
    .delete(messages)
    .where(eq(messages.id, messageId))
    .returning();
  return result.length > 0;
}

export async function getRelatedUserIds(userId: number): Promise<number[]> {
  const userChats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));

  const chatIds = userChats.map((c) => c.chatId);
  if (chatIds.length === 0) return [];

  const relatedMembers = await db
    .select({ userId: chatMembers.userId })
    .from(chatMembers)
    .where(and(
      inArray(chatMembers.chatId, chatIds),
      not(eq(chatMembers.userId, userId))
    ));

  return Array.from(new Set(relatedMembers.map((m) => m.userId)));
}

export async function searchMessages(userId: number, query: string): Promise<(Message & { sender: UserPublic; chatName?: string })[]> {
  const userChats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));

  const chatIds = userChats.map((c) => c.chatId);
  if (chatIds.length === 0) return [];

  const foundMessages = await db
    .select()
    .from(messages)
    .where(and(
      inArray(messages.chatId, chatIds),
      ilike(messages.content, `%${query}%`)
    ))
    .orderBy(desc(messages.createdAt))
    .limit(50);

  const result: (Message & { sender: UserPublic; chatName?: string })[] = [];
  for (const message of foundMessages) {
    const sender = await getUserById(message.senderId);
    const [chat] = await db.select().from(chats).where(eq(chats.id, message.chatId));
    if (sender) {
      result.push({
        ...message,
        sender,
        chatName: chat?.name || undefined,
      });
    }
  }

  return result;
}

export async function searchMessagesPaginated(userId: number, query: string, limit: number, cursor?: MessagesCursor): Promise<{ messages: (Message & { sender: UserPublic; chatName?: string })[]; pageInfo: PageInfo }> {
  const userChats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));

  const chatIds = userChats.map((c) => c.chatId);
  if (chatIds.length === 0) {
    return { messages: [], pageInfo: { hasMore: false, nextCursor: null } };
  }

  const conditions = [
    inArray(messages.chatId, chatIds),
    ilike(messages.content, `%${query}%`)
  ];

  if (cursor) {
    const cursorDate = new Date(cursor.createdAt);
    conditions.push(
      or(
        lt(messages.createdAt, cursorDate),
        and(eq(messages.createdAt, cursorDate), lt(messages.id, cursor.id))
      )!
    );
  }

  const foundMessages = await db
    .select()
    .from(messages)
    .where(and(...conditions))
    .orderBy(desc(messages.createdAt), desc(messages.id))
    .limit(limit + 1);

  const hasMore = foundMessages.length > limit;
  const messagesToReturn = hasMore ? foundMessages.slice(0, limit) : foundMessages;

  const result: (Message & { sender: UserPublic; chatName?: string })[] = [];
  for (const message of messagesToReturn) {
    const sender = await getUserById(message.senderId);
    const [chat] = await db.select().from(chats).where(eq(chats.id, message.chatId));
    if (sender) {
      result.push({
        ...message,
        sender,
        chatName: chat?.name || undefined,
      });
    }
  }

  let nextCursor: string | null = null;
  if (hasMore && messagesToReturn.length > 0) {
    const lastMessage = messagesToReturn[messagesToReturn.length - 1];
    nextCursor = Buffer.from(JSON.stringify({
      createdAt: lastMessage.createdAt.toISOString(),
      id: lastMessage.id
    })).toString('base64');
  }

  return {
    messages: result,
    pageInfo: { hasMore, nextCursor }
  };
}

export async function markMessageDelivered(messageId: number, userId: number): Promise<boolean> {
  const result = await db
    .update(messageReceipts)
    .set({ deliveredAt: new Date() })
    .where(
      and(
        eq(messageReceipts.messageId, messageId),
        eq(messageReceipts.userId, userId),
        sql`${messageReceipts.deliveredAt} IS NULL`
      )
    )
    .returning();
  
  return result.length > 0;
}

export async function getUndeliveredMessagesForUser(userId: number): Promise<{ messageId: number; chatId: number; senderId: number }[]> {
  const undelivered = await db
    .select({
      messageId: messageReceipts.messageId,
      chatId: messages.chatId,
      senderId: messages.senderId,
    })
    .from(messageReceipts)
    .innerJoin(messages, eq(messageReceipts.messageId, messages.id))
    .where(
      and(
        eq(messageReceipts.userId, userId),
        sql`${messageReceipts.deliveredAt} IS NULL`
      )
    );
  
  return undelivered;
}

export async function markUserMessagesAsDelivered(userId: number): Promise<{ messageId: number; chatId: number; senderId: number; deliveredTo: number[] }[]> {
  const undelivered = await getUndeliveredMessagesForUser(userId);
  if (undelivered.length === 0) return [];

  const now = new Date();
  await db
    .update(messageReceipts)
    .set({ deliveredAt: now })
    .where(
      and(
        eq(messageReceipts.userId, userId),
        sql`${messageReceipts.deliveredAt} IS NULL`
      )
    );

  const result: { messageId: number; chatId: number; senderId: number; deliveredTo: number[] }[] = [];
  for (const msg of undelivered) {
    const deliveredTo = await getMessageDeliveredTo(msg.messageId);
    result.push({
      messageId: msg.messageId,
      chatId: msg.chatId,
      senderId: msg.senderId,
      deliveredTo,
    });
  }

  return result;
}

export async function markMessageRead(messageId: number, userId: number): Promise<void> {
  const message = await getMessageById(messageId);
  if (!message) return;
  
  const currentReadBy = message.readBy || [];
  if (!currentReadBy.includes(userId)) {
    await db
      .update(messages)
      .set({ readBy: [...currentReadBy, userId] })
      .where(eq(messages.id, messageId));
  }
}

export async function markChatRead(chatId: number, userId: number): Promise<void> {
  const chatMessages = await db
    .select()
    .from(messages)
    .where(
      and(
        eq(messages.chatId, chatId),
        not(eq(messages.senderId, userId))
      )
    );
  
  for (const message of chatMessages) {
    const currentReadBy = message.readBy || [];
    if (!currentReadBy.includes(userId)) {
      await db
        .update(messages)
        .set({ readBy: [...currentReadBy, userId] })
        .where(eq(messages.id, message.id));
    }
  }
}

export async function getUnreadMessagesCount(userId: number): Promise<number> {
  const userChats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));
  
  if (userChats.length === 0) return 0;

  const chatIds = userChats.map(c => c.chatId);
  
  const unreadMessages = await db
    .select({ id: messages.id })
    .from(messages)
    .where(
      and(
        inArray(messages.chatId, chatIds),
        not(eq(messages.senderId, userId)),
        sql`NOT (${messages.readBy} @> ARRAY[${userId}]::integer[])`
      )
    );
  
  return unreadMessages.length;
}
