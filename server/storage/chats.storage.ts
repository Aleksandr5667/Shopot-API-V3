import {
  chats, chatMembers, messages,
  type Chat, type UserPublic, type Message, type ChatsCursor, type PageInfo,
  type ChatMemberWithUser, type ChatWithMembers
} from "@shared/schema";
import { db } from "../db";
import { eq, and, or, desc, lt, inArray, not, sql } from "drizzle-orm";
import { getUserById } from "./users.storage";

export async function getUnreadCount(chatId: number, userId: number): Promise<number> {
  const result = await db
    .select({ count: sql<number>`count(*)` })
    .from(messages)
    .where(
      and(
        eq(messages.chatId, chatId),
        not(eq(messages.senderId, userId)),
        sql`NOT (${messages.readBy} @> ARRAY[${userId}]::integer[])`
      )
    );
  return Number(result[0]?.count ?? 0);
}

export async function createChat(
  type: "private" | "group",
  name: string | null,
  avatarColor: string,
  createdBy: number,
  memberIds: number[],
  description?: string | null
): Promise<Chat> {
  const [chat] = await db
    .insert(chats)
    .values({ type, name, description, avatarColor, createdBy })
    .returning();

  const allMemberIds = Array.from(new Set([createdBy, ...memberIds]));
  for (const memberId of allMemberIds) {
    const isCreator = memberId === createdBy;
    await db.insert(chatMembers).values({ 
      chatId: chat.id, 
      userId: memberId,
      role: type === "group" && isCreator ? "admin" : "member",
      addedBy: isCreator ? null : createdBy
    });
  }

  return chat;
}

export async function getChatsForUser(userId: number): Promise<(Chat & { lastMessage?: Message; members: UserPublic[]; unreadCount: number })[]> {
  const memberRecords = await db
    .select()
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));

  const chatIds = memberRecords.map((m) => m.chatId);
  if (chatIds.length === 0) return [];

  const chatList = await db.select().from(chats).where(inArray(chats.id, chatIds));

  const result: (Chat & { lastMessage?: Message; members: UserPublic[]; unreadCount: number })[] = [];
  for (const chat of chatList) {
    const [lastMessage] = await db
      .select()
      .from(messages)
      .where(eq(messages.chatId, chat.id))
      .orderBy(desc(messages.createdAt))
      .limit(1);

    const allMembers = await db
      .select()
      .from(chatMembers)
      .where(eq(chatMembers.chatId, chat.id));

    const memberUsers: UserPublic[] = [];
    for (const member of allMembers) {
      const user = await getUserById(member.userId);
      if (user) memberUsers.push(user);
    }

    const unreadCount = await getUnreadCount(chat.id, userId);

    result.push({
      ...chat,
      lastMessage: lastMessage || undefined,
      members: memberUsers,
      unreadCount,
    });
  }

  result.sort((a, b) => {
    const aTime = a.lastMessage?.createdAt || a.createdAt;
    const bTime = b.lastMessage?.createdAt || b.createdAt;
    return new Date(bTime).getTime() - new Date(aTime).getTime();
  });

  return result;
}

export async function getChatsForUserPaginated(userId: number, limit: number, cursor?: ChatsCursor): Promise<{ chats: (Chat & { lastMessage?: Message; members: UserPublic[]; unreadCount: number })[]; pageInfo: PageInfo }> {
  const memberRecords = await db
    .select()
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId));

  const chatIds = memberRecords.map((m) => m.chatId);
  if (chatIds.length === 0) {
    return { chats: [], pageInfo: { hasMore: false, nextCursor: null } };
  }

  const conditions = [inArray(chats.id, chatIds)];
  
  if (cursor) {
    const cursorDate = new Date(cursor.updatedAt);
    conditions.push(
      or(
        lt(chats.updatedAt, cursorDate),
        and(eq(chats.updatedAt, cursorDate), lt(chats.id, cursor.id))
      )!
    );
  }

  const chatList = await db
    .select()
    .from(chats)
    .where(and(...conditions))
    .orderBy(desc(chats.updatedAt), desc(chats.id))
    .limit(limit + 1);

  const hasMore = chatList.length > limit;
  const chatsToReturn = hasMore ? chatList.slice(0, limit) : chatList;

  const result: (Chat & { lastMessage?: Message; members: UserPublic[]; unreadCount: number })[] = [];
  for (const chat of chatsToReturn) {
    const [lastMessage] = await db
      .select()
      .from(messages)
      .where(eq(messages.chatId, chat.id))
      .orderBy(desc(messages.createdAt))
      .limit(1);

    const allMembers = await db
      .select()
      .from(chatMembers)
      .where(eq(chatMembers.chatId, chat.id));

    const memberUsers: UserPublic[] = [];
    for (const member of allMembers) {
      const user = await getUserById(member.userId);
      if (user) memberUsers.push(user);
    }

    const unreadCount = await getUnreadCount(chat.id, userId);

    result.push({
      ...chat,
      lastMessage: lastMessage || undefined,
      members: memberUsers,
      unreadCount,
    });
  }

  let nextCursor: string | null = null;
  if (hasMore && chatsToReturn.length > 0) {
    const lastChat = chatsToReturn[chatsToReturn.length - 1];
    nextCursor = Buffer.from(JSON.stringify({
      updatedAt: lastChat.updatedAt.toISOString(),
      id: lastChat.id
    })).toString('base64');
  }

  return {
    chats: result,
    pageInfo: { hasMore, nextCursor }
  };
}

export async function getChatById(chatId: number, userId: number): Promise<Chat | undefined> {
  const [member] = await db
    .select()
    .from(chatMembers)
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));

  if (!member) return undefined;

  const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
  return chat || undefined;
}

export async function getChatWithMembers(chatId: number, userId: number): Promise<ChatWithMembers | undefined> {
  const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
  if (!chat) return undefined;

  const memberRecord = await db
    .select()
    .from(chatMembers)
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));
  
  if (memberRecord.length === 0) return undefined;

  const allMembers = await db
    .select()
    .from(chatMembers)
    .where(eq(chatMembers.chatId, chatId));

  const membersWithUsers: ChatMemberWithUser[] = [];
  for (const member of allMembers) {
    const user = await getUserById(member.userId);
    if (user) {
      membersWithUsers.push({ ...member, user });
    }
  }

  return {
    ...chat,
    members: membersWithUsers,
    memberCount: membersWithUsers.length
  };
}

export async function updateChat(chatId: number, data: { name?: string; description?: string }): Promise<Chat | undefined> {
  const [updated] = await db
    .update(chats)
    .set(data)
    .where(eq(chats.id, chatId))
    .returning();
  return updated || undefined;
}

export async function updateChatAvatar(chatId: number, avatarUrl: string): Promise<Chat | undefined> {
  const [updated] = await db
    .update(chats)
    .set({ avatarUrl })
    .where(eq(chats.id, chatId))
    .returning();
  return updated || undefined;
}

export async function findPrivateChat(userId1: number, userId2: number): Promise<Chat | undefined> {
  const user1Chats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId1));

  const user2Chats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .where(eq(chatMembers.userId, userId2));

  const user1ChatIds = new Set(user1Chats.map((c) => c.chatId));
  const commonChatIds = user2Chats
    .filter((c) => user1ChatIds.has(c.chatId))
    .map((c) => c.chatId);

  if (commonChatIds.length === 0) return undefined;

  for (const chatId of commonChatIds) {
    const [chat] = await db
      .select()
      .from(chats)
      .where(and(eq(chats.id, chatId), eq(chats.type, "private")));

    if (chat) {
      const members = await db
        .select()
        .from(chatMembers)
        .where(eq(chatMembers.chatId, chatId));

      if (members.length === 2) {
        return chat;
      }
    }
  }

  return undefined;
}

export async function getChatMemberRole(chatId: number, userId: number): Promise<"admin" | "member" | null> {
  const [member] = await db
    .select()
    .from(chatMembers)
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));
  
  if (!member) return null;
  return member.role;
}

export async function isUserChatAdmin(chatId: number, userId: number): Promise<boolean> {
  const role = await getChatMemberRole(chatId, userId);
  return role === "admin";
}

export async function addChatMembers(chatId: number, userIds: number[], addedBy: number): Promise<{ added: ChatMemberWithUser[]; error?: string }> {
  const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
  if (!chat) return { added: [], error: "Чат не найден" };

  const currentMembers = await db.select().from(chatMembers).where(eq(chatMembers.chatId, chatId));
  const currentCount = currentMembers.length;
  const maxAllowed = chat.maxMembers || 256;
  
  const newUserIds = userIds.filter(uid => !currentMembers.some(m => m.userId === uid));
  
  if (currentCount + newUserIds.length > maxAllowed) {
    return { added: [], error: `Превышен лимит участников (максимум ${maxAllowed})` };
  }

  const addedMembers: ChatMemberWithUser[] = [];
  
  for (const userId of newUserIds) {
    const [member] = await db
      .insert(chatMembers)
      .values({ chatId, userId, role: "member", addedBy })
      .returning();
    
    const user = await getUserById(userId);
    if (user && member) {
      addedMembers.push({ ...member, user });
    }
  }

  return { added: addedMembers };
}

export async function removeChatMember(chatId: number, userId: number): Promise<boolean> {
  const result = await db
    .delete(chatMembers)
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)))
    .returning();
  return result.length > 0;
}

export async function updateMemberRole(chatId: number, userId: number, role: "admin" | "member"): Promise<boolean> {
  const result = await db
    .update(chatMembers)
    .set({ role })
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)))
    .returning();
  return result.length > 0;
}

export async function leaveChat(chatId: number, userId: number): Promise<{ left: boolean; newAdminId?: number; newOwnerId?: number; previousOwnerId?: number; chatDeleted?: boolean }> {
  const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
  if (!chat) return { left: false };

  const members = await db.select().from(chatMembers).where(eq(chatMembers.chatId, chatId));
  const userMember = members.find(m => m.userId === userId);
  if (!userMember) return { left: false };

  if (members.length === 1) {
    await db.delete(messages).where(eq(messages.chatId, chatId));
    await db.delete(chatMembers).where(eq(chatMembers.chatId, chatId));
    await db.delete(chats).where(eq(chats.id, chatId));
    return { left: true, chatDeleted: true };
  }

  let newAdminId: number | undefined;
  let newOwnerId: number | undefined;
  let previousOwnerId: number | undefined;
  
  if (chat.createdBy === userId) {
    previousOwnerId = userId;
    const otherMembers = members
      .filter(m => m.userId !== userId)
      .sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
    
    if (otherMembers.length > 0) {
      newOwnerId = otherMembers[0].userId;
      
      await db
        .update(chats)
        .set({ createdBy: newOwnerId })
        .where(eq(chats.id, chatId));
      
      await db
        .update(chatMembers)
        .set({ role: "admin" })
        .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, newOwnerId)));
      
      newAdminId = newOwnerId;
    }
  } else if (userMember.role === "admin") {
    const otherAdmins = members.filter(m => m.userId !== userId && m.role === "admin");
    
    if (otherAdmins.length === 0) {
      const otherMembers = members
        .filter(m => m.userId !== userId)
        .sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
      
      if (otherMembers.length > 0) {
        newAdminId = otherMembers[0].userId;
        await db
          .update(chatMembers)
          .set({ role: "admin" })
          .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, newAdminId)));
      }
    }
  }

  await db.delete(chatMembers).where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));
  
  return { left: true, newAdminId, newOwnerId, previousOwnerId };
}

export async function getChatMemberIds(chatId: number): Promise<number[]> {
  const members = await db
    .select({ userId: chatMembers.userId })
    .from(chatMembers)
    .where(eq(chatMembers.chatId, chatId));
  return members.map((m) => m.userId);
}

export async function deleteChat(chatId: number, userId: number): Promise<{ deleted: boolean; mediaUrls: string[]; memberIds: number[] }> {
  const [member] = await db
    .select()
    .from(chatMembers)
    .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));

  if (!member) {
    return { deleted: false, mediaUrls: [], memberIds: [] };
  }

  const memberIds = await getChatMemberIds(chatId);

  const allMessages = await db
    .select()
    .from(messages)
    .where(eq(messages.chatId, chatId));
  const mediaUrls = allMessages
    .filter((m) => m.mediaUrl)
    .map((m) => m.mediaUrl as string);

  await db.delete(messages).where(eq(messages.chatId, chatId));
  await db.delete(chatMembers).where(eq(chatMembers.chatId, chatId));
  const result = await db.delete(chats).where(eq(chats.id, chatId)).returning();

  return { deleted: result.length > 0, mediaUrls, memberIds };
}

export async function getAllChatMessages(chatId: number): Promise<Message[]> {
  const messageList = await db
    .select()
    .from(messages)
    .where(eq(messages.chatId, chatId));
  return messageList;
}
