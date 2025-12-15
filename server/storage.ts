import {
  users,
  contacts,
  chats,
  chatMembers,
  messages,
  messageReceipts,
  verificationCodes,
  uploadSessions,
  type User,
  type UserPublic,
  type InsertUser,
  type Contact,
  type Chat,
  type ChatMember,
  type ChatMemberWithUser,
  type ChatWithMembers,
  type Message,
  type InsertMessage,
  type UpdateProfileInput,
  type ReplyToMessage,
  type MessageWithReply,
  type MessageReceipt,
  type UploadSession,
  type InitUploadInput,
  type PageInfo,
  type ChatsCursor,
  type ContactsCursor,
  type MessagesCursor,
} from "@shared/schema";
import { db } from "./db";
import { eq, and, or, desc, sql, inArray, ilike, not, gt, lt } from "drizzle-orm";
import bcrypt from "bcrypt";

export type VerificationCode = typeof verificationCodes.$inferSelect;
export type VerificationType = "email_verification" | "password_reset";

export interface IStorage {
  createUser(data: InsertUser): Promise<UserPublic>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserById(id: number): Promise<UserPublic | undefined>;
  getUserByIdFull(id: number): Promise<User | undefined>;
  searchUsersByEmail(email: string, excludeUserId: number, limit?: number): Promise<UserPublic[]>;
  updateProfile(userId: number, data: UpdateProfileInput): Promise<UserPublic | undefined>;
  updateLastSeen(userId: number): Promise<void>;
  
  getContacts(userId: number): Promise<(Contact & { contactUser: UserPublic })[]>;
  getContactsPaginated(userId: number, limit: number, cursor?: ContactsCursor): Promise<{ contacts: (Contact & { contactUser: UserPublic })[]; pageInfo: PageInfo }>;
  addContact(userId: number, contactUserId: number): Promise<Contact>;
  removeContact(id: number, userId: number): Promise<boolean>;
  
  createChat(
    type: "private" | "group",
    name: string | null,
    avatarColor: string,
    createdBy: number,
    memberIds: number[],
    description?: string | null
  ): Promise<Chat>;
  getChatsForUser(userId: number): Promise<(Chat & { lastMessage?: Message; members: UserPublic[] })[]>;
  getChatsForUserPaginated(userId: number, limit: number, cursor?: ChatsCursor): Promise<{ chats: (Chat & { lastMessage?: Message; members: UserPublic[] })[]; pageInfo: PageInfo }>;
  getChatById(chatId: number, userId: number): Promise<Chat | undefined>;
  getChatWithMembers(chatId: number, userId: number): Promise<ChatWithMembers | undefined>;
  updateChat(chatId: number, data: { name?: string; description?: string }): Promise<Chat | undefined>;
  updateChatAvatar(chatId: number, avatarUrl: string): Promise<Chat | undefined>;
  getChatMessages(chatId: number, limit?: number, before?: Date): Promise<MessageWithReply[]>;
  findPrivateChat(userId1: number, userId2: number): Promise<Chat | undefined>;
  
  getChatMemberRole(chatId: number, userId: number): Promise<"admin" | "member" | null>;
  isUserChatAdmin(chatId: number, userId: number): Promise<boolean>;
  addChatMembers(chatId: number, userIds: number[], addedBy: number): Promise<{ added: ChatMemberWithUser[]; error?: string }>;
  removeChatMember(chatId: number, userId: number): Promise<boolean>;
  updateMemberRole(chatId: number, userId: number, role: "admin" | "member"): Promise<boolean>;
  leaveChat(chatId: number, userId: number): Promise<{ left: boolean; newAdminId?: number; newOwnerId?: number; previousOwnerId?: number; chatDeleted?: boolean }>;
  
  createMessage(chatId: number, senderId: number, data: InsertMessage): Promise<MessageWithReply>;
  createSystemMessage(chatId: number, content: string): Promise<Message>;
  getReplyToMessage(messageId: number, chatId: number): Promise<ReplyToMessage | null>;
  getChatMemberIds(chatId: number): Promise<number[]>;
  getMessageById(messageId: number): Promise<Message | undefined>;
  updateMessage(messageId: number, content: string): Promise<Message | undefined>;
  deleteMessage(messageId: number): Promise<boolean>;
  getRelatedUserIds(userId: number): Promise<number[]>;
  searchMessages(userId: number, query: string): Promise<(Message & { sender: UserPublic; chatName?: string })[]>;
  searchMessagesPaginated(userId: number, query: string, limit: number, cursor?: MessagesCursor): Promise<{ messages: (Message & { sender: UserPublic; chatName?: string })[]; pageInfo: PageInfo }>;
  deleteChat(chatId: number, userId: number): Promise<{ deleted: boolean; mediaUrls: string[]; memberIds: number[] }>;
  getAllChatMessages(chatId: number): Promise<Message[]>;
  
  createVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode>;
  getValidVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode | undefined>;
  markVerificationCodeUsed(id: number): Promise<void>;
  getLastVerificationCodeTime(email: string, type: VerificationType): Promise<Date | undefined>;
  markEmailVerified(userId: number): Promise<void>;
  updateUserPassword(email: string, newPasswordHash: string): Promise<boolean>;
  
  incrementFailedLoginAttempts(email: string): Promise<{ attempts: number; lockedUntil: Date | null }>;
  resetFailedLoginAttempts(email: string): Promise<void>;
  isAccountLocked(email: string): Promise<{ locked: boolean; lockedUntil: Date | null }>;
  
  createMessageReceipts(messageId: number, userIds: number[]): Promise<void>;
  markMessageDelivered(messageId: number, userId: number): Promise<boolean>;
  getMessageDeliveredTo(messageId: number): Promise<number[]>;
  getUndeliveredMessagesForUser(userId: number): Promise<{ messageId: number; chatId: number; senderId: number }[]>;
  markUserMessagesAsDelivered(userId: number): Promise<{ messageId: number; chatId: number; senderId: number; deliveredTo: number[] }[]>;
  
  createUploadSession(userId: number, data: InitUploadInput): Promise<UploadSession>;
  getUploadSession(sessionId: string): Promise<UploadSession | undefined>;
  markChunkUploaded(sessionId: string, chunkIndex: number): Promise<UploadSession | undefined>;
  completeUploadSession(sessionId: string, objectPath: string): Promise<UploadSession | undefined>;
  getExpiredSessions(): Promise<UploadSession[]>;
  deleteUploadSession(sessionId: string): Promise<boolean>;
  
  markMessageRead(messageId: number, userId: number): Promise<void>;
  markChatRead(chatId: number, userId: number): Promise<void>;
  savePushToken(userId: number, token: string): Promise<void>;
  removePushToken(userId: number): Promise<void>;
  
  // Account deletion
  getPrivateChatPartnerIds(userId: number): Promise<number[]>;
  deleteUserAccount(userId: number): Promise<{ deleted: boolean; mediaUrls: string[] }>;
}

function toPublicUser(user: User): UserPublic {
  const { passwordHash, ...publicUser } = user;
  return publicUser;
}

export class DatabaseStorage implements IStorage {
  async createUser(data: InsertUser): Promise<UserPublic> {
    const passwordHash = await bcrypt.hash(data.password, 10);
    const [user] = await db
      .insert(users)
      .values({
        email: data.email,
        passwordHash,
        displayName: data.displayName,
        avatarColor: data.avatarColor || "#3B82F6",
        bio: data.bio,
      })
      .returning();
    return toPublicUser(user);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || undefined;
  }

  async getUserById(id: number): Promise<UserPublic | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user ? toPublicUser(user) : undefined;
  }

  async getUserByIdFull(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async searchUsersByEmail(email: string, excludeUserId: number, limit: number = 20): Promise<UserPublic[]> {
    const foundUsers = await db
      .select()
      .from(users)
      .where(and(
        ilike(users.email, `%${email}%`),
        sql`${users.id} != ${excludeUserId}`
      ))
      .limit(limit);
    return foundUsers.map(toPublicUser);
  }

  async updateProfile(userId: number, data: UpdateProfileInput): Promise<UserPublic | undefined> {
    const updateData: Partial<typeof users.$inferInsert> = {};
    if (data.displayName !== undefined) updateData.displayName = data.displayName;
    if (data.avatarColor !== undefined) updateData.avatarColor = data.avatarColor;
    if (data.avatarUrl !== undefined) updateData.avatarUrl = data.avatarUrl;
    if (data.bio !== undefined) updateData.bio = data.bio;

    const [user] = await db
      .update(users)
      .set(updateData)
      .where(eq(users.id, userId))
      .returning();
    return user ? toPublicUser(user) : undefined;
  }

  async updateLastSeen(userId: number): Promise<void> {
    await db.update(users).set({ lastSeen: new Date() }).where(eq(users.id, userId));
  }

  async getContacts(userId: number): Promise<(Contact & { contactUser: UserPublic })[]> {
    const contactList = await db
      .select()
      .from(contacts)
      .where(eq(contacts.userId, userId));

    const result: (Contact & { contactUser: UserPublic })[] = [];
    for (const contact of contactList) {
      const contactUser = await this.getUserById(contact.contactUserId);
      if (contactUser) {
        result.push({ ...contact, contactUser });
      }
    }
    return result;
  }

  async getContactsPaginated(userId: number, limit: number, cursor?: ContactsCursor): Promise<{ contacts: (Contact & { contactUser: UserPublic })[]; pageInfo: PageInfo }> {
    const conditions = [eq(contacts.userId, userId)];
    
    if (cursor) {
      const cursorDate = new Date(cursor.createdAt);
      conditions.push(
        or(
          lt(contacts.createdAt, cursorDate),
          and(eq(contacts.createdAt, cursorDate), lt(contacts.id, cursor.id))
        )!
      );
    }

    const contactList = await db
      .select()
      .from(contacts)
      .where(and(...conditions))
      .orderBy(desc(contacts.createdAt), desc(contacts.id))
      .limit(limit + 1);

    const hasMore = contactList.length > limit;
    const contactsToReturn = hasMore ? contactList.slice(0, limit) : contactList;

    const result: (Contact & { contactUser: UserPublic })[] = [];
    for (const contact of contactsToReturn) {
      const contactUser = await this.getUserById(contact.contactUserId);
      if (contactUser) {
        result.push({ ...contact, contactUser });
      }
    }

    let nextCursor: string | null = null;
    if (hasMore && contactsToReturn.length > 0) {
      const lastContact = contactsToReturn[contactsToReturn.length - 1];
      nextCursor = Buffer.from(JSON.stringify({
        createdAt: lastContact.createdAt.toISOString(),
        id: lastContact.id
      })).toString('base64');
    }

    return {
      contacts: result,
      pageInfo: { hasMore, nextCursor }
    };
  }

  async addContact(userId: number, contactUserId: number): Promise<Contact> {
    const [contact] = await db
      .insert(contacts)
      .values({ userId, contactUserId })
      .returning();
    return contact;
  }

  async removeContact(id: number, userId: number): Promise<boolean> {
    const result = await db
      .delete(contacts)
      .where(and(eq(contacts.id, id), eq(contacts.userId, userId)))
      .returning();
    return result.length > 0;
  }

  async createChat(
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

  async getChatsForUser(userId: number): Promise<(Chat & { lastMessage?: Message; members: UserPublic[] })[]> {
    const memberRecords = await db
      .select()
      .from(chatMembers)
      .where(eq(chatMembers.userId, userId));

    const chatIds = memberRecords.map((m) => m.chatId);
    if (chatIds.length === 0) return [];

    const chatList = await db.select().from(chats).where(inArray(chats.id, chatIds));

    const result: (Chat & { lastMessage?: Message; members: UserPublic[] })[] = [];
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
        const user = await this.getUserById(member.userId);
        if (user) memberUsers.push(user);
      }

      result.push({
        ...chat,
        lastMessage: lastMessage || undefined,
        members: memberUsers,
      });
    }

    result.sort((a, b) => {
      const aTime = a.lastMessage?.createdAt || a.createdAt;
      const bTime = b.lastMessage?.createdAt || b.createdAt;
      return new Date(bTime).getTime() - new Date(aTime).getTime();
    });

    return result;
  }

  async getChatsForUserPaginated(userId: number, limit: number, cursor?: ChatsCursor): Promise<{ chats: (Chat & { lastMessage?: Message; members: UserPublic[] })[]; pageInfo: PageInfo }> {
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

    const result: (Chat & { lastMessage?: Message; members: UserPublic[] })[] = [];
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
        const user = await this.getUserById(member.userId);
        if (user) memberUsers.push(user);
      }

      result.push({
        ...chat,
        lastMessage: lastMessage || undefined,
        members: memberUsers,
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

  async getChatById(chatId: number, userId: number): Promise<Chat | undefined> {
    const [member] = await db
      .select()
      .from(chatMembers)
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));

    if (!member) return undefined;

    const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
    return chat || undefined;
  }

  async getChatMessages(chatId: number, limit: number = 50, before?: Date): Promise<MessageWithReply[]> {
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
      const sender = await this.getUserById(message.senderId);
      if (sender) {
        let replyToMessage: ReplyToMessage | null = null;
        if (message.replyToId) {
          replyToMessage = await this.getReplyToMessage(message.replyToId, chatId);
        }
        const deliveredTo = await this.getMessageDeliveredTo(message.id);
        result.push({ ...message, sender, replyToMessage, deliveredTo });
      }
    }

    // Return sorted from old to new (ASC)
    return result.reverse();
  }

  async findPrivateChat(userId1: number, userId2: number): Promise<Chat | undefined> {
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

  async getChatWithMembers(chatId: number, userId: number): Promise<ChatWithMembers | undefined> {
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
      const user = await this.getUserById(member.userId);
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

  async updateChat(chatId: number, data: { name?: string; description?: string }): Promise<Chat | undefined> {
    const [updated] = await db
      .update(chats)
      .set(data)
      .where(eq(chats.id, chatId))
      .returning();
    return updated || undefined;
  }

  async getChatMemberRole(chatId: number, userId: number): Promise<"admin" | "member" | null> {
    const [member] = await db
      .select()
      .from(chatMembers)
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));
    
    if (!member) return null;
    return member.role;
  }

  async isUserChatAdmin(chatId: number, userId: number): Promise<boolean> {
    const role = await this.getChatMemberRole(chatId, userId);
    return role === "admin";
  }

  async addChatMembers(chatId: number, userIds: number[], addedBy: number): Promise<{ added: ChatMemberWithUser[]; error?: string }> {
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
      
      const user = await this.getUserById(userId);
      if (user && member) {
        addedMembers.push({ ...member, user });
      }
    }

    return { added: addedMembers };
  }

  async removeChatMember(chatId: number, userId: number): Promise<boolean> {
    const result = await db
      .delete(chatMembers)
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)))
      .returning();
    return result.length > 0;
  }

  async updateMemberRole(chatId: number, userId: number, role: "admin" | "member"): Promise<boolean> {
    const result = await db
      .update(chatMembers)
      .set({ role })
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)))
      .returning();
    return result.length > 0;
  }

  async leaveChat(chatId: number, userId: number): Promise<{ left: boolean; newAdminId?: number; newOwnerId?: number; previousOwnerId?: number; chatDeleted?: boolean }> {
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
    
    // If the creator is leaving, transfer ownership to the oldest member
    if (chat.createdBy === userId) {
      previousOwnerId = userId;
      const otherMembers = members
        .filter(m => m.userId !== userId)
        .sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
      
      if (otherMembers.length > 0) {
        newOwnerId = otherMembers[0].userId;
        
        // Transfer ownership (update createdBy in chats table)
        await db
          .update(chats)
          .set({ createdBy: newOwnerId })
          .where(eq(chats.id, chatId));
        
        // Make new owner an admin if not already
        await db
          .update(chatMembers)
          .set({ role: "admin" })
          .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, newOwnerId)));
        
        newAdminId = newOwnerId;
      }
    } else if (userMember.role === "admin") {
      // If non-creator admin is leaving, check if we need to promote someone
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

  async getReplyToMessage(messageId: number, chatId: number): Promise<ReplyToMessage | null> {
    const [message] = await db.select().from(messages).where(eq(messages.id, messageId));
    if (!message) return null;

    // Security check: verify the message belongs to the specified chat
    if (message.chatId !== chatId) {
      return null;
    }

    const sender = await this.getUserById(message.senderId);
    if (!sender) return null;

    return {
      id: message.id,
      senderId: message.senderId,
      senderName: sender.displayName,
      content: message.content,
      type: message.type,
    };
  }

  async createMessage(chatId: number, senderId: number, data: InsertMessage): Promise<MessageWithReply> {
    // Validate replyToId belongs to the same chat before creating message
    let validatedReplyToId: number | null = null;
    if (data.replyToId) {
      const replyMessage = await this.getReplyToMessage(data.replyToId, chatId);
      if (replyMessage) {
        validatedReplyToId = data.replyToId;
      }
      // If replyToMessage is null (not found or wrong chat), we silently ignore the replyToId
    }

    const [message] = await db
      .insert(messages)
      .values({
        chatId,
        senderId,
        content: data.content,
        type: data.type || "text",
        mediaUrl: data.mediaUrl,
        replyToId: validatedReplyToId,
        readBy: [senderId],
      })
      .returning();

    // Create message receipts for all chat members except sender
    const memberIds = await this.getChatMemberIds(chatId);
    const recipientIds = memberIds.filter(id => id !== senderId);
    await this.createMessageReceipts(message.id, recipientIds);

    const sender = await this.getUserById(senderId);
    let replyToMessage: ReplyToMessage | null = null;
    
    if (message.replyToId) {
      replyToMessage = await this.getReplyToMessage(message.replyToId, chatId);
    }

    return { ...message, sender: sender!, replyToMessage, deliveredTo: [senderId] };
  }

  async createSystemMessage(chatId: number, content: string): Promise<Message> {
    const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
    if (!chat) throw new Error("Chat not found");
    
    // For system messages, use createdBy if available, otherwise get first admin/member
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

  async updateChatAvatar(chatId: number, avatarUrl: string): Promise<Chat | undefined> {
    const [updated] = await db
      .update(chats)
      .set({ avatarUrl })
      .where(eq(chats.id, chatId))
      .returning();
    return updated || undefined;
  }

  async getChatMemberIds(chatId: number): Promise<number[]> {
    const members = await db
      .select({ userId: chatMembers.userId })
      .from(chatMembers)
      .where(eq(chatMembers.chatId, chatId));
    return members.map((m) => m.userId);
  }

  async getMessageById(messageId: number): Promise<Message | undefined> {
    const [message] = await db.select().from(messages).where(eq(messages.id, messageId));
    return message || undefined;
  }

  async updateMessage(messageId: number, content: string): Promise<Message | undefined> {
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

  async deleteMessage(messageId: number): Promise<boolean> {
    const result = await db
      .delete(messages)
      .where(eq(messages.id, messageId))
      .returning();
    return result.length > 0;
  }

  async getRelatedUserIds(userId: number): Promise<number[]> {
    // Get all users who share at least one chat with this user
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

  async searchMessages(userId: number, query: string): Promise<(Message & { sender: UserPublic; chatName?: string })[]> {
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
      const sender = await this.getUserById(message.senderId);
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

  async searchMessagesPaginated(userId: number, query: string, limit: number, cursor?: MessagesCursor): Promise<{ messages: (Message & { sender: UserPublic; chatName?: string })[]; pageInfo: PageInfo }> {
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
      const sender = await this.getUserById(message.senderId);
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

  async getAllChatMessages(chatId: number): Promise<Message[]> {
    const messageList = await db
      .select()
      .from(messages)
      .where(eq(messages.chatId, chatId));
    return messageList;
  }

  async deleteChat(chatId: number, userId: number): Promise<{ deleted: boolean; mediaUrls: string[]; memberIds: number[] }> {
    // Check if user is a member of the chat
    const [member] = await db
      .select()
      .from(chatMembers)
      .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));

    if (!member) {
      return { deleted: false, mediaUrls: [], memberIds: [] };
    }

    // Get all member IDs BEFORE deletion for WebSocket notification
    const memberIds = await this.getChatMemberIds(chatId);

    // Get all messages with media URLs before deletion
    const allMessages = await this.getAllChatMessages(chatId);
    const mediaUrls = allMessages
      .filter((m) => m.mediaUrl)
      .map((m) => m.mediaUrl as string);

    // Delete all messages (cascade will handle this, but we do it explicitly for clarity)
    await db.delete(messages).where(eq(messages.chatId, chatId));

    // Delete all chat members
    await db.delete(chatMembers).where(eq(chatMembers.chatId, chatId));

    // Delete the chat itself
    const result = await db.delete(chats).where(eq(chats.id, chatId)).returning();

    return { deleted: result.length > 0, mediaUrls, memberIds };
  }

  async createVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode> {
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const [verificationCode] = await db
      .insert(verificationCodes)
      .values({ email, code, type, expiresAt })
      .returning();
    return verificationCode;
  }

  async getValidVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode | undefined> {
    const [verificationCode] = await db
      .select()
      .from(verificationCodes)
      .where(and(
        eq(verificationCodes.email, email),
        eq(verificationCodes.code, code),
        eq(verificationCodes.type, type),
        gt(verificationCodes.expiresAt, new Date()),
        sql`${verificationCodes.used} IS NULL`
      ));
    return verificationCode || undefined;
  }

  async markVerificationCodeUsed(id: number): Promise<void> {
    await db
      .update(verificationCodes)
      .set({ used: new Date() })
      .where(eq(verificationCodes.id, id));
  }

  async getLastVerificationCodeTime(email: string, type: VerificationType): Promise<Date | undefined> {
    const [lastCode] = await db
      .select({ createdAt: verificationCodes.createdAt })
      .from(verificationCodes)
      .where(and(
        eq(verificationCodes.email, email),
        eq(verificationCodes.type, type)
      ))
      .orderBy(desc(verificationCodes.createdAt))
      .limit(1);
    return lastCode?.createdAt || undefined;
  }

  async markEmailVerified(userId: number): Promise<void> {
    await db
      .update(users)
      .set({ emailVerified: new Date() })
      .where(eq(users.id, userId));
  }

  async updateUserPassword(email: string, newPasswordHash: string): Promise<boolean> {
    const result = await db
      .update(users)
      .set({ passwordHash: newPasswordHash })
      .where(eq(users.email, email))
      .returning();
    return result.length > 0;
  }

  async incrementFailedLoginAttempts(email: string): Promise<{ attempts: number; lockedUntil: Date | null }> {
    const MAX_ATTEMPTS = 5;
    const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes
    
    const user = await this.getUserByEmail(email);
    if (!user) {
      return { attempts: 0, lockedUntil: null };
    }

    const newAttempts = (user.failedLoginAttempts || 0) + 1;
    let lockedUntil: Date | null = null;

    if (newAttempts >= MAX_ATTEMPTS) {
      lockedUntil = new Date(Date.now() + LOCK_DURATION_MS);
    }

    await db
      .update(users)
      .set({ 
        failedLoginAttempts: newAttempts,
        lockedUntil: lockedUntil 
      })
      .where(eq(users.email, email));

    return { attempts: newAttempts, lockedUntil };
  }

  async resetFailedLoginAttempts(email: string): Promise<void> {
    await db
      .update(users)
      .set({ 
        failedLoginAttempts: 0,
        lockedUntil: null 
      })
      .where(eq(users.email, email));
  }

  async isAccountLocked(email: string): Promise<{ locked: boolean; lockedUntil: Date | null }> {
    const user = await this.getUserByEmail(email);
    if (!user) {
      return { locked: false, lockedUntil: null };
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return { locked: true, lockedUntil: user.lockedUntil };
    }

    // If lock has expired, reset the counter
    if (user.lockedUntil && user.lockedUntil <= new Date()) {
      await this.resetFailedLoginAttempts(email);
    }

    return { locked: false, lockedUntil: null };
  }

  async createMessageReceipts(messageId: number, userIds: number[]): Promise<void> {
    if (userIds.length === 0) return;
    
    const receipts = userIds.map(userId => ({
      messageId,
      userId,
    }));
    
    await db.insert(messageReceipts).values(receipts);
  }

  async markMessageDelivered(messageId: number, userId: number): Promise<boolean> {
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

  async getMessageDeliveredTo(messageId: number): Promise<number[]> {
    // Get the message to include sender in deliveredTo
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
    
    // Sender is always in deliveredTo, plus recipients who have received it
    const deliveredUserIds = new Set([message.senderId, ...receipts.map(r => r.userId)]);
    return Array.from(deliveredUserIds);
  }

  async getUndeliveredMessagesForUser(userId: number): Promise<{ messageId: number; chatId: number; senderId: number }[]> {
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

  async markUserMessagesAsDelivered(userId: number): Promise<{ messageId: number; chatId: number; senderId: number; deliveredTo: number[] }[]> {
    const undelivered = await this.getUndeliveredMessagesForUser(userId);
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
      const deliveredTo = await this.getMessageDeliveredTo(msg.messageId);
      result.push({
        messageId: msg.messageId,
        chatId: msg.chatId,
        senderId: msg.senderId,
        deliveredTo,
      });
    }

    return result;
  }

  async createUploadSession(userId: number, data: InitUploadInput): Promise<UploadSession> {
    const sessionId = crypto.randomUUID();
    const chunkSize = 1048576; // 1 MB
    const totalChunks = Math.ceil(data.fileSize / chunkSize);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    const [session] = await db
      .insert(uploadSessions)
      .values({
        id: sessionId,
        userId,
        filename: data.filename,
        fileSize: data.fileSize,
        mimeType: data.mimeType,
        chunkSize,
        totalChunks,
        category: data.category || "files",
        expiresAt,
      })
      .returning();
    
    return session;
  }

  async getUploadSession(sessionId: string): Promise<UploadSession | undefined> {
    const [session] = await db
      .select()
      .from(uploadSessions)
      .where(eq(uploadSessions.id, sessionId));
    return session || undefined;
  }

  async markChunkUploaded(sessionId: string, chunkIndex: number): Promise<UploadSession | undefined> {
    const session = await this.getUploadSession(sessionId);
    if (!session) return undefined;
    
    const uploadedChunks = session.uploadedChunks || [];
    if (uploadedChunks.includes(chunkIndex)) {
      return session;
    }
    
    const newUploadedChunks = [...uploadedChunks, chunkIndex].sort((a, b) => a - b);
    const newStatus = newUploadedChunks.length === session.totalChunks ? "uploading" : "uploading";
    
    const [updated] = await db
      .update(uploadSessions)
      .set({
        uploadedChunks: newUploadedChunks,
        status: newStatus,
      })
      .where(eq(uploadSessions.id, sessionId))
      .returning();
    
    return updated || undefined;
  }

  async completeUploadSession(sessionId: string, objectPath: string): Promise<UploadSession | undefined> {
    const [updated] = await db
      .update(uploadSessions)
      .set({
        status: "completed",
        objectPath,
        completedAt: new Date(),
      })
      .where(eq(uploadSessions.id, sessionId))
      .returning();
    
    return updated || undefined;
  }

  async getExpiredSessions(): Promise<UploadSession[]> {
    return await db
      .select()
      .from(uploadSessions)
      .where(
        and(
          lt(uploadSessions.expiresAt, new Date()),
          not(eq(uploadSessions.status, "completed"))
        )
      );
  }

  async deleteUploadSession(sessionId: string): Promise<boolean> {
    const result = await db
      .delete(uploadSessions)
      .where(eq(uploadSessions.id, sessionId))
      .returning();
    return result.length > 0;
  }

  async markUploadSessionFailed(sessionId: string): Promise<UploadSession | undefined> {
    const [updated] = await db
      .update(uploadSessions)
      .set({
        status: "failed",
      })
      .where(eq(uploadSessions.id, sessionId))
      .returning();
    
    return updated || undefined;
  }

  async markMessageRead(messageId: number, userId: number): Promise<void> {
    const message = await this.getMessageById(messageId);
    if (!message) return;
    
    const currentReadBy = message.readBy || [];
    if (!currentReadBy.includes(userId)) {
      await db
        .update(messages)
        .set({ readBy: [...currentReadBy, userId] })
        .where(eq(messages.id, messageId));
    }
  }

  async markChatRead(chatId: number, userId: number): Promise<void> {
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

  async savePushToken(userId: number, token: string): Promise<void> {
    await db
      .update(users)
      .set({ pushToken: token })
      .where(eq(users.id, userId));
  }

  async removePushToken(userId: number): Promise<void> {
    await db
      .update(users)
      .set({ pushToken: null })
      .where(eq(users.id, userId));
  }

  // Get all private chat partner IDs for a user (to notify them when account is deleted)
  async getPrivateChatPartnerIds(userId: number): Promise<number[]> {
    // Find all private chats where user is a member
    const userChats = await db
      .select({ chatId: chatMembers.chatId })
      .from(chatMembers)
      .innerJoin(chats, eq(chats.id, chatMembers.chatId))
      .where(
        and(
          eq(chatMembers.userId, userId),
          eq(chats.type, "private")
        )
      );

    if (userChats.length === 0) return [];

    const chatIds = userChats.map(c => c.chatId);

    // Get all other members of these private chats
    const partners = await db
      .select({ userId: chatMembers.userId })
      .from(chatMembers)
      .where(
        and(
          inArray(chatMembers.chatId, chatIds),
          not(eq(chatMembers.userId, userId))
        )
      );

    // Return unique partner IDs
    return Array.from(new Set(partners.map(p => p.userId)));
  }

  // Delete user account and all associated data
  async deleteUserAccount(userId: number): Promise<{ deleted: boolean; mediaUrls: string[] }> {
    const mediaUrls: string[] = [];

    // Get user's avatar URL to delete
    const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (user.length === 0) {
      return { deleted: false, mediaUrls: [] };
    }
    if (user[0].avatarUrl) {
      mediaUrls.push(user[0].avatarUrl);
    }

    // Get all media URLs from messages sent by this user
    const userMessages = await db
      .select({ mediaUrl: messages.mediaUrl })
      .from(messages)
      .where(
        and(
          eq(messages.senderId, userId),
          sql`${messages.mediaUrl} IS NOT NULL`
        )
      );
    userMessages.forEach(m => {
      if (m.mediaUrl) mediaUrls.push(m.mediaUrl);
    });

    // Delete all private chats where user is a member (and their messages)
    const privateChats = await db
      .select({ chatId: chatMembers.chatId })
      .from(chatMembers)
      .innerJoin(chats, eq(chats.id, chatMembers.chatId))
      .where(
        and(
          eq(chatMembers.userId, userId),
          eq(chats.type, "private")
        )
      );

    if (privateChats.length > 0) {
      const privateChatIds = privateChats.map(c => c.chatId);
      
      // Get all media URLs from private chat messages
      const privateChatMessages = await db
        .select({ mediaUrl: messages.mediaUrl })
        .from(messages)
        .where(
          and(
            inArray(messages.chatId, privateChatIds),
            sql`${messages.mediaUrl} IS NOT NULL`
          )
        );
      privateChatMessages.forEach(m => {
        if (m.mediaUrl) mediaUrls.push(m.mediaUrl);
      });

      // Delete message receipts for private chats
      await db.delete(messageReceipts)
        .where(inArray(messageReceipts.messageId, 
          db.select({ id: messages.id }).from(messages).where(inArray(messages.chatId, privateChatIds))
        ));

      // Delete messages from private chats
      await db.delete(messages).where(inArray(messages.chatId, privateChatIds));

      // Delete chat members from private chats
      await db.delete(chatMembers).where(inArray(chatMembers.chatId, privateChatIds));

      // Delete the private chats
      await db.delete(chats).where(inArray(chats.id, privateChatIds));
    }

    // For group chats, remove user from membership but don't delete messages
    await db.delete(chatMembers).where(eq(chatMembers.userId, userId));

    // Delete contacts where user is involved
    await db.delete(contacts).where(
      or(
        eq(contacts.userId, userId),
        eq(contacts.contactUserId, userId)
      )
    );

    // Delete verification codes for this user's email
    const userEmail = user[0].email;
    await db.delete(verificationCodes).where(eq(verificationCodes.email, userEmail));

    // Delete upload sessions
    await db.delete(uploadSessions).where(eq(uploadSessions.userId, userId));

    // Finally delete the user
    await db.delete(users).where(eq(users.id, userId));

    return { deleted: true, mediaUrls };
  }
}

export const storage = new DatabaseStorage();
