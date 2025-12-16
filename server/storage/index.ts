import type { IStorage, VerificationCode, VerificationType } from "./types";
import type {
  User,
  UserPublic,
  InsertUser,
  Contact,
  Chat,
  ChatMemberWithUser,
  ChatWithMembers,
  Message,
  InsertMessage,
  UpdateProfileInput,
  ReplyToMessage,
  MessageWithReply,
  UploadSession,
  InitUploadInput,
  PageInfo,
  ChatsCursor,
  ContactsCursor,
  MessagesCursor,
} from "@shared/schema";

import * as usersStorage from "./users.storage";
import * as contactsStorage from "./contacts.storage";
import * as chatsStorage from "./chats.storage";
import * as messagesStorage from "./messages.storage";
import * as authStorage from "./auth.storage";
import * as uploadsStorage from "./uploads.storage";
import * as accountStorage from "./account.storage";

export type { VerificationCode, VerificationType } from "./types";
export type { IStorage } from "./types";

export class DatabaseStorage implements IStorage {
  // Users
  async createUser(data: InsertUser): Promise<UserPublic> {
    return usersStorage.createUser(data);
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    return usersStorage.getUserByEmail(email);
  }

  async getUserById(id: number): Promise<UserPublic | undefined> {
    return usersStorage.getUserById(id);
  }

  async getUserByIdFull(id: number): Promise<User | undefined> {
    return usersStorage.getUserByIdFull(id);
  }

  async searchUsersByEmail(email: string, excludeUserId: number, limit?: number): Promise<UserPublic[]> {
    return usersStorage.searchUsersByEmail(email, excludeUserId, limit);
  }

  async updateProfile(userId: number, data: UpdateProfileInput): Promise<UserPublic | undefined> {
    return usersStorage.updateProfile(userId, data);
  }

  async updateLastSeen(userId: number): Promise<void> {
    return usersStorage.updateLastSeen(userId);
  }

  async savePushToken(userId: number, token: string): Promise<void> {
    return usersStorage.savePushToken(userId, token);
  }

  async removePushToken(userId: number): Promise<void> {
    return usersStorage.removePushToken(userId);
  }

  // Contacts
  async getContacts(userId: number): Promise<(Contact & { contactUser: UserPublic })[]> {
    return contactsStorage.getContacts(userId);
  }

  async getContactsPaginated(userId: number, limit: number, cursor?: ContactsCursor): Promise<{ contacts: (Contact & { contactUser: UserPublic })[]; pageInfo: PageInfo }> {
    return contactsStorage.getContactsPaginated(userId, limit, cursor);
  }

  async addContact(userId: number, contactUserId: number): Promise<Contact> {
    return contactsStorage.addContact(userId, contactUserId);
  }

  async removeContact(id: number, userId: number): Promise<boolean> {
    return contactsStorage.removeContact(id, userId);
  }

  // Chats
  async createChat(
    type: "private" | "group",
    name: string | null,
    avatarColor: string,
    createdBy: number,
    memberIds: number[],
    description?: string | null
  ): Promise<Chat> {
    return chatsStorage.createChat(type, name, avatarColor, createdBy, memberIds, description);
  }

  async getChatsForUser(userId: number): Promise<(Chat & { lastMessage?: Message; members: UserPublic[] })[]> {
    return chatsStorage.getChatsForUser(userId);
  }

  async getChatsForUserPaginated(userId: number, limit: number, cursor?: ChatsCursor): Promise<{ chats: (Chat & { lastMessage?: Message; members: UserPublic[] })[]; pageInfo: PageInfo }> {
    return chatsStorage.getChatsForUserPaginated(userId, limit, cursor);
  }

  async getChatById(chatId: number, userId: number): Promise<Chat | undefined> {
    return chatsStorage.getChatById(chatId, userId);
  }

  async getChatWithMembers(chatId: number, userId: number): Promise<ChatWithMembers | undefined> {
    return chatsStorage.getChatWithMembers(chatId, userId);
  }

  async updateChat(chatId: number, data: { name?: string; description?: string }): Promise<Chat | undefined> {
    return chatsStorage.updateChat(chatId, data);
  }

  async updateChatAvatar(chatId: number, avatarUrl: string): Promise<Chat | undefined> {
    return chatsStorage.updateChatAvatar(chatId, avatarUrl);
  }

  async findPrivateChat(userId1: number, userId2: number): Promise<Chat | undefined> {
    return chatsStorage.findPrivateChat(userId1, userId2);
  }

  async getChatMemberRole(chatId: number, userId: number): Promise<"admin" | "member" | null> {
    return chatsStorage.getChatMemberRole(chatId, userId);
  }

  async isUserChatAdmin(chatId: number, userId: number): Promise<boolean> {
    return chatsStorage.isUserChatAdmin(chatId, userId);
  }

  async addChatMembers(chatId: number, userIds: number[], addedBy: number): Promise<{ added: ChatMemberWithUser[]; error?: string }> {
    return chatsStorage.addChatMembers(chatId, userIds, addedBy);
  }

  async removeChatMember(chatId: number, userId: number): Promise<boolean> {
    return chatsStorage.removeChatMember(chatId, userId);
  }

  async updateMemberRole(chatId: number, userId: number, role: "admin" | "member"): Promise<boolean> {
    return chatsStorage.updateMemberRole(chatId, userId, role);
  }

  async leaveChat(chatId: number, userId: number): Promise<{ left: boolean; newAdminId?: number; newOwnerId?: number; previousOwnerId?: number; chatDeleted?: boolean }> {
    return chatsStorage.leaveChat(chatId, userId);
  }

  async getChatMemberIds(chatId: number): Promise<number[]> {
    return chatsStorage.getChatMemberIds(chatId);
  }

  async deleteChat(chatId: number, userId: number): Promise<{ deleted: boolean; mediaUrls: string[]; memberIds: number[] }> {
    return chatsStorage.deleteChat(chatId, userId);
  }

  async getAllChatMessages(chatId: number): Promise<Message[]> {
    return chatsStorage.getAllChatMessages(chatId);
  }

  // Messages
  async createMessage(chatId: number, senderId: number, data: InsertMessage): Promise<MessageWithReply> {
    return messagesStorage.createMessage(chatId, senderId, data);
  }

  async createSystemMessage(chatId: number, content: string): Promise<Message> {
    return messagesStorage.createSystemMessage(chatId, content);
  }

  async getReplyToMessage(messageId: number, chatId: number): Promise<ReplyToMessage | null> {
    return messagesStorage.getReplyToMessage(messageId, chatId);
  }

  async getChatMessages(chatId: number, limit?: number, before?: Date): Promise<MessageWithReply[]> {
    return messagesStorage.getChatMessages(chatId, limit, before);
  }

  async getMessageById(messageId: number): Promise<Message | undefined> {
    return messagesStorage.getMessageById(messageId);
  }

  async updateMessage(messageId: number, content: string): Promise<Message | undefined> {
    return messagesStorage.updateMessage(messageId, content);
  }

  async deleteMessage(messageId: number): Promise<boolean> {
    return messagesStorage.deleteMessage(messageId);
  }

  async getRelatedUserIds(userId: number): Promise<number[]> {
    return messagesStorage.getRelatedUserIds(userId);
  }

  async searchMessages(userId: number, query: string): Promise<(Message & { sender: UserPublic; chatName?: string })[]> {
    return messagesStorage.searchMessages(userId, query);
  }

  async searchMessagesPaginated(userId: number, query: string, limit: number, cursor?: MessagesCursor): Promise<{ messages: (Message & { sender: UserPublic; chatName?: string })[]; pageInfo: PageInfo }> {
    return messagesStorage.searchMessagesPaginated(userId, query, limit, cursor);
  }

  async createMessageReceipts(messageId: number, userIds: number[]): Promise<void> {
    return messagesStorage.createMessageReceipts(messageId, userIds);
  }

  async markMessageDelivered(messageId: number, userId: number): Promise<boolean> {
    return messagesStorage.markMessageDelivered(messageId, userId);
  }

  async getMessageDeliveredTo(messageId: number): Promise<number[]> {
    return messagesStorage.getMessageDeliveredTo(messageId);
  }

  async getUndeliveredMessagesForUser(userId: number): Promise<{ messageId: number; chatId: number; senderId: number }[]> {
    return messagesStorage.getUndeliveredMessagesForUser(userId);
  }

  async markUserMessagesAsDelivered(userId: number): Promise<{ messageId: number; chatId: number; senderId: number; deliveredTo: number[] }[]> {
    return messagesStorage.markUserMessagesAsDelivered(userId);
  }

  async markMessageRead(messageId: number, userId: number): Promise<void> {
    return messagesStorage.markMessageRead(messageId, userId);
  }

  async markChatRead(chatId: number, userId: number): Promise<void> {
    return messagesStorage.markChatRead(chatId, userId);
  }

  // Auth
  async createVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode> {
    return authStorage.createVerificationCode(email, code, type);
  }

  async getValidVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode | undefined> {
    return authStorage.getValidVerificationCode(email, code, type);
  }

  async markVerificationCodeUsed(id: number): Promise<void> {
    return authStorage.markVerificationCodeUsed(id);
  }

  async getLastVerificationCodeTime(email: string, type: VerificationType): Promise<Date | undefined> {
    return authStorage.getLastVerificationCodeTime(email, type);
  }

  async markEmailVerified(userId: number): Promise<void> {
    return authStorage.markEmailVerified(userId);
  }

  async updateUserPassword(email: string, newPasswordHash: string): Promise<boolean> {
    return authStorage.updateUserPassword(email, newPasswordHash);
  }

  async incrementFailedLoginAttempts(email: string): Promise<{ attempts: number; lockedUntil: Date | null }> {
    return authStorage.incrementFailedLoginAttempts(email);
  }

  async resetFailedLoginAttempts(email: string): Promise<void> {
    return authStorage.resetFailedLoginAttempts(email);
  }

  async isAccountLocked(email: string): Promise<{ locked: boolean; lockedUntil: Date | null }> {
    return authStorage.isAccountLocked(email);
  }

  // Uploads
  async createUploadSession(userId: number, data: InitUploadInput): Promise<UploadSession> {
    return uploadsStorage.createUploadSession(userId, data);
  }

  async getUploadSession(sessionId: string): Promise<UploadSession | undefined> {
    return uploadsStorage.getUploadSession(sessionId);
  }

  async markChunkUploaded(sessionId: string, chunkIndex: number): Promise<UploadSession | undefined> {
    return uploadsStorage.markChunkUploaded(sessionId, chunkIndex);
  }

  async completeUploadSession(sessionId: string, objectPath: string): Promise<UploadSession | undefined> {
    return uploadsStorage.completeUploadSession(sessionId, objectPath);
  }

  async markUploadSessionFailed(sessionId: string): Promise<UploadSession | undefined> {
    return uploadsStorage.markUploadSessionFailed(sessionId);
  }

  async getExpiredSessions(): Promise<UploadSession[]> {
    return uploadsStorage.getExpiredSessions();
  }

  async deleteUploadSession(sessionId: string): Promise<boolean> {
    return uploadsStorage.deleteUploadSession(sessionId);
  }

  // Account
  async getPrivateChatPartnerIds(userId: number): Promise<number[]> {
    return accountStorage.getPrivateChatPartnerIds(userId);
  }

  async deleteUserAccount(userId: number): Promise<{ deleted: boolean; mediaUrls: string[] }> {
    return accountStorage.deleteUserAccount(userId);
  }
}

export const storage = new DatabaseStorage();
