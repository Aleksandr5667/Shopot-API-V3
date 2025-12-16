import {
  type User,
  type UserPublic,
  type InsertUser,
  type Contact,
  type Chat,
  type ChatMemberWithUser,
  type ChatWithMembers,
  type Message,
  type InsertMessage,
  type UpdateProfileInput,
  type ReplyToMessage,
  type MessageWithReply,
  type UploadSession,
  type InitUploadInput,
  type PageInfo,
  type ChatsCursor,
  type ContactsCursor,
  type MessagesCursor,
  verificationCodes,
} from "@shared/schema";

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
  markUploadSessionFailed(sessionId: string): Promise<UploadSession | undefined>;
  getExpiredSessions(): Promise<UploadSession[]>;
  deleteUploadSession(sessionId: string): Promise<boolean>;
  
  markMessageRead(messageId: number, userId: number): Promise<void>;
  markChatRead(chatId: number, userId: number): Promise<void>;
  savePushToken(userId: number, token: string): Promise<void>;
  removePushToken(userId: number): Promise<void>;
  
  getPrivateChatPartnerIds(userId: number): Promise<number[]>;
  deleteUserAccount(userId: number): Promise<{ deleted: boolean; mediaUrls: string[] }>;
}
