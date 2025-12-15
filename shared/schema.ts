import { sql } from "drizzle-orm";
import { pgTable, text, varchar, timestamp, integer, pgEnum, index } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const chatTypeEnum = pgEnum("chat_type", ["private", "group"]);
export const messageTypeEnum = pgEnum("message_type", ["text", "image", "video", "voice", "system"]);
export const memberRoleEnum = pgEnum("member_role", ["admin", "member"]);
export const verificationTypeEnum = pgEnum("verification_type", ["email_verification", "password_reset"]);

export const users = pgTable("users", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  displayName: text("display_name").notNull(),
  avatarColor: text("avatar_color").notNull().default("#3B82F6"),
  avatarUrl: text("avatar_url"),
  bio: text("bio"),
  emailVerified: timestamp("email_verified"),
  failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),
  lockedUntil: timestamp("locked_until"),
  pushToken: text("push_token"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  lastSeen: timestamp("last_seen").notNull().defaultNow(),
});

export const verificationCodes = pgTable("verification_codes", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  email: text("email").notNull(),
  code: text("code").notNull(),
  type: verificationTypeEnum("type").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  used: timestamp("used"),
}, (table) => ({
  emailTypeIdx: index("idx_verification_email_type").on(table.email, table.type),
}));

export const usersRelations = relations(users, ({ many }) => ({
  contacts: many(contacts),
  chatMembers: many(chatMembers),
  messages: many(messages),
}));

export const contacts = pgTable("contacts", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  contactUserId: integer("contact_user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  userIdIdx: index("idx_contacts_user_id").on(table.userId),
  contactUserIdIdx: index("idx_contacts_contact_user_id").on(table.contactUserId),
}));

export const contactsRelations = relations(contacts, ({ one }) => ({
  user: one(users, {
    fields: [contacts.userId],
    references: [users.id],
  }),
  contactUser: one(users, {
    fields: [contacts.contactUserId],
    references: [users.id],
  }),
}));

export const chats = pgTable("chats", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  type: chatTypeEnum("type").notNull().default("private"),
  name: text("name"),
  description: text("description"),
  avatarColor: text("avatar_color").notNull().default("#3B82F6"),
  avatarUrl: text("avatar_url"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  createdBy: integer("created_by").references(() => users.id),
  maxMembers: integer("max_members").notNull().default(256),
}, (table) => ({
  updatedAtIdx: index("idx_chats_updated_at").on(table.updatedAt),
  createdByIdx: index("idx_chats_created_by").on(table.createdBy),
}));

export const chatsRelations = relations(chats, ({ one, many }) => ({
  creator: one(users, {
    fields: [chats.createdBy],
    references: [users.id],
  }),
  members: many(chatMembers),
  messages: many(messages),
}));

export const chatMembers = pgTable("chat_members", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  chatId: integer("chat_id").notNull().references(() => chats.id, { onDelete: "cascade" }),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role: memberRoleEnum("role").notNull().default("member"),
  joinedAt: timestamp("joined_at").notNull().defaultNow(),
  addedBy: integer("added_by").references(() => users.id),
}, (table) => ({
  chatIdIdx: index("idx_chat_members_chat_id").on(table.chatId),
  userIdIdx: index("idx_chat_members_user_id").on(table.userId),
  chatUserIdx: index("idx_chat_members_chat_user").on(table.chatId, table.userId),
}));

export const chatMembersRelations = relations(chatMembers, ({ one }) => ({
  chat: one(chats, {
    fields: [chatMembers.chatId],
    references: [chats.id],
  }),
  user: one(users, {
    fields: [chatMembers.userId],
    references: [users.id],
  }),
}));

export const messages = pgTable("messages", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  chatId: integer("chat_id").notNull().references(() => chats.id, { onDelete: "cascade" }),
  senderId: integer("sender_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  content: text("content"),
  type: messageTypeEnum("type").notNull().default("text"),
  mediaUrl: text("media_url"),
  replyToId: integer("reply_to_id").$type<number | null>().references((): any => messages.id, { onDelete: "set null" }),
  edited: timestamp("edited"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  readBy: integer("read_by").array().notNull().default(sql`ARRAY[]::integer[]`),
}, (table) => ({
  chatIdCreatedAtIdx: index("idx_messages_chat_id_created_at").on(table.chatId, table.createdAt),
  senderIdIdx: index("idx_messages_sender_id").on(table.senderId),
  replyToIdIdx: index("idx_messages_reply_to_id").on(table.replyToId),
}));

export const messagesRelations = relations(messages, ({ one, many }) => ({
  chat: one(chats, {
    fields: [messages.chatId],
    references: [chats.id],
  }),
  sender: one(users, {
    fields: [messages.senderId],
    references: [users.id],
  }),
  replyTo: one(messages, {
    fields: [messages.replyToId],
    references: [messages.id],
  }),
  receipts: many(messageReceipts),
}));

export const messageReceipts = pgTable("message_receipts", {
  id: integer("id").primaryKey().generatedAlwaysAsIdentity(),
  messageId: integer("message_id").notNull().references(() => messages.id, { onDelete: "cascade" }),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  deliveredAt: timestamp("delivered_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => ({
  messageIdIdx: index("idx_receipts_message_id").on(table.messageId),
  userIdIdx: index("idx_receipts_user_id").on(table.userId),
  userDeliveredIdx: index("idx_receipts_user_delivered").on(table.userId, table.deliveredAt),
}));

export const messageReceiptsRelations = relations(messageReceipts, ({ one }) => ({
  message: one(messages, {
    fields: [messageReceipts.messageId],
    references: [messages.id],
  }),
  user: one(users, {
    fields: [messageReceipts.userId],
    references: [users.id],
  }),
}));

export const uploadStatusEnum = pgEnum("upload_status", ["pending", "uploading", "completed", "failed", "expired"]);

export const uploadSessions = pgTable("upload_sessions", {
  id: text("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  filename: text("filename").notNull(),
  fileSize: integer("file_size").notNull(),
  mimeType: text("mime_type").notNull(),
  chunkSize: integer("chunk_size").notNull().default(1048576),
  totalChunks: integer("total_chunks").notNull(),
  uploadedChunks: integer("uploaded_chunks").array().notNull().default(sql`ARRAY[]::integer[]`),
  status: uploadStatusEnum("status").notNull().default("pending"),
  category: text("category").notNull().default("files"),
  objectPath: text("object_path"),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
}, (table) => ({
  userIdIdx: index("idx_upload_user_id").on(table.userId),
  statusExpiresIdx: index("idx_upload_status_expires").on(table.status, table.expiresAt),
}));

export const uploadSessionsRelations = relations(uploadSessions, ({ one }) => ({
  user: one(users, {
    fields: [uploadSessions.userId],
    references: [users.id],
  }),
}));

export const insertUserSchema = z.object({
  email: z.string().email("Некорректный email"),
  password: z.string().min(8, "Пароль должен быть не менее 8 символов"),
  displayName: z.string().min(1, "Имя обязательно").max(25, "Display name must be 25 characters or less"),
  avatarColor: z.string().optional(),
  avatarUrl: z.string().url().optional().nullable(),
  bio: z.string().max(150, "Bio must be 150 characters or less").optional().nullable(),
  emailVerified: z.date().optional().nullable(),
  failedLoginAttempts: z.number().int().optional(),
  lockedUntil: z.date().optional().nullable(),
});

export const loginSchema = z.object({
  email: z.string().email("Некорректный email"),
  password: z.string().min(1, "Пароль обязателен"),
});

export const updateProfileSchema = z.object({
  displayName: z.string().min(1, "Имя обязательно").max(25, "Display name must be 25 characters or less").optional(),
  avatarColor: z.string().optional(),
  avatarUrl: z.string().url("Некорректный URL аватарки").optional().nullable(),
  bio: z.string().max(150, "Bio must be 150 characters or less").optional(),
});

export const insertContactSchema = z.object({
  contactUserId: z.number().int().positive(),
});

export const insertChatSchema = z.object({
  type: z.enum(["private", "group"]).optional(),
  name: z.string().optional().nullable(),
  description: z.string().optional().nullable(),
  avatarColor: z.string().optional(),
  memberIds: z.array(z.number()).min(1, "Необходим хотя бы один участник"),
});

export const insertMessageSchema = z.object({
  chatId: z.number().int().positive(),
  content: z.string().optional().nullable(),
  type: z.enum(["text", "image", "video", "voice", "system"]).optional(),
  mediaUrl: z.string().optional().nullable(),
  replyToId: z.number().int().positive().optional().nullable(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;

export type Contact = typeof contacts.$inferSelect;
export type InsertContact = z.infer<typeof insertContactSchema>;

export type Chat = typeof chats.$inferSelect;
export type InsertChat = z.infer<typeof insertChatSchema>;

export type ChatMember = typeof chatMembers.$inferSelect;

export type ChatMemberWithUser = ChatMember & {
  user: UserPublic;
};

export type ChatWithMembers = Chat & {
  members: ChatMemberWithUser[];
  memberCount: number;
};

export type Message = typeof messages.$inferSelect;
export type InsertMessage = z.infer<typeof insertMessageSchema>;

export type UserPublic = Omit<User, "passwordHash">;

export type ReplyToMessage = {
  id: number;
  senderId: number;
  senderName: string;
  content: string | null;
  type: "text" | "image" | "video" | "voice" | "system";
};

export type MessageReceipt = typeof messageReceipts.$inferSelect;

export type MessageWithReply = Message & { 
  sender: UserPublic;
  replyToMessage?: ReplyToMessage | null;
  deliveredTo?: number[];
};

export type UploadSession = typeof uploadSessions.$inferSelect;

export const initUploadSchema = z.object({
  filename: z.string().min(1),
  fileSize: z.number().int().positive().max(500 * 1024 * 1024),
  mimeType: z.string().min(1),
  category: z.enum(["avatars", "images", "videos", "voice", "files"]).optional(),
});

export type InitUploadInput = z.infer<typeof initUploadSchema>;

// Pagination types
export interface PageInfo {
  hasMore: boolean;
  nextCursor: string | null;
}

export interface ChatsCursor {
  updatedAt: string;
  id: number;
}

export interface ContactsCursor {
  createdAt: string;
  id: number;
}

export interface MessagesCursor {
  createdAt: string;
  id: number;
}
