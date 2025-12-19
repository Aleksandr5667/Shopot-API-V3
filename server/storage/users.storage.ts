import { users, type User, type UserPublic, type InsertUser, type UpdateProfileInput } from "@shared/schema";
import { db } from "../db";
import { eq, and, sql, ilike } from "drizzle-orm";
import bcrypt from "bcrypt";
import { toPublicUser } from "./utils";

export async function createUser(data: InsertUser): Promise<UserPublic> {
  const passwordHash = await bcrypt.hash(data.password, 10);
  const normalizedEmail = data.email.toLowerCase().trim();
  const [user] = await db
    .insert(users)
    .values({
      email: normalizedEmail,
      passwordHash,
      displayName: data.displayName,
      avatarColor: data.avatarColor || "#3B82F6",
      bio: data.bio,
    })
    .returning();
  return toPublicUser(user);
}

export async function getUserByEmail(email: string): Promise<User | undefined> {
  const normalizedEmail = email.toLowerCase().trim();
  const [user] = await db.select().from(users).where(eq(users.email, normalizedEmail));
  return user || undefined;
}

export async function getUserById(id: number): Promise<UserPublic | undefined> {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user ? toPublicUser(user) : undefined;
}

export async function getUserByIdFull(id: number): Promise<User | undefined> {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user || undefined;
}

export async function searchUsersByEmail(email: string, excludeUserId: number, limit: number = 20): Promise<UserPublic[]> {
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

export async function updateProfile(userId: number, data: UpdateProfileInput): Promise<UserPublic | undefined> {
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

export async function updateLastSeen(userId: number): Promise<void> {
  await db.update(users).set({ lastSeen: new Date() }).where(eq(users.id, userId));
}

export async function savePushToken(userId: number, token: string): Promise<void> {
  await db
    .update(users)
    .set({ pushToken: token })
    .where(eq(users.id, userId));
}

export async function removePushToken(userId: number): Promise<void> {
  await db
    .update(users)
    .set({ pushToken: null })
    .where(eq(users.id, userId));
}

export async function getPushToken(userId: number): Promise<string | null> {
  const [user] = await db.select({ pushToken: users.pushToken }).from(users).where(eq(users.id, userId));
  return user?.pushToken || null;
}
