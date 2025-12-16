import { users, verificationCodes } from "@shared/schema";
import { db } from "../db";
import { eq, and, desc, gt, sql } from "drizzle-orm";
import type { VerificationCode, VerificationType } from "./types";
import { getUserByEmail } from "./users.storage";

export async function createVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode> {
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const [verificationCode] = await db
    .insert(verificationCodes)
    .values({ email, code, type, expiresAt })
    .returning();
  return verificationCode;
}

export async function getValidVerificationCode(email: string, code: string, type: VerificationType): Promise<VerificationCode | undefined> {
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

export async function markVerificationCodeUsed(id: number): Promise<void> {
  await db
    .update(verificationCodes)
    .set({ used: new Date() })
    .where(eq(verificationCodes.id, id));
}

export async function getLastVerificationCodeTime(email: string, type: VerificationType): Promise<Date | undefined> {
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

export async function markEmailVerified(userId: number): Promise<void> {
  await db
    .update(users)
    .set({ emailVerified: new Date() })
    .where(eq(users.id, userId));
}

export async function updateUserPassword(email: string, newPasswordHash: string): Promise<boolean> {
  const result = await db
    .update(users)
    .set({ passwordHash: newPasswordHash })
    .where(eq(users.email, email))
    .returning();
  return result.length > 0;
}

export async function incrementFailedLoginAttempts(email: string): Promise<{ attempts: number; lockedUntil: Date | null }> {
  const MAX_ATTEMPTS = 5;
  const LOCK_DURATION_MS = 15 * 60 * 1000;
  
  const user = await getUserByEmail(email);
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

export async function resetFailedLoginAttempts(email: string): Promise<void> {
  await db
    .update(users)
    .set({ 
      failedLoginAttempts: 0,
      lockedUntil: null 
    })
    .where(eq(users.email, email));
}

export async function isAccountLocked(email: string): Promise<{ locked: boolean; lockedUntil: Date | null }> {
  const user = await getUserByEmail(email);
  if (!user) {
    return { locked: false, lockedUntil: null };
  }

  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return { locked: true, lockedUntil: user.lockedUntil };
  }

  if (user.lockedUntil && user.lockedUntil <= new Date()) {
    await resetFailedLoginAttempts(email);
  }

  return { locked: false, lockedUntil: null };
}
