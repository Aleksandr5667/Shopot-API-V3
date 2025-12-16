import {
  users, contacts, chats, chatMembers, messages, messageReceipts, verificationCodes, uploadSessions
} from "@shared/schema";
import { db } from "../db";
import { eq, and, or, inArray, not, sql } from "drizzle-orm";

export async function getPrivateChatPartnerIds(userId: number): Promise<number[]> {
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

  const partners = await db
    .select({ userId: chatMembers.userId })
    .from(chatMembers)
    .where(
      and(
        inArray(chatMembers.chatId, chatIds),
        not(eq(chatMembers.userId, userId))
      )
    );

  return Array.from(new Set(partners.map(p => p.userId)));
}

export async function deleteUserAccount(userId: number): Promise<{ deleted: boolean; mediaUrls: string[] }> {
  const mediaUrls: string[] = [];

  const user = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (user.length === 0) {
    return { deleted: false, mediaUrls: [] };
  }
  if (user[0].avatarUrl) {
    mediaUrls.push(user[0].avatarUrl);
  }

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

    await db.delete(messageReceipts)
      .where(inArray(messageReceipts.messageId, 
        db.select({ id: messages.id }).from(messages).where(inArray(messages.chatId, privateChatIds))
      ));

    await db.delete(messages).where(inArray(messages.chatId, privateChatIds));
    await db.delete(chatMembers).where(inArray(chatMembers.chatId, privateChatIds));
    await db.delete(chats).where(inArray(chats.id, privateChatIds));
  }

  const groupChats = await db
    .select({ chatId: chatMembers.chatId })
    .from(chatMembers)
    .innerJoin(chats, eq(chats.id, chatMembers.chatId))
    .where(
      and(
        eq(chatMembers.userId, userId),
        eq(chats.type, "group")
      )
    );

  for (const { chatId } of groupChats) {
    const [chat] = await db.select().from(chats).where(eq(chats.id, chatId));
    if (!chat) continue;

    const members = await db.select().from(chatMembers).where(eq(chatMembers.chatId, chatId));
    const userMember = members.find(m => m.userId === userId);
    if (!userMember) continue;

    if (members.length === 1) {
      const chatMessages = await db
        .select({ mediaUrl: messages.mediaUrl })
        .from(messages)
        .where(and(eq(messages.chatId, chatId), sql`${messages.mediaUrl} IS NOT NULL`));
      chatMessages.forEach(m => {
        if (m.mediaUrl) mediaUrls.push(m.mediaUrl);
      });

      await db.delete(messageReceipts)
        .where(inArray(messageReceipts.messageId, 
          db.select({ id: messages.id }).from(messages).where(eq(messages.chatId, chatId))
        ));
      await db.delete(messages).where(eq(messages.chatId, chatId));
      await db.delete(chatMembers).where(eq(chatMembers.chatId, chatId));
      await db.delete(chats).where(eq(chats.id, chatId));
      continue;
    }

    if (chat.createdBy === userId) {
      const otherMembers = members
        .filter(m => m.userId !== userId)
        .sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
      
      if (otherMembers.length > 0) {
        const newOwnerId = otherMembers[0].userId;
        
        await db
          .update(chats)
          .set({ createdBy: newOwnerId })
          .where(eq(chats.id, chatId));
        
        await db
          .update(chatMembers)
          .set({ role: "admin" })
          .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, newOwnerId)));
      }
    } else if (userMember.role === "admin") {
      const otherAdmins = members.filter(m => m.userId !== userId && m.role === "admin");
      
      if (otherAdmins.length === 0) {
        const otherMembers = members
          .filter(m => m.userId !== userId)
          .sort((a, b) => new Date(a.joinedAt).getTime() - new Date(b.joinedAt).getTime());
        
        if (otherMembers.length > 0) {
          await db
            .update(chatMembers)
            .set({ role: "admin" })
            .where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, otherMembers[0].userId)));
        }
      }
    }

    await db.delete(chatMembers).where(and(eq(chatMembers.chatId, chatId), eq(chatMembers.userId, userId)));
  }

  await db.delete(messages).where(eq(messages.senderId, userId));

  await db.delete(contacts).where(
    or(
      eq(contacts.userId, userId),
      eq(contacts.contactUserId, userId)
    )
  );

  const userEmail = user[0].email;
  await db.delete(verificationCodes).where(eq(verificationCodes.email, userEmail));

  await db.delete(uploadSessions).where(eq(uploadSessions.userId, userId));

  await db.delete(users).where(eq(users.id, userId));

  return { deleted: true, mediaUrls };
}
