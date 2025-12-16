import { contacts, type Contact, type UserPublic, type ContactsCursor, type PageInfo } from "@shared/schema";
import { db } from "../db";
import { eq, and, or, desc, lt } from "drizzle-orm";
import { getUserById } from "./users.storage";

export async function getContacts(userId: number): Promise<(Contact & { contactUser: UserPublic })[]> {
  const contactList = await db
    .select()
    .from(contacts)
    .where(eq(contacts.userId, userId));

  const result: (Contact & { contactUser: UserPublic })[] = [];
  for (const contact of contactList) {
    const contactUser = await getUserById(contact.contactUserId);
    if (contactUser) {
      result.push({ ...contact, contactUser });
    }
  }
  return result;
}

export async function getContactsPaginated(userId: number, limit: number, cursor?: ContactsCursor): Promise<{ contacts: (Contact & { contactUser: UserPublic })[]; pageInfo: PageInfo }> {
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
    const contactUser = await getUserById(contact.contactUserId);
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

export async function addContact(userId: number, contactUserId: number): Promise<Contact> {
  const [contact] = await db
    .insert(contacts)
    .values({ userId, contactUserId })
    .returning();
  return contact;
}

export async function removeContact(id: number, userId: number): Promise<boolean> {
  const result = await db
    .delete(contacts)
    .where(and(eq(contacts.id, id), eq(contacts.userId, userId)))
    .returning();
  return result.length > 0;
}
