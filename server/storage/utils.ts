import type { User, UserPublic, Message, Chat, MessageWithReply } from "@shared/schema";

export function getBaseUrl(): string {
  const devDomain = process.env.REPLIT_DEV_DOMAIN;
  const domains = process.env.REPLIT_DOMAINS;
  
  if (devDomain) {
    return `https://${devDomain}`;
  }
  
  if (domains) {
    const firstDomain = domains.split(',')[0]?.trim();
    if (firstDomain) {
      return `https://${firstDomain}`;
    }
  }
  
  return '';
}

export function toFullUrl(relativePath: string | null | undefined): string | null {
  if (!relativePath) return null;
  
  if (relativePath.startsWith('http://') || relativePath.startsWith('https://')) {
    return relativePath;
  }
  
  const baseUrl = getBaseUrl();
  if (!baseUrl) {
    return relativePath;
  }
  
  return `${baseUrl}${relativePath}`;
}

export function toPublicUser(user: User): UserPublic {
  const { passwordHash, ...publicUser } = user;
  
  return {
    ...publicUser,
    avatarUrl: toFullUrl(publicUser.avatarUrl),
  };
}

export function transformMessageUrls<T extends Message>(message: T): T {
  return {
    ...message,
    mediaUrl: toFullUrl(message.mediaUrl),
    thumbnailUrl: toFullUrl(message.thumbnailUrl),
  };
}

export function transformChatUrls<T extends Chat>(chat: T): T {
  return {
    ...chat,
    avatarUrl: toFullUrl(chat.avatarUrl),
  };
}
