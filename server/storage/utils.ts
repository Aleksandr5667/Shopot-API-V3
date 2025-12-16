import type { User, UserPublic } from "@shared/schema";

export function toPublicUser(user: User): UserPublic {
  const { passwordHash, ...publicUser } = user;
  return publicUser;
}
