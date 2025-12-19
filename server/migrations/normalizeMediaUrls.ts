import { db } from "../db";
import { sql } from "drizzle-orm";

export async function normalizeMediaUrls(): Promise<void> {
  console.log("[migration] Starting media URL normalization...");
  
  try {
    const messagesResult = await db.execute(sql`
      UPDATE messages 
      SET 
        media_url = REGEXP_REPLACE(media_url, '^https?://[^/]+(/objects/.+)$', '\1'),
        thumbnail_url = REGEXP_REPLACE(thumbnail_url, '^https?://[^/]+(/objects/.+)$', '\1')
      WHERE 
        (media_url ~ '^https?://[^/]+/objects/' OR thumbnail_url ~ '^https?://[^/]+/objects/')
      RETURNING id
    `);
    
    const messagesUpdated = messagesResult.rowCount || 0;
    if (messagesUpdated > 0) {
      console.log(`[migration] Normalized ${messagesUpdated} message media URLs`);
    }

    const usersResult = await db.execute(sql`
      UPDATE users 
      SET avatar_url = REGEXP_REPLACE(avatar_url, '^https?://[^/]+(/objects/.+)$', '\1')
      WHERE avatar_url ~ '^https?://[^/]+/objects/'
      RETURNING id
    `);
    
    const usersUpdated = usersResult.rowCount || 0;
    if (usersUpdated > 0) {
      console.log(`[migration] Normalized ${usersUpdated} user avatar URLs`);
    }

    const chatsResult = await db.execute(sql`
      UPDATE chats 
      SET avatar_url = REGEXP_REPLACE(avatar_url, '^https?://[^/]+(/objects/.+)$', '\1')
      WHERE avatar_url ~ '^https?://[^/]+/objects/'
      RETURNING id
    `);
    
    const chatsUpdated = chatsResult.rowCount || 0;
    if (chatsUpdated > 0) {
      console.log(`[migration] Normalized ${chatsUpdated} chat avatar URLs`);
    }

    if (messagesUpdated === 0 && usersUpdated === 0 && chatsUpdated === 0) {
      console.log("[migration] No URLs needed normalization");
    } else {
      console.log("[migration] Media URL normalization completed");
    }
  } catch (error) {
    console.error("[migration] Error normalizing media URLs:", error);
  }
}
