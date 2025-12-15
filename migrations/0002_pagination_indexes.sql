-- Add indexes for cursor-based pagination performance
CREATE INDEX IF NOT EXISTS idx_contacts_user_created_at ON contacts (user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_chats_updated_at ON chats (updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_chat_created_at ON messages (chat_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_chat_members_user_chat ON chat_members (user_id, chat_id);
