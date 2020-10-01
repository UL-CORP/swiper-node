CREATE INDEX IF NOT EXISTS seen_local_chat_id_idx ON user_messages(local_chat_id, seen);
