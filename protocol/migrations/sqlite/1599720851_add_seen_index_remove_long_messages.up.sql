CREATE INDEX seen_local_chat_id_idx ON user_messages(local_chat_id, seen);
UPDATE user_messags SET hide = 1 WHERE length(text) > 4096;
