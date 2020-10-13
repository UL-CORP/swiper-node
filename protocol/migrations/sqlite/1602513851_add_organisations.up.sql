ALTER TABLE chats ADD COLUMN organisation_id TEXT DEFAULT "";
UPDATE chats SET organisation_id = "";

ALTER TABLE user_messages ADD COLUMN organisation_id TEXT DEFAULT "";
UPDATE user_messages SET organisation_id = "";
