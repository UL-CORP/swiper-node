ALTER TABLE chats ADD COLUMN community_id TEXT DEFAULT "";
UPDATE chats SET community_id = "";

ALTER TABLE user_messages ADD COLUMN community_id TEXT DEFAULT "";
UPDATE user_messages SET community_id = "";

CREATE TABLE IF NOT EXISTS communities_communities (
  id BLOB NOT NULL PRIMARY KEY ON CONFLICT REPLACE,
  private_key BLOB,
  description BLOB NOT NULL,
  joined BOOL NOT NULL DEFAULT FALSE
  );
