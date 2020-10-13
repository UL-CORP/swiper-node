CREATE TABLE IF NOT EXISTS organisations_organisations (
  id BLOB NOT NULL,
  private_key BLOB,
  description BLOB NOT NULL,
  joined BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE(id) ON CONFLICT REPLACE
);
