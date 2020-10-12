CREATE TABLE IF NOT EXISTS organisations_organisations (
  id BLOB NOT NULL,
  private_key BLOB,
  description BLOB NOT NULL,
  UNIQUE(id) ON CONFLICT REPLACE
);
