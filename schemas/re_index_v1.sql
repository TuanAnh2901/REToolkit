PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  profile_name TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  created_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS binaries (
  id INTEGER PRIMARY KEY,
  sha256 TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  image_base INTEGER,
  architecture TEXT
);

CREATE TABLE IF NOT EXISTS method_maps (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id),
  sha256 TEXT NOT NULL,
  method_count INTEGER NOT NULL,
  imported_utc TEXT NOT NULL,
  UNIQUE(binary_id, sha256)
);

CREATE TABLE IF NOT EXISTS methods (
  id INTEGER PRIMARY KEY,
  method_map_id INTEGER NOT NULL REFERENCES method_maps(id) ON DELETE CASCADE,
  assembly TEXT NOT NULL,
  type_name TEXT NOT NULL,
  method_name TEXT NOT NULL,
  signature TEXT NOT NULL,
  rva INTEGER NOT NULL,
  pointer INTEGER,
  full_identity TEXT NOT NULL,
  collision_key TEXT NOT NULL,
  UNIQUE(method_map_id, collision_key)
);

CREATE INDEX IF NOT EXISTS ix_methods_identity ON methods(full_identity);
CREATE INDEX IF NOT EXISTS ix_methods_rva ON methods(rva);
CREATE INDEX IF NOT EXISTS ix_methods_type_method ON methods(type_name, method_name);

CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id),
  requested_depth TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  UNIQUE(method_id, requested_depth)
);

CREATE TABLE IF NOT EXISTS tools (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  sha256 TEXT,
  UNIQUE(name, version, sha256)
);

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  logical_name TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  producer TEXT NOT NULL,
  UNIQUE(run_id, logical_name, sha256)
);

PRAGMA user_version = 1;
