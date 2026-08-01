CREATE TABLE IF NOT EXISTS functions (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id),
  entry_rva INTEGER NOT NULL,
  end_rva INTEGER,
  name TEXT,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  UNIQUE(binary_id, entry_rva, source)
);

CREATE TABLE IF NOT EXISTS static_findings (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id),
  analyzer TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  finding_json TEXT NOT NULL,
  UNIQUE(method_id, analyzer, input_hash)
);

CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY,
  source_method_id INTEGER NOT NULL REFERENCES methods(id),
  target_method_id INTEGER REFERENCES methods(id),
  target_rva INTEGER,
  kind TEXT NOT NULL,
  evidence_source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  UNIQUE(source_method_id, target_method_id, target_rva, kind, evidence_source)
);

CREATE TABLE IF NOT EXISTS ghidra_runs (
  id TEXT PRIMARY KEY,
  cache_key TEXT NOT NULL,
  mode TEXT NOT NULL,
  worker_count INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_utc TEXT NOT NULL,
  ended_utc TEXT
);

CREATE TABLE IF NOT EXISTS decompilations (
  id INTEGER PRIMARY KEY,
  ghidra_run_id TEXT NOT NULL REFERENCES ghidra_runs(id),
  method_id INTEGER NOT NULL REFERENCES methods(id),
  input_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  function_name TEXT,
  function_entry_rva INTEGER,
  function_end_rva INTEGER,
  pseudocode TEXT,
  error TEXT,
  duration_ms INTEGER NOT NULL,
  UNIQUE(method_id, input_hash)
);

PRAGMA user_version = 2;
