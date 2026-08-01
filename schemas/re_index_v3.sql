PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS trace_sessions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), recipe_sha256 TEXT NOT NULL, target_process TEXT NOT NULL, mode TEXT NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runtime_events (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL REFERENCES trace_sessions(id) ON DELETE CASCADE, sequence INTEGER NOT NULL, target_id INTEGER NOT NULL REFERENCES targets(id), method_id INTEGER NOT NULL REFERENCES methods(id), thread_id INTEGER, runtime_address INTEGER NOT NULL, module_base INTEGER NOT NULL, rva INTEGER NOT NULL, event_kind TEXT NOT NULL, payload_json TEXT NOT NULL, UNIQUE(session_id, sequence));
CREATE INDEX IF NOT EXISTS ix_runtime_events_target ON runtime_events(target_id);
CREATE INDEX IF NOT EXISTS ix_runtime_events_rva ON runtime_events(rva);
CREATE TABLE IF NOT EXISTS trace_aggregates (session_id TEXT NOT NULL REFERENCES trace_sessions(id) ON DELETE CASCADE, target_id INTEGER NOT NULL REFERENCES targets(id), call_count INTEGER NOT NULL, emitted_count INTEGER NOT NULL, dropped_count INTEGER NOT NULL, first_timestamp REAL, last_timestamp REAL, PRIMARY KEY(session_id, target_id));
PRAGMA user_version = 3;
