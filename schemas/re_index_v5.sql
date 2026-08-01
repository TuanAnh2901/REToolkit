PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS work_items (id INTEGER PRIMARY KEY,request_id TEXT NOT NULL,target_id INTEGER NOT NULL REFERENCES targets(id),operation TEXT NOT NULL,priority INTEGER NOT NULL,state TEXT NOT NULL,attempt INTEGER NOT NULL DEFAULT 0,worker_id TEXT,input_hash TEXT NOT NULL,updated_utc TEXT NOT NULL,UNIQUE(request_id,target_id,operation,input_hash));
CREATE INDEX IF NOT EXISTS ix_work_claim ON work_items(request_id,state,priority DESC,id);
PRAGMA user_version=5;
