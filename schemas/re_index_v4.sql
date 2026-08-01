PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS correlated_claims (id INTEGER PRIMARY KEY,target_id INTEGER NOT NULL REFERENCES targets(id),claim_name TEXT NOT NULL,claim_json TEXT NOT NULL,evidence_hash TEXT NOT NULL,created_utc TEXT NOT NULL,UNIQUE(target_id,claim_name,evidence_hash));
CREATE TABLE IF NOT EXISTS dossier_artifacts (target_id INTEGER NOT NULL REFERENCES targets(id),depth TEXT NOT NULL,evidence_hash TEXT NOT NULL,artifact_id INTEGER NOT NULL REFERENCES artifacts(id),PRIMARY KEY(target_id,depth,evidence_hash));
PRAGMA user_version=4;
