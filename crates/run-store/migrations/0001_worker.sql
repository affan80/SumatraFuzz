-- Schema v1. Worker-local only. Journal writes use BEGIN IMMEDIATE.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);

CREATE TABLE IF NOT EXISTS run_state (
    run_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('created','preparing','running','stopping','completed','failed','interrupted')),
    last_seq INTEGER NOT NULL DEFAULT 0 CHECK (last_seq >= 0)
);

CREATE TABLE IF NOT EXISTS worker_slot (
    slot INTEGER PRIMARY KEY CHECK (slot = 1),
    run_id TEXT NOT NULL UNIQUE REFERENCES run_state(run_id)
);

CREATE TABLE IF NOT EXISTS command_idempotency (
    controller_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    run_id TEXT NOT NULL REFERENCES run_state(run_id),
    PRIMARY KEY (controller_id, request_id)
);

CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL REFERENCES run_state(run_id),
    seq INTEGER NOT NULL CHECK (seq > 0),
    time_utc TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);

CREATE TABLE IF NOT EXISTS evidence_index (
    run_id TEXT NOT NULL REFERENCES run_state(run_id),
    artifact_id TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    is_final INTEGER NOT NULL DEFAULT 0 CHECK (is_final IN (0, 1)),
    PRIMARY KEY (run_id, artifact_id)
);
