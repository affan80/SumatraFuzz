use run_store::SqliteRunStore;
use rusqlite::Connection;
use std::fs;
use uuid::Uuid;
use worker_protocol::{ControllerId, EventType, RunId, RunState};

#[test]
fn fresh_and_legacy_version_zero_schema_upgrades_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE existing_application_data (value TEXT NOT NULL);
         INSERT INTO existing_application_data (value) VALUES ('retain-me');
         PRAGMA user_version = 0;",
    )
    .unwrap();
    drop(conn);

    let store = SqliteRunStore::open(&path).unwrap();
    drop(store);
    let conn = Connection::open(&path).unwrap();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    let value: String = conn
        .query_row("SELECT value FROM existing_application_data", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 1);
    assert_eq!(value, "retain-me");
    drop(conn);
    assert!(SqliteRunStore::open(&path).is_ok());
}

#[test]
fn corrupted_existing_database_is_rejected_without_overwriting_its_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.db");
    let original = b"not-an-sqlite-database";
    fs::write(&path, original).unwrap();
    assert!(SqliteRunStore::open(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn injected_event_write_failure_rolls_back_transition_and_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failure.db");
    let store = SqliteRunStore::open(&path).unwrap();
    let run_id = RunId(Uuid::from_u128(2026));
    store
        .claim_worker_slot(
            ControllerId(Uuid::from_u128(9)),
            Uuid::from_u128(10),
            &"f".repeat(64),
            run_id,
        )
        .unwrap();
    // Deterministic SQLite write-failure injection; not a claim to have
    // exercised a physical disk-full Windows VM.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER fail_event_write BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'injected event write failure'); END;",
    )
    .unwrap();
    drop(conn);
    assert!(store
        .transition_state(
            run_id,
            RunState::Created,
            RunState::Preparing,
            EventType::StateChanged
        )
        .is_err());
    assert_eq!(store.run_state(run_id).unwrap(), RunState::Created);
    assert!(store.read_events_after(run_id, 0, 10).unwrap().is_empty());
}

#[test]
fn event_reads_reject_unbounded_and_zero_size_requests() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("limits.db")).unwrap();
    let run_id = RunId(Uuid::from_u128(1));
    assert!(store.read_events_after(run_id, 0, 0).is_err());
    assert!(store.read_events_after(run_id, 0, 10_001).is_err());
}
