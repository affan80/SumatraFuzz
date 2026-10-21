use run_store::{ClaimOutcome, SqliteRunStore, StoreError};
use rusqlite::{params, Connection};
use uuid::Uuid;
use worker_protocol::{ControllerId, EventType, RunId, RunState};

fn running(path: &std::path::Path) -> (SqliteRunStore, RunId) {
    let store = SqliteRunStore::open(path).unwrap();
    let run = RunId(Uuid::from_u128(42));
    store
        .claim_worker_slot(
            ControllerId(Uuid::from_u128(7)),
            Uuid::from_u128(19),
            &"a".repeat(64),
            run,
        )
        .unwrap();
    for (from, to) in [
        (RunState::Created, RunState::Preparing),
        (RunState::Preparing, RunState::Running),
    ] {
        store
            .transition_state(run, from, to, EventType::StateChanged)
            .unwrap();
    }
    (store, run)
}

#[test]
fn missing_version_one_tables_are_rejected_without_recreating_them() {
    for table in [
        "schema_migrations",
        "run_state",
        "events",
        "evidence_index",
        "worker_slot",
        "command_idempotency",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.db");
        drop(SqliteRunStore::open(&path).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();
        assert!(
            matches!(SqliteRunStore::open(&path), Err(StoreError::Corrupt)),
            "missing {table} was accepted"
        );
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "open reconstructed {table}");
    }
}

#[test]
fn version_zero_partial_worker_schema_is_not_repaired_into_an_empty_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.db");
    let (store, _) = running(&path);
    drop(store);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE worker_slot; PRAGMA user_version=0;")
        .unwrap();
    assert!(matches!(
        SqliteRunStore::open(&path),
        Err(StoreError::Corrupt)
    ));
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 0);
}

#[test]
fn altered_schema_and_missing_migration_record_are_rejected() {
    for sql in [
        "ALTER TABLE worker_slot ADD COLUMN extra TEXT",
        "DELETE FROM schema_migrations",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schema.db");
        drop(SqliteRunStore::open(&path).unwrap());
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        assert!(
            matches!(SqliteRunStore::open(&path), Err(StoreError::Corrupt)),
            "accepted {sql}"
        );
    }
}

#[test]
fn replay_rejects_missing_head_and_tail_even_when_cursor_skips_damage() {
    for missing in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gap.db");
        let (store, run) = running(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM events WHERE seq=?1", [missing])
            .unwrap();
        for cursor in [0, 1, 2, 100] {
            assert!(
                matches!(
                    store.read_events_after(run, cursor, 1),
                    Err(StoreError::Corrupt)
                ),
                "missed sequence {missing}, cursor {cursor}"
            );
        }
        assert!(matches!(
            store.transition_state(
                run,
                RunState::Running,
                RunState::Stopping,
                EventType::StateChanged
            ),
            Err(StoreError::Corrupt)
        ));
        let last_seq: i64 = conn
            .query_row("SELECT last_seq FROM run_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(last_seq, 2);
        drop(store);
        assert!(matches!(
            SqliteRunStore::open(&path),
            Err(StoreError::Corrupt)
        ));
    }
}

#[test]
fn replay_rejects_a_missing_middle_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("middle.db");
    let (store, run) = running(&path);
    store
        .transition_state(
            run,
            RunState::Running,
            RunState::Stopping,
            EventType::StateChanged,
        )
        .unwrap();
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM events WHERE seq=2", [])
        .unwrap();
    assert!(matches!(
        store.read_events_after(run, 0, 10),
        Err(StoreError::Corrupt)
    ));
}

#[test]
fn lost_active_lease_is_rejected_instead_of_allowing_another_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lease.db");
    let (store, _) = running(&path);
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM worker_slot", [])
        .unwrap();
    assert!(matches!(
        store.claim_worker_slot(
            ControllerId(Uuid::from_u128(8)),
            Uuid::from_u128(20),
            &"b".repeat(64),
            RunId(Uuid::from_u128(43))
        ),
        Err(StoreError::Corrupt)
    ));
    drop(store);
    assert!(matches!(
        SqliteRunStore::open(&path),
        Err(StoreError::Corrupt)
    ));
}

#[test]
fn foreign_key_damage_is_rejected_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign-key.db");
    drop(SqliteRunStore::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    conn.execute(
        "INSERT INTO worker_slot VALUES (1, ?1)",
        params![Uuid::from_u128(99).to_string()],
    )
    .unwrap();
    assert!(matches!(
        SqliteRunStore::open(&path),
        Err(StoreError::Corrupt)
    ));
}

#[test]
fn generic_transition_cannot_claim_completed_without_finalization_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("completion.db");
    let (store, run) = running(&path);
    store
        .transition_state(
            run,
            RunState::Running,
            RunState::Stopping,
            EventType::StateChanged,
        )
        .unwrap();
    assert!(matches!(
        store.transition_state(
            run,
            RunState::Stopping,
            RunState::Completed,
            EventType::StateChanged
        ),
        Err(StoreError::InvalidTransition)
    ));
    assert_eq!(store.run_state(run).unwrap(), RunState::Stopping);
    assert_eq!(store.read_events_after(run, 0, 10).unwrap().len(), 3);
    assert!(store.release_after_teardown(run, true).is_err());
    assert_eq!(
        store
            .claim_worker_slot(
                ControllerId(Uuid::from_u128(8)),
                Uuid::from_u128(20),
                &"b".repeat(64),
                RunId(Uuid::from_u128(43))
            )
            .unwrap(),
        ClaimOutcome::WorkerBusy
    );
}

#[test]
fn replay_rejects_cursor_outside_sqlite_integer_range() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("cursor.db")).unwrap();
    assert!(matches!(
        store.read_events_after(RunId(Uuid::from_u128(42)), u64::MAX, 1),
        Err(StoreError::InvalidRequest)
    ));
}
