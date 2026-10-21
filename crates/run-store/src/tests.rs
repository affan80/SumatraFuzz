use super::*;

#[test]
fn sqlite_full_rolls_back_state_event_and_pressure_write_then_reopens_with_lease() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("full.db");
    let store = SqliteRunStore::open(&path).unwrap();
    let run = RunId(Uuid::from_u128(42));
    let controller = ControllerId(Uuid::from_u128(7));
    store
        .claim_worker_slot(controller, Uuid::from_u128(19), &"a".repeat(64), run)
        .unwrap();
    {
        let conn = store.connection.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE disk_pressure (data BLOB);
             CREATE TRIGGER pressure_on_event BEFORE INSERT ON events
             BEGIN INSERT INTO disk_pressure VALUES (zeroblob(1048576)); END;",
        )
        .unwrap();
        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        conn.pragma_update(None, "max_page_count", pages).unwrap();
    }
    let error = store
        .transition_state(
            run,
            RunState::Created,
            RunState::Preparing,
            EventType::StateChanged,
        )
        .unwrap_err();
    assert!(
        matches!(error, StoreError::Database(rusqlite::Error::SqliteFailure(code, _)) if code.code == rusqlite::ErrorCode::DiskFull)
    );
    assert_eq!(store.run_state(run).unwrap(), RunState::Created);
    assert!(store.read_events_after(run, 0, 10).unwrap().is_empty());
    {
        let conn = store.connection.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM disk_pressure", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        conn.execute_batch("DROP TRIGGER pressure_on_event")
            .unwrap();
    }
    drop(store);
    let reopened = SqliteRunStore::open(&path).unwrap();
    assert_eq!(reopened.run_state(run).unwrap(), RunState::Created);
    assert_eq!(
        reopened
            .claim_worker_slot(
                controller,
                Uuid::from_u128(20),
                &"b".repeat(64),
                RunId(Uuid::from_u128(43))
            )
            .unwrap(),
        ClaimOutcome::WorkerBusy
    );
    assert_eq!(
        reopened
            .transition_state(
                run,
                RunState::Created,
                RunState::Preparing,
                EventType::StateChanged
            )
            .unwrap(),
        1
    );
}
