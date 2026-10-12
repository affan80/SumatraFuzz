use run_store::{ClaimOutcome, SqliteRunStore, StoreError};
use std::{
    sync::{Arc, Barrier},
    thread,
};
use uuid::Uuid;
use worker_protocol::{ControllerId, EventType, RunId, RunState};

#[test]
fn simultaneous_claims_share_one_durable_worker_slot() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("race.db");
    let ready = Arc::new(Barrier::new(2));
    let a = {
        let ready = Arc::clone(&ready);
        let path = db_path.clone();
        thread::spawn(move || {
            let store = SqliteRunStore::open(&path).unwrap();
            ready.wait();
            store
                .claim_worker_slot(
                    ControllerId(Uuid::from_u128(1)),
                    Uuid::from_u128(11),
                    &"a".repeat(64),
                    RunId(Uuid::from_u128(101)),
                )
                .unwrap()
        })
    };
    let b = {
        let ready = Arc::clone(&ready);
        let path = db_path.clone();
        thread::spawn(move || {
            let store = SqliteRunStore::open(&path).unwrap();
            ready.wait();
            store
                .claim_worker_slot(
                    ControllerId(Uuid::from_u128(2)),
                    Uuid::from_u128(12),
                    &"b".repeat(64),
                    RunId(Uuid::from_u128(102)),
                )
                .unwrap()
        })
    };
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|x| matches!(x, ClaimOutcome::New(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|x| **x == ClaimOutcome::WorkerBusy)
            .count(),
        1
    );
}

#[test]
fn terminal_transition_releases_worker_slot_for_next_campaign() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("next.db")).unwrap();
    let principal = ControllerId(Uuid::from_u128(1));
    let old = RunId(Uuid::from_u128(44));
    assert_eq!(
        store
            .claim_worker_slot(principal, Uuid::from_u128(5), &"f".repeat(64), old)
            .unwrap(),
        ClaimOutcome::New(old)
    );
    store
        .transition_state(
            old,
            RunState::Created,
            RunState::Preparing,
            EventType::StateChanged,
        )
        .unwrap();
    store
        .transition_state(
            old,
            RunState::Preparing,
            RunState::Running,
            EventType::StateChanged,
        )
        .unwrap();
    store
        .transition_state(
            old,
            RunState::Running,
            RunState::Stopping,
            EventType::StateChanged,
        )
        .unwrap();
    store
        .transition_state(
            old,
            RunState::Stopping,
            RunState::Completed,
            EventType::StateChanged,
        )
        .unwrap();
    let next = RunId(Uuid::from_u128(45));
    assert_eq!(
        store
            .claim_worker_slot(principal, Uuid::from_u128(6), &"a".repeat(64), next)
            .unwrap(),
        ClaimOutcome::New(next)
    );
}

#[test]
fn cas_mismatch_does_not_write_event_or_change_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("cas.db")).unwrap();
    let run = RunId(Uuid::from_u128(200));
    store
        .claim_worker_slot(
            ControllerId(Uuid::from_u128(4)),
            Uuid::from_u128(8),
            &"f".repeat(64),
            run,
        )
        .unwrap();
    store
        .transition_state(
            run,
            RunState::Created,
            RunState::Preparing,
            EventType::StateChanged,
        )
        .unwrap();
    assert!(matches!(
        store.transition_state(
            run,
            RunState::Created,
            RunState::Preparing,
            EventType::StateChanged
        ),
        Err(StoreError::InvalidTransition)
    ));
    assert_eq!(store.run_state(run).unwrap(), RunState::Preparing);
    let events = store.read_events_after(run, 0, 50).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 1);
    assert!(store.read_events_after(run, 1, 50).unwrap().is_empty());
}

#[test]
fn unsupported_newer_schema_is_refused_not_downgraded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 2_i64).unwrap();
    drop(conn);
    assert!(matches!(
        SqliteRunStore::open(&path),
        Err(StoreError::UnsupportedVersion)
    ));
}
