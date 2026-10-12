use run_store::{ClaimOutcome, SqliteRunStore, StoreError};
use uuid::Uuid;
use worker_protocol::{ControllerId, EventType, RunId, RunState};

fn ids() -> (ControllerId, Uuid, RunId) {
    (
        ControllerId(Uuid::from_u128(7)),
        Uuid::from_u128(19),
        RunId(Uuid::from_u128(42)),
    )
}

#[test]
fn retry_is_idempotent_but_payload_conflict_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("journal.db")).unwrap();
    let (controller, request, run) = ids();
    let hash = "a".repeat(64);
    assert_eq!(
        store
            .claim_worker_slot(controller, request, &hash, run)
            .unwrap(),
        ClaimOutcome::New(run)
    );
    assert_eq!(
        store
            .claim_worker_slot(controller, request, &hash, run)
            .unwrap(),
        ClaimOutcome::Existing(run)
    );
    assert!(matches!(
        store.claim_worker_slot(controller, request, &"b".repeat(64), run),
        Err(StoreError::IdempotencyConflict)
    ));
}

#[test]
fn one_worker_slot_survives_reopen_and_rejects_racing_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.db");
    let (controller, request, run) = ids();
    let store = SqliteRunStore::open(&path).unwrap();
    assert_eq!(
        store
            .claim_worker_slot(controller, request, &"a".repeat(64), run)
            .unwrap(),
        ClaimOutcome::New(run)
    );
    drop(store);
    let reopened = SqliteRunStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .claim_worker_slot(
                controller,
                Uuid::from_u128(20),
                &"a".repeat(64),
                RunId(Uuid::from_u128(43))
            )
            .unwrap(),
        ClaimOutcome::WorkerBusy
    );
}

#[test]
fn state_transition_and_event_are_atomic_and_replayable() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteRunStore::open(&dir.path().join("journal.db")).unwrap();
    let (controller, request, run) = ids();
    store
        .claim_worker_slot(controller, request, &"a".repeat(64), run)
        .unwrap();
    let first = store
        .transition_state(run, RunState::Created, RunState::Preparing, EventType::StateChanged)
        .unwrap();
    let second = store
        .transition_state(run, RunState::Preparing, RunState::Running, EventType::StateChanged)
        .unwrap();
    assert_eq!((first, second), (1, 2));
    assert!(matches!(
        store.transition_state(run, RunState::Created, RunState::Completed, EventType::StateChanged),
        Err(StoreError::InvalidTransition)
    ));
    let events = store.read_events_after(run, 0, 20).unwrap();
    assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(store.run_state(run).unwrap(), RunState::Running);
}
