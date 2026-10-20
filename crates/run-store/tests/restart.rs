use run_store::{ClaimOutcome, SqliteRunStore};
use std::process::Command;
use uuid::Uuid;
use worker_protocol::{ControllerId, EventType, RunId, RunState};

const CONTROLLER: ControllerId = ControllerId(Uuid::from_u128(7));
const REQUEST: Uuid = Uuid::from_u128(19);
const RUN: RunId = RunId(Uuid::from_u128(42));

// The child exits without Rust destructors, leaving committed WAL data for a
// different process to recover. This does not simulate Windows Job Objects.
#[test]
fn abrupt_writer_helper() {
    let Some(path) = std::env::var_os("RUN_STORE_ABRUPT_TEST_DB") else {
        return;
    };
    let store = SqliteRunStore::open(std::path::Path::new(&path)).unwrap();
    store
        .claim_worker_slot(CONTROLLER, REQUEST, &"a".repeat(64), RUN)
        .unwrap();
    for (from, to) in [
        (RunState::Created, RunState::Preparing),
        (RunState::Preparing, RunState::Running),
    ] {
        store
            .transition_state(RUN, from, to, EventType::StateChanged)
            .unwrap();
    }
    std::process::exit(91);
}

#[test]
fn committed_wal_and_lease_survive_abrupt_writer_exit_without_duplicate_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abrupt.db");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "abrupt_writer_helper", "--nocapture"])
        .env("RUN_STORE_ABRUPT_TEST_DB", &path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(91));
    let store = SqliteRunStore::open(&path).unwrap();
    assert_eq!(store.run_state(RUN).unwrap(), RunState::Running);
    assert_eq!(
        store
            .read_events_after(RUN, 0, 10)
            .unwrap()
            .iter()
            .map(|e| e.seq)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        store
            .claim_worker_slot(
                CONTROLLER,
                REQUEST,
                &"a".repeat(64),
                RunId(Uuid::from_u128(43))
            )
            .unwrap(),
        ClaimOutcome::Existing(RUN)
    );
    assert_eq!(
        store
            .claim_worker_slot(
                CONTROLLER,
                Uuid::from_u128(20),
                &"b".repeat(64),
                RunId(Uuid::from_u128(43))
            )
            .unwrap(),
        ClaimOutcome::WorkerBusy
    );
    // Storage cannot assume the old process tree is gone or auto-finalize.
    assert!(store.release_after_teardown(RUN, true).is_err());
}
