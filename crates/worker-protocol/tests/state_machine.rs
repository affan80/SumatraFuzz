use serde_json::json;
use std::num::{NonZeroU64, NonZeroU8};
use uuid::Uuid;
use worker_protocol::{valid_transition, CampaignLimits, ControllerId, RunRequest, RunState};

fn valid_request() -> RunRequest {
    RunRequest {
        request_id: Uuid::from_u128(42),
        controller_id: ControllerId(Uuid::from_u128(7)),
        input_bundle_id: "approved-seed-bundle".to_owned(),
        target_lock_sha256: "a".repeat(64),
        limits: CampaignLimits {
            max_duration_s: NonZeroU64::new(60).unwrap(),
            max_memory_bytes: NonZeroU64::new(128 * 1024 * 1024).unwrap(),
            max_disk_bytes: NonZeroU64::new(1024 * 1024 * 1024).unwrap(),
            max_cpu_percent: NonZeroU8::new(75).unwrap(),
        },
        label: "corpus smoke".to_owned(),
    }
}

#[test]
fn normal_worker_campaign_has_explicit_ordered_transitions() {
    let states = [
        RunState::Created,
        RunState::Preparing,
        RunState::Running,
        RunState::Stopping,
        RunState::Completed,
    ];
    for pair in states.windows(2) {
        assert!(valid_transition(pair[0], pair[1]), "{pair:?}");
    }
}

#[test]
fn setup_and_runtime_failures_and_worker_loss_have_explicit_transitions() {
    assert!(valid_transition(RunState::Preparing, RunState::Failed));
    assert!(valid_transition(RunState::Running, RunState::Failed));
    assert!(valid_transition(RunState::Stopping, RunState::Failed));
    assert!(valid_transition(RunState::Running, RunState::Interrupted));
}

#[test]
fn terminal_and_regressive_transitions_are_rejected() {
    for (from, to) in [
        (RunState::Completed, RunState::Running),
        (RunState::Failed, RunState::Running),
        (RunState::Interrupted, RunState::Completed),
        (RunState::Running, RunState::Created),
        (RunState::Running, RunState::Preparing),
        (RunState::Created, RunState::Completed),
    ] {
        assert!(!valid_transition(from, to), "{from:?} -> {to:?}");
    }
}

#[test]
fn valid_request_carries_positive_bounded_limits_and_pinned_hash() {
    let request = valid_request();
    assert!(request.validate().is_ok());
    assert_eq!(request.limits.max_cpu_percent.get(), 75);
}

#[test]
fn requests_reject_cpu_limits_above_100_percent() {
    let mut request = valid_request();
    request.limits.max_cpu_percent = NonZeroU8::new(101).unwrap();
    assert!(request.validate().is_err());
}

#[test]
fn requests_reject_missing_or_malformed_target_hashes_and_empty_bundle() {
    let mut request = valid_request();
    for hash in ["".to_owned(), "not-a-sha".to_owned(), "A".repeat(63)] {
        request.target_lock_sha256 = hash;
        assert!(request.validate().is_err(), "accepted invalid hash");
    }
    request.target_lock_sha256 = "f".repeat(64);
    request.input_bundle_id.clear();
    assert!(request.validate().is_err());
}

#[test]
fn deserialization_rejects_zero_and_missing_resource_limits() {
    let valid = serde_json::to_value(valid_request()).unwrap();
    for key in [
        "max_duration_s",
        "max_memory_bytes",
        "max_disk_bytes",
        "max_cpu_percent",
    ] {
        let mut zero = valid.clone();
        zero["limits"][key] = json!(0);
        assert!(
            serde_json::from_value::<RunRequest>(zero).is_err(),
            "{key}=0"
        );
        let mut absent = valid.clone();
        absent["limits"].as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<RunRequest>(absent).is_err(),
            "{key} missing"
        );
    }
}

#[test]
fn request_ids_are_uuid_only() {
    let mut payload = serde_json::to_value(valid_request()).unwrap();
    payload["request_id"] = json!("bogus-id");
    assert!(serde_json::from_value::<RunRequest>(payload).is_err());
}
