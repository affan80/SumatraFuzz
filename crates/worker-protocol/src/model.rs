//! Run model and protocol types shared by local and remote worker clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU64, NonZeroU8};
use uuid::Uuid;

use crate::{ControllerId, RunId, WorkerError, WorkerId};

/// Worker-authoritative campaign lifecycle. Connectivity is tracked separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Created,
    Preparing,
    Running,
    Stopping,
    Completed,
    Failed,
    Interrupted,
}

/// Explicit state transitions; no terminal state may become active again.
pub fn valid_transition(from: RunState, to: RunState) -> bool {
    matches!(
        (from, to),
        (RunState::Created, RunState::Preparing)
            | (RunState::Preparing, RunState::Running)
            | (RunState::Preparing, RunState::Failed)
            | (RunState::Running, RunState::Stopping)
            | (RunState::Running, RunState::Failed)
            | (RunState::Running, RunState::Interrupted)
            | (RunState::Stopping, RunState::Completed)
            | (RunState::Stopping, RunState::Failed)
            | (RunState::Stopping, RunState::Interrupted)
    )
}

/// Hard limits supplied in the request. Worker policy applies tighter ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignLimits {
    pub max_duration_s: NonZeroU64,
    pub max_memory_bytes: NonZeroU64,
    pub max_disk_bytes: NonZeroU64,
    pub max_cpu_percent: NonZeroU8,
}

impl CampaignLimits {
    pub fn validate(&self) -> Result<(), WorkerError> {
        if self.max_cpu_percent.get() > 100 {
            return Err(WorkerError::InvalidConfig);
        }
        Ok(())
    }
}

/// Versioned command payload. File paths and native arguments are never accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    pub request_id: Uuid,
    pub controller_id: ControllerId,
    pub input_bundle_id: String,
    pub target_lock_sha256: String,
    pub limits: CampaignLimits,
    pub label: String,
}

impl RunRequest {
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.limits.validate()?;
        if self.request_id.is_nil() || self.controller_id.0.is_nil() {
            return Err(WorkerError::InvalidConfig);
        }
        if self.input_bundle_id.is_empty()
            || self.input_bundle_id.len() > 128
            || !self
                .input_bundle_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(WorkerError::InvalidConfig);
        }
        if self.target_lock_sha256.len() != 64
            || !self
                .target_lock_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(WorkerError::InvalidConfig);
        }
        if self.label.len() > 128 || self.label.chars().any(|c| c.is_control()) {
            return Err(WorkerError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Requested,
    TimeLimit,
    CpuLimit,
    MemoryLimit,
    DiskLimit,
    NativeExit,
    ProcessFailure,
    WorkerRestart,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RunStatus {
    pub run_id: RunId,
    pub worker_id: WorkerId,
    pub state: RunState,
    pub last_event_seq: u64,
    pub stop_reason: Option<StopReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    StateChanged,
    MetricSample,
    EvidenceFinalized,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunEvent {
    pub run_id: RunId,
    pub seq: u64,
    pub time_utc: DateTime<Utc>,
    pub event_type: EventType,
    pub payload: serde_json::Value,
}
