//! Canonical SumatraFuzz worker identity and command protocol.
//! Deliberately free of transport and native process dependencies.

mod errors;
mod model;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use errors::WorkerError;
pub use model::{
    valid_transition, CampaignLimits, EventType, RunEvent, RunRequest, RunState, RunStatus,
    StopReason,
};

/// Stable identity for one concrete execution, never reused across workers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub Uuid);

/// Stable identity of the executing worker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkerId(pub Uuid);

/// Stable identity of the controller authorized to operate a worker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControllerId(pub Uuid);
