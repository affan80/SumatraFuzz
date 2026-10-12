//! User- and API-facing failures independent of HTTP status codes.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerError {
    #[error("another campaign is already active")]
    WorkerBusy,
    #[error("request ID was reused with different command content")]
    IdempotencyConflict,
    #[error("invalid campaign configuration")]
    InvalidConfig,
    #[error("controller not authorized")]
    Unauthorized,
    #[error("this operation requires a Windows x64 worker")]
    UnsupportedPlatform,
    #[error("native toolchain provenance could not be verified")]
    UnverifiedToolchain,
    #[error("campaign resource limit exceeded")]
    LimitExceeded,
    #[error("illegal campaign state transition")]
    InvalidTransition,
    #[error("native process supervisor failed")]
    ProcessError,
    #[error("durable worker storage failed")]
    StorageError,
}
