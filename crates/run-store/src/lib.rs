//! Worker-local, transactional SQLite journal and exclusive worker slot.
//! This module deliberately has no network or native-process responsibilities.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex, time::Duration};
use thiserror::Error;
use uuid::Uuid;
use worker_protocol::{valid_transition, ControllerId, EventType, RunEvent, RunId, RunState};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite operation failed: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("state transition rejected")]
    InvalidTransition,
    #[error("idempotency key reused with different content")]
    IdempotencyConflict,
    #[error("invalid command or event")]
    InvalidRequest,
    #[error("durable store lock poisoned")]
    Poisoned,
    #[error("stored journal data is corrupt")]
    Corrupt,
    #[error("unsupported database version")]
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    New(RunId),
    Existing(RunId),
    WorkerBusy,
}

pub struct SqliteRunStore {
    connection: Mutex<Connection>,
}

fn state_name(state: RunState) -> &'static str {
    match state {
        RunState::Created => "created",
        RunState::Preparing => "preparing",
        RunState::Running => "running",
        RunState::Stopping => "stopping",
        RunState::Completed => "completed",
        RunState::Failed => "failed",
        RunState::Interrupted => "interrupted",
    }
}

fn parse_state(value: &str) -> Result<RunState, StoreError> {
    match value {
        "created" => Ok(RunState::Created),
        "preparing" => Ok(RunState::Preparing),
        "running" => Ok(RunState::Running),
        "stopping" => Ok(RunState::Stopping),
        "completed" => Ok(RunState::Completed),
        "failed" => Ok(RunState::Failed),
        "interrupted" => Ok(RunState::Interrupted),
        _ => Err(StoreError::Corrupt),
    }
}

impl SqliteRunStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; PRAGMA journal_mode = WAL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 1 {
            return Err(StoreError::UnsupportedVersion);
        }
        conn.execute_batch(include_str!("../migrations/0001_worker.sql"))?;
        if version == 0 {
            conn.pragma_update(None, "user_version", 1_i64)?;
        }
        Ok(Self { connection: Mutex::new(conn) })
    }

    pub fn claim_worker_slot(
        &self,
        controller_id: ControllerId,
        request_id: Uuid,
        payload_digest: &str,
        run_id: RunId,
    ) -> Result<ClaimOutcome, StoreError> {
        if controller_id.0.is_nil() || request_id.is_nil() || run_id.0.is_nil()
            || payload_digest.len() != 64
            || !payload_digest.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(StoreError::InvalidRequest);
        }
        let mut conn = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let earlier: Option<(String, String)> = tx.query_row(
            "SELECT payload_digest, run_id FROM command_idempotency WHERE controller_id = ?1 AND request_id = ?2",
            params![controller_id.0.to_string(), request_id.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).optional()?;
        if let Some((recorded_digest, recorded_run)) = earlier {
            if recorded_digest != payload_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let saved_id = Uuid::parse_str(&recorded_run).map_err(|_| StoreError::Corrupt)?;
            tx.commit()?;
            return Ok(ClaimOutcome::Existing(RunId(saved_id)));
        }
        let active: Option<String> = tx.query_row(
            "SELECT run_id FROM worker_slot WHERE slot = 1", [], |r| r.get(0)
        ).optional()?;
        if active.is_some() {
            return Ok(ClaimOutcome::WorkerBusy);
        }
        tx.execute("INSERT INTO run_state (run_id, state, last_seq) VALUES (?1, 'created', 0)",
            params![run_id.0.to_string()])?;
        tx.execute("INSERT INTO worker_slot (slot, run_id) VALUES (1, ?1)", params![run_id.0.to_string()])?;
        tx.execute("INSERT INTO command_idempotency (controller_id, request_id, payload_digest, run_id) VALUES (?1, ?2, ?3, ?4)",
            params![controller_id.0.to_string(), request_id.to_string(), payload_digest, run_id.0.to_string()])?;
        tx.commit()?;
        Ok(ClaimOutcome::New(run_id))
    }

    pub fn transition_state(
        &self,
        run_id: RunId,
        expected: RunState,
        next: RunState,
        kind: EventType,
    ) -> Result<u64, StoreError> {
        if !valid_transition(expected, next) {
            return Err(StoreError::InvalidTransition);
        }
        let mut conn = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record: Option<(String, i64)> = tx.query_row(
            "SELECT state, last_seq FROM run_state WHERE run_id = ?1",
            params![run_id.0.to_string()], |r| Ok((r.get(0)?, r.get(1)?))
        ).optional()?;
        let (previous, seq) = record.ok_or(StoreError::InvalidTransition)?;
        if parse_state(&previous)? != expected || seq < 0 {
            return Err(StoreError::InvalidTransition);
        }
        let next_seq = seq.checked_add(1).ok_or(StoreError::Corrupt)?;
        let when = Utc::now().to_rfc3339();
        let payload = serde_json::json!({"from": state_name(expected), "to": state_name(next)}).to_string();
        tx.execute(
            "UPDATE run_state SET state = ?1, last_seq = ?2 WHERE run_id = ?3 AND state = ?4 AND last_seq = ?5",
            params![state_name(next), next_seq, run_id.0.to_string(), state_name(expected), seq],
        )?;
        let event_type = serde_json::to_string(&kind).map_err(|_| StoreError::Corrupt)?;
        tx.execute(
            "INSERT INTO events (run_id, seq, time_utc, event_type, payload) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run_id.0.to_string(), next_seq, when, event_type, payload],
        )?;
        // Releasing the slot is only legal on an explicit terminal transition.
        // The coordinator must call this only *after* owned native processes stop.
        if matches!(next, RunState::Completed | RunState::Failed | RunState::Interrupted) {
            tx.execute("DELETE FROM worker_slot WHERE slot = 1 AND run_id = ?1",
                params![run_id.0.to_string()])?;
        }
        tx.commit()?;
        u64::try_from(next_seq).map_err(|_| StoreError::Corrupt)
    }

    pub fn run_state(&self, run_id: RunId) -> Result<RunState, StoreError> {
        let conn = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let saved: Option<String> = conn.query_row(
            "SELECT state FROM run_state WHERE run_id = ?1",
            params![run_id.0.to_string()], |r| r.get(0)
        ).optional()?;
        parse_state(&saved.ok_or(StoreError::InvalidTransition)?)
    }

    pub fn read_events_after(
        &self,
        run_id: RunId,
        seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        if limit == 0 || limit > 10_000 {
            return Err(StoreError::InvalidRequest);
        }
        let conn = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT seq, time_utc, event_type, payload FROM events WHERE run_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3"
        )?;
        let rows = stmt.query_map(params![run_id.0.to_string(), seq, limit], |r| {
            let seq: i64 = r.get(0)?;
            let time: String = r.get(1)?;
            let kind: String = r.get(2)?;
            let payload: String = r.get(3)?;
            Ok((seq, time, kind, payload))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (seq, time, kind, payload) = row?;
            let seq = u64::try_from(seq).map_err(|_| StoreError::Corrupt)?;
            let time_utc = DateTime::parse_from_rfc3339(&time)
                .map_err(|_| StoreError::Corrupt)?.with_timezone(&Utc);
            let event_type = serde_json::from_str(&kind).map_err(|_| StoreError::Corrupt)?;
            let payload = serde_json::from_str(&payload).map_err(|_| StoreError::Corrupt)?;
            events.push(RunEvent { run_id, seq, time_utc, event_type, payload });
        }
        Ok(events)
    }
}
