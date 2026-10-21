//! Conservative checks; never reconstruct lost journal or lease information.
use crate::{parse_state, StoreError};
use rusqlite::{Connection, OptionalExtension};

const TABLES: [&str; 6] = [
    "schema_migrations",
    "run_state",
    "events",
    "evidence_index",
    "worker_slot",
    "command_idempotency",
];

pub(super) fn initialize(conn: &Connection, version: i64) -> Result<(), StoreError> {
    let existing: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN
         ('schema_migrations','run_state','events','evidence_index','worker_slot','command_idempotency')",
        [],
        |row| row.get(0),
    )?;
    if version == 0 && existing == 0 {
        conn.execute_batch(include_str!("../migrations/0001_worker.sql"))?;
    }

    // Compare against SQLite's own representation of the checked-in migration.
    // This checks constraints/keys as well as columns, without accepting a
    // partially reconstructed or altered v1 schema. Unrelated tables are allowed.
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(include_str!("../migrations/0001_worker.sql"))?;
    for table in TABLES {
        let expected: String = reference.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
            [table],
            |r| r.get(0),
        )?;
        let actual: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected.as_str()) {
            return Err(StoreError::Corrupt);
        }
    }
    let migrations: (i64, Option<i64>) = conn.query_row(
        "SELECT count(*), max(version) FROM schema_migrations",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if migrations != (1, Some(1)) {
        return Err(StoreError::Corrupt);
    }
    let check: String = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
    if check != "ok" || conn.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(StoreError::Corrupt);
    }
    validate_lease(conn)?;
    let mut runs = conn.prepare("SELECT run_id FROM run_state")?;
    for id in runs.query_map([], |r| r.get::<_, String>(0))? {
        validate_run(conn, &id?)?;
    }
    Ok(())
}

pub(super) fn validate_lease(conn: &Connection) -> Result<(), StoreError> {
    let unleased: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM run_state r LEFT JOIN worker_slot w ON w.run_id=r.run_id
         WHERE r.state NOT IN ('completed','failed','interrupted') AND w.run_id IS NULL)",
        [],
        |r| r.get(0),
    )?;
    if unleased {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

pub(super) fn validate_run(conn: &Connection, run_id: &str) -> Result<(), StoreError> {
    let saved: Option<(String, i64)> = conn
        .query_row(
            "SELECT state, last_seq FROM run_state WHERE run_id=?1",
            [run_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (count, first, last): (i64, Option<i64>, Option<i64>) = conn.query_row(
        "SELECT count(*), min(seq), max(seq) FROM events WHERE run_id=?1",
        [run_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let Some((state, last_seq)) = saved else {
        return if count == 0 {
            Ok(())
        } else {
            Err(StoreError::Corrupt)
        };
    };
    parse_state(&state)?;
    // Positive unique sequences, count == last_seq and endpoints 1..last_seq
    // prove continuity across the entire run, including outside a replay page.
    if last_seq < 0
        || count != last_seq
        || (last_seq == 0 && (first.is_some() || last.is_some()))
        || (last_seq > 0 && (first != Some(1) || last != Some(last_seq)))
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}
