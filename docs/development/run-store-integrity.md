# Worker-local journal integrity and recovery (#39)

The worker journal remains a local SQLite file. Provision its path on local
storage with appropriate OS permissions; the storage API does not detect network
mounts or authenticate callers. Never share the live DB through SMB or mount it
on another worker. No network or process-launch capability is added here.

## Storage guarantees

- Fresh databases and version-zero databases without worker tables receive the
  checked-in v1 schema transactionally. A complete canonical v1 schema with a
  zero version can be upgraded without rewriting its data. Partial worker
  schemas, missing migration records, changed table definitions and unsupported
  versions fail closed. Existing v1 tables are never silently reconstructed.
- Opening checks SQLite page integrity, foreign keys, active lease consistency
  and each run's event sequence. The six worker tables must have the same SQL
  definitions SQLite derives from the checked-in migration. Even semantically
  equivalent hand-edited definitions are unsupported; unrelated tables and
  diagnostic triggers are not schema attestations.
- Immediate transactions preserve claim/idempotency and state/event atomicity.
  An active nonterminal run without its slot is corruption, not a free worker.
- Replay checks the complete run's count and sequence endpoints against
  `last_seq`, including gaps before the cursor and missing tails beyond a page.
  Validation and the returned page share one deferred WAL read transaction.
  Empty and unknown runs retain the existing empty-replay behavior. Cursors
  outside SQLite's signed integer range return `InvalidRequest`.
- Validation proves sequence continuity using positive unique sequence IDs; it
  does not cryptographically attest event contents or resist an actor who can
  replace the database. Full-run sequence validation scans the run's sequence
  index on replay and transition, so its cost grows with journal history. Page
  size remains bounded to 10,000 returned events.

## Completion and lease authority

The generic `transition_state` method rejects `Completed`. Its arguments cannot
prove a normal stop and finalized evidence, so allowing that transition would
record a stronger outcome than the API can establish. Invalid completion writes
neither state nor event and retains the lease. Existing historical terminal
records remain readable; opening does not rewrite their outcome.

This is an intentional conservative behavior change, not a completed success
finalization API. A future trusted coordinator/supervisor integration must supply
the stop/finalization authority before it exposes successful completion. The
protocol's lifecycle still permits `Stopping -> Completed` at that future
boundary; it is the current generic storage operation that refuses it.

`Failed` and `Interrupted` remain available on permitted edges. Terminal state
alone never releases the slot. `release_after_teardown(run, true)` still means
the trusted caller asserted teardown; the boolean is **not OS evidence**. These
storage changes do not implement or claim Windows Job Object supervision,
callback authorization, artifact immutability, quota enforcement or automatic
restart reconciliation (#40–#42). Do not mark a failed run successful to free a
slot, or release an active lease merely because a worker restarted.

## Failure, rollback and recovery

SQLite write errors roll back the entire command transaction. Return the error;
do not publish a state/event or success response before commit. A failed commit
can require later conservative reconciliation: storage cannot establish native
process ownership or guarantee that an I/O failure's outcome is known to an
external caller. Retry the same authorized controller/request/digest after
reopening a healthy journal rather than issuing an independent start.

On `Corrupt` or an unsupported schema, stop new claims and preserve the database,
WAL, SHM and run artifacts for diagnosis. Do not delete/recreate missing tables,
remove an active slot, reset `user_version`, or manufacture missing events.
Restore only a consistent, reviewed backup with the worker stopped and process
ownership reconciled. A plain copy of a live SQLite main file without its WAL
is not a reliable backup.

No schema version or dependency change is introduced. To roll back the binary,
first disable new starts and preserve a consistent journal/evidence backup.
Older code does not enforce these integrity checks and allows generic completion;
rollback is not a repair or permission to ignore the failed acceptance gate.

## Test-first and negative evidence

The new `tests/integrity.rs` suite was run against the original implementation:
**0 passed, 9 failed**, with the expected missing-table, gap, lease, completion
and cursor assertions. After the fix: **9 passed, 0 failed**. Together with the
existing tests and new failure/restart tests, `cargo test -p run-store --locked`
reported **23 passed, 0 failed** on macOS (including one child helper test).

The added storage failure tests exercise real SQLite and separate processes:

- `sqlite_full_rolls_back_state_event_and_pressure_write_then_reopens_with_lease`
  uses a real SQLite `max_page_count` ceiling and a pressure insert to produce
  the engine's `SQLITE_FULL`/`DiskFull` error, then verifies atomic rollback,
  durable lease retention and subsequent sequence allocation after reopening.
  This is database-capacity exhaustion, **not physical filesystem exhaustion**.
- `committed_wal_and_lease_survive_abrupt_writer_exit_without_duplicate_claim`
  starts a separate process that exits without running Rust destructors after
  committing its journal. Reopen preserves `Running`, ordered events, retry
  identity and the occupied slot. It does not relaunch or mark completion. This
  is an abrupt process-exit test, **not host power-loss or native-tree recovery**.

Commands:

```text
cargo test -p run-store --test integrity --locked
cargo test -p run-store --locked
cargo test --workspace --all-targets --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
git diff --check
```

On this macOS host the existing worker-core verifier fixture fails with the
default temporary path (`UnverifiedToolchain`). The full portable suite passes
when `TMPDIR` points to a canonical local directory without symlink ancestors.
No verifier or fixture was changed for this storage PR. Windows/Linux CI uses
its existing commands and must independently pass at the reviewed commit.

Physical disk-full, actual Windows worker-kill/descendant teardown, trusted
finalization, and exact-integration native acceptance remain outstanding. The
existing native workflow is unchanged, and earlier native gate results do not
establish acceptance for this change. This PR must not automatically close #39
or parent #32, and AI branch review does not constitute maintainer approval.
