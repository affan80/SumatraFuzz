# SumatraFuzz B1 Windows Worker Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Windows x64, nonadministrator, one-slot campaign worker with deterministic state transitions, durable journal, bounded tool execution, and safe process-tree teardown, independent of Tauri and network transport.

**Architecture:** A small Rust workspace defines canonical worker identifiers and run states, persists authoritative state/events in worker-local SQLite, and delegates Windows execution to a testable `ProcessRunner` abstraction. The controller, REST/mTLS transport, SSE, evidence bundle sync and Tauri UI will be built in separately reviewed later increments.

**Tech Stack:** Rust stable (pin `rust-toolchain.toml` during implementation), Cargo workspace, Serde, UUID, `thiserror`, `rusqlite` bundled SQLite, Tokio for timed supervision, `windows-sys` for Windows Job Objects. Use a single reviewed `Cargo.lock`; no Redis, PostgreSQL, microservices or task queues.

**Spec:** [SumatraFuzz v1 local/remote desktop design](../specs/2026-10-10-sumatrafuzz-v1-local-remote-desktop-design.md). **Stage map:** [Stage B delivery map](2026-10-10-sumatrafuzz-stage-b-delivery-map.md).

## Global Constraints

- **First gate:** The current `dev` commit's Windows CI must pass unchanged including genuine A4 ten-cycle DynamoRIO, A5 >=1,000 measured WinAFL executions, A6 verified evidence and nonadministrator policy. Existing runs in progress are not a pass.
- Only launch verified x64 pinned SumatraPDF `3.6.1rel`, commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`, with matching tool/harness hashes in existing native manifest.
- Worker process runs nonadministrator on isolated Windows x64; tool binaries are preprovisioned, never downloaded or substituted by run requests.
- Exactly one active campaign per worker, enforced durably across restarts; no duplicate execution on retries. The future controller also enforces one campaign independently.
- Every campaign request has positive, worker-policy-bounded wall time, CPU, memory and disk limits; never use an unlimited default.
- No dynamic shell command strings, unreviewed PDF corpora, vulnerabilities fabricated from crashes, mock WinAFL metrics, credentials in run logs or uploaded crash PDFs.
- This plan has no HTTP server, Tauri, SQLite controller database or report UI. Interfaces created here stay transport-agnostic.
- Respect repository `AGENTS.md`, Conventional Commits, test-first RED → GREEN → review → commit and PR to `dev`. Do not merge without a complete green required-check set.
- Implement functionality in small module-owned files, not a single large `main.rs`. Keep error variants and DTOs explicit; database commits precede outward events.

## Review Focus

1. **Two concurrent Start requests:** test that only one execution slot is granted and the other yields a typed `WorkerBusy` error (Task 4).
2. **Controller retry after timeout:** same `request_id` and matching request digest returns the recorded result without relaunch; conflicting payload with same key returns `IdempotencyConflict` (Task 3/4).
3. **Worker process or host restart:** unfinished journal entries reconcile as `Interrupted` without secretly restarting a WinAFL process or claiming `Completed` (Task 5).
4. **Disk or memory exhaustion:** enforce hard limits, terminate the supervised process tree and preserve hashes of finalized evidence; do not mislabel forced termination as clean finish (Task 4/6).
5. **Malformed/untrusted paths or shell characters:** fail before spawning, never concatenate argv into a command string, and never accept a stale or hash-mismatched `target-lock` (Task 2/4).

---

## Repository map and execution strategy

Create `Cargo.toml` and `rust-toolchain.toml` at root without changing native build manifests. Initial crates:
- `crates/worker-protocol/src/lib.rs`: opaque IDs, domain states, run request, limits, typed errors. No transport dependencies.
- `crates/run-store/src/lib.rs`, `src/migrations.rs`, `migrations/0001_worker.sql`: worker SQLite journal with a single active slot, idempotency results and append-only event sequence.
- `crates/worker-core/src/lib.rs`, `src/policy.rs`, `src/runner.rs`, `src/campaign.rs`, `src/recovery.rs`: verification/limits, injected runner contract, campaign lifecycle and restart reconciliation.
- `crates/worker-core/src/windows_job.rs`: Windows x64 implementation only, behind `cfg(windows)`; uses structured ProcessStartInfo-equivalent args and Windows Job Object.
- Unit/integration tests live adjacent to their crate; scripts/CI integration changes are made only in the task owning the tested behavior.

Types and names in the tasks below are architectural contracts to preserve in later B2/B3 plans. The transport layer may adapt DTO representation but not silently alter lifecycle semantics.

### Task 0: Native foundation, repository lock and initial Rust workspace

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `crates/worker-protocol/Cargo.toml`, `crates/worker-protocol/src/lib.rs`
- Modify: `.github/workflows/repository-checks.yml` to add Rust checks (preserve existing jobs)
- Test: `crates/worker-protocol/tests/metadata.rs`

**Interfaces:**
- `pub struct RunId(pub uuid::Uuid);`
- `pub struct WorkerId(pub uuid::Uuid);`
- `pub struct ControllerId(pub uuid::Uuid);`

- [ ] **Step 1:** Check the native CI status for the exact proposed base commit. Record run IDs, required job conclusions, verified toolchain/source hashes and evidence artifacts. **STOP if any native gate is failed, skipped or pending**; fix on a separate native PR and rerun.
- [ ] **Step 2:** Create an isolated git worktree/feature branch from current, verified `dev`. Create `metadata.rs` tests requiring `RunId`, `WorkerId`, `ControllerId` to serialize/deserialize without loss and reject invalid IDs. RED: types or workspace absent.
- [ ] **Step 3:** Pin a supported Rust toolchain and introduce the minimal workspace/serde/uuid crates. Do not add Tauri or networking crates. GREEN: `cargo test -p worker-protocol --test metadata`.
- [ ] **Step 4:** Add Linux and Windows `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets` to existing workflow. Required native jobs stay unchanged. Check the actual CI results.
- [ ] **Step 5:** Commit as `chore(worker): pin Rust workspace and preserve native gates`.

### Task 1: Canonical states, limits, run requests and transition validation

**Files:**
- Create: `crates/worker-protocol/src/model.rs`, `src/errors.rs`
- Modify: `crates/worker-protocol/src/lib.rs`
- Test: `crates/worker-protocol/tests/state_machine.rs`

**Interfaces:**
- `pub enum RunState { Created, Preparing, Running, Stopping, Completed, Failed, Interrupted }`
- `pub struct CampaignLimits { max_duration_s: NonZeroU64, max_memory_bytes: NonZeroU64, max_disk_bytes: NonZeroU64, max_cpu_percent: NonZeroU8 }`
- `pub struct RunRequest { request_id: Uuid, controller_id: ControllerId, input_bundle_id: String, target_lock_sha256: String, limits: CampaignLimits, label: String }`
- `pub fn valid_transition(from: RunState, to: RunState) -> bool`
- `pub enum WorkerError { WorkerBusy, IdempotencyConflict, InvalidConfig, Unauthorized, UnsupportedPlatform, UnverifiedToolchain, LimitExceeded, InvalidTransition, ProcessError, StorageError }`

- [ ] **Step 1:** Add tests for `Created→Preparing→Running→Stopping→Completed`, setup failure, execution failure, and `Running→Interrupted`; reject `Completed→Running`, `Running→Created` and `Interrupted→Completed`. RED: missing models/validator.
- [ ] **Step 2:** Implement domain types, serde serialization, explicit error strings and a pure transition checker. State and network connection status are distinct types; there is **no Disconnected run state**.
- [ ] **Step 3:** Test that missing/zero/over-100 CPU percentage, zero limits, invalid SHA-256 and malformed UUID are rejected during request validation.
- [ ] **Step 4:** Run `cargo test -p worker-protocol`, `cargo clippy -p worker-protocol --all-targets -- -D warnings`, commit `feat(worker): define versioned run domain contract`.

### Task 2: Verified toolchain policy and safe launch specification

**Files:**
- Create: `crates/worker-core/Cargo.toml`, `src/lib.rs`, `src/policy.rs`, `src/launch.rs`
- Test: `crates/worker-core/tests/verified_launch.rs`

**Interfaces:**
- `pub struct WorkerPolicy { max_limits: CampaignLimits, target_lock_path: PathBuf, allowed_input_root: PathBuf, output_root: PathBuf }`
- `pub struct VerifiedRunSpec { run_id: RunId, executable: PathBuf, argv: Vec<OsString>, working_dir: PathBuf, limits: CampaignLimits, evidence_dir: PathBuf }`
- `pub fn verify_and_build_launch(req: &RunRequest, policy: &WorkerPolicy) -> Result<VerifiedRunSpec, WorkerError>`

- [ ] **Step 1:** Test a valid request produces a complete structured argv, stable unique evidence directory and verified `target-lock`; RED before verifier exists.
- [ ] **Step 2:** Test stale toolchain hash, missing DLL/harness, different source revision, input outside allowed root, network/UNC/device path, shell metacharacters in labels, symlink/relative escape and excess worker quota are rejected **before process spawn**.
- [ ] **Step 3:** Implement file/manifest checks against existing `target-lock.json` and `a4-confirmed.json`, hash allowlisted binaries, canonicalize paths within trusted roots, check existing A4 source/module verification and build argv as a `Vec<OsString>` without shell expansion. Select actual native WinAFL executable and options from verified A5 launcher behavior, not guesses.
- [ ] **Step 4:** Run `cargo test -p worker-core --test verified_launch` and full worker tests; commit `feat(worker): validate bounded native launch specification`.

### Task 3: Durable SQLite worker journal and command idempotency

**Files:**
- Create: `crates/run-store/Cargo.toml`, `src/lib.rs`, `src/migrations.rs`, `migrations/0001_worker.sql`
- Test: `crates/run-store/tests/journal.rs`, `tests/migration.rs`

**Interfaces:**
- `pub struct SqliteRunStore { /* private SQLite connection pool or serialized writer */ }`
- `pub fn append_state_event(&self, run: RunId, expected: RunState, next: RunState, event: RunEvent) -> Result<u64, StoreError>`
- `pub fn claim_worker_slot(&self, request_id: Uuid, payload_digest: &str, run_id: RunId) -> Result<ClaimOutcome, StoreError>`
- `pub fn read_events_after(&self, run_id: RunId, seq: u64, limit: u32) -> Result<Vec<RunEvent>, StoreError>`
- `pub enum ClaimOutcome { New(RunId), Existing(RunId), WorkerBusy }`

- [ ] **Step 1:** Add RED tests: fresh migration, migrate-existing DB, one active persisted slot, duplicate command replay, same ID with changed digest -> conflict, run-local strict monotonic sequence, transactional state-and-event rollback on invalid transition.
- [ ] **Step 2:** Implement transactional schema tables `schema_migrations`, `run_state`, `events`, `command_idempotency`, `worker_slot` (single key 1), `evidence_index`. Set foreign keys and WAL, use parameterized queries and unique constraints; no shared SQLite file across hosts.
- [ ] **Step 3:** Make all exposed store operations atomic and reopen-safe; ensure user-supplied `request_id` is scoped to an authorized controller ID for future mTLS binding.
- [ ] **Step 4:** Run `cargo test -p run-store` on fresh and upgraded schema fixtures; commit `feat(worker): persist run journal and idempotent slot lease`.

### Task 4: Campaign coordinator and process-supervision abstraction

**Files:**
- Create: `crates/worker-core/src/runner.rs`, `src/campaign.rs`
- Test: `crates/worker-core/tests/campaign_lifecycle.rs`

**Interfaces:**
- `pub trait ProcessRunner: Send + Sync { fn spawn(&self, spec: &VerifiedRunSpec) -> Result<Box<dyn RunningProcess>, WorkerError>; }`
- `pub trait RunningProcess: Send { fn try_wait(&mut self) -> Result<Option<i32>, WorkerError>; fn request_stop(&mut self) -> Result<(), WorkerError>; fn force_kill_tree(&mut self) -> Result<(), WorkerError>; }`
- `pub struct CampaignCoordinator<R: ProcessRunner> { /* store, policy, runner, active guard */ }`
- `pub fn start_run(&self, req: RunRequest) -> Result<RunId, WorkerError>` and `pub fn stop_run(&self, run_id: RunId, request_id: Uuid) -> Result<RunStatus, WorkerError>`

- [ ] **Step 1:** Write deterministic RED tests with an injected fake runner that records starts/stops (not fuzzer coverage): concurrent start requests -> exactly one spawned; same request replay -> exactly one spawn; launch failure -> `Failed` with released slot; run stopping -> only one stop; stop unknown ID -> typed error.
- [ ] **Step 2:** Implement coordinator with persisted claim-before-spawn, journal commits, in-process mutex for races plus DB lease for restarts, safe idempotent stop and finalized outcome. Emit ordered events only after journal commits; no direct network code.
- [ ] **Step 3:** Add tests for missing snapshot, stale metrics and "controller disconnected": no run-state transition on a simulated transport disconnect. Force stop with explicit `stop_reason`, never `Completed` for an abnormal child exit.
- [ ] **Step 4:** Run `cargo test -p worker-core --test campaign_lifecycle`; commit `feat(worker): coordinate one durable campaign slot`.

### Task 5: Windows x64 Job Object runner and bounded execution

**Files:**
- Create: `crates/worker-core/src/windows_job.rs`, `tests/windows_runner.rs`
- Modify: `crates/worker-core/src/runner.rs`
- Test: `crates/worker-core/tests/windows_runner.rs`

**Interfaces:**
- `pub struct WindowsJobRunner { /* runtime policy, no arbitrary commands */ }`
- `impl ProcessRunner for WindowsJobRunner`
- `pub fn enforce_quota(&mut self, observed_disk_bytes: u64, elapsed: Duration) -> Result<(), WorkerError>`

- [ ] **Step 1:** On Windows x64, write an integration test using a harmless helper subprocess that spawns a descendant. RED: without process-tree supervision, the descendant survives worker stop.
- [ ] **Step 2:** Implement a Job Object attached **before resuming the child** to prevent escape from the job, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, configured per-process/job memory and CPU throttling limits, explicit bounded wall-time and disk accounting; close handles deterministically.
- [ ] **Step 3:** Test hard wall-time, memory/CPU policy checks, disk limit, parent termination and process descendant termination; verify no lingering process or orphaned output writer. If an OS quota feature is unsupported, fail closed; never silently ignore a limit.
- [ ] **Step 4:** Verify actual user token is **nonadministrator** before native execution. Windows ARM and x86 must fail; Linux can compile portable models but cannot pass Windows native runner tests.
- [ ] **Step 5:** Run `cargo test -p worker-core --test windows_runner` on Windows x64 CI (no skips), plus the existing full native gate; commit `feat(worker): supervise bounded Windows process trees`.

### Task 6: Restart reconciliation, evidence finalization and B1 acceptance

**Files:**
- Create: `crates/worker-core/src/recovery.rs`, `tests/restart_recovery.rs`
- Modify: `crates/run-store/src/lib.rs`, `.github/workflows/repository-checks.yml`, `docs/DEVELOPMENT.md`
- Test: `crates/worker-core/tests/restart_recovery.rs`

**Interfaces:**
- `pub enum RecoveryOutcome { ResumedObserved, Interrupted(RunId), NoActiveRun }`
- `pub fn reconcile_startup(&self) -> Result<RecoveryOutcome, WorkerError>`
- `pub fn finalize_run(&self, run_id: RunId, reason: StopReason) -> Result<RunStatus, WorkerError>`

- [ ] **Step 1:** Write RED tests: stale DB active slot with no live process becomes `Interrupted`, a second startup never spawns another process, finalized artifact checksums remain stable, a crash does not claim `Completed`, and retrying finalization cannot overwrite an existing evidence artifact.
- [ ] **Step 2:** Implement bounded reconciliation by verifying process identity/ownership if available; if not provable, safely terminate owned process tree and record `Interrupted`. Clear/release lease only in a journal transaction after process teardown or confirmed loss.
- [ ] **Step 3:** Add failure tests: abruptly killed controller has no effect on worker; killed worker preserves last durable event and replays it after recovery; full filesystem prevents further artifact writes and records a failure without overwriting prior evidence.
- [ ] **Step 4:** Add Rust unit and Windows lifecycle jobs to existing CI **without removing or weakening any native job**; run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets` and the existing genuine Windows A4–A6 gate.
- [ ] **Step 5:** Record test command/output, pinned source, tool binary hashes, job IDs, transition and quota evidence in PR. Commit `test(worker): verify restart recovery and bounded execution`, request review and keep unmerged until green.

## Definition of done for B1

1. The exact base native Stage A CI gate has succeeded on real Windows x64, with actual A4–A6 evidence preserved.
2. Windows x64 worker starts only hash-verified pinned native tools in a nonadministrator context.
3. A second concurrent start cannot create a second fuzzing process, including after journal recovery.
4. Every run transition, event sequence and idempotency response is persisted transactionally in worker-local SQLite.
5. Process descendants are stopped and hard CPU/memory/disk/time limits actually enforced.
6. No network transport, browser UI, cloud DB, generic command execution or invented fuzzing metrics were introduced.
7. Focused RED/GREEN logs, Rust format/lint/unit tests, native Windows acceptance and full CI are green. If any required step fails, mark B1 BLOCKED instead of merging.

## After B1 — follow-on gates

- **B2:** Write its own plan against the approved spec; preserve the `WorkerProtocol` model, add mTLS REST, explicit trust enrollment, SSE `Last-Event-ID`, idempotency headers and Range+ETag contract tests. Confirm the operator enrollment workflow before B2 implementation.
- **B3:** Versioned controller SQLite, local cached `event_offsets`, SHA-256 verified resumable transfers, immutable run bundle import/export, archive traversal/symlink/zip bomb defenses.
- **B4:** Tauri/React UI uses typed `WorkerClient` only; worker status distinct from connection state; no UI starts processes directly. Product visual selection/review before desktop construction.
- **B5:** Windows VM local+remote E2E, mTLS expiry/unpairing, VPN disconnect/reconnect, process crash, quota failures, artifact integrity, accessibility and installer checks.

**Execution handoff:** Review this plan before writing Rust, creating a worktree, installing tools or opening any implementation PR. Choose a Superpowers execution method. Prefer task-by-task implementation with a separate review gate after each task. The plan does not authorize automatic progression across a failed milestone.
