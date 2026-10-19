# Electron + TypeScript Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SumatraFuzz's Rust/Python application stack and planned Tauri desktop with a secure Electron/TypeScript controller and worker while preserving native parser verification and Windows process containment.

**Architecture:** A sandboxed Electron + React renderer talks only to typed main-process IPC. A separate TypeScript worker service owns its authoritative SQLite journal and authenticated API; a narrow C++ Node-API module in the worker creates and supervises the native process tree. Rust protocol/core/store and Python application utilities remain until matching TypeScript behavior and tests pass.

**Tech Stack:** Electron 44.9.0 (Node 24.22.0 runtime), standalone Node.js 24.22.0 LTS, React/React DOM 19.3.1, TypeScript 6.0.3, Vite 7.3.7, @vitejs/plugin-react 5.2.0, Vitest 5.0.5, Biome 2.5.15, TypeBox 0.34.52 + Ajv 8.20.0, better-sqlite3 13.0.3, node-addon-api 8.9.2, node-gyp 13.1.0, @electron/rebuild 4.2.1, electron-builder 26.17.0, @electron/fuses 2.1.3 and @cyclonedx/cyclonedx-npm 6.0.1. Pin all direct npm dependencies exactly and commit one root `package-lock.json`.

**Spec:** `docs/superpowers/specs/2026-10-19-sumatrafuzz-electron-typescript-migration-design.md`

## Global Constraints

- Target SumatraPDF `3.6.1rel`, commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.
- Do not ship the desktop fuzzing flow unless genuine Windows x64 parser and A4–A6 acceptance remain green.
- Execute untrusted PDFs only in isolated, nonadministrator Windows x64 workers.
- Use structured argv, never shell-concatenated commands; only allowlisted, provenance-verified binaries may launch.
- Permit one active campaign per worker; worker SQLite is authoritative, state/event/lease mutations are atomic, request retries are idempotent, and recovery never silently relaunches.
- Persist the native teardown receipt as a `process_teardown` event in the same transaction that releases the one-slot lease.
- Provision the worker as a nonadministrator Windows service with a dedicated service SID and a dedicated NTFS data volume. In v1, `max_disk_bytes` is the administrator-provisioned hard quota for the worker data volume; a run request must equal that worker quota. This uses the OS-enforced cap for all service-owned run data instead of claiming that polling alone can impose a strict per-run disk limit.
- Keep SQLite in WAL mode with foreign keys and `synchronous=FULL`; retain the 5-second busy timeout and bounded transient WAL initialization retry behavior.
- Keep local worker transport on loopback and remote worker transport on an explicit private/VPN interface; require mutual TLS and explicit pairing in both modes.
- Electron renderer uses sandboxing, `contextIsolation: true`, `nodeIntegration: false`, restrictive CSP, sender-checked typed IPC, navigation/window-open restrictions, and no remote content in privileged windows.
- Keep the Windows C++ harness, PowerShell native workflows, and the narrow native Job Object/DPAPI supervisor boundary. Port all existing Python utilities/tests to TypeScript; retain Python 3 only as a native build prerequisite for node-gyp if the selected runner requires it.
- Keep Actions pinned by full commit SHA, least privilege, `persist-credentials: false`, cache by lockfile/runtime, and no skipped or soft-failed acceptance gate.
- Version baseline: Electron `44.9.0`, standalone Node `24.22.0`, TypeScript `6.0.3`; exact versions are committed in manifests and lockfile. Recheck Electron's supported stable lines before the first package build and take a security patch update if the pinned line has been superseded.

## Review Focus

- A symlink/reparse-point swap or forged target/A4 manifest must be rejected before launch; cover with worker-core path/hash trust-anchor tests.
- Concurrent start, reused idempotency key, corrupted journal, missing event tail, or absent active lease must not create a second campaign or silently repair state; cover with run-store transaction/reopen tests.
- Malformed IPC, wrong renderer sender, unpaired/expired mTLS identity, or untrusted remote address must be rejected before any state or process change; cover with Electron IPC and worker API security tests.
- A traversal path, symlink, oversized archive, corrupt hash, bad ETag or invalid Range must never write outside staging or become trusted evidence; cover with evidence importer and artifact-transfer tests.
- CreateProcess, Job Object assignment, quota setup or descendant teardown failure must fail closed and preserve observed evidence; cover on Windows with child-process probes under a standard user.

---

## Delivery order and dependencies

```text
1 workspace/tooling -> 2 protocol -> (3 worker core, 4 store, 5 native supervisor)
                                      -> 6 worker API/security
2 protocol + 6 API -> 8 controller client/catalog -> 9 Electron workflows
1 tooling -> 7 evidence -> 10 analysis (parallel with 3-6 where interfaces permit)
3-10 -> 11 packaging, CI cutover, docs and Rust/Python removal
```

Each workstream is a focused PR into `dev` under its existing tracker: #90 worker/native lifecycle, #91 trust, #92 API, #93 controller catalog, #94 evidence, #95 desktop, #96 CI/release, and #97 analysis. Do not merge or close issues automatically; acceptance evidence and normal review remain required.

### Task 1: TypeScript workspace and fast feedback CI

**Files:**
- Create: `package.json`, `package-lock.json`, `.node-version`, `tsconfig.base.json`, `biome.json`, `vitest.workspace.ts`
- Create: `packages/worker-protocol/package.json`, `packages/worker-protocol/tsconfig.json`, `packages/worker-protocol/src/index.ts`, `packages/worker-protocol/test/index.test.ts`
- Modify: `.github/workflows/repository-checks.yml`, `.github/dependabot.yml`

**Interfaces:**
- Produces root commands `npm run format:check`, `npm run lint`, `npm run typecheck`, `npm test -- --run`, and workspace package resolution for `@sumatrafuzz/*`.
- The worker protocol package exports the types and functions specified in Task 2.

- [x] **Step 1: Add failing workspace configuration tests** asserting root scripts, exact Node engine, workspace globs and lockfile are present; add a compiler fixture with an expected diagnostic.
- [x] **Step 2: Run `npm test -- --run` and `npm run typecheck`;** confirm the workspace scripts/types are missing before scaffolding.
- [x] **Step 3: Add root workspace configuration and exact dependency pins.** Set `.node-version` and `engines.node` to `24.22.0`. Use Electron `44.9.0`, TypeScript `6.0.3`, React/React DOM `19.3.1`, Vite `7.3.7`, @vitejs/plugin-react `5.2.0`, Vitest `5.0.5`, Biome `2.5.15`, TypeBox `0.34.52`, Ajv `8.20.0`, better-sqlite3 `13.0.3`, node-addon-api `8.9.2`, node-gyp `13.1.0`, @electron/rebuild `4.2.1`, electron-builder `26.17.0`, @electron/fuses `2.1.3`, @cyclonedx/cyclonedx-npm `6.0.1`, @types/node `24.19.2`, @types/react/@types/react-dom `19.3.0`, and @types/better-sqlite3 `9.6.0`; use exact versions without ranges. Build worker native modules against standalone Node; use `@electron/rebuild` for the controller's SQLite binding against Electron.
- [x] **Step 4: Add Linux/Windows Node CI** using pinned `actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020` with npm lockfile caching; run install, format, lint, typecheck, tests and `npm audit --audit-level=high`. Keep every current native and Rust job while migration is in progress.
- [x] **Step 5: Run all five root commands locally** and inspect `npm ls --all`; require a clean lockfile and no duplicate incompatible direct runtime versions.
- [x] **Step 6: Commit** `chore: scaffold TypeScript workspace and CI`.

### Task 2: Canonical typed protocol and state machine (#92)

**Files:**
- Create: `packages/worker-protocol/src/model.ts`, `errors.ts`, `validation.ts`, `index.ts`
- Create: `packages/worker-protocol/test/state-machine.test.ts`, `metadata.test.ts`, `validation.test.ts`
- Keep Rust source until Task 11.

**Interfaces:**
- `validTransition(from: RunState, to: RunState): boolean`
- `validateRunRequest(value: unknown): RunRequest`, throwing `WorkerError.InvalidConfig` on invalid input.
- Export `RunId`, `WorkerId`, `ControllerId` as validated UUID strings; `RunState`, `CampaignLimits`, `RunRequest`, `StopReason`, `RunStatus`, `EventType`, `RunEvent`, and the Rust-equivalent `WorkerError` values.
- `RunRequest` JSON fields exactly: `request_id`, `controller_id`, `input_bundle_id`, `target_lock_sha256`, `limits`, `label`.
- `RunEvent.seq` and `RunStatus.last_event_seq` use SQLite `INTEGER`/TypeScript `bigint` internally and decimal strings in JSON/SSE, avoiding JavaScript number precision loss; schemas reject nondecimal sequence IDs and tests round-trip values above `Number.MAX_SAFE_INTEGER`.

- [x] **Step 1: Port the existing Rust protocol test cases** to Vitest. Preserve legal transitions, reject terminal/regressive transitions, round-trip UUID strings, reject nil IDs/unknown fields, require each limit > 0, require CPU 1–100, enforce bundle ID length 1–128 and `[A-Za-z0-9_-]+`, 64 hex SHA-256, label length ≤128 with no control characters.
- [x] **Step 2: Run `npm test -- --run --project @sumatrafuzz/worker-protocol`;** verify the new tests fail because exports do not exist.
- [x] **Step 3: Implement TypeBox schemas as the single runtime/type source, with Ajv validation and exact snake_case serialization.** Keep connectivity state separate from `RunState`.
- [x] **Step 4: Run protocol tests, typecheck and format check;** require all parity cases pass.
- [x] **Step 5: Commit** `feat(protocol): port typed worker contract to TypeScript`.

### Task 3: Provenance, policy and verified launch specification (#90)

**Files:**
- Create: `packages/worker-core/package.json`, `src/policy.ts`, `src/verified-launch.ts`, `src/path-verification.ts`, `test/verified-launch.test.ts`
- Consume: `@sumatrafuzz/worker-protocol` from Task 2.

**Interfaces:**
- `WorkerPolicy`: max limits, pinned target-lock digest, pinned A4-manifest digest, lock/A4/harness paths, allowed binary/tool/input roots and output root.
- `VerifiedRunSpec`: `runId`, verified executable, frozen `argv: readonly string[]`, working directory, limits and evidence directory.
- `verifyAndBuildLaunch(request: RunRequest, policy: WorkerPolicy): Promise<VerifiedRunSpec>`; does not spawn.

- [x] **Step 1: Port existing verified-launch tests** for wrong client lock digest, forged client-supplied trust anchors, mutated native binaries, unknown bundles and ceilings.
- [x] **Step 2: Run `npm test -- --run --project @sumatrafuzz/worker-core`;** verify the trust cases fail before implementation.
- [x] **Step 3: Implement SHA-256 streaming, canonical containment and Windows reparse-point checks for trusted roots/files; verify pinned source commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`, A4 cycles ≥10 and nonzero confirmed map; reject malformed identities and any limit above administrator ceilings.** Preserve legacy WinAFL ordinary DOS-path argv behavior while keeping canonical paths for trust checks.
- [x] **Step 4: Test reordered JSON, case-insensitive hex, symlink/reparse ancestors, changed-after-verification hashes, UNC/device paths, `\\?\` argv, path traversal and missing A4 fields;** all invalid cases must fail closed.
- [ ] **Step 5: Run worker-core tests on Linux and Windows CI;** add no process spawn in this package.
- [ ] **Step 6: Commit** `feat(worker): port provenance-checked launch policy`.

### Task 4: Transactional worker SQLite journal and one-slot lease (#90/#93)

**Files:**
- Create: `packages/run-store/package.json`, `src/sqlite-run-store.ts`, `src/errors.ts`, `src/migrations/0001_worker.sql`, `test/migration.test.ts`, `test/journal.test.ts`, `test/concurrency.test.ts`
- Reuse: current `crates/run-store/migrations/0001_worker.sql` as the schema source until this task establishes parity.

**Interfaces:**
- `SqliteRunStore.open(path: string): SqliteRunStore`
- `claimWorkerSlot(controllerId: ControllerId, requestId: string, payloadDigest: string, runId: RunId): ClaimOutcome`, where the result is `{ kind: 'new' | 'existing'; runId: RunId } | { kind: 'worker_busy' }`.
- `transitionState(runId: RunId, expected: RunState, next: RunState, kind: EventType): bigint`
- `releaseAfterTeardown(runId: RunId, receipt: TeardownReceipt): void`; receipt fields are `jobId: string`, `stoppedAtUtc: string`, `remainingProcesses: number`, `exitCode: number | null`, and `stopReason: StopReason`.
- `runState(runId: RunId): RunState`; `readEventsAfter(runId: RunId, seq: bigint, limit: number): RunEvent[]`.

- [x] **Step 1: Port tests** for fresh/legacy version-0 migration, corruption refusal without byte overwrite, injected write rollback, bounded replay, idempotent matching retry, conflicting payload rejection, one durable active slot, terminal release only with teardown receipt, CAS mismatch, unsupported version, and concurrent claims across independent connections.
- [x] **Step 2: Run `npm test -- --run --project @sumatrafuzz/run-store`;** verify expected missing API/database failures.
- [x] **Step 3: Implement `better-sqlite3` transactions with `BEGIN IMMEDIATE`;** enable safe-integer mode so SQLite `INTEGER` values are returned as `bigint`; apply foreign keys, WAL, `synchronous=FULL`, 5-second busy timeout and at most 16 WAL activation attempts with 80 ms delay on BUSY/LOCKED only. Preserve `user_version=1`; reject newer schema, malformed rows, missing active lease and missing event tail. Accept only replay limits 1–10,000 and test sequence values above `Number.MAX_SAFE_INTEGER` without loss.
- [x] **Step 4: Require claim, idempotency record and lease to commit atomically;** state CAS and event sequence/payload commit atomically; `Completed` can only originate from `Stopping`; slot release requires terminal state and a `TeardownReceipt` with `remainingProcesses: 0` and persists it in the same transaction.
- [ ] **Step 5: Run the store suite repeatedly on Linux and Windows** and run the process-exit/reopen and `SQLITE_FULL` rollback tests.
- [ ] **Step 6: Commit** `feat(store): port authoritative worker journal to TypeScript`.

### Task 5: Windows Job Object Node-API supervisor (#90)

**Files:**
- Create: `native/worker-supervisor/binding.gyp`, `src/addon.cpp`, `src/command_line.cpp`, `include/supervisor.h`, `test/command_line.test.ts`, `test/supervisor-windows.test.ts`, `CMakeLists.txt`
- Create: `scripts/windows/install-worker-service.ps1`, `scripts/windows/tests/worker-service.Tests.ps1`
- Modify: `.github/workflows/repository-checks.yml`
- Consume: `VerifiedRunSpec` from Task 3 and `TeardownReceipt` shape from Task 4.

**Interfaces:**
- `launchSuspended(spec: VerifiedRunSpec): Promise<JobHandle>`; creates a Windows process suspended, assigns the whole tree to a Job Object, applies kill-on-close and requested quotas, then resumes.
- `stopJob(handle: JobHandle, graceMs: number): Promise<TeardownReceipt>`; returns only after Windows confirms zero active processes or returns `ProcessError`.
- `sampleJob(handle: JobHandle): Promise<ResourceSample>`; reports observed CPU, memory and process count.
- `protectSecret(plaintext: Buffer): Buffer` and `unprotectSecret(ciphertext: Buffer): Buffer`; use Windows DPAPI under the worker service identity for its private key material.

- [ ] **Step 1: Write C++/Windows child-probe tests** that assert no child executes before Job Object assignment and quota setup, descendants are killed, a failed assignment never resumes a child, and close/stop reports remaining process count.
- [ ] **Step 2: Run the new Windows tests** and capture expected failure against the missing addon; Linux tests must report unsupported platform for launch, not pretend success.
- [ ] **Step 3: Implement N-API exports using `node-addon-api 8.9.2` and `node-gyp 13.1.0`;** use `CREATE_SUSPENDED`, assign/configure Job Object before `ResumeThread`, set kill-on-close, enforce wall time/CPU/memory policy, and build argv using Windows command-line quoting from a vector only.
- [ ] **Step 4: Add negative Windows probes** for spaces/quotes, shell metacharacters, wrong architecture, quota setup error, process escape, timeout, force-stop, child crash, service exit and DPAPI wrong-user/tamper cases. Require nonadministrator worker and child tokens.
- [ ] **Step 5: Add one-time elevated provisioning** that installs the Windows service under a dedicated nonadmin virtual service identity, ACLs tool/data roots to the service SID, enables an NTFS hard quota on the dedicated data volume, and configures local/private-only firewall bindings. The service worker must fail closed if required volume quota enforcement or ACL checks are absent; no fuzzing process runs elevated.
- [ ] **Step 6: Test provisioning** with Pester: installed identity is nonadmin/noninteractive, tool roots are read-only, data volume enforces the exact fixed worker quota, and install/uninstall refuses to remove an active worker or delete run evidence.
- [ ] **Step 7: Build addon separately for standalone Node 24.22.0;** do not load it in Electron. Test clean `npm ci` + native build on `windows-2022` without fetching unpinned binaries.
- [ ] **Step 8: Commit** `feat(worker): add bounded Windows Job Object supervisor`.

### Task 6: Worker API, trust and recovery (#91/#92)

**Files:**
- Create: `apps/worker-service/package.json`, `src/server.ts`, `src/auth.ts`, `src/routes.ts`, `src/events.ts`, `src/artifacts.ts`, `src/quota-monitor.ts`, `src/service-lifecycle.ts`, `test/api-contract.test.ts`, `test/mtls.test.ts`, `test/recovery.test.ts`, `test/quota-monitor.test.ts`
- Consume: Tasks 2–5.

**Interfaces:**
- `createWorkerServer(config: WorkerServerConfig): Promise<WorkerServer>` using Node HTTPS and client-certificate validation.
- Routes: `GET /v1/capabilities`; `POST /v1/input-bundles`; `POST /v1/runs`; `GET /v1/runs/{run_id}`; `POST /v1/runs/{run_id}/stop`; `GET /v1/runs/{run_id}/events`; `GET /v1/runs/{run_id}/manifest`; `GET /v1/runs/{run_id}/artifacts/{artifact_id}`.
- Worker service calls `SqliteRunStore`, `verifyAndBuildLaunch`, and native supervisor APIs; routes never accept arbitrary executables, shell commands or host paths.

- [ ] **Step 1: Add API contract tests** for version negotiation, missing/invalid idempotency, same-key replay, conflicting request body, worker-busy 409, unpaired controller, invalid limits, event replay, journal gap and artifact range/ETag.
- [ ] **Step 2: Add TLS trust tests** for missing, expired, revoked, wrong-worker and unpaired client certificates plus loopback/private-interface binding policy, fingerprint-confirmed pairing, and rejection of public/loopback/DNS-rebound remote addresses.
- [ ] **Step 3: Run `npm test -- --run --project @sumatrafuzz/worker-service`;** verify routes/auth/SSE are absent.
- [ ] **Step 4: Implement HTTPS/mTLS server, explicit pair allowlist, per-run/per-artifact authorization, bounded archive staging, idempotent mutation routes, replayable SSE and verified resumable downloads.** Worker continues during controller loss; startup reconciles existing job ownership conservatively and never relaunches silently.
- [ ] **Step 5: Add quota monitoring** that samples native CPU/memory and observes NTFS quota exhaustion; on time, CPU, memory or disk ceiling, request bounded stop and journal the observed reason before lease release. Reject requests whose `max_disk_bytes` differs from the provisioned hard worker-volume quota.
- [ ] **Step 6: Add local service lifecycle** that connects to the installed worker service on loopback and checks its identity/capabilities; controller disconnect/window close does not terminate an active run, while service exit/restart is journaled conservatively.
- [ ] **Step 7: Run API tests on both platforms and Windows worker lifecycle tests under a standard user.** Fail closed if the native supervisor is unavailable.
- [ ] **Step 8: Commit** `feat(worker): add authenticated versioned worker API`.

### Task 7: Evidence and instrumentation utility port (#94/#97)

**Files:**
- Create: `packages/evidence/src/stats.ts`, `collect.ts`, `bundle.ts`, `paths.ts`, `seeds.ts`, `test/stats.test.ts`, `collect.test.ts`, `bundle.test.ts`, `seeds.test.ts`
- Create: `packages/instrumentation/src/verify-debug.ts`, `make-debug-seed.ts`, `test/verify-debug.test.ts`
- Create: `scripts/windows/generate-fixtures.ts`, `scripts/windows/tests/generate-fixtures.test.ts`
- Modify: `scripts/windows/run-winafl-smoke.ps1`, `scripts/windows/verify-native-gate.ps1`, `scripts/windows/ci-native-gate.ps1`
- Keep existing Python implementations/tests until parity passes in CI; remove Python scripts/tests in Task 11, retaining Python 3 only where node-gyp requires it to build native code.

**Interfaces:**
- `parseWinAflStats(text: string): WinAflStats`; `collectEvidence(runRoot: string): Promise<EvidenceManifest>`; `verifyDebugEvidence(input: unknown): DebugEvidence`; `generateDeterministicSeed(options: SeedOptions): Buffer`; `importRunBundle(source: string, destinationRoot: string): Promise<ImportedRun>`.

- [ ] **Step 1: Port every Python test case and pin serialized outputs** for valid/invalid stats, real-only finding inventory, symlinks/reparse paths, hashes, counter/sample mismatch, debug log rejection, deterministic seed bytes, and fixture generation.
- [ ] **Step 2: Run the TypeScript parity suite against existing safe fixtures** and verify failures for missing parsers/importer/generator.
- [ ] **Step 3: Implement parity** with bounded archive expansion, normalized relative paths, no-follow file creation, atomic staging/promotion, fsync/hash-based finalization, immutable completed artifacts and explicit privacy omissions.
- [ ] **Step 4: Add retention and backup/restore**; reject deletion of an active run and require verified export or explicit retention policy before deleting finalized worker evidence. Test partial/corrupt backup restore and repeated finalization.
- [ ] **Step 5: Invoke the TypeScript CLI from PowerShell** with structured `node.exe` argv; update each PowerShell Pester test to cover exit code, stderr, cancellation and path quoting.
- [ ] **Step 6: Run both old Python and new TypeScript suites** and require identical manifest/stat outputs for the same non-sensitive fixtures before removing the old implementation in Task 11.
- [ ] **Step 7: Commit** `feat(evidence): port evidence and instrumentation tools to TypeScript`.

### Task 8: Controller catalog and typed worker client (#92/#93)

**Files:**
- Create: `packages/worker-client/src/client.ts`, `events.ts`, `transfer.ts`, `test/client.test.ts`, `test/reconnect.test.ts`
- Create: `packages/controller-store/src/catalog.ts`, `src/coordinator.ts`, `migrations/0001_controller.sql`, `test/catalog.test.ts`, `test/coordinator.test.ts`, `test/import.test.ts`
- Consume: Tasks 2, 4, 6 and 7.

**Interfaces:**
- `WorkerClient`: `capabilities()`, `startRun(request)`, `getRun(runId)`, `stopRun(runId)`, `eventsAfter(runId, seq)`, `manifest(runId)`, `downloadArtifact(runId, artifactId, offset, etag)`.
- `SqliteControllerCatalog`: `recordWorker`, `recordRunSnapshot`, `recordEventOffset`, `listRuns`, `importRunBundle`, and `exportRunBundle`.
- `ControllerCoordinator.startRunOnce(request: RunRequest): Promise<RunId>` atomically permits at most one active controller run and uses worker-side idempotency for retries.

- [ ] **Step 1: Write shared local/remote contract tests** requiring the same request/response/error semantics, version mismatch behavior, duplicate SSE dedupe, replay gap snapshot, `Range` resume, stable ETag and hash verification.
- [ ] **Step 2: Write catalog tests** for migrations, offline worker/run snapshots, source provenance, import transaction, safe staged files and retained event offset after restart.
- [ ] **Step 3: Run package tests** and verify both implementations fail before additions.
- [ ] **Step 4: Implement HTTPS/SSE client with mutual TLS and controller catalog**; local mode uses authenticated loopback URL, remote mode uses operator-paired private/VPN endpoint. Never store private key material or worker absolute paths in SQLite.
- [ ] **Step 5: Test controller-slot concurrency and disconnection during active run**: only one controller campaign is active; controller remains `Disconnected` while worker stays `Running`; reconnect fetches authoritative snapshot and replay offset without starting another process.
- [ ] **Step 6: Commit** `feat(controller): add catalog and worker synchronization`.

### Task 9: Secure Electron desktop and operator flows (#95)

**Files:**
- Create: `apps/desktop/package.json`, `src/main/index.ts`, `src/main/ipc.ts`, `src/main/window.ts`, `src/main/local-worker.ts`, `src/preload/index.ts`, `src/preload/api.ts`, `src/renderer/index.html`, `src/renderer/App.tsx`, `src/renderer/views/Workers.tsx`, `Campaigns.tsx`, `RunDetail.tsx`, `Evidence.tsx`, and corresponding tests.
- Create: `apps/desktop/test/ipc-security.test.ts`, `window-security.test.ts`, `workflow.test.ts`
- Consume: Tasks 2, 7 and 8.

**Interfaces:**
- Preload exports a fixed `window.sumatraFuzz` API with `listWorkers`, `pairWorker`, `startRun`, `getRun`, `stopRun`, `subscribeRunEvents`, `listEvidence`, `importBundle`, and `exportBundle`; every IPC channel checks sender frame/origin and validates payload with Task 2 schemas. Main-process local-worker startup connects only to the provisioned worker service over authenticated loopback TLS; it does not launch the worker itself.
- Renderer displays run state separately from connection state and never reads SQLite/filesystem or starts processes directly.

- [ ] **Step 1: Add tests** rejecting unrecognized IPC channels, wrong sender, cross-origin frame, extra payload fields, path/shell values, navigation, window opening and remote content.
- [ ] **Step 2: Run Electron main/preload tests** and confirm failure before secure window/IPC implementation.
- [ ] **Step 3: Add BrowserWindow with sandbox, context isolation, disabled Node integration, CSP, navigation/window-open deny policy, permission deny policy, Electron fuses and no remote URL.** Use custom `app://` protocol for local UI resources.
- [ ] **Step 4: Implement typed preload and minimal workflows**: connect to the provisioned local worker, pair/verify remote workers, configure campaigns using the worker's advertised disk quota, start/stop, show live status, reconnect, browse history and review/export evidence. Display `no metrics yet` distinctly from zero and never label untriaged crashes vulnerabilities.
- [ ] **Step 5: Run renderer and IPC tests plus Windows x64 packaged smoke test;** inspect package to confirm it contains no private keys, crash corpus or WinAFL/DynamoRIO binaries.
- [ ] **Step 6: Commit** `feat(desktop): add secure Electron campaign workflows`.

### Task 10: Factual telemetry and reports (#97)

**Files:**
- Create: `packages/analysis/src/telemetry.ts`, `triage.ts`, `report.ts`, `test/telemetry.test.ts`, `triage.test.ts`, `report.test.ts`
- Consume: Tasks 7 and 8.

**Interfaces:**
- `summarizeRun(events: readonly RunEvent[], stats: WinAflStats | null): RunSummary` preserves source timestamps and raw counters.
- `classifyFinding(input: FindingInput, replay: ReplayResult): FindingClassification`; classifications are `untriaged`, `reproduced`, `rejected`, or `needs_review`, never `vulnerability`.
- `buildReport(summary, findings, provenance): ReportDocument` includes source/tool hashes, counts, gaps and omissions.

- [ ] **Step 1: Write tests** for stale/missing counters, nonmonotonic events, raw-vs-validated finding count differences, replay timeout nonreproducibility, sensitive sample omission and provenance mismatch.
- [ ] **Step 2: Run the analysis test suite** and confirm missing behavior.
- [ ] **Step 3: Implement factual summaries only**; preserve original metrics, distinguish additional saved samples from reported counters, and do not infer vulnerabilities or performance percentages.
- [ ] **Step 4: Test report bundle import/export** through evidence verification and commit `feat(analysis): add provenance-aware run reports`.

### Task 11: Packaging, CI cutover and legacy removal (#96)

**Files:**
- Create: `apps/desktop/electron-builder.yml`, `scripts/ci/stage-node-runtime.mjs`, `scripts/ci/verify-package.mjs`.
- Modify: `.github/workflows/repository-checks.yml`, `.github/dependabot.yml`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/DEVELOPMENT.md`, `docs/ROADMAP.md`, `docs/development/ci-action-pins.md`, `docs/verification/*`, `docs/superpowers/specs/2026-10-10-sumatrafuzz-v1-local-remote-desktop-design.md`, old Tauri/Rust plans, `scripts/windows/*` call sites.
- Remove only after parity: `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `crates/*`, Python utilities/tests and obsolete Rust/Python CI commands.

**Interfaces:**
- Root scripts `npm run verify`, `npm run package:win:x64`, `npm run test:native`.
- CI jobs: TypeScript tests (Ubuntu + Windows), native supervisor (Windows), PowerShell Pester, C++ contract, genuine parser, A4–A6, package inspection and unsigned Windows NSIS installer artifact.

- [ ] **Step 1: Add package-content tests** that reject secrets, run data/corpora, crash samples, WinAFL/DynamoRIO binaries and unallowlisted executables from the installer.
- [ ] **Step 2: Add electron-builder Windows x64 NSIS config** with package allowlist, no auto-update publishing, stable app ID, Electron security fuses and unsigned artifact output; stage the official Node `24.22.0` Windows x64 runtime from the pinned CI tool cache and verify its version and SHA-256 before packaging; add `npm run package:win:x64` and test it on Windows.
- [ ] **Step 3: Generate and retain an SBOM** from the lockfile and fail CI on high/critical production dependency audit findings; add npm Dependabot updates while retaining Actions pin review policy.
- [ ] **Step 4: Reorganize CI by artifact dependencies**: build verified parser once; pass exact-run artifacts to instrumentation jobs; run independent Node/package checks in parallel; cache npm by lockfile/runtime; retain all PowerShell, C++ and genuine native gates with no skipped checks or reduced execution thresholds.
- [ ] **Step 5: Run cross-language parity suites**; only then remove Rust/Python packages and test jobs. Mark archived design/plans superseded and rewrite active docs with Electron setup, test, packaging and rollback instructions.
- [ ] **Step 6: Run `npm run verify`, `npm run package:win:x64`, the complete GitHub Actions workflow, and the exact Windows A4–A6 native gate;** inspect uploaded artifacts and SBOM. Record cold/warm Node job timings and compare them with the current documented baseline without treating Rust-job savings as total-workflow savings.
- [ ] **Step 7: Commit** `chore(ci): enforce Electron packaging and migration acceptance`.

## Verification and release handoff

A workstream is accepted only when its focused tests pass locally, its Linux/Windows CI checks pass at the exact PR commit, and its behavior-level parity tests pass before any old implementation is removed. Final migration acceptance requires clean `npm ci`, formatting, lint, typecheck, all Vitest suites, native supervisor tests under a standard user, PowerShell Pester, C++ contract and genuine parser jobs, A4–A6 evidence, package inspection, dependency audit and SBOM generation.

Do not merge or release without the repository's normal approval. The final PR targets `dev`, links the relevant consolidated issue, lists exact CI runs and Windows-native evidence, and documents any limit that was not observed. No migration step may claim completion from Linux mocks or package build success alone.

## Official references used for version and security decisions

- Electron stable release list (Electron `44.9.0` embeds Node `24.22.0`): https://releases.electronjs.org/release
- Node.js version status and LTS schedule: https://nodejs.org/en/about/previous-releases
- Electron support policy (latest three stable major lines): https://www.electronjs.org/docs/latest/tutorial/electron-timelines
- Electron security checklist (sandbox, context isolation, CSP, IPC sender checks, navigation restrictions and fuses): https://www.electronjs.org/docs/latest/tutorial/security
- Electron native module rebuild requirement and `@electron/rebuild`: https://www.electronjs.org/docs/latest/tutorial/using-native-node-modules
- electron-builder Windows/NSIS packaging: https://www.electron.build/docs/win/
- Windows Job Objects enforce process-tree, time, CPU and memory limits: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
- NTFS per-user hard quotas can deny additional disk allocation after the provisioned limit: https://learn.microsoft.com/en-us/windows/win32/fileio/disk-quota-limits
