# SumatraFuzz v1 — Local/Remote Worker and Desktop Architecture

**Status:** DESIGN FOR USER REVIEW — no desktop or remote-worker implementation is authorized by this document.
**Date:** 2026-10-10
**Repository:** [affan80/SumatraFuzz](https://github.com/affan80/SumatraFuzz)
**Dependencies:** Native Stage A4–A6 acceptance, verified on genuine Windows x64; see [roadmap](../../ROADMAP.md).
**Scope:** Stage B: local/remote campaign control, recovery, evidence synchronization, and a maintainable desktop user experience. Stage C advanced reporting is a follow-on.

## 1. Intent, users, and success

SumatraFuzz is a local-first, defensive PDF parser fuzzing workbench. Its primary user configures a campaign, runs WinAFL/DynamoRIO against pinned real SumatraPDF builds on an authorized Windows x64 worker, observes reliable status, and preserves reproducible evidence. The same application must support a local worker (on Windows x64) and a paired remote Windows x64 worker over private LAN/VPN.

**Success:** one operator can safely create, monitor, stop, reconnect to, inspect, import/export, and later reproduce a genuine campaign without confusing connection loss with execution failure. A third-party reviewer can verify evidence hashes and repeat critical commands. The code stays split into small, testable modules.

## 2. Confirmed architectural decisions

1. CI verification on GitHub Actions Windows x64 **and** extended execution on an isolated Windows x64 VM.
2. **At most one active campaign per controller** and an independently enforced **one-slot capacity per worker** in v1. Saved configurations and historical runs are unlimited subject to storage policy. Future concurrency should not require public interface redesign.
3. SQLite holds campaign/worker/finding metadata, backed by immutable-at-application-level filesystem artifacts and portable integrity-checked run bundles.
4. Windows x64 desktop can run a local worker; cross-platform Tauri desktop builds may manage a remote Windows x64 worker only. WinAFL and the native parser remain Windows x64.
5. Remote workers are reachable only via private LAN/VPN. Client/server authentication uses mutual TLS with explicit pairing. Public internet listeners and unauthenticated worker endpoints are prohibited.
6. On controller or VPN disconnection, remote campaigns **continue within predeclared time, CPU, memory, and disk limits**, store all evidence locally, and support authenticated, session-aware recovery.
7. **HTTPS REST for commands/status, SSE for ordered run events, and resumable HTTPS downloads for evidence.** Both local and remote clients implement one typed interface and one versioned API contract.

The agreed priorities are correctness, readability, maintainability, least privilege, and real evidence over fabricated metrics or UI convenience.

## 3. Scope and boundaries

### In scope — Stage B

- Worker runtime and one-slot campaign supervisor on Windows x64.
- Local loopback and remote VPN-bound transport for the **same versioned worker API**. Local mode also authenticates the desktop controller; no unauthenticated loopback bypass.
- Controller-side Tauri 2 + React/TypeScript application with typed Rust commands, worker pairing, campaign editing, live status, reconnection, and evidence import.
- Worker-local persistent run journal and evidence directories; controller-local SQLite catalog with local copies and validated references.
- Portable run bundles; integrity-checking import and explicit retention.
- Security, failure, compatibility, integration and UX tests.

### Out of scope

- Internet-exposed worker servers, cloud hosting, multi-user RBAC platform, distributed scheduling, simultaneous campaigns, a central PostgreSQL service, ML crash classification, exploit development, browser-based control of untrusted workers, and replacing real WinAFL/DynamoRIO with simulations.
- Stage C's full crash-triage workflow and polished reporting; Stage B may expose raw evidence and basic factual summaries.

**Prerequisite:** Do not accept or ship a Stage B end-to-end fuzzing flow without passing all native Stage A gates (genuine parser, persistent DynamoRIO coverage, measured WinAFL run and verified evidence). Unit-test mocks can test UI logic but cannot satisfy native acceptance.

## 4. System decomposition

```text
Tauri Desktop (React views, no native process logic)
  └── Rust application services
        ├── CampaignCoordinator (controller-side one-active-run policy)
        ├── WorkerClient trait (typed operations and error contracts)
        │     ├── LocalWorkerClient (loopback TLS)
        │     └── RemoteWorkerClient (VPN-reachable mTLS)
        ├── RunCatalog (controller SQLite, migrations, worker/run/finding references)
        └── EvidenceImporter (verify hashes, safe import, resumable download)
                       |
            versioned HTTPS REST + SSE + artifact streaming
                       |
Windows Worker Service (nonadministrator execution identity)
  ├── WorkerAPI (mTLS auth, pairing, authorization, payload validation)
  ├── CampaignSupervisor (durable state machine, exclusive worker slot)
  ├── ProcessSupervisor (WinAFL/DynamoRIO argv; Windows Job Object, quotas)
  ├── RunJournal (worker SQLite WAL; monotonic event IDs)
  ├── EvidenceStore (worker-local filesystem, hashes, manifests)
  └── native/sumatra-harness (verified A4–A6 existing engine)
```

These are **logical modules**, not independent network services. Favor a Rust workspace with focused modules/crates by responsibility, rather than premature microservices. UI cannot reference filesystem paths or start a native subprocess directly. Native Windows tool invocation is owned by the worker, with structured argv and allowlisted binaries from verified toolchain lock.

Local and remote clients share command validation, idempotency, error semantics and response types. The only difference is endpoint discovery/pairing: local listener binds loopback; remote listener binds a configured VPN/private interface. No automatic bind to `0.0.0.0`.

### Planned source structure (adapt to existing repository when implementation begins)

```text
apps/desktop/                  # Tauri shell and React UI
crates/worker-client/          # WorkerClient trait, typed DTOs, REST/SSE client
crates/worker-core/            # Worker state machine, supervision, interfaces
crates/worker-api/             # Windows HTTPS/mTLS service, handlers and auth
crates/run-store/              # SQLite migrations, journal, metadata repositories
crates/evidence/               # Manifests, hashes, safe import/export, resumable I/O
scripts/windows/               # Existing source-verified native launch commands
native/sumatra-harness/        # Existing real parser and fuzz_one_file ABI
tests/                         # Contract, recovery and Windows integration tests
```

Do not create a crate until it has a coherent independently testable responsibility. Cross-crate types live in `worker-client` (API) or a small common schema module, not ad hoc duplicated interfaces.

## 5. Command API v1 and typed contracts

All remote requests use mTLS and a paired-controller authorization check. Mutating operations require an `Idempotency-Key` and a unique request ID; the worker stores decisions durably and replays the prior result for retries. Clients never send arbitrary shell commands, dynamic process arguments, or unrestricted host paths.

| Method and path | Purpose | Required behavior |
| --- | --- | --- |
| `GET /v1/capabilities` | Worker identity, engine/version, available resources | Authenticated; disclose supported APIs and verified toolchain identity |
| `POST /v1/input-bundles` | Upload bounded input archive | Validate content/hashes, reject zip-slip/symlinks/bombs, return opaque input bundle ID |
| `POST /v1/runs` | Start with `RunRequest` referencing verified input bundle and toolchain | Enforce one slot; atomically persist request and state; `202` with run ID or `409` |
| `GET /v1/runs/{run_id}` | Authoritative worker run state | Return state, limits, progress snapshot, last event ID and connected worker ID |
| `POST /v1/runs/{run_id}/stop` | Request safe stop | Idempotent; terminate job tree safely, preserve artifacts |
| `GET /v1/runs/{run_id}/events` | Ordered SSE events | Run-local increasing IDs; support `Last-Event-ID`, heartbeat and replay/gap detection |
| `GET /v1/runs/{run_id}/manifest` | Verified artifact inventory | JSON with normalized paths, sizes, SHA-256 and manifest revision |
| `GET /v1/runs/{run_id}/artifacts/{artifact_id}` | Resumable artifact bytes | Opaque ID, HTTP Range, stable ETag/digest, length; `416` for invalid range |

**DTOs:**
- `RunRequest`: `request_id`, `controller_id`, `input_bundle_id`, `target_lock_digest`, `limits` (`max_duration_s`, `max_memory_bytes`, `max_disk_bytes`, `max_cpu_percent`), `seed_policy`, `campaign_label`. All resource values are validated against an administrator-provisioned worker policy; no zero/unlimited default.
- `RunStatus`: `run_id`, `worker_id`, `state`, `started_utc`, `last_event_seq`, `limits`, `stop_reason`, `last_observed_metrics`. Never infer completed from missing heartbeat.
- `RunEvent`: `schema_version`, `run_id`, `seq`, `time_utc`, `event_type`, `payload`. Sequence IDs are durable and monotonic **per run**.
- `ArtifactRef`: opaque `artifact_id`, `run_id`, relative safe path, size, SHA-256, content type, finalization status.

Define a stable version negotiation header and explicit error codes (`unauthorized`, `incompatible_version`, `worker_busy`, `invalid_config`, `missing_artifact`, `quota_exceeded`, `event_history_gap`). Generate Rust/TypeScript DTOs from a checked-in OpenAPI contract or one schema source; prohibit manually drifted copies.

## 6. Campaign and connectivity state machines

**Campaign state (worker authoritative):**

```text
Created -> Preparing -> Running -> Stopping -> Completed
             |           |          |        |
             +----------> Failed <---+--------+
                          ^
                          |
                    Interrupted (worker process lost; explicit reconciliation)
```

- `Completed` is only for a recorded normal finish or authorized stop after artifacts are finalized.
- `Failed` preserves a structured failure reason and any available artifacts.
- `Interrupted` is reserved for **worker/process execution loss**, not controller VPN loss. Recovery never starts a new fuzzing process silently.
- State changes and new event sequence numbers commit atomically in the worker journal.
- The worker owns the actual process and the run slot; the controller caches state but never overrides the worker's terminal outcome.
- Worker restart: reconcile persisted run and any existing supervised process. If ownership/safety cannot be proven, stop orphaned jobs and finalize `Interrupted` / `Failed`; never launch a second duplicate.
- Windows Job Objects or equivalent process-tree supervision enforce teardown; implement bounded graceful stop then terminate and record reason.

**Connection state (controller-only):** `Connecting`, `Connected`, `Degraded`, `Disconnected`, `Reconnecting`. These states are orthogonal to the run. `Running · Disconnected` is valid and must be distinguishable in the UI.

**Reconnection:**
1. Authenticate the peer again; verify expected worker ID, certificate and run ID.
2. Request authoritative `GET /v1/runs/{run_id}`, then SSE with the last durable acknowledged event sequence.
3. Deduplicate replayed IDs; if event history is truncated, fetch a fresh snapshot and report a journal gap without pretending it never happened.
4. Resume downloads via `Range` and `ETag` only if the remote hash/size matches the local partial file. Verify SHA-256 before committing.
5. Continue fuzzing through temporary network interruptions unless configured hard resource limits are reached.

## 7. Trust boundaries, authentication and data security

- Windows VM/worker uses a dedicated nonadministrator identity; privilege separation for any one-time service installation. Never run the fuzzer as SYSTEM/Administrator.
- Bind local transport to `127.0.0.1` / `::1`; bind remote transport to explicit VPN/private interface(s). Firewall rules deny unsolicited public ingress. TLS and mutual certificate validation required even over VPN.
- Pairing is an explicit out-of-band trust step: show identities/fingerprints and confirm on both ends. Store private keys in OS-protected key material, not in SQLite plaintext or run bundles. Support certificate expiry, rotation, revocation/unpairing.
- Enforce authorization *per run and per artifact*, not merely connection-level authentication. Read-only observations and start/stop permissions use typed policy decisions.
- Validate all input content, size, archive expansion and relative paths; reject absolute paths, traversal, symlinks and device paths. Use atomic file creation and no-follow policies where supported.
- Do not execute any user-supplied executable or shell string; worker uses allowlisted pinned harness/tool binaries and a fixed argv generator.
- Worker hard limits include wall time, process memory, CPU allowance, disk quota and total evidence retention. On disk exhaustion, stop safely and preserve existing evidence; never silently overwrite a historical run.
- Treat remote workers as security-sensitive: do not trust client-reported CI metrics or filenames; use raw worker evidence and cryptographic hashes. SHA-256 gives integrity checking, not a cryptographic guarantee of original authorship.

## 8. Storage and evidence contracts

**Controller SQLite (local catalog):** `schema_migrations`, `workers`, `campaigns`, `runs`, `findings`, `artifacts`, `event_offsets`. Store UUID/ULID opaque keys, run/worker identity, immutable artifact references, timestamps, status snapshots and metadata only. Use transactions, WAL mode and forward versioned migrations.

**Worker SQLite (durable journal):** `schema_migrations`, `run_state`, `events`, `command_idempotency`, `evidence_index`, `worker_lease`. This is a **separate physical database**, not shared over SMB or a network mount. The worker journal is authoritative for execution events; controller copies are an offline cache.

**Filesystem per run:**
```text
data/runs/<run_id>/
  manifest.json
  config.json
  input-manifest.json
  logs/
  corpus/
  crashes/
  metrics/
  checksums.sha256
```
Active runs may write to a staging area. Once an artifact is finalized its bytes and SHA-256 are frozen by application policy (prefer OS ACL read-only on complete run directories). Append-only event log and evolving `manifest` revisions are allowed *before finalization*, but published hashes identify a precise revision; never overwrite a finalized artifact.

**Portable run bundle:** ZIP with `bundle-schema-version`, manifest, hashes, relative paths, source/toolchain identity, raw evidence and factual summaries. Export may intentionally omit private crash samples, with such omissions explicit and verified. Import uses a staging directory, full hash/size validation, archive-limit checks, then atomic promotion and transactional catalog update. Bundle version incompatibilities fail with an actionable error.

Artifacts are referenced by worker-assigned IDs, never absolute server file paths. Controller resolves downloaded files under its own data root.

## 9. User journeys (v1)

1. **Onboard:** select `Local` (Windows x64 only) or `Remote`, pair with fingerprint confirmation over LAN/VPN, verify worker capabilities/toolchain.
2. **Configure:** select verified SumatraPDF target, validated seed bundle, campaign limits, output policy; surface realistic resource constraints before start.
3. **Run:** display active worker, status, elapsed time, observed executions, raw stats timestamps and stop controls; distinguish `no metrics yet` from zero.
4. **Disconnect:** show `Running · Disconnected`; never manufacture end state. Worker continues under its cap.
5. **Reconnect:** authenticate, reconcile journal, replay missed SSE events, resume evidence transfer and show any journal gap.
6. **Review/export:** browse raw evidence/finding indexes, hashes, source versions and genuine observed metrics; export/import integrity-checked bundle. Untriaged crashes are not labelled vulnerabilities.

Accessibility and UX: keyboard-operable controls, readable status and error messages, reduced-motion compatibility, straightforward navigation, clear provenance/uncertainty, no fabricated charts.

## 10. Test strategy and gates

**Unit/contract (cross-platform):**
- Same typed tests exercise local/remote clients (including API version mismatch and authorization errors).
- Idempotency retries never create a second run; concurrent start attempts yield at most one active worker slot.
- State transitions and event sequences are journal-atomic; duplicated/out-of-order SSE events reconcile correctly.
- Import rejects wrong SHA-256, unexpected ETag, mismatched Range, traversal paths, symlinks and oversized archive entries.
- SQLite migration upgrade/rollback policy and schema incompatibility behavior are tested.

**Integration (Windows x64):**
- Windows nonadministrator worker starts genuine verified harness using structured process args.
- mTLS rejects missing, expired, revoked, wrong-worker and unpaired client identities.
- WinAFL run remains active after simulated desktop/VPN disconnect; reconnect resumes from saved event offset.
- Controller restart uses persisted campaign/worker/run IDs and never spawns a duplicate.
- Worker crash or process tree failure is represented as interrupted/failed, not completed.
- Hard timeout, disk and resource limits stop execution safely while preserving already-collected artifacts.
- Raw A4 DynamoRIO logs and A5 WinAFL stats remain genuine and verifiable; no mock instrumentation passes release gates.

**CI and deployment:**
- Existing Windows Pester, real parser, native contract and DynamoRIO checks remain required. Add API/worker integration and a bounded actual WinAFL smoke gate on Windows x64. Extended campaign on isolated VM provides separate durable evidence.
- GitHub Actions artifacts may be imported as verified run bundles. No source-code secrets or third-party executables committed.
- Keep hard failures hard; `continue-on-error`, disabled assertions, arbitrary mock results and silent skips cannot qualify for a release.
- Do not ship a public remote listener or a desktop fuzzing workflow until the native evidence gate passes.

## 11. Rollout sequencing and maintainability

Each piece is a separately reviewable workstream with its own spec/plan and PR into `dev`:

1. **B0 — Native foundation gate:** reconcile and complete A4–A6 real Windows verification and evidence; no UI gate bypass. Existing [issue #4](https://github.com/affan80/SumatraFuzz/issues/4).
2. **B1 — Worker-core and journal:** state machine, run slots, process supervision, persistent event journal and resource limits; test-first, no network yet.
3. **B2 — Versioned authenticated worker API:** REST, mTLS/pairing, SSE replay, resumable artifacts, protocol contract tests; local loopback + private VPN transport.
4. **B3 — Controller catalog and evidence sync:** SQLite migrations, integrity checked imports/exports, reconnect offset and idempotency.
5. **B4 — Desktop workflows:** Tauri/React, worker pairing/config, launch/stop, live metrics, status disconnection and basic evidence review.
6. **B5 — Hardening and packaging:** negative-security tests, VM end-to-end, nonadmin installation path and Windows packaging.

Use small modules, one-responsibility files, typed DTOs from one schema, dependency inversion at `WorkerClient`, and no premature multi-worker scheduling. Stage C advanced reporting follows verified Stage B acceptance and a separately approved design.

## 12. Review focus and unresolved decisions

The following outcomes are **defined**, even though exact policy numbers will be configured during the implementation plan:
- Resource limits are mandatory, strictly positive, and bounded by worker policy; no unlimited worker campaigns.
- Truncated/replayed SSE events cannot falsify run state.
- Changing a pinned native tool requires renewed provenance and native acceptance checks.
- Losing network connectivity must not stop the worker by itself.
- Every finalized artifact must be hash-verified before inclusion in controller storage.
- An unavailable Windows x64 worker cannot be replaced by simulated measurements.

No source changes, native-run claims or UI builds are authorized by this spec. The design requires review and explicit approval before a detailed implementation plan and later execution.
