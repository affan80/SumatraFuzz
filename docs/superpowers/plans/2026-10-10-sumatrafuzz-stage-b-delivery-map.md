# SumatraFuzz Stage B — Delivery Map

**Status:** Proposed implementation sequencing for review, not authorization to implement.
**Architecture:** [Approved v1 architecture](../specs/2026-10-10-sumatrafuzz-v1-local-remote-desktop-design.md).
**Implementation details:** [B1 worker-core plan](2026-10-10-sumatrafuzz-b1-worker-core.md).

## Non-negotiable prerequisites

- The **specific dev commit** used as native basis must have green genuine Windows x64 A4–A6 gates and available artifacts: pinned source, real parser, ten-cycle DynamoRIO debug evidence, >=1,000 actual WinAFL executions, consistent verified hashes.
- Preserve the existing protections: nonadministrator native execution, real toolchain, real corpus, immutable evidence; do not skip, mock, downgrade, or mark `continue-on-error` on any native gate.
- Open one feature PR per bounded stage from current `dev`; never write to `main`, rewrite shared history, or merge unverified work.

## Incremental releases

| Milestone | Owning component / files | Observable deliverable and stop condition |
| --- | --- | --- |
| B0: Native gate | Existing `scripts/windows/ci-native-gate.ps1`, `.github/workflows/repository-checks.yml` | Green native workflow on source SHA with preserved A4–A6 evidence; otherwise Stage B implementation remains blocked |
| B1: Worker core | `crates/worker-protocol`, `crates/worker-core`, `crates/run-store` | A single Windows x64 worker can persistently start/stop one bounded, verified run, recover journal state without duplicate launches, and terminate process trees safely |
| B2: Authenticated worker API | `crates/worker-api`, `crates/worker-client`, `api/worker-v1.yaml` | REST + mTLS, explicit pairing, SSE ordered replay/gap handling, HTTP Range + ETag, versioned API; no public listener |
| B3: Controller persistence and evidence | `crates/controller-store`, `crates/evidence` | SQLite migrations, durable SSE offsets, safe resumable downloads, SHA-256 bundle import/export, rejection of traversal/symlink/archive bombs |
| B4: Desktop | `apps/desktop`, Tauri/Rust adapter and React presentation | Same typed `WorkerClient` over local TLS or VPN mTLS, one active campaign, disconnection visible without falsifying run state, accessible operator interface |
| B5: Security, recovery and packaging | Windows integration / UI E2E tests, installer and docs | Certificate expiry/unpairing, no-admin enforcement, resource quota, disk-full/reboot/disconnect scenarios, actual WinAFL E2E, reproducible packaging |

Every milestone produces its own implementation plan and reviewed PR. A green mock/process test is necessary but insufficient to claim a genuine Windows fuzzing run. B4 may only become production ready after a verified B0 gate and the B1–B3 real-worker paths pass.

## Stable system boundaries

- `WorkerProtocol`: canonical versioned identifiers, commands, events, errors, schemas. Generate TypeScript bindings from source-defined API; never maintain hand-duplicated wire formats.
- `WorkerCore`: state machine and sole worker execution-slot authority. It knows nothing about HTTP, VPN, Tauri, or React.
- `ProcessRunner`: explicit process path and argv; Windows Job Object/limits. Unit tests may use a fake process, but native release verification must execute real tools.
- `RunStore`: worker-local SQLite journal and idempotency records; transactional state+event changes. Controller SQLite has its own database and schema.
- `WorkerAPI`: authenticated adapter for REST/SSE/downloads. Local loopback and VPN are deployment configurations for the same service, not separate fuzzing engines.
- `WorkerClient`: stable typed contract consumed by desktop services; reconnect and idempotency handling above transport adapters.
- `EvidenceStore`: content integrity, staging and atomic finalization; no untrusted archive may write outside the run root.

## Required code quality gates

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, Windows-specific lifecycle tests, API contract tests, security negative tests, SQLite fresh/upgrade tests, and existing native Windows Pester/CMake/DynamoRIO/WinAFL gates. Build with locked dependencies and capture exact versioned artifacts. Do not conflate authenticated networking checks with proof of parser instrumentation.

## Risk register / questions for planning

- **Enrollment trust:** recommend *operator-provisioned certificate identities and explicit fingerprint confirmation* in v1 rather than an unauthenticated pairing listener. Confirmation requested before B2 plan.
- **Remote worker binary provisioning:** define in B2 how the installation binds worker ID to a private VPN interface, protected Windows certificate storage, and revocation. No public bind.
- **Process quotas:** B1 will require bounded worker policy defaults, not unlimited campaigns. Exact installed machine limits become configuration and are validated before accepting a run.
- **Native evidence privacy:** raw PDFs and crashes remain local/private; CI may publish only safe metadata and hashed manifests.
- **Backward compatibility:** use versioned Rust DTOs/OpenAPI contracts and SQLite migrations; changes to native parser or WinAFL require renewed A4–A6 evidence.
