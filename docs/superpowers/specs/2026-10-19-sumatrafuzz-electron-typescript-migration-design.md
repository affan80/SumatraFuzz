# SumatraFuzz Electron and TypeScript Migration

**Status:** Approved by the user for implementation on 2026-10-19; migration remains in progress.
**Date:** 2026-10-19
**Repository:** `affan80/SumatraFuzz`
**Target branch:** `dev`

## 1. Intent and success

Move SumatraFuzz's desktop and application logic from the planned Tauri/Rust design to Electron and TypeScript. The operator should be able to control the same verified local or paired private-network Windows worker, inspect durable runs and evidence, and receive a signed Windows installer once release signing is configured.

The requested full application migration includes the Rust protocol, worker core, SQLite store, and Python evidence/statistics/instrumentation application utilities. It replaces Tauri with Electron and React/TypeScript. It does not rewrite SumatraPDF, WinAFL, DynamoRIO, or the C++ harness: those native components are the system under test and remain native. A narrow C++ Node-API supervisor remains responsible for Windows Job Objects and suspended process creation, since Node/Electron alone cannot safely assign a child to a Job Object before it executes.

Success means behavior is preserved, not merely that Electron launches:

- the worker-local SQLite journal remains the execution source of truth, with state, event sequence and one-slot claim committed atomically;
- controller catalog data is an offline cache and never overrides worker state;
- one worker cannot run two campaigns; retries are idempotent; recovery never silently starts a duplicate;
- verified pinned binaries are launched using structured arguments, under a nonadministrator identity and enforced Windows resource limits;
- the genuine pinned SumatraPDF parser and A4–A6 WinAFL/DynamoRIO checks stay required and real;
- all replacement dependencies are locked, audited, packaged and tested on CI;
- no desktop fuzzing workflow ships unless the genuine native acceptance gate remains green.

## 2. Current repository and verified baseline

The repository currently has no Electron/Tauri app, JavaScript package manifest, or JavaScript lockfile. It contains Rust crates `worker-protocol`, `worker-core`, and `run-store`; a native C++ Sumatra-integrated harness; Python evidence and instrumentation utilities; and PowerShell Windows provisioning and verification scripts. Its current approved design names Tauri, so this spec supersedes that desktop choice if approved.

The native acceptance workflow completed successfully in GitHub Actions run [39201869051](https://github.com/affan80/SumatraFuzz/actions/runs/39201869051), on PR head `bae73282e641d37645438599a8c83fad05d9e2f8`, with all seven repository checks green including real parser and A4–A6 jobs. Every migration PR must still pass the exact-commit current workflow. This baseline does not authorize weakening any native gate.

## 3. Approaches considered

1. **Electron UI with Rust worker retained.** Lowest migration risk, but does not meet the selected full TypeScript scope.
2. **Electron plus TypeScript application and worker, with native parser/supervisor boundaries.** Selected. It removes Rust application dependencies and ports Python application utilities while retaining the minimum native code needed to exercise and contain the real Windows parser workload.
3. **Rewrite the parser and all native tooling in JavaScript.** Rejected: SumatraPDF, WinAFL and DynamoRIO are native C/C++ programs, and the harness must call Sumatra-integrated parsing code. Replacing those pieces would invalidate the project's purpose and acceptance evidence.

## 4. Architecture and component boundaries

```text
Electron desktop
  ├── React + TypeScript renderer (sandboxed; no Node access)
  ├── Electron main process (typed, schema-validated IPC; controller only)
  └── TypeScript controller packages
        ├── worker client (REST, SSE, authenticated artifact transfer)
        ├── controller catalog (SQLite cache and migration/import logic)
        └── evidence UI and validated bundle workflows
                         |
                versioned worker API
                         |
Windows worker service (standalone Node LTS, nonadministrator)
  ├── TypeScript protocol, policy, coordinator and recovery
  ├── worker-local SQLite journal and evidence index
  ├── TypeScript toolchain verification and evidence/statistics utilities
  └── narrow C++ Node-API supervisor
        ├── CreateProcess suspended + verified structured argv
        ├── assign process tree to Job Object before resume
        ├── enforce time/CPU/memory limits and safe teardown
        └── report observed exit/teardown result to the worker
                         |
        native/sumatra-harness + pinned WinAFL/DynamoRIO
```

The worker is a separate service process, not code running in Electron's main or renderer process. Local and remote operation use the same authenticated, versioned worker API. The listener binds to loopback in local mode or an explicitly selected private/VPN interface in remote mode; it never binds publicly by default. The worker continues within configured limits during a controller disconnect and journals events durably.

The renderer uses `contextIsolation`, sandboxing, and disabled `nodeIntegration`; remote content is never loaded into privileged windows. Main-process IPC methods accept typed data validated at runtime and expose no arbitrary paths, shell commands, or generic process launch. Worker pairing uses mutual TLS and explicit identity verification. Private keys use OS-protected storage. API mutation idempotency, authorization and artifact path validation remain mandatory.

The C++ Node-API boundary is intentionally narrow and worker-only. It does not choose tools, interpret user-supplied commands, or own run policy. It accepts a trusted executable identity, verified local paths and a structured argv vector from the TypeScript worker, reports a process/job handle, and returns observed stop/exit evidence. Electron itself does not load the addon. Its protocol, resource-limit semantics and teardown behavior receive focused Windows tests.

## 5. Data, API, evidence and migration contracts

The existing worker and controller database roles remain separate physical SQLite databases. The worker journal stays authoritative for execution. Each transition, its monotonic per-run event, idempotency record and lease/slot effects are transactional. A missing lease, damaged schema or missing event remains a hard recovery error; startup never repairs by silently recreating empty state. Controller records are snapshots and offsets only.

The TypeScript protocol package becomes the sole source for request/response and error types, backed by runtime validation and a checked-in OpenAPI contract (or generated bindings from one schema). REST commands, SSE replay with `Last-Event-ID`, resumable range downloads, API version negotiation, mutual TLS and worker authorization retain the approved v1 semantics. Local calls use the same API and cannot bypass authentication.

The TypeScript tooling packages port all current Python behavior and tests, including raw WinAFL counter parsing, instrumentation validation, deterministic seed and fixture generation, finding inventory, safe path checks, hashes, run bundle import/export, and the current PowerShell-to-Python CLI calls. They must preserve the distinction between raw counters and validated findings, reject traversal/symlinks/oversize archives, and never claim a crash is a vulnerability. Existing evidence formats remain readable. SQLite upgrades are forward-only, transactional, backup-aware, and reject unsupported or damaged databases without overwriting bytes.

Existing tests become behavior-level parity tests before Rust/Python implementation removal. Security-sensitive tests cover invalid hashes, changed toolchain locks, forged manifests, malformed resource limits, duplicate and concurrent claims, journal corruption and replay gaps, archive traversal, bad ranges/ETags, expired/wrong certificates, unauthorized runs, spawn failure, Windows descendant teardown and quota exhaustion. Tests use fakes only for logic that can be isolated; no fake can satisfy the genuine native gate.

## 6. Dependency and packaging policy

Use TypeScript with a committed npm lockfile and pinned Node/Electron build tool versions. Select runtime packages only after checking current official Node/Electron support and native-addon compatibility. Any SQLite driver or other native npm module must have a supported Electron/Node ABI strategy, reproducible Windows builds, and security review; prefer a Node-API ABI-stable binding where feasible. No install-time remote binary download is permitted in release builds.

Electron Builder (or an equivalent pinned packager) produces a Windows x64 installer and an unsigned CI artifact until signing credentials are configured. Package only the renderer, main process, required TypeScript runtime bundles, worker service/runtime, the built supervisor addon and allowlisted application assets. Never bundle WinAFL/DynamoRIO or crash corpora. Use Electron security fuses and a restrictive Content Security Policy. Generate an SBOM, run lockfile/dependency audit checks, and document the exact Electron, Node, native addon and toolchain versions.

After parity and required checks pass, remove the Rust workspace, `Cargo.lock`, Rust toolchain pin and Rust CI jobs. After Python parity passes, remove the Python scripts and tests, replace their CI and PowerShell call sites with the TypeScript CLI, and remove Python setup from developer instructions. Keep CMake/MSVC harness builds and PowerShell Windows provisioning/tests. Update README, development guide, roadmap, security policy, dependency automation, setup instructions and release notes; mark prior Tauri/Rust plans as superseded and link them to this design so no active documentation gives conflicting setup or architecture instructions.

## 7. CI and delivery flow

Preserve fast feedback and hard acceptance checks. CI will be reorganized into independent jobs with dependency edges only where artifacts are required:

1. Cross-platform TypeScript validation: lockfile install, formatting/lint, typecheck, unit/contract tests and dependency audit, with npm cache keyed from lockfile and Node version.
2. Windows worker/native-addon validation: build the C++ Node-API supervisor, run worker integration and Windows process containment tests as a standard user, and run existing PowerShell Pester and syntax checks.
3. Native parser contract: build and test the real pinned SumatraPDF filter/harness, then publish only the verified binaries needed by instrumentation jobs.
4. Genuine A4–A6 instrumentation: preserve pinned source and tools, nonadministrator execution, real measured WinAFL feedback, evidence integrity checks and privacy-safe artifacts. This gate remains blocking.
5. Packaging: build the Electron Windows x64 installer, inspect package contents for secrets/corpora/forbidden binaries, and upload a short-retention unsigned artifact. Keep packaging independent of unrelated Linux tests after required contracts are satisfied.

Keep Actions pinned to full commit SHAs, `persist-credentials: false`, least-privilege permissions, concurrency cancellation, dependency caching and no `continue-on-error` on acceptance gates. Avoid rebuilding the same native artifact in downstream jobs; pass it only through verified workflow artifacts with exact run identity. Required checks must be stable and branch rules documented. CI timing improvements may split jobs and use caches, but may not reduce run duration/iterations, skip native work, share untrusted cache artifacts, or replace real Windows evidence with mocks.

## 8. Workstream sequencing

Use the existing eight consolidated trackers as the workstream map, updating their scope and acceptance text only after this spec is approved:

- **#90 worker and native boundary:** port state/core behavior; implement and test the narrow Job Object supervisor; maintain safe verified launch and recovery.
- **#91 worker trust:** TypeScript worker identity, pairing, TLS, authorization, policy and security tests.
- **#92 protocol:** generated/validated typed contract, REST/SSE, idempotency and reconnect.
- **#93 controller data:** SQLite catalog, journal-compatible data types, migrations, provenance and replay offsets.
- **#94 evidence:** port Python evidence/instrumentation behavior and harden bundle import/export/retention.
- **#95 desktop:** Electron shell, secure IPC and operator flows, gated by native acceptance.
- **#96 engineering acceptance:** dependency governance, CI, packaging, SBOM, supply-chain and release gates.
- **#97 analysis:** factual telemetry and safe report handoff, only after source parity and evidence integrity.

Each stream has its own reviewed PR into `dev`; no single broad commit replaces the Rust/Python stack. The existing `dev` and `main` protection remains. Do not close an issue on merge alone; close only when its defined evidence and required checks pass. No merge, release or force-push is included in this design authorization.

## 9. Acceptance criteria

- No Rust application crates or Python scripts/tests remain after their TypeScript parity suites pass; native C++, PowerShell and Windows tooling are documented as platform boundaries.
- No Tauri dependency or instruction remains. Electron/Node dependencies are locked, reviewed, reproducible and represented in CI and Dependabot.
- Electron renderer privilege restrictions and CSP are tested; IPC rejects malformed/unauthorized payloads.
- Windows worker and native supervisor tests prove verified executable/hash checks, structured argv, suspended assignment-before-resume, process-tree teardown, policy ceilings and nonadministrator operation.
- Existing storage schema/data remains recoverable; event/state atomicity, idempotency, one-slot exclusivity, and event replay tests pass against the TypeScript implementation.
- Python evidence utility behavior is covered by TypeScript parity tests; hashes, path safety, archive limits and raw metric provenance remain intact.
- All required current CI checks pass on the exact PR commit, including genuine pinned parser/A4–A6 acceptance; packaging and dependency scans also pass.
- Documentation and workflow files describe the Electron/TypeScript architecture and exact install, test, package and rollback flow.

## 10. Rollback and unresolved implementation choices

Migrate incrementally behind versioned package boundaries. Keep the current Rust and Python implementations until their TypeScript equivalents pass parity tests; remove each legacy implementation only in the PR that demonstrates replacement behavior. Database schema versions and existing SQLite bytes remain forward-readable; no automated destructive downgrade is allowed. If the native supervisor or Electron ABI cannot be built reproducibly on supported Windows CI, stop that workstream and revise the boundary before shipping.

Implementation research still needs to select exact supported Electron/Node versions, SQLite package, validation/OpenAPI tooling, installer tool, and Node-API binding. Confirm these against official current documentation and repository support constraints in the implementation plan; do not guess package versions in this design.
