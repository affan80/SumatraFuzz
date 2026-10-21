# Campaign and Run Workflow UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved Electron campaign workflow with signed controller identity, bounded PDF ZIP import, one active run with authenticated restart recovery, and a Windows x64 NSIS installer.

**Architecture:** Keep campaign authority in the Electron main process and worker. The signed pairing profile and authenticated capabilities bind one controller UUID to the paired worker. The worker API accepts bounded input uploads and returns a controller-scoped active run from its durable SQLite journal. The renderer receives only validated summaries and run status through narrow IPC. Package the desktop with the locked electron-builder dependency.

**Tech Stack:** Electron 44, TypeScript 6, Node 24, TypeBox/Ajv protocol validation, Vitest, existing worker API and SQLite store, electron-builder 26.

**Spec:** `docs/superpowers/specs/2026-10-19-sumatrafuzz-campaign-run-ui-design.md`

## Global Constraints

- Windows x64 is the only desktop release target in this slice.
- The worker SQLite journal remains the source of truth; the UI supports one active run and no historical run list.
- Input archives are PDF ZIP bundles, at most 32 MiB compressed and within the worker's existing expanded-data policy.
- The signed pairing profile's `controller_id` must match the controller identity resolved from the authenticated client certificate before credentials are persisted.
- The renderer remains sandboxed, context-isolated, without Node integration, and only communicates through exact-document-checked IPC.
- Preserve genuine native parser and A4–A6 acceptance gates, full-SHA Actions pins, least-privilege permissions and dependency audit checks.
- CI produces an unsigned NSIS installer until Authenticode signing is configured.
- Commits use `affan80 <mrzaidzaid@gmail.com>` as requested; do not merge or release.

## Review Focus

- A legacy encrypted profile has no signed controller UUID; preserve its bytes and require safe re-pairing. Test in Task 1.
- A valid signature can still contain malformed or nil controller identity; reject it before persistence. Test in Task 1.
- A valid authenticated controller can ask for another controller's active run; return no identifying data. Test in Task 2.
- ZIP size or file metadata can change between selection and read; reject safely without exposing a path or bytes to the renderer. Test in Task 4.
- A renderer can replay a stale input bundle ID or forge limits/request identity; bind IDs to the current pair and build the final request in main. Test in Task 4.

---

### Task 1: Bind pairing profiles to a signed controller UUID

**Files:**
- Modify: `apps/desktop/src/main/worker-bundle.ts`
- Modify: `apps/desktop/src/main/worker-profile-store.ts`
- Modify: `apps/desktop/src/main/index.ts`
- Modify: `scripts/sign-worker-pairing-bundle.mjs`
- Modify: `README.md`
- Modify: `apps/desktop/test/worker-bundle.test.ts`
- Modify: `apps/desktop/test/worker-profile-store.test.ts`

**Interfaces:** `WorkerProfile.controllerId: string` is a non-nil UUID. Signed bundle payloads carry the profile field under the existing Ed25519 envelope. The desktop writes `worker-profile.v2.enc`, detects but never loads or rewrites `worker-profile.v1.enc`, and requires signed re-pairing when only the legacy file exists.

- [ ] **Step 1: Write failing tests** for missing, nil, malformed and tampered `controllerId`; assert the signature covers it and the profile validator accepts a valid UUID.
- [ ] **Step 2: Run focused tests and confirm failure.** Run: `npx vitest run apps/desktop/test/worker-bundle.test.ts apps/desktop/test/worker-profile-store.test.ts`.
- [ ] **Step 3: Implement the profile and bundle contract.** Require `controllerId` in profile validation, update signing input validation, and introduce a versioned encrypted profile path without deleting or rewriting legacy bytes.
- [ ] **Step 4: Add a legacy-profile test** proving startup reports re-pairing is required and the old encrypted file remains unchanged.
- [ ] **Step 5: Run focused tests.** Run: `npx vitest run apps/desktop/test/worker-bundle.test.ts apps/desktop/test/worker-profile-store.test.ts`.
- [ ] **Step 6: Commit** `feat(desktop): bind pairing profile to controller identity` using the requested author identity.

### Task 2: Add authenticated worker identity and active-run API

**Files:**
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/src/run-coordinator.ts`
- Modify: `apps/worker-service/src/application.ts`
- Modify: `apps/worker-service/test/server-contract.test.ts`
- Modify: `apps/worker-service/test/run-coordinator.test.ts`

**Interfaces:** `WorkerApiHandlers.activeRun(controllerId: string): Promise<unknown>` returns a run status or `null`. `GET /v1/runs/active` responds with exactly `{ active_run: RunStatus | null }`. Capabilities include the authenticated `controller_id` resolved from the paired certificate.

- [ ] **Step 1: Write failing tests** for matching controller capabilities, active run owned by the caller, empty slot, and another controller's slot returning `{ active_run: null }` without its run ID.
- [ ] **Step 2: Run focused tests and confirm failure.** Run: `npx vitest run apps/worker-service/test/server-contract.test.ts apps/worker-service/test/run-coordinator.test.ts`.
- [ ] **Step 3: Implement capabilities and recovery.** Add controller ID to capabilities; read `activeRunSnapshot()`, filter by certificate-resolved owner, and return the existing status shape only to that owner.
- [ ] **Step 4: Add HTTP contract tests** for unauthorized requests, exact response shape, invalid IDs, no cross-controller disclosure and route dispatch for `/v1/runs/active`.
- [ ] **Step 5: Check protocol compatibility.** Confirm whether any released v1 worker/client exists. If so, explicitly version the wire contract before shipping the required capability field; do not silently change a released exact-key contract.
- [ ] **Step 6: Run focused tests.** Run: `npx vitest run apps/worker-service/test/server-contract.test.ts apps/worker-service/test/run-coordinator.test.ts`.
- [ ] **Step 7: Commit** `feat(worker): add controller identity and active run lookup` using the requested author identity.

### Task 3: Add typed upload and active-run methods to WorkerClient

**Files:**
- Modify: `packages/worker-client/src/client.ts`
- Modify: `packages/worker-client/src/index.ts`
- Modify: `packages/worker-client/test/client.test.ts`

**Interfaces:** `WorkerClient.importInputBundle(archive: Buffer): Promise<ImportedInputBundle>` sends bounded `application/zip` bytes. `WorkerClient.activeRun(): Promise<RunStatus | null>` parses `{ active_run }` and verifies worker identity. `WorkerCapabilities.controller_id` is a non-nil UUID.

- [ ] **Step 1: Write failing transport tests** for required capability identity, upload content type, empty and over-32-MiB input rejection, HTTP error handling, malformed summary fields and empty/valid active-run responses.
- [ ] **Step 2: Run focused tests and confirm failure.** Run: `npx vitest run packages/worker-client/test/client.test.ts`.
- [ ] **Step 3: Implement strict response validators and methods.** Reuse the certificate-pinned transport; expose no generic request method. Validate bundle ID, SHA-256, file count and expanded byte count.
- [ ] **Step 4: Test worker identity mismatch** for both capabilities and active-run status; ensure the client fails closed.
- [ ] **Step 5: Run focused tests.** Run: `npx vitest run packages/worker-client/test/client.test.ts packages/worker-protocol/test/validation.test.ts`.
- [ ] **Step 6: Commit** `feat(client): support bounded input upload and active run recovery` using the requested author identity.

### Task 4: Keep import and run authority in Electron main

**Files:**
- Create: `apps/desktop/src/main/input-bundle-file.ts`
- Create: `apps/desktop/test/input-bundle-file.test.ts`
- Modify: `apps/desktop/src/main/index.ts`
- Modify: `apps/desktop/src/main/ipc.ts`
- Modify: `apps/desktop/src/main/worker-controller.ts`
- Modify: `apps/desktop/src/preload/api.ts`
- Modify: `apps/desktop/src/preload/global.d.ts`
- Modify: `apps/desktop/test/ipc-security.test.ts`
- Modify: `apps/desktop/test/worker-controller.test.ts`

**Interfaces:** Renderer `RunDraft` is `{ label: string; limits: CampaignLimits }`. Main exposes `importInputBundle()`, `getCampaignStatus()`, `startCampaign(draft)`, and `stopActiveRun()`; renderer supplies no path, archive bytes, controller ID, request ID, target lock, bundle ID or run ID.

- [ ] **Step 1: Write failing tests** that IPC rejects extra fields, wrong argument counts, stale imports, arbitrary run IDs, and limits above worker capabilities.
- [ ] **Step 2: Run focused tests and confirm failure.** Run: `npx vitest run apps/desktop/test/ipc-security.test.ts apps/desktop/test/worker-controller.test.ts`.
- [ ] **Step 3: Add bounded file reader tests** for symlink, empty/oversized ZIP, and file replacement or growth while reading; confirm no path is returned.
- [ ] **Step 4: Implement main-process import.** Open a ZIP-only file picker; read at most 32 MiB; upload through `WorkerClient.importInputBundle`; return only validated bundle ID, archive hash, file count and expanded bytes.
- [ ] **Step 5: Implement controller-owned run methods.** Verify both worker and controller IDs during pairing before saving; bind imported bundle IDs to the current worker/controller and clear them on unpair/re-pair; generate request ID and populate controller ID, target lock and bundle ID in main.
- [ ] **Step 6: Implement status recovery and stop.** Recover one active run after profile restore, keep its ID in main, and stop only that run; clear state and close the client on identity mismatch.
- [ ] **Step 7: Add/adjust IPC and controller tests** for successful identity match, either identity mismatch, no-save-on-failure, import summary allowlist and renderer-forged run fields.
- [ ] **Step 8: Run focused tests.** Run: `npx vitest run apps/desktop/test/input-bundle-file.test.ts apps/desktop/test/ipc-security.test.ts apps/desktop/test/worker-controller.test.ts apps/desktop/test/worker-profile-store.test.ts`.
- [ ] **Step 9: Commit** `feat(desktop): add secure campaign controller IPC` using the requested author identity.

### Task 5: Build the campaign page and serialized status polling

**Files:**
- Modify: `apps/desktop/src/renderer/index.html`
- Modify: `apps/desktop/src/renderer/app.ts`
- Create: `apps/desktop/src/renderer/campaign-poller.ts`
- Create: `apps/desktop/test/campaign-poller.test.ts`
- Modify: `apps/desktop/src/preload/api.ts`
- Modify: `apps/desktop/src/preload/global.d.ts`

**Interfaces:** UI consumes only the preload methods from Task 4. `createCampaignPoller(fetchStatus, onStatus, onError)` returns `{ start(): void; stop(): void }`, schedules the next poll after the prior call settles, starts at 1 second and caps transient-error backoff at 15 seconds. Display fields are worker connection, policy ceilings, validated import summary, campaign label, current run state and allowlisted stop reason.

- [ ] **Step 1: Write failing poller tests** proving no overlapping requests, 1-second normal interval, bounded 15-second transient-error backoff, and stop cancels future requests.
- [ ] **Step 2: Run focused tests and confirm failure.** Run: `npx vitest run apps/desktop/test/campaign-poller.test.ts`.
- [ ] **Step 3: Implement `createCampaignPoller`** in `campaign-poller.ts`, scheduling the next request only after the previous request settles.
- [ ] **Step 4: Run poller tests and confirm they pass.** Run: `npx vitest run apps/desktop/test/campaign-poller.test.ts`.
- [ ] **Step 5: Implement the one-page campaign flow.** Add ZIP import, label and limits, start/stop controls and status. Use `textContent`; never render filenames, HTML, paths, worker errors or raw event payloads.
- [ ] **Step 6: Add renderer mapping tests** for unknown run states, invalid limits, validated import summaries and allowlisted stop reasons.
- [ ] **Step 7: Preserve and verify window security.** Run: `npx vitest run apps/desktop/test`; inspect compiled renderer for unsafe HTML/eval sinks.
- [ ] **Step 8: Commit** `feat(desktop): add campaign and run workflow UI` using the requested author identity.

### Task 6: Package and smoke-test the Windows x64 NSIS installer

**Files:**
- Create: `electron-builder.yml` at repository root
- Modify: `package.json`
- Create: `scripts/check-desktop-package.mjs`
- Modify: `.github/workflows/repository-checks.yml`
- Modify: `README.md`

**Interfaces:** `npm run desktop:package:win` emits one unsigned Windows x64 NSIS `.exe` to the configured output directory. Package inspection returns failure if forbidden files or credentials are present.

- [ ] **Step 1: Write failing package-policy tests** for private signing keys, pairing credentials, test corpora, native fuzzing executables and build-only files.
- [ ] **Step 2: Run the package-policy check and confirm failure** on a deliberately invalid fixture manifest.
- [ ] **Step 3: Configure electron-builder.** Pin the NSIS x64 target and explicit file allowlist; include only desktop output, worker runtime, required assets and security fuses.
- [ ] **Step 4: Add package script and inspection.** Build unsigned CI output; inspect the actual packaged file list and reject secret/corpus/native-tool matches.
- [ ] **Step 5: Add a Windows packaging workflow job** using existing full-SHA Actions, `persist-credentials: false`, least-privilege permissions and concurrency controls. Build, inspect, silently install, launch and verify process, uninstall, and upload the artifact.
- [ ] **Step 6: Keep native acceptance gates blocking and unchanged.** Verify the parser and A4–A6 jobs still consume their genuine pinned artifacts and remain required.
- [ ] **Step 7: Run package-policy tests locally** and run the installer smoke check on Windows CI.
- [ ] **Step 8: Commit** `build(desktop): package Windows x64 NSIS installer` using the requested author identity.

### Task 7: Verify the full slice and prepare PR evidence

**Files:** final changed files from Tasks 1–6 and the approved spec.

- [ ] **Step 1: Run full local verification.** Run: `npm run verify`.
- [ ] **Step 2: Inspect the final diff** for secret exposure, unsafe renderer sinks, broad IPC, stale profile handling, compatibility changes and accidental native-gate weakening.
- [ ] **Step 3: Run exact-commit GitHub Actions checks** for Windows service/native behavior, Pester, genuine parser/A4–A6 and NSIS installation. Report local versus CI evidence accurately.
- [ ] **Step 4: Prepare a PR description** describing behavior, security boundaries and validation evidence. Do not merge or release.

## Execution Notes

- The active-run lookup is for desktop restart while the worker remains available; it does not recover or relaunch a process after worker failure. Existing conservative worker reconciliation remains authoritative.
- Confirm released protocol consumers before changing the exact-key capabilities contract; version the wire contract explicitly if compatibility requires it.
- Apply `superpowers:test-driven-development` for each implementation task and `superpowers:verification-before-completion` before reporting completion.
- The tasks are sequential because each produces interfaces consumed by the next. Native execution in this thread is recommended for lower context and coordination overhead; choose it only after reviewing this plan.
