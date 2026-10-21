# Durable Windows Worker Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete issue #90 with merged, reviewed evidence that the Windows worker uses the durable journal, verified launch, Job Object containment/quotas, conservative recovery, and immutable finalization.

**Architecture:** Keep the existing TypeScript worker coordinator and SQLite run store. Add a real Windows x64 acceptance path that invokes the native supervisor with the pinned WinAFL/DynamoRIO/SumatraPDF artifacts, then validates durable teardown, final evidence and measured execution counts.

**Tech Stack:** TypeScript 7 / Node 24, SQLite, C++ Node-API Windows Job Objects, PowerShell, GitHub Actions.

**Spec:** Issue #90 and `docs/superpowers/specs/2026-10-10-sumatrafuzz-v1-local-remote-desktop-design.md`.

## Global Constraints

- Windows x64, nonadministrator execution for untrusted PDFs.
- SumatraPDF `3.6.1rel`, commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.
- Require pinned tool hashes and genuine WinAFL/DynamoRIO evidence; no fabricated counters or CI bypass.
- Preserve one durable active slot, transactional events, verified process teardown, strict quotas, and immutable evidence.
- Keep protected `dev` history; use a PR and do not merge until required checks and review are satisfied.

## Review Focus

- Worker launch must use the same verified files and ordinary DOS paths accepted by the legacy WinAFL chain.
- A process-tree teardown must have a matching native receipt with zero remaining processes before slot release.
- Missing or changed `fuzzer_stats` must fail acceptance; require at least 1,000 actual executions.
- A restart without durable teardown evidence must retain the lease and never relaunch or claim completion.
- Final artifact hashes and event order must be read back from SQLite after finalization.

---

### Task 1: Confirm existing acceptance already on `dev`

**Files:** Review `packages/run-store`, `apps/worker-service`, `packages/worker-core`, `native/worker-supervisor`, and Windows CI. No edits unless the end-to-end test exposes a defect.

- [ ] Record the existing transactional journal, idempotency, quota monitor, Job Object, restart, and evidence-finalization tests and CI evidence.
- [ ] Keep historical checklist items unchecked until their current exact-commit evidence is linked.

### Task 2: Add the genuine worker-native acceptance gate

**Files:**
- Create: `scripts/windows/worker-native-acceptance.ts`
- Create: `test/worker-native-acceptance.check.cjs`
- Modify: `.github/workflows/repository-checks.yml`
- Modify: `scripts/windows/verify-native-gate.ps1`

- [ ] Add static workflow-contract assertions that the native gate builds and invokes the production worker path as a standard user.
- [ ] Run the test first and confirm it fails because the workflow does not yet invoke the integrated worker acceptance.
- [ ] Prepare a unique controller/bundle, verified policy, SQLite store, evidence repository, production coordinator and native Windows supervisor from the real A4/toolchain evidence.
- [ ] Start the actual WinAFL process through `WorkerRunCoordinator`; observe real `fuzzer_stats` until `execs_done >= 1000`, then stop through the coordinator.
- [ ] Require a zero-process native teardown receipt, terminal durable state, ordered teardown/finalization events, a hash-verified final manifest, and released slot. Fail closed on timeout, missing stats, altered evidence or any unverified tool.
- [ ] Integrate this check into the nonadministrator Windows A4–A6 job and build the native addon there; raise only the step timeout needed for this genuine bounded run.
- [ ] Run the static regression test and the exact Windows CI job; retain raw, non-sensitive counters and verification logs as artifacts.

### Task 3: Resolve defects exposed by the actual worker path

**Files:** Only the affected production implementation and its focused tests.

- [ ] If the integrated run fails, identify the exact boundary from the real logs; add a failing regression, then make the smallest fix without relaxing verification, resource limits, or timing bounds.
- [ ] Re-run the focused regression and full TypeScript/Rust/native CI.

### Task 4: Record and close issue #90

**Files:** GitHub issue #90 and its implementing PR.

- [ ] Obtain independent review; merge the reviewed PR only after exact-current-commit checks pass.
- [ ] Update the issue checklist with links to the merged commit, review, Linux/Windows Rust checks, standard-user native-worker evidence, quota/recovery/finalization tests, and CI run.
- [ ] Close #90 only after every current and inherited acceptance item is backed by merged evidence; otherwise keep it open with the precise remaining blocker.
