# Strict Per-Run AppContainer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace broad restricted-token access with a per-run Windows AppContainer that allows only verified tool reads, selected input reads, and bounded run-local writes while preserving private WinAFL IPC.

**Architecture:** The native supervisor creates a unique AppContainer profile and package SID per run, grants the SID only the required resource access, and starts the verified fuzzer suspended with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` before attaching it to the existing Job Object. The profile, ACL grants, private namespace, and process tree share the job lifecycle and are cleaned up only after the job drains. Windows CI must prove service-account compatibility, profile storage bounds, IPC, negative writes, and the real native parser path before issue #91 can close.

**Tech Stack:** C++17 Win32 (`userenv`, `advapi32`), Node-API addon, PowerShell 7 Windows CI, Node.js tests, pinned WinAFL/DynamoRIO/SumatraPDF.

**Spec:** `docs/superpowers/specs/2026-10-24-worker-strict-appcontainer-design.md`

## Global Constraints

- Target Windows x64 only for the worker service milestone.
- Do not include `World`, `Authenticated Users`, `Interactive`, or `BUILTIN\\Users` as grants for child writes.
- Use no AppContainer network capabilities.
- Keep the existing Job Object CPU/memory limits, kill-on-close behavior, verified executable proofs, and one-active-campaign policy.
- Only the selected run may write its evidence/scratch area; selected inputs remain read-only.
- Fail closed on profile, ACL, namespace, token, job, or cleanup failures; do not widen permissions to force a pass.
- Keep static Linux checks, but require exact-head Windows x64 runtime and installed-service evidence for acceptance.
- Preserve the unrelated campaign-insights working tree changes; stage only issue #91 files.
- Do not merge the PR or close issue #91 without exact-head CI, installed-service evidence, and human review.

## Review Focus

- Service identity cannot create or delete an AppContainer profile: the native launch must fail safely and CI must exercise the actual virtual service account.
- AppContainer temporary storage can escape the worker disk quota: prove all writable profile paths are quota-backed and cleaned, or block release.
- A child can write a World/AuthUsers-writable file outside evidence: Windows runtime probes must test both medium- and low-integrity sentinels.
- WinAFL/DynamoRIO named mappings, events, or pipe fail under the package identity: exercise real shim creation/open paths and sibling-run denial.
- Profile deletion fails while child handles remain or after partial startup: test stop, timeout, launch failure, and service restart cleanup.

---

### Task 1: Prove service-account AppContainer and quota behavior

**Files:**
- Create: `scripts/windows/tests/appcontainer-probe.ps1`
- Modify: `scripts/windows/ci-supervisor-check.ps1`
- Modify: `native/worker-supervisor/tests/process_probe.cpp`
- Modify: `native/worker-supervisor/CMakeLists.txt`
- Test: `test/supervisor-windows.check.cjs`
- Test: `.github/workflows/electron-typescript.yml`

**Interfaces:**
- Consumes: the standard-user fixture and Windows x64 job from `ci-supervisor-check.ps1`.
- Produces: a Windows-only API probe for profile creation, unique package SID, no-capability launch, and cleanup under an ordinary nonadministrator identity. It is an API feasibility check, not service-identity acceptance; the installed-service test under `NT SERVICE\\SumatraFuzzWorker` is required in Task 5.

- [ ] **Step 1: Add a Windows probe test** for AppContainer profile creation under an ordinary nonadministrator identity, no network capabilities, unique package SID, isolated write to a per-run directory, denied writes to World-writable and Authenticated-Users-writable medium/low sentinels, and successful profile deletion.
- [ ] **Step 2: Run the probe on the hosted Windows x64 runner** and measure profile/temp paths. Treat this as API feasibility only; Task 5 must repeat the storage and service-identity checks through the installed service.
- [ ] **Step 3: Add exact-head CI invocation** after native supervisor build and before installed-service acceptance; do not proceed to product code if profile scratch cannot be bounded or cleaned.
- [ ] **Step 4: Run static Windows workflow checks** with `node --test test/supervisor-windows.check.cjs` and verify the probe is Windows-gated.

### Task 2: Add RAII AppContainer identity and per-run ACL grants

**Files:**
- Modify: `native/worker-supervisor/src/addon.cpp`
- Modify: `native/worker-supervisor/binding.gyp`
- Test: `test/supervisor-windows.check.cjs`
- Test: `native/worker-supervisor/tests/process_probe.cpp`

**Interfaces:**
- Consumes: the result of Task 1 and existing `VerifyProofs`, `AddRestrictedSidAccess`, `PrivateNamespace`, and `Job` lifecycle.
- Produces: move-only `AppContainerProfile { std::wstring name; PSID sid; }`, `CreateRunAppContainerProfile()`, `GrantRunResourceAccess(path, sid, access)`, and deterministic cleanup after process-tree drain.

- [ ] **Step 1: Add a failing contract test** proving the token setup contains only the package identity and no broad write SIDs, and that temporary ACL changes are removed after stop and partial launch.
- [ ] **Step 2: Implement profile RAII** using `CreateAppContainerProfile`/`DeleteAppContainerProfile`; use a random bounded name, zero capabilities, handle `ERROR_ALREADY_EXISTS` only by failing closed, and preserve safe error codes.
- [ ] **Step 3: Implement per-object ACL grant/removal** for verified tool files (`RX`), selected inputs (read plus directory traversal, no execute), and run evidence/scratch (`Modify`); reject reparse points and do not touch trust, audit, credential, or sibling-run paths.
- [ ] **Step 4: Run native contract tests** with `npm run native:supervisor:contract` and `node --test test/supervisor-windows.check.cjs`; verify static tests reject broad child write grants.

### Task 3: Launch the fuzz process as a suspended AppContainer child

**Files:**
- Modify: `native/worker-supervisor/src/addon.cpp`
- Modify: `native/worker-supervisor/binding.gyp`
- Test: `native/worker-supervisor/tests/process_probe.cpp`
- Test: `test/supervisor-windows.check.cjs`

**Interfaces:**
- Consumes: `AppContainerProfile` and ACL grants from Task 2.
- Produces: `CreateProcessInRunAppContainer(profile, executable, command, environment, working_dir)` that returns a suspended process handle or a safe error; Job Object assignment still occurs before resume.

- [ ] **Step 1: Add a failing Windows integration case** that launches the probe in a no-capability AppContainer, verifies package identity and no network access, writes evidence, and cannot read protected trust data or modify any external sentinel.
- [ ] **Step 2: Implement `STARTUPINFOEXW` security capabilities** with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; initialize/delete the attribute list on every path and retain `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW`.
- [ ] **Step 3: Preserve Job Object ordering**: create suspended, assign to the bounded kill-on-close job, resume only after successful assignment, and drain the job before removing ACLs/profile.
- [ ] **Step 4: Run the Windows supervisor acceptance probe** and confirm evidence writes pass, external writes/secret reads fail, and partial launch cleanup removes the profile and ACL grants.

### Task 4: Bind run-private WinAFL IPC to the AppContainer SID

**Files:**
- Modify: `native/worker-supervisor/src/addon.cpp`
- Modify: `native/worker-supervisor/tests/process_probe.cpp`
- Modify: `scripts/windows/patches/winafl-private-namespace.patch`
- Modify: `scripts/windows/provision-winafl.ps1`
- Test: `test/supervisor-windows.check.cjs`

**Interfaces:**
- Consumes: the per-run AppContainer package SID from Task 2.
- Produces: a private namespace boundary containing the worker SID and package SID; DACLs grant only the worker and that package SID; WinAFL's known mappings/events continue to use the verified alias and per-run identity.

- [ ] **Step 1: Add failing Windows tests** for child and descendant event/mapping access, denial from a sibling AppContainer, denial from the ordinary user, and namespace removal after the job drains.
- [ ] **Step 2: Update namespace boundary/DACL construction** to use the package SID instead of broad restricted SIDs; use exact object-specific rights and keep low mandatory labels only where needed.
- [ ] **Step 3: Update the pinned WinAFL shim and digest lock** so create/open names match the AppContainer-private namespace; preserve the locked upstream commit and do not add null/permissive DACLs.
- [ ] **Step 4: Run the Windows namespace integration and patch digest checks** and verify the sibling run cannot open the first run’s objects.

### Task 5: Prove bounded storage and genuine parser compatibility

**Files:**
- Modify: `scripts/windows/worker-service-acceptance.ps1`
- Modify: `scripts/windows/ci-supervisor-check.ps1`
- Modify: `.github/workflows/electron-typescript.yml`
- Modify: `.github/workflows/repository-checks.yml`
- Test: `scripts/windows/tests/worker-service-install.Tests.ps1`
- Test: `test/supervisor-windows.check.cjs`

**Interfaces:**
- Consumes: per-run profile lifecycle, ACLs, and namespace from Tasks 2–4.
- Produces: acceptance evidence for AppContainer writes, profile disk usage, cleanup, quota enforcement, installed service launch, and a real pinned WinAFL/DynamoRIO/SumatraPDF campaign.

- [ ] **Step 1: Add a failing quota test** that fills profile/scratch storage to the configured worker disk cap and verifies the run stops without exceeding the cap or writing to the system volume.
- [ ] **Step 2: Extend installed-service acceptance** to launch the actual campaign under `NT SERVICE\\SumatraFuzzWorker`, verify AppContainer identity and no network capability, and verify teardown removes profile and temporary ACLs.
- [ ] **Step 3: Run exact-head hosted Windows x64 CI** with the native parser/coverage gate and installer policy; preserve raw evidence only as workflow artifacts and log sanitized summaries.
- [ ] **Step 4: Run the full repository verification** including `npm test`, native contract checks, Windows Pester tests, and `git diff --check`.

### Task 6: Update issue acceptance and security documentation

**Files:**
- Modify: `docs/security/worker-trust-acceptance.md`
- Modify: `docs/superpowers/specs/2026-10-21-worker-trust-design.md`
- Modify: `docs/superpowers/specs/2026-10-23-private-object-namespace-design.md`
- Modify: `test/supervisor-windows.check.cjs`

**Interfaces:**
- Consumes: observed Windows results from Tasks 1–5.
- Produces: accurate issue #91 security boundary, failure behavior, limitations, and linked exact-head Windows acceptance evidence.

- [ ] **Step 1: Add a failing documentation contract check** that rejects claims of `World`/`Authenticated Users` as child restricting SIDs and requires AppContainer/no-network/quota facts.
- [ ] **Step 2: Replace the restricted-token workaround narrative** with only behaviors proven by Windows CI; record any unsupported profile/IPC behavior as an open acceptance blocker.
- [ ] **Step 3: Run documentation/static security checks** and confirm issue #91 stays open until human review, exact-head CI, and installed-service acceptance are linked.

