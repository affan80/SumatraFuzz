# Private WinAFL IPC and installed-service acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (approved execution method) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep restricted WinAFL/DynamoRIO runs working through run-scoped Windows IPC and prove trust/service behavior through the installed Windows service in CI.

**Architecture:** The native supervisor creates one per-run private namespace, retains its handle with the Job Object, and passes a random alias plus the run restricting SID in the sanitized environment. A small patch to the exactly pinned WinAFL source opens that namespace, prefixes only the known WinAFL mapping names, applies private mapping and pipe ACLs, and passes the namespace parameters explicitly to the DynamoRIO client. Windows acceptance then runs the genuine pinned campaign through a disposable installed SCM service and stores only bounded sanitized results.

**Tech Stack:** C++17, Node-API, Windows private namespace/ACL/Job Object APIs, pinned WinAFL C source, DynamoRIO 11.91.20735, Node 24/TypeScript, PowerShell 7, GitHub Actions `windows-2022`.

**Spec:** `docs/superpowers/specs/2026-10-23-private-object-namespace-design.md`; issue-wide service/trust requirements in `docs/superpowers/specs/2026-10-21-worker-trust-design.md` and `docs/superpowers/plans/2026-10-21-worker-windows-service.md`.

## Global Constraints

- Windows x64 is the only supported service target for this milestone.
- WinAFL source must match commit `fd85f38548b14352f4b70ad414f364ea6dc1a769`; DynamoRIO is locked to 11.91.20735; SumatraPDF is locked to commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.
- The supervisor creates the namespace using the worker token's user SID in the boundary descriptor and a protected DACL with the worker user SID and current run SID.
- The supervisor retains the namespace handle until the complete Job Object is empty; every failed launch path closes handles and terminates any started child.
- Pass `SUMATRAFUZZ_NAMESPACE_ALIAS` and `SUMATRAFUZZ_RUN_SID` only in the sanitized environment; pass the same non-secret identifiers as explicit DynamoRIO client options and verify the client options against its environment and restricted token.
- Grant no namespace, mapping, pipe, or test-event access to World, Authenticated Users, or `BUILTIN\Users`.
- The WinAFL named-pipe client requires `GENERIC_READ | GENERIC_WRITE`; retain only those needed rights in its protected pipe DACL.
- No security bypass, skipped native gate, broad API detour, test secret upload, raw PDF/corpus upload, bot-authored commit, or unreviewed binary/tool commit.
- Keep issue #91 open until all applicable tests, exact-head Windows CI, installed-service Windows acceptance, human review, approved merge, and linked evidence are complete.

## Review Focus

- **Boundary mismatch:** a restricted token cannot open the worker-boundary namespace, or a sibling run can. Test actual create/open operations under two distinct run tokens on Windows `windows-2022`; stop and revise the boundary design if it fails.
- **Missing or forged launch identifiers:** missing, malformed, or mismatched alias/SID must fail before WinAFL IPC and never fall back to session-global names. Test environment and client-option mismatch plus token membership.
- **Partial launch cleanup:** namespace creation, process creation, Job Object assignment, and resume failures must release the namespace and child handles in the right order. Inject each failure and assert the job is empty and retry can create a fresh alias.
- **ACL access-check differences:** mappings, events, and the named pipe must work for the intended restricted child while a different run and standard user are denied. Exercise real Windows access checks, not only ACL string/source assertions.
- **Installed-service exposure:** a service restart, controller disconnect, or network-binding loss must not leave a public listener, stale lease, permissive IPC object, secret staging file, or surviving parser process. Exercise the installed SCM path with positive and negative requests.

---

### Task 1: Supervisor-owned private namespace and lifecycle

**Files:**
- Modify: `native/worker-supervisor/src/addon.cpp`
- Modify: `native/worker-supervisor/tests/process_probe.cpp`
- Modify: `test/supervisor-windows.check.cjs`
- Modify: `native/worker-supervisor/CMakeLists.txt` only if Windows namespace/ACL libraries need explicit linking

**Interfaces:**
- `BuildWorkerEnvironment(working_dir, tool_dir, namespace_alias, run_sid)` adds exactly the two validated run identifiers to the allowlisted Unicode environment.
- A per-`Job` namespace handle is owned by the native Job record and closed only after Job Object teardown.
- Namespace creation consumes the existing `RestrictedToken` run SID and the caller token's `TokenUser`; it returns a fresh alias and owned namespace handle or fails closed.

- [ ] **Step 1: Add Windows integration assertions before implementation.** Extend the existing supervisor probe to create and signal `alias\<unique-event>`, verify a child and grandchild can open it, verify another independently launched run cannot open it, and retain the protected sentinel denial assertions. Add assertions that missing/malformed environment identifiers fail without a fallback name.
- [ ] **Step 2: Run `node --test test/supervisor-windows.check.cjs` and the `windows-2022` supervisor check.** Expected before implementation: the Windows test fails because the child cannot enter/create the private namespace; portable source contracts remain green.
- [ ] **Step 3: Add a move-only native private-namespace owner.** In `addon.cpp`, create the boundary descriptor from the current worker `TokenUser` SID; build a protected DACL granting that SID and the current `RestrictedToken.sid`; create a unique namespace alias with `CreatePrivateNamespaceW`; reject collision or any ACL/API failure. Ensure every temporary SID, ACL, descriptor, and handle has RAII cleanup.
- [ ] **Step 4: Bind namespace lifetime to launch and stop.** Add the namespace handle and alias to `Job`; create them after the restricting SID exists and before process creation; serialize the run SID with `ConvertSidToStringSidW`; pass alias and SID to `BuildWorkerEnvironment`; transfer namespace ownership into the job only after process assignment succeeds. On every failure path terminate/wait for any created process, close the Job Object, and then close the namespace. On normal stop, close the namespace after the full job reports zero active processes.
- [ ] **Step 5: Verify focused native contracts and Windows runtime tests.** Run `npm run native:supervisor:contract`, `node --test test/supervisor-windows.check.cjs`, and the equivalent Windows `ci-supervisor-check.ps1`; require the same-run event success, sibling-run denial, sentinel denial, and zero process/handle leakage.

### Task 2: Narrow WinAFL IPC compatibility patch and acquisition lock

**Files:**
- Create: `scripts/windows/patches/winafl-private-namespace.patch`
- Modify: `scripts/windows/provision-winafl.ps1`
- Modify: `scripts/windows/verify-toolchain.ps1`
- Modify: `scripts/windows/run-dynamorio-debug.ps1`
- Modify: `scripts/windows/tests/winafl-launch.Tests.ps1`
- Create: `test/winafl-private-namespace.check.cjs`

**Interfaces:**
- The tracked patch applies only to WinAFL commit `fd85f38548b14352f4b70ad414f364ea6dc1a769`; provisioning uses `git apply --check` before applying it and records the patch SHA-256 in `target-lock.json`.
- Shared helper code in the patch validates the environment alias/SID, confirms the run SID is in `TokenRestrictedSids`, derives the boundary `TokenUser` SID, and opens the existing namespace; namespace names use `alias\object`.
- Both `afl-fuzz.c` mapping creation sites use protected worker/run DACLs and prefixed names. The `winafl.c` client opens the same prefixed coverage mapping and receives alias/SID as explicit client options; it rejects disagreement with inherited environment/token values.
- The `CreateNamedPipe` null DACL is replaced with a protected worker/run DACL; retain the client's existing `GENERIC_READ | GENERIC_WRITE` request.

- [ ] **Step 1: Add failing source and Pester contracts.** In `test/winafl-private-namespace.check.cjs` and the Pester suite, assert both mapping names (`afl_shm_*`, `sample_afl_shm_*`) are prefixed on create, the coverage mapping is prefixed on open, alias/SID are forwarded to the DynamoRIO client, and the pipe no longer uses a null DACL. Assert the acquisition lock records both upstream WinAFL commit and patch digest.
- [ ] **Step 2: Run the focused contracts before patching.** Run `node --test test/winafl-private-namespace.check.cjs` and `Invoke-Pester scripts/windows/tests/winafl-launch.Tests.ps1`; require the new source/lock assertions to fail against unmodified pinned WinAFL.
- [ ] **Step 3: Implement the minimal pinned-source patch.** Use private namespace names only for the WinAFL mappings; construct explicit mapping DACLs; pass and cross-check run identifiers for the injected client; set the named-pipe DACL to the exact worker/run principals and required client rights. Do not detour arbitrary APIs or change campaign semantics.
- [ ] **Step 4: Make acquisition reproducible.** Apply the reviewed patch only after verifying the exact source commit; record `winafl_patch_sha256` with upstream acquisition metadata; reject a missing, altered, already-applied, or source-drifted patch. Update toolchain verification to require the patch digest while continuing to hash built x64 artifacts.
- [ ] **Step 5: Run Pester and source contracts.** Require the pinned checkout to patch/build, the lock to include the exact upstream commit and digest, and all compatibility source contracts to pass.

### Task 3: Installed-service native acceptance and CI gate

**Files:**
- Create: `scripts/windows/worker-service-acceptance.ts`
- Create: `test/worker-service-acceptance.check.cjs`
- Modify: `.github/workflows/repository-checks.yml`
- Modify: `scripts/windows/worker-native-acceptance.ts` only if shared sanitized result types/helpers are needed
- Modify: `docs/security/worker-trust-acceptance.md`
- Modify: `docs/superpowers/plans/2026-10-21-worker-windows-service.md`

**Interfaces:**
- The installed-service acceptance script consumes the verified packaged worker, native supervisor, pinned tool lock, genuine A4/A5 inputs, and ephemeral test trust material created at runtime.
- CI acceptance has separate elevated setup/teardown and nonadministrator service execution phases; the SCM host, TypeScript worker, WinAFL, DynamoRIO, and parser all run as the configured service identity or its restricted Job Object descendants.
- Output is a bounded, schema-validated JSON receipt with exact source SHA, service identity/token assertions, listener binding, authorization outcomes, measured WinAFL executions, coverage/evidence hashes, and teardown status; omit private keys, raw certificates, PDF bytes/corpus, and sensitive paths.

- [ ] **Step 1: Add a failing workflow/script contract.** Assert CI installs and starts the staged SCM service, runs the acceptance client against the authenticated service endpoint, checks two-controller authorization and trust revocation, and invokes genuine WinAFL/DynamoRIO/SumatraPDF through that service. Assert only the sanitized receipt is uploaded.
- [ ] **Step 2: Run `node --test test/worker-service-acceptance.check.cjs` and show the workflow check fails before adding the service job.** Keep the existing direct-coordinator acceptance as a separate lower-level regression test; it cannot satisfy this installed-service check.
- [ ] **Step 3: Implement the installed-service acceptance driver.** Provision ephemeral private test keys and signed pairing data inside the disposable Windows runner; install/configure through the production PowerShell scripts; run service operations as a standard user. Exercise TLS 1.3 and invalid/expired/revoked/mismatched peer certificates; certificate rotation and revocation on an already-reused connection; spoofed identity headers; the two-controller authorization matrix for start, active-run recovery, status, stop, event replay, manifest, artifact metadata, and artifact bytes; and default-deny unknown routes. Exercise candidate admission limits, slow/flood/body/header bounds, replay/download budgets, safe errors and redacted audit behavior; record Windows measurements and leave a threshold provisional unless measured and explicitly approved. Verify audit tamper/crash/quota recovery, service-SID ACLs, DPAPI wrong-user/tamper rejection, staging cleanup, explicit loopback/private-adapter binding, firewall refusal, controller/network disconnect, quota failure, forced service stop, restart and clean uninstall. Start the genuine pinned campaign through the authenticated service and require measured execution count, nonzero parser coverage, valid teardown receipt, and hash-verified artifact finalization.
- [ ] **Step 4: Add bounded CI cleanup and artifacts.** Ensure teardown always stops the complete Job Object, revokes/unpairs temporary identities, uninstalls the service, and removes ephemeral trust material. Upload only the sanitized receipt, toolchain digest, and existing permitted native counters. Fail if cleanup or any security assertion fails.
- [ ] **Step 5: Run full validation.** Run `npm run verify`, `npm run native:supervisor:contract`, focused Pester and source contracts, then require the complete exact-head `windows-2022` workflows to pass without skipped native acceptance. Run the production package/service acceptance command on the user's Windows x64 host after CI; record its sanitized result and hash without uploading secrets or corpora.
- [ ] **Step 6: Audit issue #91 item by item.** Link exact-head checks and retained Windows acceptance receipts for every issue/inherited requirement; run the approved security diff review; update PR #119 from draft only after the evidence is complete. Keep the issue open until human review and merge approval are obtained, merge only after explicit approval, and close #91 only after merged evidence is present.

