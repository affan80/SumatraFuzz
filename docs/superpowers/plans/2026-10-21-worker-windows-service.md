# Windows Worker Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install and operate the authenticated TypeScript worker as a protected Windows x64 service and prove the real native fuzzing path through that service.

**Architecture:** Extend the existing `native/worker-supervisor` boundary with a small SCM host that launches only the fixed Node worker entrypoint, reports status, and mediates bounded shutdown. PowerShell performs one-time elevated provisioning of the service SID, ACLs, NTFS quota and firewall; worker policy and campaigns remain in TypeScript.

**Tech Stack:** C++17/Windows SCM/Job Objects, Node 24.22.0 and TypeScript 7, PowerShell, existing Windows CI, SQLite, WinAFL/DynamoRIO/SumatraPDF pinned toolchain.

**Spec:** `docs/superpowers/specs/2026-10-21-worker-trust-design.md`, sections 1, 2, and 6.

## Global Constraints

- Target Windows x64 only; execute untrusted PDFs and the worker under a dedicated nonadministrator `NT SERVICE\SumatraFuzzWorker` identity.
- The native SCM host only handles SCM controls, fixed-process launch, readiness/shutdown IPC, and outer process containment; worker policy stays TypeScript.
- Never bind wildcard or public addresses; remote mode requires an explicitly configured private/VPN adapter, address, peer CIDRs, and scoped firewall rule.
- Protect executable/configuration/signing public-key paths from ordinary users; service writes only designated data, trust, journal, and evidence paths.
- Preserve truthful SQLite recovery and teardown receipts; forced termination never claims successful completion.
- Keep all real WinAFL/DynamoRIO/SumatraPDF integrity checks and existing CI gates; no bypass or third-party service-wrapper binary.

## Review Focus

- Service startup fails closed when identity, ACL, adapter, firewall, volume quota, credential decryption, or certificate policy is invalid; cover in Windows PowerShell/service tests.
- Ordinary users cannot replace executable, config, trust root, or credentials; prove access-denied under an unprivileged account.
- Desktop/controller disconnect leaves the service and bounded campaign intact; test installed service, not only mocks.
- Stop/restart drains and reconciles runs without fabricating completion or releasing an ambiguous lease; inspect durable journal receipts.
- The genuine native acceptance reaches required execution count through installed mTLS service and yields sanitized evidence only; test in required Windows CI.

---

### Task 1: SCM host process and control lifecycle

**Files:**
- Create: `native/worker-supervisor/src/service_host.cpp`
- Create: `native/worker-supervisor/include/service_host.h`
- Modify: `native/worker-supervisor/CMakeLists.txt`
- Modify: `native/worker-supervisor/binding.gyp` if host build integration is shared
- Create: `native/worker-supervisor/tests/service_host_contract_tests.cpp`
- Create: `apps/worker-service/src/service-entry.ts`

**Interfaces:**
- SCM host accepts no dynamic executable path, script path, or Node option from network input or user-controlled environment. It uses install-time fixed paths, a sanitized environment, and the existing Windows argument encoder.
- Host launches Node worker under the service token, assigns an outer kill-on-close Job Object, exchanges bounded ready/stop messages over inherited local handles, and reports `START_PENDING`, `RUNNING`, `STOP_PENDING`, and final status truthfully.
- TypeScript entrypoint exposes `startWorkerService(): Promise<{ close(): Promise<void> }>` and drains HTTP, finalizes coordinator state, closes journal/trust/audit stores, then acknowledges stop.

- [ ] Add native contract tests for fixed-path launch, environment sanitization, bounded IPC frames, invalid command/control input, status transitions, child exit, and timeout behavior.
- [ ] Run `npm run native:supervisor:contract`; verify new SCM tests fail because only the addon exists today.
- [ ] Implement SCM dispatch and child process control without interpreting campaigns or network requests in C++.
- [ ] Verify normal stop waits for TypeScript teardown and forced timeout kills the outer tree without fabricating a teardown receipt; run CMake/CTest and Windows addon tests.

### Task 2: Protected Windows provisioning and removal

**Files:**
- Create: `scripts/windows/install-worker-service.ps1`
- Create: `scripts/windows/uninstall-worker-service.ps1`
- Create: `scripts/windows/worker-service-config.psm1`
- Create: `scripts/windows/tests/worker-service-install.Tests.ps1`
- Modify: `scripts/windows/package.json` and root scripts only for named service commands

**Interfaces:**
- Installer requires elevation and exact Windows x64; create service `SumatraFuzzWorker` under `NT SERVICE\SumatraFuzzWorker`, enable service SID, set protected service/executable/config/trust-root ACLs, create designated data directories and enforce the configured dedicated NTFS volume quota.
- Local bind configuration accepts loopback only. Remote configuration requires exact adapter identity, assigned private/VPN address, port, peer CIDRs, firewall profile, and a scoped named rule; reject wildcard, address drift, unsupported profile, or an ineffective firewall policy.
- Uninstaller drains service, removes only named service/firewall resources created by installer, and retains evidence/trust state unless explicit operator data deletion is requested.

- [ ] Write Pester tests for missing elevation, wrong OS/architecture, invalid bind config, adapter/address drift, quota mismatch, firewall failure, idempotent install/rollback, and retention on uninstall.
- [ ] Run `pwsh -File scripts/windows/tests/worker-service-install.Tests.ps1`; confirm failures on missing service provisioning.
- [ ] Implement install/rollback/removal using explicit resource ownership markers; never modify unrelated firewall rules or grant ordinary users write access to code/config/trust.
- [ ] Run Pester under Windows CI and verify ACLs/quota/effective firewall rules using the actual service SID.

### Task 3: Runtime identity, credentials, and graceful lifecycle integration

**Files:**
- Create: `apps/worker-service/src/windows-service-policy.ts`
- Create: `apps/worker-service/test/windows-service-policy.test.ts`
- Modify: `apps/worker-service/src/application.ts`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/src/run-coordinator.ts`
- Modify: `scripts/windows/tests/worker-service-install.Tests.ps1`

**Interfaces:**
- Produce `verifyInstalledServicePolicy(config: ServiceRuntimeConfig): Promise<void>`; verify service SID, fixed roots/ACL ownership, data volume identity and quota, adapter identity/address, and protected credential availability before listening.
- Integrate the Trust plan's `CredentialProtector` before `createWorkerApplication`: read the worker certificate/private-key pair only from the fixed administrator-protected staging path under `NT SERVICE\SumatraFuzzWorker`, verify the staging ACL and certificate/key match, persist only current-user DPAPI ciphertext in the protected service configuration, remove the plaintext staging file before normal listener startup, and fail closed if protection, persistence or removal fails. On startup, unprotect under the same service identity and clear owned buffers on teardown where practical.
- `WorkerApplication.close()` first denies admissions, waits bounded in-flight handlers, performs coordinator teardown/finalization, then closes server and stores; timeout reports failure and leaves journal recovery truthful.
- Adapter/address loss closes API admission/listener while campaigns continue within existing limits; restoring networking requires explicit validated service restart.

- [ ] Add failing lifecycle tests for identity/ACL/quota/address mismatch, staged credential validation/protection/removal before listen, wrong-user/tampered DPAPI data, shutdown with active run, hung handler timeout, and network disconnect/restart.
- [ ] Run `npx vitest run apps/worker-service/test/windows-service-policy.test.ts apps/worker-service/test/run-coordinator.test.ts apps/worker-service/test/server-contract.test.ts`.
- [ ] Integrate the verified policy and stop sequence into the service entrypoint; do not add worker network calls that change campaign state.
- [ ] Run Windows integration tests as the service SID and verify stop/restart recovery preserves run journal state and receipts.

### Task 4: Required installed-service Windows acceptance

**Files:**
- Create: `scripts/windows/worker-service-acceptance.ts`
- Create: `scripts/windows/tests/worker-service-acceptance.Tests.ps1`
- Modify: `native/worker-supervisor/include/service_host.h`
- Modify: `native/worker-supervisor/src/service_host.cpp`
- Modify: `native/worker-supervisor/tests/service_host_contract_tests.cpp`
- Modify: `apps/worker-service/src/service-control.ts`
- Modify: `apps/worker-service/src/service-entry.ts`
- Modify: `apps/worker-service/test/service-control.test.ts`
- Modify: `.github/workflows/electron-typescript.yml`
- Modify: `.github/workflows/repository-checks.yml`
- Modify: `scripts/windows/ci-native-gate.ps1`
- Modify: `docs/security/worker-trust-acceptance.md`

- [x] Add failing workflow-contract tests requiring install/start/revoke/stop/restart/uninstall and the native worker acceptance to use the installed service path.
- [x] Run the static workflow tests; the direct-coordinator acceptance failed the contract and the installed-service route passes it.
- [ ] Add a disposable Windows x64 job where only install/configuration is elevated; assert service, Node worker, and parser descendants run as the service SID.
- [ ] Pair with two controllers; verify wrong user, revoked reused session, cross-controller resource access, loopback/private adapter, scoped firewall, controller disconnect, disk/quota failure, DPAPI failure, and forced stop.
- [ ] While the installed service is running, submit a signed revoke/unpair transaction through the native host's administrator-only local named pipe; verify the pipe rejects remote and nonadministrator callers, bounds frames/timeouts, returns only generic results, and the worker verifies/audits against the same persistent trust store used by the HTTPS listener.
- [ ] Submit a signed controller pairing/rotation bundle through the same pipe and verify the ignored `controllerPrivateKeyPem` never reaches audit/storage; keep worker key/certificate replacement on the protected stopped-service bootstrap path.
- [ ] Verify a revoked controller's already-open keep-alive/TLS connection is denied and destroyed after the durable trust mutation; verify audit-intent failure leaves trust unchanged and mutation/result-audit ambiguity returns failure without leaking transaction data.
- [ ] Retain protected startup staging for initial pairing/credential bootstrap and operations while stopped; verify the provisioner uses the live pipe for an active service and never reports success before worker confirmation.
- [ ] Execute genuine pinned WinAFL/DynamoRIO/SumatraPDF acceptance through the installed mTLS service; require actual execution counts, valid receipts, and hash-verified final artifacts.
- [ ] Upload only bounded sanitized metadata, hashes, identity/token assertions, and receipts; never upload credentials, PDF corpora, raw private logs, or key material.
- [ ] Run the exact Windows workflow and all required checks on its exact source commit; keep issue #91 open until review, merge, and linked Windows evidence exist.

### Task 5: Close issue #91 with merged acceptance evidence

**Files:**
- Update: GitHub issue #91 and its inherited acceptance checklist
- Update: implementing pull request into `dev`

- [ ] Compare each parent and inherited issue acceptance item against merged code, tests, reviewer approval, exact-head CI, and retained Windows artifacts; link direct evidence for every checked item.
- [ ] Obtain explicit approval before merging under `AGENTS.md`; do not use a bot-authored commit or merge that changes the intended GitHub author identity.
- [ ] After the approved merge succeeds, close issue #91 only if all acceptance items and linked Windows service evidence are complete; otherwise leave it open with the specific remaining item and evidence needed.
