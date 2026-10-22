# Persistent Worker Trust and Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist operator-managed controller trust, pairing, rotation, revocation, and integrity-checked security audit state for the Windows worker.

**Architecture:** Add a versioned trust database and repository independent from the campaign journal. Verify signed `.sfpair` bundles again on the worker provisioning path, encrypt worker private credentials with service-identity DPAPI, and resolve trust from durable state on every API request. Audit trust transitions and API authorization decisions before privileged effects.

**Tech Stack:** TypeScript 7 / Node 24.22.0, existing `better-sqlite3`, Windows DPAPI through `native/worker-supervisor`, Node crypto Ed25519/HMAC, Vitest.

**Spec:** `docs/superpowers/specs/2026-10-21-worker-trust-design.md`, sections 3 and 5.

## Global Constraints

- Trust record identity is the verified client certificate SHA-256 fingerprint mapped to exactly one signed controller UUID.
- Verify organization signatures in worker provisioning; never accept identity from renderer input, an HTTP header, or a standalone CLI UUID/fingerprint.
- Private keys never enter SQLite, logs, arguments, renderer IPC, results, or CI artifacts; use Windows current-user DPAPI for service credentials.
- Rotation overlap is bounded and explicit; revocation commits before success and denies every new request on existing connections.
- Keep audit data redacted, bounded by worker disk quota, and fail closed for new privileged operations on integrity failure.
- Do not claim defense against a compromised organization root, Windows kernel, or fully privileged local administrator.

## Review Focus

- Altered, unsigned, expired, wrong-worker, wrong-controller, or fingerprint-mismatched `.sfpair` input never changes trust state; test in `apps/worker-service/test/pairing-provision.test.ts`.
- Duplicate fingerprints, controller UUID collisions, and invalid rotation overlap fail atomically; test in `apps/worker-service/test/trust-store.test.ts`.
- Revoked certificates fail on a reused keep-alive/TLS connection and after service restart; test in `apps/worker-service/test/server-contract.test.ts`.
- Audit-record modification, truncation, sequence rollback, and checkpoint mismatch block privileged changes; test in `apps/worker-service/test/security-audit.test.ts`.
- DPAPI wrong-user, tamper, and staging-file interruption leave no listener or plaintext credential residue; test in Windows service CI.

---

### Task 1: Trust database and repository interface

**Files:**
- Create: `apps/worker-service/src/trust-store.ts`
- Create: `apps/worker-service/src/trust-schema.sql`
- Create: `apps/worker-service/test/trust-store.test.ts`
- Modify: `apps/worker-service/src/index.ts`

**Interfaces:**
- Produce `WorkerTrustRepository` with `resolveFingerprint(fingerprint: string, now: Date): TrustRecord | null`, `listActive(): readonly TrustRecord[]`, and atomic `provision`, `rotate`, `revoke`, and `unpair` methods.
- `TrustRecord` contains fingerprint, controller UUID, permission set, not-before/not-after, active/revoked status, generation, and monotonically increasing revision; no private key fields.
- Enforce unique active fingerprint and bounded trust cardinality (16 controllers, at most two nonrevoked certificate generations/controller).

- [ ] Write tests for first open/migration, atomic transactions, duplicate/collision rejection, expiry, revocation persistence, rotation overlap, rollback on failure, and database integrity.
- [ ] Run `npx vitest run apps/worker-service/test/trust-store.test.ts`; confirm new repository tests fail before schema/repository implementation.
- [ ] Implement schema with strict validation and transaction-safe mutations; keep the campaign database schema and interfaces unchanged.
- [ ] Re-run the focused suite and `npx vitest run packages/run-store/test/sqlite-run-store.test.ts`.

### Task 2: Worker-side signed bundle provisioning and credential protection

**Files:**
- Create: `apps/worker-service/src/pairing-provision.ts`
- Create: `apps/worker-service/test/pairing-provision.test.ts`
- Modify: `apps/worker-service/src/application.ts`
- Modify: `native/worker-supervisor/src/addon.cpp` only if the existing DPAPI surface lacks the required service-identity operation
- Modify: `native/worker-supervisor/tests/command_line_tests.cpp` or a focused native contract test for any new native interface

**Interfaces:**
- Produce `verifyAndProvisionPairingBundle(bundle: Buffer, context: PairingProvisionContext, now?: Date): Promise<TrustRecord>`. The context supplies the protected worker UUID, actual worker certificate/CA, explicit organization public-key set, explicit permission set, and trust repository. These expected values come from protected service configuration, never from the bundle or unauthenticated CLI identity arguments. Keep worker credential protection/import a separate helper using `CredentialProtector`; never persist the controller private key from the signed bundle on the worker.
- Validate signature, bundle format/version/lifetime, worker UUID, controller UUID, worker cert pin, client leaf purpose/strength/validity, and controller cert fingerprint before mutation.
- Produce `CredentialProtector.protect(plaintext: Buffer): Promise<Buffer>` and `unprotect(ciphertext: Buffer): Promise<Buffer>` using Windows current-user DPAPI under the service SID; staging data is ACL-protected and removed before listener startup.

- [ ] Add failure tests for invalid signature, unknown signer, altered payload, expired/future bundle, wrong worker/controller, wrong client fingerprint, wrong purpose/key, and failed DPAPI operation; prove trust remains unchanged. Test reviewed signer-root rotation with an explicit trusted-root set and prove there is no fallback to an unknown root.
- [ ] Run `npx vitest run apps/worker-service/test/pairing-provision.test.ts`; confirm the new provisioning path rejects these cases before implementation.
- [ ] Implement verify-then-commit flow with credentials kept outside SQLite, log output, CLI arguments, and ordinary result files; clear buffers where practical.
- [ ] Run pairing, profile-store, certificate-policy and native DPAPI tests; on Windows verify wrong-user and tampered ciphertext fail closed.

**Service integration handoff:** The verifier and worker-key `CredentialProtector` are implemented in this plan's Task 2. The task does not create a listener or claim staged-key handling complete. The Windows-service plan must read the worker credential from the protected staging path under the service identity, verify ACL/identity and key-certificate match, DPAPI-protect it, persist only ciphertext in the protected service configuration, remove the plaintext staging file before listener startup, and fail startup on read/protection/cleanup failure. Windows acceptance must prove wrong-user and tampered ciphertext fail closed.

### Task 3: Per-request trust resolution, rotation and revocation

**Files:**
- Modify: `apps/worker-service/src/auth.ts`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/src/application.ts`
- Modify: `apps/worker-service/test/auth.test.ts`
- Modify: `apps/worker-service/test/server-contract.test.ts`

**Interfaces:**
- Replace startup map as the authorization authority with `WorkerTrustRepository.resolveFingerprint`; retain the TLS-authenticated peer fingerprint as the lookup key.
- Trust updates publish a bounded revision notification; immediately close sockets authenticated as a revoked fingerprint and require every new request to re-resolve the record.
- An in-progress bounded handler may finish after authorization; revocation prevents all subsequent requests and releases its socket/admission state.

- [ ] Add real TLS tests that pair, serve a request, revoke, and attempt another request on the same keep-alive socket; add rotation-overlap and restart cases.
- [ ] Run `npx vitest run apps/worker-service/test/auth.test.ts apps/worker-service/test/server-contract.test.ts` and observe the reused-connection tests fail against startup snapshots.
- [ ] Implement live trust resolution and socket tracking/revocation without a network enrollment endpoint or identity-header fallback.
- [ ] Re-run the focused suite plus `npx vitest run apps/worker-service/test/run-coordinator.test.ts`; assert cross-controller run ownership remains unchanged.

### Task 4: Durable redacted security audit

**Files:**
- Create: `apps/worker-service/src/security-audit.ts`
- Create: `apps/worker-service/test/security-audit.test.ts`
- Modify: `apps/worker-service/src/trust-store.ts`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/src/application.ts`

**Interfaces:**
- Produce `SecurityAudit.append(record: AuditRecord): Promise<number>` and `verifyAndRecover(): Promise<AuditHealth>`; records include UTC timestamp, principal fingerprint/controller UUID when authenticated, request ID, action/resource identifiers, decision, safe error code, trust revision, and optional payload digest.
- Chain records with HMAC-SHA-256 using a DPAPI-protected key outside SQLite; atomically checkpoint last durable sequence/hash; rotate bounded sealed segments with continuity metadata.
- No raw request bodies, PDFs, private keys/certificate bodies, stack traces, or absolute host paths.

- [ ] Write tests for append/verify, altered record, missing prefix, stale checkpoint, truncated tail, checkpoint atomic-replace failure, quota exhaustion, retention-segment continuity, and redaction of secrets/paths.
- [ ] Run `npx vitest run apps/worker-service/test/security-audit.test.ts`; verify tamper and rollback tests fail before implementation.
- [ ] Implement chained integrity and recovery rules; record privileged-operation intent before its effect and its observed result afterward. Deny new privileged operations when audit health is degraded while preserving truthful state for an already running campaign.
- [ ] Re-run audit/trust/server suites and verify no test fixture secrets or private keys are written to artifacts.

### Task 5: Trust lifecycle and audit CI gate

**Files:**
- Modify: `.github/workflows/electron-typescript.yml`
- Modify: `apps/worker-service/test/*` only for focused trust/security fixtures
- Modify: `docs/security/worker-trust-acceptance.md`

- [ ] Make trust, pairing, live revocation, and audit-integrity tests required in Linux and Windows TypeScript CI; keep platform-specific DPAPI tests Windows-only.
- [ ] Run the focused CI test command and verify the workflow executes the same suites without skips or `continue-on-error`.
- [ ] Run `npm run verify` and the exact Windows job; record exact test evidence and remaining Windows-service-dependent checks.
