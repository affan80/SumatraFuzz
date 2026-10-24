# Worker API Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce TLS 1.3, strict certificate and route policy, bounded request admission, and safe API failures in the TypeScript worker.

**Architecture:** Keep HTTP and authorization in `apps/worker-service`. Add small certificate-policy, route-policy, and admission modules with explicit interfaces; keep the current pairing source behind a resolver that the persistent trust plan can replace. Authorization and limits run before expensive handlers.

**Tech Stack:** Node 24.22.0 HTTPS/TLS, TypeScript 7, Vitest, existing worker protocol and SQLite ownership checks.

**Spec:** `docs/superpowers/specs/2026-10-21-worker-trust-design.md`, sections 2 and 4.

## Global Constraints

- Require TLS 1.3; do not add a TLS 1.2 exception.
- Bind only loopback or an explicitly selected private/VPN IP; never fall back to wildcard binding.
- Keep worker/controller identity derived from the verified certificate fingerprint and current trust record.
- Keep the existing 32 MiB archive body ceiling, 64 MiB expanded-input cap, exclusive import gate, and aggregate disk ceiling.
- Treat rate, header, connection, request, transfer, and replay thresholds as provisional until Windows x64 benchmarks and adversarial tests justify release values.
- Add no third-party runtime dependency; preserve the real Windows native acceptance gates.

## Review Focus

- Client certificates with wrong EKU, CA constraints, weak keys, invalid dates, or an untrusted issuer fail before any handler runs; test in `apps/worker-service/test/certificate-policy.test.ts`.
- Identity headers and request JSON cannot change the principal; test every mutating route in `apps/worker-service/test/server-contract.test.ts`.
- A second controller cannot read, stop, replay, enumerate, or download another controller's run/artifact; test with two real TLS identities.
- Slow headers, oversized targets/bodies, connection floods, and aborted uploads release all counters and buffers; test in `apps/worker-service/test/admission.test.ts`.
- Unknown and cross-controller resources have identical safe not-found responses with no path, stack, body, or certificate material; test in `apps/worker-service/test/server-contract.test.ts`.

---

### Task 1: Explicit endpoint certificate policy

**Files:**
- Create: `packages/worker-security/package.json`
- Create: `packages/worker-security/tsconfig.json`
- Create: `packages/worker-security/src/index.ts`
- Create: `packages/worker-security/src/certificate-policy.ts`
- Create: `packages/worker-security/test/certificate-policy.test.ts`
- Modify: `package-lock.json`
- Modify: `packages/worker-client/package.json`
- Modify: `apps/worker-service/package.json`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `packages/worker-client/src/client.ts`
- Modify: `apps/worker-service/test/server-contract.test.ts`
- Modify: `packages/worker-client/test/client.test.ts`

**Interfaces:**
- Produce Node-only internal package `@sumatrafuzz/worker-security` with `validateEndpointCertificate(pem: Buffer | string, purpose: 'client' | 'server', now?: Date): X509Certificate`; reject CA leaves, absent/mismatched EKU or key usage, expired/not-yet-valid certificates, RSA below 2048 bits, and unsupported key types; accept RSA >=2048 and ECDSA P-256/P-384.
- Export `TLS_MIN_VERSION = 'TLSv1.3'` from the same package. Do not import Node crypto into browser-facing `worker-protocol`.
- Worker validates its configured server certificate before listen and the authenticated client peer leaf before handler dispatch. The desktop client retains Node's standard hostname/chain validation, invokes explicit leaf validation in `checkServerIdentity`, then checks the signed SHA-256 pin.

- [ ] Write failing fixtures for valid client/server certificates and wrong EKU, CA-as-leaf, weak RSA, expired, and wrong-anchor certificates. Include the observed regression: a trusted and pinned `CA:TRUE` server certificate must fail client verification.
- [ ] Run `npx vitest run packages/worker-security/test/certificate-policy.test.ts apps/worker-service/test/server-contract.test.ts packages/worker-client/test/client.test.ts`; confirm the new policy tests fail for missing explicit validation.
- [ ] Implement the Node-only internal certificate-policy package, add only the internal workspace dependencies, configure both endpoints to TLS 1.3, and retain chain and hostname verification plus the worker SHA-256 pin.
- [ ] Re-run the focused tests; assert invalid client certificates never reach API handlers, invalid worker certificates fail the client handshake, and TLS 1.2 handshakes fail.

### Task 2: Deny-default route authorization and safe errors

**Files:**
- Create: `apps/worker-service/src/route-policy.ts`
- Create: `apps/worker-service/test/route-policy.test.ts`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/test/server-contract.test.ts`
- Modify: `packages/worker-client/src/client.ts`

**Interfaces:**
- Produce `authorizeRoute(principal: AuthenticatedPrincipal, method: string, pathname: string): RouteDecision`; match exact supported methods and paths, deny every unmatched route, and identify resource scope without accepting identity headers.
- Preserve `SqliteRunStore.ownsRun` before every run/event/manifest/artifact/stop handler and the coordinator's second ownership check.
- Produce stable safe error codes and generated correlation IDs; do not return internal exception text.

- [ ] Add failing two-controller tests for capabilities, active-run, bundle import, start, run status, stop, events, manifest, artifact metadata, and artifact bytes; include spoofed identity headers and unknown routes.
- [ ] Confirm tests fail if the handler spy is called before identity/ownership authorization.
- [ ] Implement the exact route matrix and safe 404/error response contract; validate expected content types and reject ambiguous request framing before consuming bodies.
- [ ] Run `npx vitest run apps/worker-service/test/route-policy.test.ts apps/worker-service/test/server-contract.test.ts apps/worker-service/test/run-coordinator.test.ts` and verify unknown/cross-controller responses are indistinguishable.

### Task 3: Bounded API admission and cleanup

**Files:**
- Create: `apps/worker-service/src/admission.ts`
- Create: `apps/worker-service/test/admission.test.ts`
- Modify: `apps/worker-service/src/server.ts`
- Modify: `apps/worker-service/test/server-contract.test.ts`

**Interfaces:**
- Produce `createAdmissionController(policy: AdmissionPolicy)` with bounded socket, global/per-controller request, per-controller rate, artifact-transfer, and event-replay leases; every lease has idempotent release.
- Initial candidate policy: 64 sockets; 32 active requests globally and 4/controller; 10 requests/second with burst 20/controller; 2 artifact transfers/controller; 1 event replay/controller/run; retain 16 KiB headers, 4 KiB target, existing 15-second header timeout, 30-second ordinary idle and 120-second archive absolute deadline for measurement.

- [ ] Write failing tests for each limit, timer expiration, abort, disconnect, revocation hook, and repeated release; assert capacity returns to baseline in every terminal path.
- [ ] Run the focused admission tests and confirm they fail because the server has only header/request timers and an upload gate today.
- [ ] Implement admission leases before body parsing, extraction, event reads, artifact I/O, or run launch; close/clean up sockets and counters on shutdown.
- [ ] Run `npx vitest run apps/worker-service/test/admission.test.ts apps/worker-service/test/server-contract.test.ts`; record tests as provisional policy validation, not throughput benchmarks.

### Task 4: API CI and benchmark evidence

**Files:**
- Modify: `.github/workflows/electron-typescript.yml`
- Modify: `package.json` only if a dedicated security-test command is needed
- Create: `apps/worker-service/test/admission-benchmark.test.ts` only if the approved policy requires a reproducible benchmark artifact

- [ ] Add a focused API-security test command to required Linux and Windows TypeScript jobs; keep the actual Windows service acceptance in plan 3.
- [ ] Run the new test selection locally and verify the workflow invokes the same paths.
- [ ] Measure candidate thresholds on Windows x64 with valid workloads and adversarial slow/flood cases; adjust only values justified by evidence and record the chosen release policy in the spec.
- [ ] Run `npm run verify` and the exact Windows TypeScript job; fail on any bypass or skipped security test.
