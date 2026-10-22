# Worker trust acceptance — issue #91

Audit baseline: `501102a6abf0e4aec0a3efefabb7904413d0fa9a` on `dev`.
This document records source inspection and the proposed implementation order. It is not runtime acceptance evidence. Issue #91 remains open.

## Existing implementation and remaining work

| Requirement | Existing source evidence | Remaining acceptance |
| --- | --- | --- |
| Mutual TLS and private listeners | `apps/worker-service/src/server.ts` requests client certificates and rejects unauthorized chains. `network-policy.ts` rejects wildcard/public addresses. | Require TLS 1.3 on server and client; enforce named adapter identity and stop accepting traffic when that configured adapter/address disappears. Demonstrate missing/unpaired/expired/revoked/wrong-purpose certificates with real TLS requests. |
| Explicit controller identity | `auth.ts` validates fingerprint/validity and the server resolves controller UUID from an explicit pairing map. `validateStartRequest` rejects a different body controller ID. | Persist operator-managed trust records, validate certificate purpose/key strength, and apply rotation/revocation to already connected clients before dispatch. |
| Resource authorization | Server checks `ownsRun` before run status, stop, replay, manifest, and artifact routes. | Exercise every route with two real paired controllers, unknown artifacts, identity-header spoofing, revoked connections, and restart. Denial must occur before handlers or native launch. |
| Admission budgets and safe errors | Bounded JSON/archive responses, exclusive archive import, replay page limits, generic errors, header and request timers exist. | Centralize budgets; cap connections, in-flight requests and per-controller rate/transfers/replays; enforce content types, request-target/header limits and idle deadlines. Add stable error codes/correlation IDs. Candidate thresholds remain provisional until benchmarked and reviewed. |
| Security auditing | No durable security audit interface or trust-management audit exists. | Retain bounded, redacted authorization and trust-change records with integrity verification and documented retention/recovery. Audit failure must not silently permit privileged changes. |
| Protected Windows service | `createWorkerApplication` composes the worker modules; existing native addon supports DPAPI. The approved migration plan requires a dedicated virtual service identity. | Implement the actual service entrypoint/SCM lifecycle, one-time provisioning, protected configuration/keys, ACLs, dedicated volume quota verification, scoped firewall configuration, drain/restart/uninstall behavior, and Windows evidence. There is no installer or service host in the audited baseline. |
| Pairing and credential lifecycle | Signed `.sfpair` imports verify an embedded organization key, signed worker/controller UUIDs, worker certificate pin, and authenticated capabilities. Desktop profile storage uses Windows protection. | Add operator workflows for provisioning, renew/rotate/revoke/unpair and secret cleanup. Preserve existing approved signed-bundle flow; never put credentials in result bundles, audit payloads, renderer IPC or CI uploads. |

## Proposed implementation sequence

1. **Policy and API trust enforcement:** write the threat/control/test map; centralize provisional budgets; require TLS 1.3; add safe error/audit contracts and the two-controller authorization/denial integration suite. Keep existing tighter archive limits rather than raising them to the historical proposed maximum.
2. **Persistent trust and certificate lifecycle:** protected operator-only trust management, explicit certificate validation, atomic rotate/revoke operations, fresh authorization on every request, and trust-change audit/recovery. No enrollment endpoint or identity-header fallback.
3. **Windows deployment and acceptance:** standalone TypeScript worker entrypoint plus a small SCM host in the existing native boundary; dedicated nonadministrator identity, protected provisioning, private adapter/firewall binding, controlled shutdown and restart. Test installation and removal in a disposable Windows x64 CI environment, then run the genuine native gate through the installed service.

The proposed SCM host adds no third-party service-wrapper binary. It only handles SCM status/control, starts the fixed Node worker entrypoint with structured arguments, and mediates bounded shutdown. Campaign logic and API/trust policy remain TypeScript. An external pinned wrapper is an alternative requiring an additional binary trust and packaging policy.

## Closure evidence

Each slice needs its implementing PR into `dev`, observed negative tests, review, required CI and merge evidence. Before closure, Windows evidence must prove the installed worker and its children are nonadministrator, the configured listener is private/loopback only, disconnect does not stop a bounded campaign, trust rotation/revocation denies the old identity, cross-controller access cannot read or stop another run, and shutdown/restart preserves truthful journal state. Pure logic tests and the direct-coordinator acceptance from #90 do not substitute for installed-service behavior.

## Primary platform references

- Node HTTPS configuration: <https://nodejs.org/docs/latest-v24.x/api/https.html>
- Node HTTP limits/timeouts: <https://nodejs.org/docs/latest-v24.x/api/http.html>
- Windows SCM service creation and account selection: <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew>
- Service account profiles: <https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts>
