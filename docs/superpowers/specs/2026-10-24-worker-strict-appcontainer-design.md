# Strict per-run Windows fuzz sandbox

## Intent

Keep an exploited WinAFL/DynamoRIO/SumatraPDF process from writing outside its own bounded run evidence and scratch area, while still permitting its required executable, input, and run-private IPC access. The current restricted-token workaround is not acceptable: Windows CI previously demonstrated a write to a World-writable file outside evidence, and the current namespace access check allows traversal but denies object creation.

## Goals

- Replace the broad `World` and `Authenticated Users` restricting SIDs with a per-run Windows AppContainer identity and no network capabilities.
- Keep the existing Job Object process-tree, CPU, memory, timeout, and teardown controls.
- Grant the run identity read/execute access only to verified tools, read-only access to its selected input, and modify access only to its bounded evidence/scratch area.
- Preserve run-private WinAFL/DynamoRIO events and mappings. A run must not open another run's objects.
- Fail closed when the AppContainer profile, ACLs, namespace, or sandboxed process cannot be created or verified.
- Validate the real pinned WinAFL/DynamoRIO/SumatraPDF flow on Windows x64; static checks alone are insufficient.

## Non-goals

- Do not allow broad writes through World, Authenticated Users, Interactive, Users, or other machine-wide SIDs.
- Do not remove process containment, file proof verification, quotas, or service trust controls.
- Do not add another account-management service or a third-party service wrapper.
- Do not report issue #91 complete until hosted Windows and installed-service acceptance pass.

## Approaches considered

1. **Per-run AppContainer (selected).** Create a unique profile for each campaign, launch the verified target with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, and grant its package SID only the specific run access it needs. This gives Windows a distinct per-run identity and an isolated object namespace. It requires testing WinAFL/DynamoRIO compatibility and profile/scratch cleanup under the service identity.
2. **Temporary low-privilege account.** Create or lease a separate Windows account for each run and grant its SID per-run file and object access. This can preserve the current restricted-token flow but adds account/profile lifecycle, credential handling, and service privilege requirements.
3. **Current restricted-token model.** Keep World/Authenticated Users as restricting SIDs and rely on low integrity to block writes. Rejected because exact Windows CI already demonstrated an out-of-evidence write under a broad writable ACL.

## Proposed design

- The native supervisor creates a cryptographically random, bounded AppContainer profile name for each run using `CreateAppContainerProfile` and retains its package SID and profile name in the job record. It creates no capabilities, so the fuzz process has no network authority.
- Build the child with `STARTUPINFOEX` and `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; keep it suspended until assigned to the existing kill-on-close Job Object. The child and its descendants inherit the same per-run AppContainer identity.
- Apply non-inheriting, object-specific ACLs for the package SID: read/execute on verified tool/runtime files, read and traverse on approved input objects, and modify only on the run's evidence directory. Do not grant package access to worker credentials, trust state, audit database, or sibling runs. Apply a low-integrity label to the evidence directory where required.
- Preserve private named IPC. The supervisor's namespace boundary and DACL include only the worker identity and this run's AppContainer package SID. The WinAFL shim uses that namespace for its known mapping/event names and fails closed on mismatch. A sibling AppContainer cannot open the run's named objects.
- Keep AppContainer temporary/profile writes within the same quota-backed run scratch area, or demonstrate that the profile's default writable storage is bounded and removed before accepting this design. This is a release blocker; do not silently permit unbounded writes on the system volume.
- On normal stop, timeout, partial launch, and failed teardown, wait for the Job Object to drain, close process/object handles, remove temporary ACL entries, and call `DeleteAppContainerProfile`. Startup recovery must detect and safely clean only stale profiles created by this product; cleanup failure is surfaced as a safe operational error and must not weaken ACLs.
- CI must test denied writes to World-writable and Authenticated-Users-writable medium- and low-integrity sentinels outside evidence, successful evidence writes, denied secret/input writes, sibling-run namespace denial, profile cleanup, resource quotas, and genuine pinned WinAFL/DynamoRIO parser execution. Add installed-service acceptance for profile creation and cleanup under `NT SERVICE\\SumatraFuzzWorker`.

## Risks and acceptance gates

- `CreateAppContainerProfile` is per-user and creates profile storage. Confirm it works for the virtual service identity and place or bound all writable profile storage on the worker quota volume. If this cannot be done, stop and return with evidence rather than weakening write isolation.
- WinAFL, DynamoRIO, and the fuzz target may expect unrestricted named-object, registry, or temporary-file access. Test each dependency under the AppContainer before widening a grant; grant only the exact required object and rights.
- AppContainer object namespaces are isolated by default. Confirm the approved private namespace plus shim remains reachable by the sandboxed client with the package SID boundary and that event/mapping DACLs deny sibling runs.
- Exact-head Windows x64 CI and installed-service acceptance are mandatory. This design does not close issue #91 by itself.

## Evidence

- Microsoft documents AppContainer access as the intersection of user/group and package/capability ACL checks, and states that a low-integrity AppContainer can still write to a low-integrity resource when its DACL grants that access: <https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer>.
- Windows AppContainers have isolated named-object namespaces by default; sharing objects requires explicit ACLs and qualified names: <https://learn.microsoft.com/en-us/windows/apps/develop/communication/sharing-named-objects>.
- The current exact-head Windows diagnostic reports `namespace_traverse_granted=1` and `namespace_create_granted=0`; the earlier containment acceptance documented a World-writable out-of-evidence write (exit 49).
