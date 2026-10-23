# Run-private WinAFL object namespace

## Intent

The Windows supervisor currently launches the WinAFL process tree with a restricted token and a per-run restricting SID. The restricted child cannot create a named event in the logon session namespace (`CreateEventW` returns `ERROR_ACCESS_DENIED`), even when an explicit object DACL allows it. Keep run IPC available to WinAFL/DynamoRIO while making named mappings and events inaccessible to other runs and ordinary processes.

## Goals

- Make the pinned WinAFL/DynamoRIO campaign work under the existing restricted token and Job Object.
- Place WinAFL's named shared-memory mappings and the supervisor's named-event acceptance probe in a Windows private namespace with a unique per-run alias and per-run ACL.
- Require the worker identity in the namespace boundary and both the worker identity and matching per-run restricted SID in namespace/object ACLs; a sibling run must not open the first run's mapping or event.
- Remove WinAFL's null-DACL named-pipe policy and grant only the worker identity and the current run's restricted SID the rights needed for the control pipe.
- Fail closed if namespace creation, boundary membership, private ACL setup, or an IPC open fails. Keep diagnostic output safe and bounded.
- Preserve real pinned WinAFL, DynamoRIO, SumatraPDF, coverage, and throughput acceptance; do not skip or fake the native gate.

## Non-goals

- Intercept or rewrite arbitrary kernel-object APIs used by SumatraPDF or unrelated target code.
- Add a general-purpose API detour DLL, change the restricted-token privileges, grant access to `BUILTIN\Users`, or use a permissive DACL.
- Change the fuzzing protocol, campaign persistence, service trust, or worker UI.
- Vendor the WinAFL repository or commit built binaries.

## Constraints and observed interfaces

- Windows x64 is the only supported service target for this milestone.
- WinAFL is acquired at commit `fd85f38548b14352f4b70ad414f364ea6dc1a769` and DynamoRIO at the locked 11.91.20735 SDK.
- At the pinned WinAFL revision, `afl-fuzz.c` creates `afl_shm_<id>` and `sample_afl_shm_<id>` mappings, and `winafl.c` opens the coverage mapping by name. `afl-fuzz.c` creates `\\.\pipe\afl_pipe_<id>` using a null DACL; `winafl.c` connects to that pipe with `CreateFile`.
- The supervisor creates a random per-run SID, places it in the restricted token's restricting SID set, and sets a private default DACL for objects the child creates. A broad `BUILTIN\Users` restricting SID was tested and did not fix namespace access, so it was removed.
- Windows private namespaces address objects by `alias\object-name`; the boundary descriptor and namespace ACL determine which processes can enter/use the namespace. The mapping handles remain process-local, while the named mappings are shared by name.

## Approaches considered

1. **Run-private namespace plus a narrow WinAFL compatibility shim (selected).** The supervisor creates/owns the per-run namespace and the WinAFL patch opens it. Patch the pinned WinAFL acquisition step with a reviewed source patch. A small helper used by `afl-fuzz.exe`, `winafl.dll`, and the native acceptance probe reads and validates supervisor-provided run data, opens the namespace, and constructs prefixed names for only WinAFL's mappings and the probe event. Patch the named-pipe security attributes to a worker/run-only DACL. This leaves Windows security checks enabled and changes only the known IPC names.
2. **Remove restricted-token containment for WinAFL.** This would restore access to the session namespace but discards the protection this issue is implementing. Rejected.
3. **Broad Win32/NT API interception shim.** Detouring all event, mutex, semaphore, section, and mapping creation/open calls could transparently rewrite names, but expands the attack surface, depends on interception coverage across DynamoRIO and target modules, and obscures failures. Rejected.

## Proposed behavior

The supervisor owns the random per-run SID and alias generation. It adds `SUMATRAFUZZ_NAMESPACE_ALIAS` and `SUMATRAFUZZ_RUN_SID` to the existing Unicode environment block. The SID is an identifier, not a credential; the helper validates its syntax and confirms it is the unique per-run SID supplied by the supervisor, rather than trusting an arbitrary environment value. Before launch, the supervisor creates the private namespace using a boundary descriptor containing the worker token's user SID and a protected DACL granting the worker user SID and current run SID. The unrestricted supervisor can create it; the restricted fuzzer and its descendants must pass both the ordinary-user and restricting-SID checks to open it. The supervisor retains the namespace handle in the job record and closes it only after Job Object teardown, including failed or partial launches. The pinned WinAFL launch inherits the worker environment. To make the injected client configuration explicit across DynamoRIO, patch WinAFL's target command construction to pass the same alias and SID as non-secret client options; the client must compare those values to the inherited environment and current token before opening IPC. The helper derives the boundary user SID from its process token and opens the already-created namespace. It prefixes the two WinAFL mapping names and the probe event with `alias\object`. Use explicit object DACLs granting only the worker SID and run SID the minimum mapping/event rights; do not rely on WinAFL's current null DACL. The namespace, mapping, and pipe ACLs must not contain World, Authenticated Users, or `BUILTIN\Users` grants. Use a fresh random alias and run SID for each launch.

The shim prefixes the two WinAFL shared mapping names consistently on creation and open. The named pipe remains in the pipe namespace. At the pinned revision, `winafl.c` opens it with `CreateFile(..., GENERIC_READ | GENERIC_WRITE, 0, ...)`; the client runs as a descendant with the same restricted primary token. Replace the upstream null DACL with a protected DACL for the worker user SID and run SID that grants only the read/write access needed for that call. The probe creates `alias\\SumatraFuzz-Restricted-Probe-<nonce>`; its descendant opens/signals it, the protected sentinel remains inaccessible, and a separate run cannot open it. Namespace setup failures are fatal to launch and produce only a stable safe code plus Win32 error number in test-only diagnostics.

The alias is not treated as a secret. Isolation comes from the boundary SID and ACL checks, not obscurity. No private key, PDF content, local sensitive path, or token dump is emitted by production logs.

## Security and lifecycle questions the implementation must settle

- Confirm experimentally on the supported Windows x64 acceptance image (the current hosted gate is `windows-2022`) that a boundary descriptor containing the worker user SID admits both the supervisor and restricted fuzzer/client, while namespace and object DACLs containing worker user SID and run SID deny a second run's different restricting SID. If this fails, stop and revise the boundary design; do not widen ACLs or token SIDs to force a pass.
- Preserve the supervisor's namespace handle in the native job record through partial launch and stop. Close it only after the complete Job Object has no processes; rely on unique aliases as a second stale-name defense.
- Confirm the pipe DACL grants the restricted client's `GENERIC_READ | GENERIC_WRITE` request through both access-check passes without granting other local users, and derive the worker SID from the launch token rather than a hardcoded account name.
- Confirm the supervisor environment reaches `afl-fuzz.exe`; the WinAFL source patch must also pass alias and SID explicitly to the DynamoRIO client and the client must reject disagreement with environment/token state. This removes reliance on undocumented environment propagation inside DynamoRIO.
- Do not assume source patching preserves real fuzzing. Verify the built toolchain lock includes the upstream commit and patch digest, and run genuine coverage plus the existing execution-count gate.

## Acceptance tests

- Native unit/contract tests cover run SID and alias validation, boundary descriptor/namespace creation failures, protected namespace ACL construction, cleanup on partial failure, and pipe ACL construction.
- Windows x64 supervisor integration launches a restricted fuzzer-like process and descendant; both open/signal the same private event and test mapping; a second independently restricted run is denied; protected trust sentinel read/write remains denied; all processes and namespace handles close after stop and partial failure. Run hosted verification on `windows-2022` and manual installed-service acceptance on the supported Windows x64 host.
- The pinned WinAFL patch applies only to the locked commit and has a reproducible digest recorded in acquisition metadata. Source checks ensure both mapping create/open paths use the prefix and the pipe no longer uses a null DACL.
- The real installed-service CI acceptance executes pinned WinAFL + DynamoRIO + SumatraPDF through the worker, demonstrates nonzero coverage and the required measured execution count, verifies evidence hashes, and records sanitized SID/ACL/teardown receipts.
- Run the full existing repository checks and exact-head Windows CI. The issue remains open until hosted CI and the user's installed-service Windows x64 acceptance both pass.

## Builder decisions

- The helper is a compatibility shim limited to WinAFL IPC names, rather than a general API detour.
- Use the worker user SID as the private namespace boundary, and the worker user SID plus per-run restricting SID in protected namespace/object DACLs; the goal's “per-run boundary SID” refers to the namespace ACL/run identity, not the boundary descriptor. Do not broaden token groups or ACLs.
- Keep namespace lifetime in the native supervisor job record so teardown ordering is testable.
- The builder may choose concrete helper language/build integration and the narrowest Windows API surface after validating actual token/boundary behavior against the pinned tools.
