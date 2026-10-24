# Task 2 implementation report

Base: `df21ec2b67a9a1d30205c628271000e1c082ad40`.
Scope: run-owned AppContainer identity and safe per-object ACL foundations only. No push, launch/token replacement, namespace identity change, service acceptance, or issue closure.

## Changes

- Added `native/worker-supervisor/include/run_resources.h`, a shared Windows-only production header used by the addon and native probe. This small file-scope deviation was authorized so the runtime probe exercises the production implementation rather than a duplicate test implementation.
- Added move-only `AppContainerProfile` and `CreateRunAppContainerProfile()`. Profile names contain a freshly generated GUID and are bounded to 39 characters. Creation uses zero capabilities; any failure, including `ERROR_ALREADY_EXISTS`, throws with a sanitized operation and preserved Win32 error code when available. Failed creation frees any returned SID without deleting/reusing an existing profile. Successful profiles use `FreeSid` after deletion.
- Added typed `GrantRunResourceAccess(path, sid, access, policy)` and RAII grant ownership. The policy is an exact object allowlist, with protected-root exclusions taking precedence. It must be populated by the future native launch builder from held verified proof handles, selected input enumeration, and newly created run evidence/scratch objects. This helper is not exposed to JavaScript. It accepts full package SIDs only, never broad well-known identities or arbitrary access masks.
- Tool files get read/execute; input files get read without execute/write; input directories also get traversal; evidence/scratch objects get read/write/delete plus directory traversal/delete-child as appropriate, without ACL/owner mutation rights. All package ACEs are non-inheriting and object-specific. The helper intentionally does not authorize a directory tree implicitly.
- ACL changes use held handles, reject reparse points on every ancestor and final object, reject hardlinked objects and noncanonical path aliases, reject alternate streams/dot components/invalid local paths, and pin ancestor/object handles against replacement. Canonical drive-root keys are valid for exclusions; granting a volume root is always rejected. No tool-root ACL widening or recursive ACL update is added.
- Cleanup reads the current ACL and removes only this run's package allow ACE, preserving unrelated ACEs present at cleanup. Preexisting ordinary allow/deny ACEs for the same package fail closed. Removal is explicit/retryable and RAII-managed. Cleanup failure retains preallocated identity/handle records in supervisor-lifetime quarantine, emits a generic diagnostic, and does not claim success.
- Added `RunResources` to `Job` and `QuarantinedJob`. The owner is destroyed after the existing process-tree drain and namespace teardown; an unconfirmed drain transfers it into the existing job quarantine. No profile/grants are created by the legacy launch path yet. `userenv.lib` is linked for the addon.
- Added a Windows-only native contract mode and Node invocation covering package SID uniqueness, allowed masks, input directory traversal, broad-SID rejection, excluded and sibling object rejection, drive-root normalization/exclusion/no-grant, hardlink and junction rejection, partial setup ACL/profile rollback, ownership movement, normal cleanup, preserving another package's ACE, and successful recreation of deleted profile names. Static checks reject broad grants in the new helper.

## TDD and local verification

- Initial red: `node --test test/supervisor-windows.check.cjs` failed with the new assertion `production run resource owner must exist` before the production header existed.
- Additional red: the canonical drive-root/SID-failure-cleanup contract failed before implementing those branches.
- Final local `npm run native:supervisor:contract`: 2/2 CTest contracts pass. This host is macOS; Windows-only C++ branches are not compiled/executed by this result.
- Final local `node --test test/supervisor-windows.check.cjs`: 15 pass, 4 Windows-specific skips, no failures.
- Final local `npm test`: 37 Vitest files pass; 378 tests pass and 1 skips. Node checks: 39 pass, 5 skip, no failures.
- `git diff --check`: passes.
- Self-review checked handle transfers, move/unwind ownership, failure SID release, rollback ordering, canonical path and exclusion boundaries, inherited ACE avoidance, and preservation of unrelated grants. Unrelated campaign-insights changes and the Task 1 report changes were preserved and excluded from staging.

## Task boundary and acceptance gaps

The Task 2 step-1 wording asks for actual token membership and cleanup after stop/partial launch. Those assertions require Task 3's token and launcher integration. This task tests the zero-capability profile and resource owner contracts, including partial setup/unwind, while leaving the legacy launcher and its existing acceptance tests intact. It does not prove AppContainer child token membership or stop/failed-launch integration. Task 3 must move a populated owner into `Job` before creating any child, and propagate explicit `Close()` failures to the caller rather than reporting successful cleanup.

All grants are per-object and non-inheriting. Task 3 must bind the allowlist to the verified launch, enumerate the selected input objects, and prove that the child can create and subsequently access nested evidence/scratch objects using its scoped/default DACLs. This helper alone does not prove nested WinAFL output compatibility and must not be broadened to arbitrary parent directories to make it work.

The new Windows resource contract has not been compiled or executed on this macOS host. It runs via `node --test test/supervisor-windows.check.cjs` on Windows and remains an exact-head Windows acceptance requirement. No claim of runtime profile, reparse, cleanup, or permission behavior is made from static checks.

Prior Windows run `40089250286` demonstrated the separate standard-user feasibility probe through ACL update, AppContainer child launch, write/denial probes, and profile deletion. The overall Windows check still fails in the unchanged restricted-token launcher with `0xC0000135 STATUS_DLL_NOT_FOUND`; this task neither fixes nor weakens/bypasses that check. There is no exact-head Windows run for this commit yet.

Task 5 still must prove actual `NT SERVICE\\SumatraFuzzWorker` profile lifecycle and show all AppContainer profile/temp writes are charged to the worker's NTFS quota, including cleanup/restart behavior. The standard-user feasibility probe and the new helper contract do not establish service identity or quota charging. Issue #91 remains open pending the remaining plan, exact-head Windows acceptance, installed-service evidence, and human review.
