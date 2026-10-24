# Task 1 report: AppContainer API feasibility

**Status: DONE_WITH_CONCERNS**

Implemented a Windows-only API feasibility probe, invoked from the ordinary nonadministrator fixture in `ci-supervisor-check.ps1`. It creates two uniquely named AppContainer profiles and requires distinct package SIDs, queries and prints the first profile folder and per-run temporary output paths, grants the first package SID access only to the temporary output directory, then launches a copied probe executable with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and zero capabilities. The child verifies that its token is an AppContainer with no capabilities, writes its marker inside the per-run output directory, and requires `ERROR_ACCESS_DENIED` for World and Authenticated Users writable sentinels at medium and low integrity. The parent requires successful profile deletion for both profiles; any failed condition fails the fixture.

The workflow invokes this through the existing standard-user Windows x64 CI step after `native:supervisor:contract` builds `process_probe.exe`. The static check confirms the Windows gate, invocation ordering, profile APIs, zero-capability launch, path reporting, and all four broad-ACL sentinels.

Validation run on this host:

- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped (Windows-only runtime checks), 0 failed.
- `git diff --check`: passed.

Concern: this workspace is running on macOS, so the Windows C++ APIs could not be compiled or exercised here, and actual profile/temp measurements and cleanup behavior remain pending the hosted Windows x64 job. This result is only an API feasibility slice. It does not establish installed-service identity acceptance or quota-backed storage; those remain later gates, including Task 5's installed-service check. If Windows CI cannot prove bounded profile scratch and cleanup, the sandbox must fail closed and product-code work must not claim acceptance.

## Fix round: cleanup must fail closed

Addressed both review findings. The PowerShell probe now checks that its output directory is absent after `Remove-Item`; removal errors or a surviving directory raise a terminating error. Native profile cleanup now runs through one helper on both normal and exception paths. The helper attempts deletion of each profile independently, checks both HRESULTs, and emits a profile-specific stderr diagnostic for every deletion failure. An exception path remains failed and additionally reports incomplete profile cleanup.

Focused verification for this fix round:

- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped (Windows-only runtime checks), 0 failed.
- `git diff --check`: passed.

The Windows runtime caveat in the initial report still applies.

## Fix round: AppContainer folder-path argument

Hosted Windows x64 compilation identified that `GetAppContainerFolderPath` takes the profile name (`PCWSTR`), not the package SID. Updated the probe to pass `profile.c_str()` and added a static regression assertion for that exact call plus a negative assertion against passing `sid`.

Local covering checks:

- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped, 0 failed.
- `git diff --check`: passed.

The API correction is based on the hosted Windows SDK compiler diagnostic. Local Windows API compilation remains pending because this workspace is macOS; the next hosted Windows x64 run must confirm the corrected native build and probe execution.

## Fix round: format the Windows static check

Ran the repository Biome formatter on `test/supervisor-windows.check.cjs` to wrap the new assertions. Requested local checks:

- `npm run format:check`: passed; Biome checked 139 files with no remaining fixes.
- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped, 0 failed.
- `git diff --check`: passed.

Hosted run status was checked with `gh run view 40087447795 --job 120853170488 --log-failed`. That run used head `69c9af3fac47959136f566af7ac47807eecfaee3`. Its Windows native build/contract step completed, but the standard-user step failed at the pre-existing restricted-child startup-marker assertion (`test/supervisor-windows.check.cjs:160`) before the AppContainer probe invocation. Therefore this hosted run provides no AppContainer execution or cleanup result.

## Fix round: run AppContainer feasibility before the legacy probe

Reordered child-mode checks so `appcontainer-probe.ps1` runs before the legacy `node --test` suite. Both checks remain enabled, and either still stops the fixture on failure. Added a static assertion that enforces this order within the child-mode block.

Requested local checks:

- `npm run format:check`: passed; Biome checked 139 files with no remaining fixes.
- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped, 0 failed.
- `git diff --check`: passed.

The previous hosted exact-head run failed in the legacy restricted-child startup-marker assertion, before the AppContainer invocation. This reordering should emit feasibility evidence before that blocker, but a clean exact-head Windows run is still required to confirm the probe's execution and cleanup. The legacy runtime failure remains unresolved.

## Fix round: pass the package SID string and report failed stages

The latest hosted Windows run reached the AppContainer probe and returned exit 82. The `GetAppContainerFolderPath` argument was incorrect: Microsoft documents `pszAppContainerSid` as the SID string, so the probe now converts the package SID with `ConvertSidToStringSidW`, passes the resulting string, and releases it with `LocalFree`. The profile name remains in use for profile creation and deletion. Source: [Microsoft Learn: GetAppContainerFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappcontainerfolderpath).

Added failure diagnostics with a stable stage name plus HRESULT and/or Win32 error for profile creation, SID conversion, folder query, unique SID validation, ACL setup, executable copy, process attribute setup, child launch, wait, child exit, and cleanup. These failure messages do not include filesystem paths. Static checks require the SID string conversion, correct API argument, its `LocalFree`, and representative stage diagnostics.

Local checks:

- `npm run format:check`: passed; Biome checked 139 files.
- `node --test test/supervisor-windows.check.cjs`: 14 passed, 3 skipped, 0 failed.
- `git diff --check`: passed.

This macOS workspace cannot compile or run the Windows APIs. The latest hosted execution reached the probe but failed before the SID-string correction; a clean exact-head Windows run is still required to confirm the corrected API query and probe cleanup.
