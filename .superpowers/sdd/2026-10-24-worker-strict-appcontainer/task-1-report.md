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
