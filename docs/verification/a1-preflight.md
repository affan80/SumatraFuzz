# A1 preflight status

Source tag `3.6.1rel` resolved upstream to commit `16c59fde8b824ab54c56f23aef910a6fdd874ad0`.

- GitHub source-reference lookup: **PASS**.
- Target JSON static checks: **PASS** (manual source review).
- Windows PowerShell Pester: **NOT RUN** until Windows workflow runs.
- Live Windows x64 native WinAFL/DynamoRIO tool binaries: **NOT PROVIDED**.
- Actual `target-lock.json`: **NOT GENERATED**.
- Sumatra-integrated harness, DynamoRIO coverage and WinAFL campaign: **NOT RUN**.

To complete A1 on isolated Windows x64:
```powershell
Install-Module Pester -MinimumVersion 5 -Scope CurrentUser -Force
Invoke-Pester -Path scripts/windows/tests/verify-toolchain.Tests.ps1 -CI
pwsh -File scripts/windows/verify-toolchain.ps1 -SumatraSource $env:SF_SUMATRA_SRC -WinAflExe $env:SF_AFL_EXE -WinAflDll $env:SF_WINAFL_DLL -DrrunExe $env:SF_DRRUN_EXE -Workspace $env:SF_WORKSPACE
```
Do not mark Stage A PASS on the basis of mocked tool PE tests. Real x64 tools and real parser are still required.
