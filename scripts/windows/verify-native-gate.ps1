#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'Windows x64 required'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Native gate requires a nonadministrator process'
}
Set-Location -LiteralPath $RepoRoot
$runs = Join-Path $RepoRoot 'runs'
$null = New-Item -ItemType Directory -Path $runs -Force
@{ identity=$identity.Name; sid=$identity.User.Value; administrator=$false; architecture='x64'; checked_utc=[DateTime]::UtcNow.ToString('o') } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runs 'native-execution-context.json') -Encoding utf8
Write-Output "Verified standard-user native execution: $($identity.Name)"
$seed = Join-Path $RepoRoot 'runs/a4/seed.pdf'
python tools/instrumentation/make_debug_seed.py --out $seed
if ($LASTEXITCODE -ne 0) { throw 'Seed generation failed' }
& scripts/windows/run-dynamorio-debug.ps1 `
    -ToolchainLock (Join-Path $RepoRoot 'external/native-tools/locks/target-lock.json') `
    -HarnessExe (Join-Path $RepoRoot 'build/a3/Release/sumatrafuzz-harness.exe') `
    -InputPdf $seed -OutputDir (Join-Path $RepoRoot 'runs/a4/debug-evidence')

$seeds = Join-Path $RepoRoot 'runs/a5/seeds'
python scripts/windows/generate_fixtures.py --out $seeds
if ($LASTEXITCODE -ne 0) { throw 'Deterministic PDF seed generation failed' }
$harness = Join-Path $RepoRoot 'build/a3/Release/sumatrafuzz-harness.exe'
foreach ($file in @(Get-ChildItem -LiteralPath $seeds -Filter '*.pdf' -File)) {
    & $harness $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "Pinned SumatraPDF parser rejected a seed: $($file.Name)" }
}
# Integration regression: old parent-level snapshots must never certify a new campaign.
# These deliberately invalid test sentinels are not run evidence or uploaded artifacts.
$stale = Join-Path $RepoRoot 'runs/a5/first.stats'
'stale snapshot regression fixture' | Set-Content -LiteralPath $stale
& scripts/windows/run-winafl-smoke.ps1 `
    -ToolchainLock (Join-Path $RepoRoot 'external/native-tools/locks/target-lock.json') `
    -A4Manifest (Join-Path $RepoRoot 'runs/a4/debug-evidence/a4-confirmed.json') `
    -HarnessExe $harness -InputDir $seeds `
    -OutputDir (Join-Path $RepoRoot 'runs/a5/campaign') `
    -DurationSeconds 720 -TimeoutMs 20000 -FuzzIterations 1000
if ((Get-Content -LiteralPath $stale -Raw).Trim() -ne 'stale snapshot regression fixture') {
    throw 'Current campaign modified another campaign snapshot'
}
python tools/evidence/collect.py `
    --toolchain-lock (Join-Path $RepoRoot 'external/native-tools/locks/target-lock.json') `
    --a4-manifest (Join-Path $RepoRoot 'runs/a4/debug-evidence/a4-confirmed.json') `
    --harness $harness --run-dir (Join-Path $RepoRoot 'runs/a5/campaign') `
    --before-stats (Join-Path $RepoRoot 'runs/a5/campaign/first.stats') `
    --after-stats (Join-Path $RepoRoot 'runs/a5/campaign/second.stats') `
    --output (Join-Path $RepoRoot 'runs/a6/evidence.json')
if ($LASTEXITCODE -ne 0) { throw 'A6 cryptographic evidence verification failed' }
