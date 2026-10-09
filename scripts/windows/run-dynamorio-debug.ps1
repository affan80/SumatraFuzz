#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ToolchainLock,
  [Parameter(Mandatory)][string]$HarnessExe,
  [Parameter(Mandatory)][string]$InputPdf,
  [Parameter(Mandatory)][string]$OutputDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw 'Real Windows x64 DynamoRIO runner required'
}
foreach ($p in @($ToolchainLock,$HarnessExe,$InputPdf,$OutputDir)) {
  if (-not [IO.Path]::IsPathFullyQualified($p)) { throw "Absolute path required: $p" }
}
$lock = Get-Content -LiteralPath $ToolchainLock -Raw | ConvertFrom-Json
if ($lock.source_commit -ne '16c59fde8b824ab54c56f23aef910a6fdd874ad0' -or
    $lock.architecture -ne 'x64' -or $lock.harness_entry -ne 'fuzz_one_file' -or $lock.nargs -ne 1) {
  throw 'Pinned SumatraPDF toolchain contract mismatch'
}
foreach ($entry in @($lock.tools.drrun, $lock.tools.winafl_client, $lock.tools.afl_fuzz)) {
  if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) { throw "Missing tool: $($entry.path)" }
  $hash = (Get-FileHash -LiteralPath $entry.path -Algorithm SHA256).Hash
  if ($hash -ne $entry.sha256) { throw "Hash mismatch: $($entry.path)" }
}
foreach ($path in @($HarnessExe, $InputPdf,
    (Join-Path (Split-Path $HarnessExe -Parent) 'PdfFilter.dll'),
    (Join-Path (Split-Path $HarnessExe -Parent) 'libmupdf.dll'))) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Native input/component missing: $path" }
}
if (Test-Path -LiteralPath $OutputDir) { throw 'Refusing to overwrite an existing debug evidence directory' }
$null=New-Item -ItemType Directory -Path $OutputDir -Force
$debugTool = $lock.tools.drrun.path
$client = $lock.tools.winafl_client.path
$pythonScript = (Resolve-Path (Join-Path $PSScriptRoot '../../tools/instrumentation/verify_debug.py')).Path
$harnessName = [IO.Path]::GetFileName($HarnessExe)
& $HarnessExe $InputPdf
if ($LASTEXITCODE -ne 0) { throw 'Genuine A3 parser rejected debug seed before instrumentation' }

# Phase 1: Discover the module names from a genuine executed target. Its
# all-zero bitmap does NOT certify coverage; the next run must confirm it.
$discoveryDir=Join-Path $OutputDir 'discovery'
$null=New-Item -ItemType Directory -Path $discoveryDir
& $debugTool -c $client -debug -logdir $discoveryDir -target_module $harnessName `
  -target_method 'fuzz_one_file' -fuzz_iterations 10 -nargs 1 -- $HarnessExe $InputPdf
if ($LASTEXITCODE -ne 0) { throw "DynamoRIO discovery run failed: $LASTEXITCODE" }
$files=@(Get-ChildItem -LiteralPath $discoveryDir -File -Recurse | Where-Object {$_.Name -like '*proc.log'})
if ($files.Count -ne 1) { throw "Expected one real WinAFL debug log; got $($files.Count)" }
$discoveryJson=Join-Path $OutputDir 'discovery.json'
& python $pythonScript --log $files[0].FullName --out $discoveryJson --expected-cycles 10 --discovery-only
if ($LASTEXITCODE -ne 0) { throw 'Real module discovery failed' }
$observed=Get-Content -LiteralPath $discoveryJson -Raw | ConvertFrom-Json
$modules=@($observed.confirmed_coverage_modules)
if ($modules.Count -ne 2) { throw 'Unexpected actual parser coverage module count' }

# Phase 2: Real edge feedback from the exact observed parser modules only.
$confirmationDir=Join-Path $OutputDir 'confirmation'
$null=New-Item -ItemType Directory -Path $confirmationDir
$drArgs=@('-c',$client,'-debug','-logdir',$confirmationDir,'-covtype','edge')
foreach($name in $modules) { $drArgs += @('-coverage_module',$name) }
$drArgs += @('-target_module',$harnessName,'-target_method','fuzz_one_file',
             '-fuzz_iterations','10','-nargs','1','--',$HarnessExe,$InputPdf)
& $debugTool @drArgs
if ($LASTEXITCODE -ne 0) { throw "DynamoRIO coverage confirmation failed: $LASTEXITCODE" }
$confirmed=@(Get-ChildItem -LiteralPath $confirmationDir -File -Recurse | Where-Object {$_.Name -like '*proc.log'})
if ($confirmed.Count -ne 1) { throw 'Expected one real confirmed WinAFL debug log' }
$confirmedJson=Join-Path $OutputDir 'confirmed.json'
& python $pythonScript --log $confirmed[0].FullName --out $confirmedJson --expected-cycles 10
if ($LASTEXITCODE -ne 0) { throw 'No genuine repeated parser instrumentation/coverage' }
$record=Get-Content -LiteralPath $confirmedJson -Raw | ConvertFrom-Json
if ($record.bitmap_nonzero_bytes -lt 1) { throw 'Empty edge feedback map' }
$manifest = [ordered]@{
  target_commit=$lock.source_commit
  target_module=$harnessName
  target_method='fuzz_one_file'
  cycles=10
  confirmed_modules=$modules
  harness_sha256=(Get-FileHash -LiteralPath $HarnessExe -Algorithm SHA256).Hash
  pdf_filter_sha256=(Get-FileHash -LiteralPath (Join-Path (Split-Path $HarnessExe -Parent) 'PdfFilter.dll') -Algorithm SHA256).Hash
  mupdf_sha256=(Get-FileHash -LiteralPath (Join-Path (Split-Path $HarnessExe -Parent) 'libmupdf.dll') -Algorithm SHA256).Hash
  input_sha256=(Get-FileHash -LiteralPath $InputPdf -Algorithm SHA256).Hash
  confirmed_log_sha256=$record.sha256
  confirmed_map_nonzero_bytes=$record.bitmap_nonzero_bytes
  toolchain_lock_sha256=(Get-FileHash -LiteralPath $ToolchainLock -Algorithm SHA256).Hash
  confirmed_log=$confirmed[0].FullName
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDir 'a4-confirmed.json') -Encoding utf8
Write-Output "A4 real DynamoRIO verification PASS: 10 pre/post cycles, nonzero edge map, observed modules: $($modules -join ', ')"
