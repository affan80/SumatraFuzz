#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ToolchainLock,
  [Parameter(Mandatory)][string]$A4Manifest,
  [Parameter(Mandatory)][string]$HarnessExe,
  [Parameter(Mandatory)][string]$InputDir,
  [Parameter(Mandatory)][string]$OutputDir,
  [ValidateRange(15,1200)][int]$DurationSeconds=180,
  [ValidateRange(100,120000)][int]$TimeoutMs=20000,
  [ValidateRange(10,10000)][int]$FuzzIterations=1000
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw 'Windows x64 required'
}
foreach ($p in @($ToolchainLock,$A4Manifest,$HarnessExe,$InputDir,$OutputDir)) {
  if (-not [IO.Path]::IsPathFullyQualified($p)) { throw "Absolute paths required: $p" }
}
if (Test-Path -LiteralPath $OutputDir) { throw "Refusing to overwrite WinAFL campaign: $OutputDir" }
if (-not (Test-Path -LiteralPath $InputDir -PathType Container)) { throw 'Seed input directory missing' }
if (([IO.Path]::GetFullPath($InputDir)).TrimEnd('\') -ieq ([IO.Path]::GetFullPath($OutputDir)).TrimEnd('\')) {
  throw 'Seed and output directories cannot be the same'
}
$lock=Get-Content -LiteralPath $ToolchainLock -Raw | ConvertFrom-Json
$a4=Get-Content -LiteralPath $A4Manifest -Raw | ConvertFrom-Json
if ($lock.source_commit -ne '16c59fde8b824ab54c56f23aef910a6fdd874ad0' -or
    $a4.target_commit -ne $lock.source_commit -or $a4.cycles -ne 10 -or
    $a4.confirmed_map_nonzero_bytes -lt 1) { throw 'Real A4 instrumented run evidence missing' }
$lockHash=(Get-FileHash -LiteralPath $ToolchainLock -Algorithm SHA256).Hash
if ($lockHash -ne $a4.toolchain_lock_sha256) { throw 'A4 toolchain lock hash mismatch' }
$filter=Join-Path (Split-Path $HarnessExe -Parent) 'PdfFilter.dll'
$mu=Join-Path (Split-Path $HarnessExe -Parent) 'libmupdf.dll'
foreach ($tuple in @(@($HarnessExe,$a4.harness_sha256),@($filter,$a4.pdf_filter_sha256),@($mu,$a4.mupdf_sha256))) {
  if (-not (Test-Path -LiteralPath $tuple[0] -PathType Leaf)) { throw "Parser binary missing: $($tuple[0])" }
  if ((Get-FileHash -LiteralPath $tuple[0] -Algorithm SHA256).Hash -ne $tuple[1]) {
    throw "Parser binary changed since A4: $($tuple[0])"
  }
}
foreach ($name in @('drrun','winafl_client','afl_fuzz')) {
  $item=$lock.tools.$name
  if (-not (Test-Path -LiteralPath $item.path -PathType Leaf)) { throw "Missing real tool: $name" }
  if ((Get-FileHash -LiteralPath $item.path -Algorithm SHA256).Hash -ne $item.sha256) {
    throw "Tool binary hash mismatch: $name"
  }
}
$observed=@($a4.confirmed_modules)
if ($observed.Count -lt 1 -or $observed.Count -gt 8 -or @($observed | Select-Object -Unique).Count -ne $observed.Count) {
  throw 'Expected unique coverage modules observed in real A4 logs'
}
foreach ($name in $observed) {
  if ($name -notmatch '^[A-Za-z0-9_.-]+\.dll$') { throw "Invalid observed module name: $name" }
}
$seeds=@(Get-ChildItem -LiteralPath $InputDir -File -Filter '*.pdf')
if ($seeds.Count -lt 2) { throw 'Expected two or more genuine valid seed PDFs' }
foreach ($seed in $seeds) {
  if ($seed.Length -lt 64) { throw "PDF seed too small: $($seed.Name)" }
  & $HarnessExe $seed.FullName
  if ($LASTEXITCODE -ne 0) { throw "Genuine SumatraPDF parser rejected seed $($seed.Name)" }
}
$logPath=[IO.Path]::GetFullPath([string]$a4.confirmed_log)
if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) { throw 'Raw genuine A4 debug log missing' }
if ((Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash -ne $a4.confirmed_log_sha256) {
  throw 'Raw A4 debug log no longer matches evidence'
}

$parent=Split-Path $OutputDir -Parent
[void](New-Item -ItemType Directory -Path $parent -Force)
$afl=[string]$lock.tools.afl_fuzz.path
$client=[string]$lock.tools.winafl_client.path
$drBin=Split-Path ([string]$lock.tools.drrun.path) -Parent
$aflArguments=@('-i',$InputDir,'-o',$OutputDir,'-D',$drBin,'-w',$client,
        '-t',[string]$TimeoutMs,'--','-covtype','edge')
foreach ($name in $observed) { $aflArguments+=@('-coverage_module',[string]$name) }
$aflArguments+=@('-target_module',[IO.Path]::GetFileName($HarnessExe),'-target_method','fuzz_one_file',
         '-fuzz_iterations',[string]$FuzzIterations,'-nargs','1','--',$HarnessExe,'@@')
$info=[Diagnostics.ProcessStartInfo]::new()
$info.FileName=$afl
$info.UseShellExecute=$false
$info.CreateNoWindow=$true
$info.WorkingDirectory=[IO.Path]::GetFullPath($parent)
foreach ($arg in $aflArguments) { [void]$info.ArgumentList.Add([string]$arg) }
$info.Environment['AFL_NO_UI']='1'
$begin=[DateTime]::UtcNow
$proc=[Diagnostics.Process]::new()
$proc.StartInfo=$info
if (-not $proc.Start()) { throw 'Real WinAFL process did not start' }
$stopReason='unknown'
$statsPath=Join-Path $OutputDir 'fuzzer_stats'
$first=Join-Path $parent 'first.stats'
$second=Join-Path $parent 'second.stats'
$end=$begin.AddSeconds($DurationSeconds)
try {
  while ([DateTime]::UtcNow -lt $end) {
    if ($proc.WaitForExit(3000)) {
      throw "WinAFL terminated before bounded campaign ended with code $($proc.ExitCode)"
    }
    if (Test-Path -LiteralPath $statsPath -PathType Leaf) {
      if (-not (Test-Path -LiteralPath $first)) {
        Copy-Item -LiteralPath $statsPath -Destination $first
      } else {
        Copy-Item -LiteralPath $statsPath -Destination $second -Force
      }
    }
  }
  $stopReason='bounded_limit_reached'
} finally {
  if (-not $proc.HasExited) {
    # Explicitly record this as a bounded forced stop; never call it a clean exit.
    $proc.Kill($true)
    [void]$proc.WaitForExit(30000)
  }
  $proc.Dispose()
}
if (-not (Test-Path -LiteralPath $first -PathType Leaf) -or
    -not (Test-Path -LiteralPath $second -PathType Leaf) -or
    -not (Test-Path -LiteralPath $statsPath -PathType Leaf)) {
  throw 'Real WinAFL failed to generate multiple raw fuzzer_stats snapshots'
}
$metadata=[ordered]@{
  start_utc=$begin.ToString('o')
  end_utc=[DateTime]::UtcNow.ToString('o')
  stop_reason=$stopReason
  argv=@($afl) + $aflArguments
  source_commit=$lock.source_commit
  a4_evidence_sha256=(Get-FileHash -LiteralPath $A4Manifest -Algorithm SHA256).Hash
  stats_initial=(Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash
  stats_later=(Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash
}
$metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDir 'campaign-metadata.json') -Encoding utf8
$script=Resolve-Path (Join-Path $PSScriptRoot '../../tools/evidence/stats_cli.py')
& python $script --before $first --after $second --final $statsPath
if ($LASTEXITCODE -ne 0) { throw 'Real WinAFL execution counts did not progress' }
Write-Output "Real bounded WinAFL campaign validated: $OutputDir"
