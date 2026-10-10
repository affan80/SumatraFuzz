#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ToolchainLock,
  [Parameter(Mandatory)][string]$DebugEvidence,
  [Parameter(Mandatory)][string]$HarnessExe,
  [Parameter(Mandatory)][string]$InputDir,
  [Parameter(Mandatory)][string]$OutputDir,
  [ValidateRange(30,600)][int]$DurationSeconds=180,
  [ValidateRange(1000,120000)][int]$TimeoutMs=20000,
  [ValidateRange(1,1000000)][int]$MinExecutions=1000
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'Windows x64 required' }
foreach ($pair in @(@('ToolchainLock',$ToolchainLock),@('DebugEvidence',$DebugEvidence),@('HarnessExe',$HarnessExe),@('InputDir',$InputDir),@('OutputDir',$OutputDir))) {
  if (-not [IO.Path]::IsPathFullyQualified($pair[1])) { throw "$($pair[0]) must be absolute" }
}
if (Test-Path -LiteralPath $OutputDir) { throw "OutputDir already exists; refusing overwrite: $OutputDir" }
if (-not (Test-Path -LiteralPath $DebugEvidence -PathType Leaf)) { throw "Required A4 debug evidence missing: $DebugEvidence" }
if (-not (Test-Path -LiteralPath $ToolchainLock -PathType Leaf)) { throw "Toolchain lock missing: $ToolchainLock" }
if (-not (Test-Path -LiteralPath $HarnessExe -PathType Leaf)) { throw "Harness executable missing: $HarnessExe" }
if ((Split-Path -Leaf $HarnessExe) -cne 'sumatrafuzz-harness.exe') { throw 'Unexpected target module executable' }
if (-not (Test-Path -LiteralPath $InputDir -PathType Container)) { throw 'Seed input directory missing' }
$inputs=@(Get-ChildItem -LiteralPath $InputDir -File -Filter '*.pdf')
if ($inputs.Count -lt 2) { throw 'At least two validated PDF seeds required' }
$inputRoot=[IO.Path]::GetFullPath($InputDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
$outputRoot=[IO.Path]::GetFullPath($OutputDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
if ($inputRoot -ieq $outputRoot -or $outputRoot.StartsWith($inputRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'InputDir and OutputDir must be separate' }
$lock=Get-Content -LiteralPath $ToolchainLock -Raw | ConvertFrom-Json
if ($lock.architecture -ne 'x64' -or $lock.winafl_commit -ne 'fd85f38548b14352f4b70ad414f364ea6dc1a769' -or $lock.dynamorio_release -ne 'cronbuild-11.91.20735') { throw 'Unrecognized toolchain lock' }
foreach($name in @('afl_fuzz','winafl_client','drrun')) {
  $tool=$lock.tools.$name
  if (-not $tool -or -not (Test-Path -LiteralPath $tool.path -PathType Leaf)) { throw "Missing tool binary $name" }
  if ((Get-FileHash -LiteralPath $tool.path -Algorithm SHA256).Hash -ne $tool.sha256) { throw "Tool checksum mismatch: $name" }
}
if (-not (Test-Path -LiteralPath $lock.dynamorio_bin64 -PathType Container)) { throw 'DynamoRIO bin64 directory missing' }
$proof=Get-Content -LiteralPath $DebugEvidence -Raw | ConvertFrom-Json
if ($proof.source -ne 'observed-dynamorio-debug' -or $proof.target_module -cne 'sumatrafuzz-harness.exe' -or $proof.target_method -cne 'fuzz_one_file' -or $proof.nargs -ne 1 -or $proof.iterations -lt 10 -or $proof.nonzero_coverage_slots -le 0) { throw 'Valid genuine DynamoRIO evidence required' }
if ((Get-FileHash -LiteralPath $HarnessExe -Algorithm SHA256).Hash -ne $proof.harness_sha256) { throw 'A4 harness checksum mismatch' }
if ((Get-FileHash -LiteralPath $ToolchainLock -Algorithm SHA256).Hash -ne $proof.toolchain_lock_sha256) { throw 'A4 toolchain checksum mismatch' }
$modules=@($proof.observed_modules)
if ($modules.Count -eq 0) { throw 'No observed parser modules' }
foreach($module in $modules) {
  if ($module -cnotmatch '^(PdfFilter|libmupdf)\.dll$') { throw "Unverified parser module: $module" }
}
$launch=[Collections.Generic.List[string]]::new()
foreach ($arg in @('-i',$InputDir,'-o',$OutputDir,'-D',$lock.dynamorio_bin64,'-w',$lock.tools.winafl_client.path,'-t',"$TimeoutMs",'--','-covtype','edge')) { $launch.Add([string]$arg) }
foreach ($module in $modules) { $launch.Add('-coverage_module');$launch.Add([string]$module) }
foreach ($arg in @('-target_module','sumatrafuzz-harness.exe','-target_method','fuzz_one_file','-fuzz_iterations','1000','-nargs','1','--',$HarnessExe,'@@')) { $launch.Add([string]$arg) }
[void](New-Item -ItemType Directory -Path $OutputDir -Force)
$start=[DateTime]::UtcNow
$psi=[Diagnostics.ProcessStartInfo]::new()
$psi.FileName=$lock.tools.afl_fuzz.path
$psi.UseShellExecute=$false
$psi.CreateNoWindow=$true
$psi.WorkingDirectory=(Split-Path -Parent $HarnessExe)
foreach($arg in $launch) { [void]$psi.ArgumentList.Add($arg) }
$psi.Environment['AFL_NO_UI']='1'
$process=[Diagnostics.Process]::new()
$process.StartInfo=$psi
$statsPath=Join-Path $OutputDir 'fuzzer_stats'
$snapshots=[Collections.Generic.List[object]]::new()
$stopped='unknown'
function Read-Stats([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  $table=@{}
  foreach($line in [IO.File]::ReadAllLines($Path)) {
    if($line -match '^\s*([a-zA-Z_]+)\s*:\s*(.*?)\s*$') { $table[$matches[1]]=$matches[2] }
  }
  foreach($key in @('execs_done','paths_total','unique_crashes','unique_hangs')) {
    [long]$parsed=0
    if(-not $table.ContainsKey($key) -or -not [long]::TryParse($table[$key],[ref]$parsed) -or $parsed -lt 0) { return $null }
  }
  return $table
}
try {
  if (-not $process.Start()) { throw 'WinAFL process could not start' }
  while (($span=([DateTime]::UtcNow-$start)).TotalSeconds -lt $DurationSeconds) {
    Start-Sleep -Seconds 2
    $sample=Read-Stats $statsPath
    if ($sample) {
      $snapshots.Add([ordered]@{utc=[DateTime]::UtcNow.ToString('o');execs_done=[long]$sample.execs_done;paths_total=[long]$sample.paths_total})
      if ([long]$sample.execs_done -ge $MinExecutions -and $snapshots.Count -ge 2) {
        $first=$snapshots[0].execs_done
        if ([long]$sample.execs_done -gt $first) { $stopped='execution-goal-observed'; break }
      }
    }
    if ($process.HasExited) { $stopped='process-exited';break }
  }
  if ($stopped -eq 'unknown') { $stopped='duration-limit' }
} finally {
  if (-not $process.HasExited) { $process.Kill($true) }
  [void]$process.WaitForExit(15000)
}
$finish=[DateTime]::UtcNow
$final=Read-Stats $statsPath
if (-not $final) { throw 'WinAFL did not produce parseable real fuzzer_stats' }
$queue=Join-Path $OutputDir 'queue'
if (-not (Test-Path -LiteralPath $queue -PathType Container) -or @(Get-ChildItem -LiteralPath $queue -File).Count -lt 1) { throw 'WinAFL queue is empty or missing' }
$progress=$false
if ($snapshots.Count -ge 2) { $progress=($snapshots[-1].execs_done -gt $snapshots[0].execs_done) }
$report=[ordered]@{
  schema_version=1
  status='measured-unverified'
  started_utc=$start.ToString('o')
  ended_utc=$finish.ToString('o')
  stopped_reason=$stopped
  observed_stats=$final
  first_sample=if($snapshots.Count){$snapshots[0]}else{$null}
  last_sample=if($snapshots.Count){$snapshots[-1]}else{$null}
  samples_count=$snapshots.Count
  execution_progress=$progress
  afl_argv=@($launch)
  debug_evidence_sha256=(Get-FileHash -LiteralPath $DebugEvidence -Algorithm SHA256).Hash.ToLowerInvariant()
  toolchain_lock_sha256=(Get-FileHash -LiteralPath $ToolchainLock -Algorithm SHA256).Hash.ToLowerInvariant()
  harness_sha256=(Get-FileHash -LiteralPath $HarnessExe -Algorithm SHA256).Hash.ToLowerInvariant()
  input_seeds=@($inputs | ForEach-Object { @{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
}
if ([long]$final.execs_done -ge $MinExecutions -and [long]$final.paths_total -ge 1 -and $progress) { $report.status='verified-winAFL-campaign' }
$manifest=Join-Path $OutputDir 'a5-campaign-evidence.json'
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifest -Encoding utf8
Write-Output "WinAFL measured execs_done=$($final.execs_done); paths_total=$($final.paths_total); progresses=$progress; stop=$stopped"
Write-Output "Raw campaign evidence: $manifest"
if ($report.status -ne 'verified-winAFL-campaign') { throw 'WinAFL campaign did not satisfy real execution progression and measured minimum' }
