#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ToolchainLock,
  [Parameter(Mandatory)][string]$HarnessExe,
  [Parameter(Mandatory)][string]$InputPdf,
  [Parameter(Mandatory)][string]$LogDir,
  [ValidateRange(10,10000)][int]$Iterations=10
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'Windows x64 required' }
foreach($pair in @(@('ToolchainLock',$ToolchainLock),@('HarnessExe',$HarnessExe),@('InputPdf',$InputPdf),@('LogDir',$LogDir))) {
  if (-not [IO.Path]::IsPathFullyQualified($pair[1])) { throw "$($pair[0]) must be absolute" }
}
if (-not (Test-Path -LiteralPath $HarnessExe -PathType Leaf)) { throw 'Harness executable missing' }
if (-not (Test-Path -LiteralPath $InputPdf -PathType Leaf)) { throw 'PDF input missing' }
$lock=Get-Content -LiteralPath $ToolchainLock -Raw | ConvertFrom-Json
if ($lock.architecture -ne 'x64' -or $lock.winafl_commit -ne 'fd85f38548b14352f4b70ad414f364ea6dc1a769' -or $lock.dynamorio_release -ne 'release_11.3.0-1') { throw 'Unrecognized toolchain revision' }
foreach($name in @('drrun','winafl_client','afl_fuzz')) {
  $tool=$lock.tools.$name
  if (-not (Test-Path -LiteralPath $tool.path -PathType Leaf)) { throw "Missing tool: $name" }
  if ((Get-FileHash -LiteralPath $tool.path -Algorithm SHA256).Hash -ne $tool.sha256) { throw "Tool checksum mismatch: $name" }
}
$target='sumatrafuzz-harness.exe'
if ((Split-Path -Leaf $HarnessExe) -cne $target) { throw "Expected named target module: $target" }
[void](New-Item -ItemType Directory -Path $LogDir -Force)
$drrun=$lock.tools.drrun.path
$client=$lock.tools.winafl_client.path
function Invoke-DebugCycle([string]$SessionDir,[string[]]$Modules) {
  [void](New-Item -ItemType Directory -Path $SessionDir -Force)
  $argsList=@('-c',$client,'-debug','-logdir',$SessionDir,'-covtype','edge')
  foreach($m in $Modules){$argsList+=@('-coverage_module',$m)}
  $argsList+=@('-target_module',$target,'-target_method','fuzz_one_file','-fuzz_iterations',"$Iterations",'-nargs','1','--',$HarnessExe,$InputPdf)
  & $drrun @argsList 2>&1 | Out-File -LiteralPath (Join-Path $SessionDir 'process-output.txt') -Encoding utf8
  if ($LASTEXITCODE -ne 0) { throw "DynamoRIO debug returned nonzero ($LASTEXITCODE)" }
  $logs=@(Get-ChildItem -LiteralPath $SessionDir -File -Filter '*.log')
  if ($logs.Count -eq 0) { throw "Missing actual WinAFL debug log in $SessionDir" }
  $raw=($logs | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
  $pre=([regex]::Matches($raw,'pre_fuzz_handler')).Count
  $post=([regex]::Matches($raw,'post_fuzz_handler')).Count
  if ($pre -ne $Iterations -or $post -ne $Iterations) {
    throw "Expected $Iterations pre/post handlers; observed pre=$pre post=$post"
  }
  return $raw
}
$discovery=Join-Path $LogDir '01-discovery'
$raw=Invoke-DebugCycle $discovery @($target)
# Module names are admitted ONLY if the live debug log mentions them.
$observed=@()
foreach($name in @('PdfFilter.dll','libmupdf.dll')) {
  if ($raw -match [regex]::Escape($name)) { $observed+= $name }
}
if ($observed.Count -eq 0) { throw 'No genuine parser DLL module observed in WinAFL debug log' }
$coverageRun=Join-Path $LogDir '02-parser-coverage'
$raw2=Invoke-DebugCycle $coverageRun $observed
if ($raw2 -notmatch '(?i)coverage|afl.*map') { throw 'No coverage-map evidence found in parser instrumentation log' }
$manifest=[ordered]@{
  source='observed-dynamorio-debug'
  checked_utc=[DateTime]::UtcNow.ToString('o')
  target_module=$target
  target_method='fuzz_one_file'
  nargs=1
  iterations=$Iterations
  observed_modules=$observed
  harness_sha256=(Get-FileHash -LiteralPath $HarnessExe -Algorithm SHA256).Hash.ToLowerInvariant()
  input_sha256=(Get-FileHash -LiteralPath $InputPdf -Algorithm SHA256).Hash.ToLowerInvariant()
  toolchain_lock_sha256=(Get-FileHash -LiteralPath $ToolchainLock -Algorithm SHA256).Hash.ToLowerInvariant()
  raw_log_directory=[IO.Path]::GetFullPath($LogDir)
}
$out=Join-Path $LogDir 'a4-debug-evidence.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $out -Encoding utf8
Write-Output "Observed $Iterations real pre/post cycles and parser modules: $($observed -join ', ')"
Write-Output "A4 evidence (requires raw logs): $out"
