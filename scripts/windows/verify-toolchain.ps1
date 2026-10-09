#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SumatraSource,
  [Parameter(Mandatory)][string]$WinAflExe,
  [Parameter(Mandatory)][string]$WinAflDll,
  [Parameter(Mandatory)][string]$DrrunExe,
  [Parameter(Mandatory)][string]$Workspace,
  [string]$TargetConfig = (Join-Path $PSScriptRoot '../../configs/targets/sumatrapdf-3.6.1rel.json')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Absolute([string]$Path,[string]$Label) {
  if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw "$Label must be an absolute path: $Path" }
}
function Assert-X64PE([string]$Path,[string]$Label) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label missing: $Path" }
  $s = [IO.File]::OpenRead($Path)
  try {
    $r = [IO.BinaryReader]::new($s)
    if ($s.Length -lt 0x90 -or $r.ReadUInt16() -ne 0x5a4d) { throw "$Label is not a PE file" }
    [void]$s.Seek(0x3c,[IO.SeekOrigin]::Begin)
    $pe = $r.ReadInt32()
    if ($pe -lt 0x40 -or $pe -gt ($s.Length - 6)) { throw "$Label invalid PE offset" }
    [void]$s.Seek($pe,[IO.SeekOrigin]::Begin)
    if ($r.ReadUInt32() -ne 0x4550) { throw "$Label invalid PE signature" }
    $machine = $r.ReadUInt16()
    if ($machine -ne 0x8664) { throw "$Label must be x64, found $machine" }
  } finally { $s.Dispose() }
}
function GitResult([string]$Path,[string[]]$Args) {
  $output = @(& git -C $Path @Args 2>&1)
  if ($LASTEXITCODE -ne 0 -or $output.Count -ne 1) { throw "git failed: $($Args -join ' ')" }
  return [string]$output[0]
}

if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw 'Windows x64 required. Windows ARM not supported.'
}
foreach($pair in @(
  @('SumatraSource',$SumatraSource), @('WinAflExe',$WinAflExe),
  @('WinAflDll',$WinAflDll), @('DrrunExe',$DrrunExe),
  @('Workspace',$Workspace), @('TargetConfig',$TargetConfig)
)) { Assert-Absolute $pair[1] $pair[0] }
if (-not (Test-Path -LiteralPath $SumatraSource -PathType Container)) { throw 'Sumatra source directory missing' }
$config = Get-Content -LiteralPath $TargetConfig -Raw | ConvertFrom-Json
if ($config.source_tag -ne '3.6.1rel' -or $config.source_commit -notmatch '^[a-fA-F0-9]{40}
$head = (GitResult $SumatraSource @('rev-parse','HEAD')).Trim()
$tag = (GitResult $SumatraSource @('rev-parse','refs/tags/3.6.1rel^{commit}')).Trim()
if ($head -ne $config.source_commit -or $tag -ne $head) { throw "Source commit/tag drift: HEAD=$head" }
$dirty = @(& git -C $SumatraSource status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) { throw 'Pinned checkout has modified tracked files' }
foreach($pair in @(@('WinAflExe',$WinAflExe),@('WinAflDll',$WinAflDll),@('DrrunExe',$DrrunExe))) { Assert-X64PE $pair[1] $pair[0] }
if (Test-Path -LiteralPath $Workspace -PathType Leaf) { throw 'Workspace must be a directory' }
[void](New-Item -ItemType Directory -Path $Workspace -Force)
$probe = Join-Path $Workspace ('probe-' + [guid]::NewGuid().ToString('N'))
try { [IO.File]::WriteAllText($probe,'probe') } catch { throw "Workspace unwritable: $($_.Exception.Message)" } finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
$lock = [ordered]@{
  schema_version=1
  target_id=$config.target_id
  source_commit=$head
  source_tag=$config.source_tag
  architecture='x64'
  harness_entry=$config.harness_entry
  nargs=1
  coverage_modules=@()
  verified_utc=[DateTime]::UtcNow.ToString('o')
  tools=[ordered]@{}
}
foreach($pair in @(@('afl_fuzz',$WinAflExe),@('winafl_client',$WinAflDll),@('drrun',$DrrunExe))) {
  $lock.tools[$pair[0]] = [ordered]@{
    path=[IO.Path]::GetFullPath($pair[1])
    sha256=(Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash.ToLowerInvariant()
    pe_machine='0x8664'
  }
}
$outfile = Join-Path $Workspace 'target-lock.json'
$tmp = Join-Path $Workspace ('target-lock-'+[guid]::NewGuid().ToString('N')+'.tmp')
try {
  [IO.File]::WriteAllText($tmp,($lock | ConvertTo-Json -Depth 8))
  Move-Item -LiteralPath $tmp -Destination $outfile -Force
} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
Write-Output "x64 toolchain metadata verified: $outfile"
 -or $config.source_repository -ne 'https://github.com/sumatrapdfreader/sumatrapdf' -or $config.target_id -ne 'sumatrapdf-3.6.1rel' -or $config.architecture -ne 'x64' -or $config.harness_entry -ne 'fuzz_one_file' -or $config.nargs -ne 1) { throw 'Unexpected target configuration' }
$head = (GitResult $SumatraSource @('rev-parse','HEAD')).Trim()
$tag = (GitResult $SumatraSource @('rev-parse','refs/tags/3.6.1rel^{commit}')).Trim()
if ($head -ne $config.source_commit -or $tag -ne $head) { throw "Source commit/tag drift: HEAD=$head" }
$dirty = @(& git -C $SumatraSource status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) { throw 'Pinned checkout has modified tracked files' }
foreach($pair in @(@('WinAflExe',$WinAflExe),@('WinAflDll',$WinAflDll),@('DrrunExe',$DrrunExe))) { Assert-X64PE $pair[1] $pair[0] }
if (Test-Path -LiteralPath $Workspace -PathType Leaf) { throw 'Workspace must be a directory' }
[void](New-Item -ItemType Directory -Path $Workspace -Force)
$probe = Join-Path $Workspace ('probe-' + [guid]::NewGuid().ToString('N'))
try { [IO.File]::WriteAllText($probe,'probe') } catch { throw "Workspace unwritable: $($_.Exception.Message)" } finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
$lock = [ordered]@{
  schema_version=1
  target_id=$config.target_id
  source_commit=$head
  source_tag=$config.source_tag
  architecture='x64'
  harness_entry=$config.harness_entry
  nargs=1
  coverage_modules=@()
  verified_utc=[DateTime]::UtcNow.ToString('o')
  tools=[ordered]@{}
}
foreach($pair in @(@('afl_fuzz',$WinAflExe),@('winafl_client',$WinAflDll),@('drrun',$DrrunExe))) {
  $lock.tools[$pair[0]] = [ordered]@{
    path=[IO.Path]::GetFullPath($pair[1])
    sha256=(Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash.ToLowerInvariant()
    pe_machine='0x8664'
  }
}
$outfile = Join-Path $Workspace 'target-lock.json'
$tmp = Join-Path $Workspace ('target-lock-'+[guid]::NewGuid().ToString('N')+'.tmp')
try {
  [IO.File]::WriteAllText($tmp,($lock | ConvertTo-Json -Depth 8))
  Move-Item -LiteralPath $tmp -Destination $outfile -Force
} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
Write-Output "x64 toolchain metadata verified: $outfile"
