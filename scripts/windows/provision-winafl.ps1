#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Workspace,
  [Parameter(Mandatory)][string]$SumatraSource
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$winAflCommit = 'fd85f38548b14352f4b70ad414f364ea6dc1a769'
$drRelease = 'DynamoRIO-Windows-11.91.20735.zip'
$drUrl = "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-11.91.20735/$drRelease"
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw 'Windows x64 required'
}
if (-not [IO.Path]::IsPathFullyQualified($Workspace) -or -not [IO.Path]::IsPathFullyQualified($SumatraSource)) {
  throw 'Workspace and SumatraSource must be absolute'
}
$null = New-Item -ItemType Directory -Path $Workspace -Force
$archive = Join-Path $Workspace $drRelease
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
  Invoke-WebRequest -Uri $drUrl -OutFile $archive -ErrorAction Stop
}
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$unpacked = Join-Path $Workspace 'dynamorio'
if (-not (Test-Path -LiteralPath $unpacked -PathType Container)) {
  Expand-Archive -LiteralPath $archive -DestinationPath $unpacked -ErrorAction Stop
}
$binCandidates = @(Get-ChildItem -LiteralPath $unpacked -Filter 'drrun.exe' -Recurse -File |
  Where-Object { $_.DirectoryName -match '[\\/]bin64$' })
$installs = @()
foreach ($binary in $binCandidates) {
  $candidateRoot = Split-Path (Split-Path $binary.FullName -Parent) -Parent
  $candidateConfig = Join-Path $candidateRoot 'cmake/DynamoRIOConfig.cmake'
  if (Test-Path -LiteralPath $candidateConfig -PathType Leaf) {
    $installs += [pscustomobject]@{ drrun = $binary.FullName; root = $candidateRoot; config = $candidateConfig }
  }
}
if ($installs.Count -ne 1) {
  $locations = $binCandidates.FullName -join '; '
  throw "Expected one x64 DynamoRIO SDK installation; found $($installs.Count). Candidates: $locations"
}
$drrun = $installs[0].drrun
$drRoot = $installs[0].root
$drConfig = $installs[0].config
# Fail early and explicitly if the pinned SDK does not provide the API
# required by WinAFL commit fd85f385. Earlier DynamoRIO 11.3 fails the link
# with unresolved drmgr_register_exit_event.
$drmgrHeaders = @(Get-ChildItem -LiteralPath (Join-Path $drRoot 'ext/include') -Filter 'drmgr.h' -Recurse -File -ErrorAction Stop)
if ($drmgrHeaders.Count -ne 1) { throw 'Expected a unique drmgr.h in pinned DynamoRIO SDK' }
if (-not (Select-String -LiteralPath $drmgrHeaders[0].FullName -Pattern 'drmgr_register_exit_event' -Quiet)) {
  throw 'Incompatible DynamoRIO SDK: drmgr_register_exit_event API is not declared'
}
Write-Output "Selected SDK-backed x64 DynamoRIO: $drrun"
$src = Join-Path $Workspace 'winafl-source'
if (-not (Test-Path -LiteralPath $src -PathType Container)) {
  & git clone 'https://github.com/googleprojectzero/winafl.git' $src
  if ($LASTEXITCODE -ne 0) { throw 'WinAFL clone failed' }
}
& git -C $src checkout --detach $winAflCommit
if ($LASTEXITCODE -ne 0) { throw 'Pinned WinAFL checkout failed' }
$actual = (& git -C $src rev-parse HEAD).Trim()
if ($actual -ne $winAflCommit) { throw 'WinAFL revision mismatch' }
$build = Join-Path $Workspace 'winafl-build'
& cmake -S $src -B $build -A x64 "-DDynamoRIO_DIR=$(Split-Path $drConfig -Parent)" '-DINTELPT=OFF' '-DTINYINST=OFF' '-DUSE_DRSYMS=OFF'
if ($LASTEXITCODE -ne 0) { throw 'WinAFL configure failed' }
& cmake --build $build --config Release --target afl-fuzz winafl
if ($LASTEXITCODE -ne 0) { throw 'WinAFL build failed' }
$aflCandidates = @(Get-ChildItem -LiteralPath $build -Filter 'afl-fuzz.exe' -Recurse -File)
$dllCandidates = @(Get-ChildItem -LiteralPath $build -Filter 'winafl.dll' -Recurse -File)
if ($aflCandidates.Count -ne 1 -or $dllCandidates.Count -ne 1) { throw 'WinAFL x64 artifacts missing/ambiguous' }
$lockDir = Join-Path $Workspace 'locks'
$null = New-Item -ItemType Directory -Path $lockDir -Force
& (Join-Path $PSScriptRoot 'verify-toolchain.ps1') -SumatraSource $SumatraSource `
   -WinAflExe $aflCandidates[0].FullName -WinAflDll $dllCandidates[0].FullName `
   -DrrunExe $drrun -Workspace $lockDir
if ($LASTEXITCODE -ne 0) { throw 'Real WinAFL toolchain validation failed' }
$lockPath = Join-Path $lockDir 'target-lock.json'
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'target-lock.json missing' }
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$lock | Add-Member -NotePropertyName acquisition -NotePropertyValue ([ordered]@{
  dynamorio_release = 'cronbuild-11.91.20735'
  dynamorio_archive_url = $drUrl
  dynamorio_archive_sha256 = $archiveHash
  dynamorio_source_commit = '53f74f09dcb548531d08b2d76b37daa05fe58908'
  winafl_source_commit = $winAflCommit
  winafl_repository = 'https://github.com/googleprojectzero/winafl'
}) -Force
$lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $lockPath -Encoding utf8
Write-Output "Real toolchain lock: $lockPath"
