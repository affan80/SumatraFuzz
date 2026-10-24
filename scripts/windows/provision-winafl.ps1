#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Workspace,
  [Parameter(Mandatory)][string]$SumatraSource
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$winAflCommit = 'fd85f38548b14352f4b70ad414f364ea6dc1a769'
$patchPath = Join-Path $PSScriptRoot 'patches/winafl-private-namespace.patch'
$expectedPatchHash = 'bd16e8457a0f7b61f602b6d03c3ef740496382f559f2852335f6be1e6c9c8d33'
if (-not (Test-Path -LiteralPath $patchPath -PathType Leaf)) { throw 'Reviewed WinAFL namespace patch missing' }
$patchHash = (Get-FileHash -LiteralPath $patchPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($patchHash -cne $expectedPatchHash) { throw 'Reviewed WinAFL namespace patch digest mismatch' }
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
# GitHub's published SHA-256 digest for this exact immutable release asset.
# Reject tampering, accidental asset replacement, and partial downloads.
$expectedArchiveHash = '55724756d2646aa47ef3f67046b67c090ddc7b26f3f14d63fdc144a571d6a0e6'
if ($archiveHash -ne $expectedArchiveHash) {
  throw "Pinned DynamoRIO archive SHA-256 mismatch. Got $archiveHash; expected $expectedArchiveHash"
}
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
# A repeated acquisition must use a fresh checkout; never reset or silently reuse patched source.
$sourceState = @(& git -C $src status --porcelain --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $sourceState.Count -ne 0) { throw 'WinAFL source is dirty or already patched' }
& git -C $src checkout --detach $winAflCommit
if ($LASTEXITCODE -ne 0) { throw 'Pinned WinAFL checkout failed' }
$actual = (& git -C $src rev-parse HEAD).Trim()
if ($actual -ne $winAflCommit) { throw 'WinAFL revision mismatch' }
& git -C $src apply --check -- $patchPath
if ($LASTEXITCODE -ne 0) { throw 'Pinned WinAFL namespace patch does not apply cleanly' }
& git -C $src apply -- $patchPath
if ($LASTEXITCODE -ne 0) { throw 'Pinned WinAFL namespace patch application failed' }
$build = Join-Path $Workspace 'winafl-build'
& cmake -S $src -B $build -A x64 "-DDynamoRIO_DIR=$(Split-Path $drConfig -Parent)" '-DINTELPT=OFF' '-DTINYINST=OFF' '-DUSE_DRSYMS=OFF'
if ($LASTEXITCODE -ne 0) { throw 'WinAFL configure failed' }
& cmake --build $build --config Release --target afl-fuzz winafl
if ($LASTEXITCODE -ne 0) { throw 'WinAFL build failed' }
$aflCandidates = @(Get-ChildItem -LiteralPath $build -Filter 'afl-fuzz.exe' -Recurse -File)
$dllCandidates = @(Get-ChildItem -LiteralPath $build -Filter 'winafl.dll' -Recurse -File)
if ($aflCandidates.Count -ne 1 -or $dllCandidates.Count -ne 1) { throw 'WinAFL x64 artifacts missing/ambiguous' }
$cmakeCache = Join-Path $build 'CMakeCache.txt'
$compilerEntries = @(Get-Content -LiteralPath $cmakeCache | Where-Object { $_ -match '^CMAKE_C_COMPILER:FILEPATH=' })
if ($compilerEntries.Count -ne 1) { throw 'Cannot resolve the configured Visual Studio compiler from CMake' }
$compilerPath = $compilerEntries[0] -replace '^CMAKE_C_COMPILER:FILEPATH=', ''
$compilerDirectory = Split-Path $compilerPath -Parent
$dumpbin = Join-Path $compilerDirectory 'dumpbin.exe'
if (-not (Test-Path -LiteralPath $dumpbin -PathType Leaf)) { throw 'Visual Studio dumpbin.exe is required to inspect WinAFL runtime imports' }
$compilerToolsetDirectory = $compilerPath
for ($level = 0; $level -lt 3; $level++) { $compilerToolsetDirectory = Split-Path $compilerToolsetDirectory -Parent }
$compilerToolsetVersion = Split-Path -Leaf $compilerToolsetDirectory
if ($compilerToolsetVersion -notmatch '^\d+\.\d+\.') { throw 'Unexpected Visual Studio compiler toolset path' }
$compilerRuntimeFamily = ($compilerToolsetVersion -split '\.')[0..1] -join '.'
$redistRoots = @()
if ($env:VCToolsRedistDir -and (Test-Path -LiteralPath $env:VCToolsRedistDir -PathType Container)) {
  $redistRoots += $env:VCToolsRedistDir
} else {
  $msvcRoot = Split-Path -Parent $compilerToolsetDirectory
  $toolsRoot = Split-Path -Parent $msvcRoot
  $vcRoot = Split-Path -Parent $toolsRoot
  $candidate = Join-Path $vcRoot 'Redist/MSVC'
  if (Test-Path -LiteralPath $candidate -PathType Container) { $redistRoots += $candidate }
}
if ($redistRoots.Count -eq 0) { throw 'Cannot locate Visual Studio x64 VC runtime redistributables' }
$runtimeDependencies = @{}
foreach ($binary in @($aflCandidates[0].FullName, $dllCandidates[0].FullName)) {
  $imports = @(& $dumpbin /nologo /dependents $binary)
  if ($LASTEXITCODE -ne 0) { throw "Cannot inspect WinAFL imports: $(Split-Path $binary -Leaf)" }
  $importNames = @($imports | ForEach-Object { "$($_)".Trim() } |
    Where-Object { $_ -match '^[A-Za-z0-9_.+-]+\.dll$' } | Select-Object -Unique)
  foreach ($name in $importNames) {
    if ($name -match '^(?i:api-ms-win-|ext-ms-win-)') { continue }
    $systemDll = Join-Path (Join-Path $env:SystemRoot 'System32') $name
    $localDll = Join-Path (Split-Path $binary -Parent) $name
    $dynamoDll = Join-Path (Split-Path $drrun -Parent) $name
    if ((Test-Path -LiteralPath $systemDll -PathType Leaf) -or
        (Test-Path -LiteralPath $localDll -PathType Leaf) -or
        (Test-Path -LiteralPath $dynamoDll -PathType Leaf)) { continue }
    $candidates = @()
    foreach ($root in $redistRoots) {
      $candidates += @(Get-ChildItem -LiteralPath $root -Filter $name -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
          $_.FullName -match '[\\/]x64[\\/]Microsoft\.VC[0-9]+\.CRT[\\/]' -and
          $_.FullName -match "[\\/]MSVC[\\/]$([regex]::Escape($compilerRuntimeFamily))\."
        })
    }
    $candidates = @($candidates | Sort-Object -Property FullName -Unique)
    if ($candidates.Count -ne 1) { throw "Missing or ambiguous Microsoft x64 runtime import: $name" }
    $signature = Get-AuthenticodeSignature -LiteralPath $candidates[0].FullName
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
      throw "WinAFL runtime import is not signed by Microsoft: $name"
    }
    $destination = Join-Path (Split-Path $aflCandidates[0].FullName -Parent) $name
    Copy-Item -LiteralPath $candidates[0].FullName -Destination $destination -Force
    $runtimeDependencies[$name.ToLowerInvariant()] = [ordered]@{
      path = [IO.Path]::GetFullPath($destination)
      sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }
}
$lockDir = Join-Path $Workspace 'locks'
$null = New-Item -ItemType Directory -Path $lockDir -Force
& (Join-Path $PSScriptRoot 'verify-toolchain.ps1') -SumatraSource $SumatraSource `
   -WinAflExe $aflCandidates[0].FullName -WinAflDll $dllCandidates[0].FullName `
   -DrrunExe $drrun -Workspace $lockDir -WinAflPatchSha256 $patchHash
if ($LASTEXITCODE -ne 0) { throw 'Real WinAFL toolchain validation failed' }
$lockPath = Join-Path $lockDir 'target-lock.json'
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'target-lock.json missing' }
$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
$lock | Add-Member -NotePropertyName runtime_dependencies -NotePropertyValue @($runtimeDependencies.Values) -Force
$lock | Add-Member -NotePropertyName acquisition -NotePropertyValue ([ordered]@{
  dynamorio_release = 'cronbuild-11.91.20735'
  dynamorio_archive_url = $drUrl
  dynamorio_archive_sha256 = $archiveHash
  dynamorio_source_commit = '53f74f09dcb548531d08b2d76b37daa05fe58908'
  winafl_source_commit = $winAflCommit
  winafl_patch_sha256 = $patchHash
  winafl_repository = 'https://github.com/googleprojectzero/winafl'
}) -Force
$lock | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $lockPath -Encoding utf8
Write-Output "Real toolchain lock: $lockPath"
