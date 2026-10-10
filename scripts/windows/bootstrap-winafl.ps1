#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Workspace,
  [string]$WinAflCommit='fd85f38548b14352f4b70ad414f364ea6dc1a769',
  [string]$DynamoRioTag='release_11.3.0-1'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'Windows x64 required' }
if (-not [IO.Path]::IsPathFullyQualified($Workspace)) { throw 'Workspace must be absolute' }
if ($DynamoRioTag -ne 'release_11.3.0-1' -or $WinAflCommit -ne 'fd85f38548b14352f4b70ad414f364ea6dc1a769') { throw 'Unexpected toolchain source revision' }
[void](New-Item -Type Directory -Path $Workspace -Force)
$archive=Join-Path $Workspace 'DynamoRIO-Windows-11.3.0.zip'
$uri='https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Windows-11.3.0.zip'
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { Invoke-WebRequest -Uri $uri -OutFile $archive -MaximumRedirection 5 }
$archiveHash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$unpack=Join-Path $Workspace 'DynamoRIO'
if (-not (Test-Path -LiteralPath $unpack -PathType Container)) { Expand-Archive -LiteralPath $archive -DestinationPath $unpack }
$drConfig=Get-ChildItem -LiteralPath $unpack -Filter 'DynamoRIOConfig.cmake' -File -Recurse | Select-Object -First 1
if (-not $drConfig) { throw 'DynamoRIO CMake package missing in downloaded artifact' }
$drRoot=$drConfig.Directory.Parent.FullName
$drrun=Join-Path $drRoot 'bin64/drrun.exe'
if (-not (Test-Path -LiteralPath $drrun -PathType Leaf)) { throw 'Windows x64 drrun.exe missing' }
$wsrc=Join-Path $Workspace 'winafl-src'
if (-not (Test-Path -LiteralPath $wsrc -PathType Container)) {
  & git clone https://github.com/googleprojectzero/winafl.git $wsrc
  if ($LASTEXITCODE -ne 0) { throw 'WinAFL clone failed' }
}
& git -C $wsrc checkout --detach $WinAflCommit
if ($LASTEXITCODE -ne 0 -or ((& git -C $wsrc rev-parse HEAD).Trim() -ne $WinAflCommit)) { throw 'WinAFL checkout mismatch' }
$wbuild=Join-Path $Workspace 'winafl-build'
& cmake -S $wsrc -B $wbuild -G 'Visual Studio 17 2022' -A x64 "-DDynamoRIO_DIR=$($drConfig.Directory.FullName)" '-DINTELPT=OFF' '-DTINYINST=OFF'
if ($LASTEXITCODE -ne 0) { throw 'WinAFL configuration failed' }
& cmake --build $wbuild --config Release --target afl-fuzz winafl
if ($LASTEXITCODE -ne 0) { throw 'WinAFL build failed against pinned DynamoRIO' }
$afl=Get-ChildItem -LiteralPath $wbuild -Filter 'afl-fuzz.exe' -File -Recurse | Where-Object { $_.FullName -match '[\\/]Release[\\/]' } | Select-Object -First 1
$client=Get-ChildItem -LiteralPath $wbuild -Filter 'winafl.dll' -File -Recurse | Where-Object { $_.FullName -match '[\\/]Release[\\/]' } | Select-Object -First 1
if (-not $afl -or -not $client) { throw 'Required WinAFL x64 binaries missing after build' }
$tools=[ordered]@{}
foreach($pair in @(@('afl_fuzz',$afl.FullName),@('winafl_client',$client.FullName),@('drrun',$drrun))) {
  $tools[$pair[0]]=[ordered]@{path=$pair[1];sha256=(Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$lock=[ordered]@{
  schema_version=1
  architecture='x64'
  winafl_repository='https://github.com/googleprojectzero/winafl'
  winafl_commit=$WinAflCommit
  dynamorio_release=$DynamoRioTag
  dynamorio_archive_url=$uri
  dynamorio_archive_sha256=$archiveHash
  dynamorio_cmake=$drConfig.Directory.FullName
  dynamorio_bin64=(Join-Path $drRoot 'bin64')
  tools=$tools
}
$lockPath=Join-Path $Workspace 'winafl-toolchain-lock.json'
$lock | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $lockPath -Encoding utf8
Write-Output "Built real WinAFL against pinned DynamoRIO and captured hashes: $lockPath"
