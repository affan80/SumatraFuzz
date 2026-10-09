#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$SumatraSource,
  [string]$BuildDir = (Join-Path $PSScriptRoot '../../build/a3'),
  [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
  [string]$MSBuildPath = 'MSBuild.exe'
)
$ErrorActionPreference='Stop'
$expected='16c59fde8b824ab54c56f23aef910a6fdd874ad0'
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) { throw 'Windows x64 required' }
if (-not [IO.Path]::IsPathFullyQualified($SumatraSource)) { throw 'SumatraSource must be absolute' }
$actual = (& git -C $SumatraSource rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $actual.Trim() -ne $expected) { throw "Pinned source checkout required: $expected" }
$solution = Join-Path $SumatraSource 'vs2022/SumatraPDF.sln'
if (-not (Test-Path -LiteralPath $solution)) { throw "Pinned Visual Studio solution missing: $solution" }
& $MSBuildPath $solution '/t:PdfFilter' "/p:Configuration=$Configuration" '/p:Platform=x64' '/m'
if ($LASTEXITCODE -ne 0) { throw 'Pinned SumatraPDF PdfFilter build failed' }
$folder = if ($Configuration -eq 'Release') { 'rel64' } else { 'dbg64' }
$filter=Join-Path $SumatraSource "out/$folder/PdfFilter.dll"
if (-not (Test-Path -LiteralPath $filter -PathType Leaf)) { throw "Expected genuine PdfFilter.dll missing: $filter" }
$engine=Join-Path $SumatraSource "out/$folder/libmupdf.dll"
if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) { throw "Expected pinned libmupdf.dll dependency missing: $engine" }
& cmake -S (Join-Path $PSScriptRoot '../../native/sumatra-harness') -B $BuildDir -A x64 '-DSUMATRAFUZZ_REAL_ENGINE=ON' "-DSUMATRAFUZZ_PDF_FILTER_DLL=$filter"
if ($LASTEXITCODE -ne 0) { throw 'A3 CMake configure failed' }
& cmake --build $BuildDir --config $Configuration
if ($LASTEXITCODE -ne 0) { throw 'A3 native build failed' }
$bin=Join-Path $BuildDir $Configuration
Copy-Item -LiteralPath $engine -Destination (Join-Path $bin 'libmupdf.dll') -Force
& ctest --test-dir $BuildDir -C $Configuration --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'A3 real engine tests failed' }
$exe=Join-Path $BuildDir "$Configuration/sumatrafuzz-harness.exe"
# GitHub-hosted PowerShell shells do not populate the Visual Studio C++ tools PATH.
# Locate the genuine x64 dumpbin in the installed MSVC toolchain; do not skip
# the symbol verification if the binary is missing.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
  throw "Visual Studio locator missing: $vswhere"
}
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsRoot)) {
  throw 'Visual Studio x64 C++ toolchain not found'
}
$vcTools = Join-Path $vsRoot 'VC/Tools/MSVC'
if (-not (Test-Path -LiteralPath $vcTools -PathType Container)) {
  throw "MSVC toolchain directory missing: $vcTools"
}
$dumpbin = $null
foreach ($toolVersion in (Get-ChildItem -LiteralPath $vcTools -Directory | Sort-Object Name -Descending)) {
  $candidate = Join-Path $toolVersion.FullName 'bin/Hostx64/x64/dumpbin.exe'
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    $dumpbin = $candidate
    break
  }
}
if (-not $dumpbin) { throw 'x64 dumpbin.exe not found in installed MSVC toolchains' }
Write-Output "Checking WinAFL harness export with: $dumpbin"
$exports = @(& $dumpbin /nologo /exports $exe 2>&1)
if ($LASTEXITCODE -ne 0) {
  throw "dumpbin /exports failed with exit code $LASTEXITCODE : $($exports -join [Environment]::NewLine)"
}
# A successful process exit is not enough: require the actual unmangled
# exported symbol in the PE export table. Printed string matches elsewhere
# (e.g. path or message) must not count.
$exportText = $exports -join [Environment]::NewLine
if ($exportText -notmatch '(?m)^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+fuzz_one_file(?:\s|$)') {
  throw "The harness does not export the required unmangled fuzz_one_file symbol: $exe"
}
Write-Output 'Verified x64 harness export: fuzz_one_file'
$sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $filter).Hash
Write-Output "Validated pinned PdfFilter: $filter SHA256=$sha"
Write-Output "Validated pinned libmupdf: $engine SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $engine).Hash)"
Write-Output "Validated A3 harness: $exe"
