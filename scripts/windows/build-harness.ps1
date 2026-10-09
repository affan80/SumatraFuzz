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
& dumpbin /exports $exe | Select-String -Pattern 'fuzz_one_file' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'dumpbin export check failed' }
$sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $filter).Hash
Write-Output "Validated pinned PdfFilter: $filter SHA256=$sha"
Write-Output "Validated pinned libmupdf: $engine SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $engine).Hash)"
Write-Output "Validated A3 harness: $exe"
