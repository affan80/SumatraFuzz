#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$EvidenceManifest,
  [Parameter(Mandatory)][string]$RunDir,
  [Parameter(Mandatory)][string]$HarnessExe,
  [Parameter(Mandatory)][string]$Finding
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw 'Windows x64 required for genuine SumatraPDF replay'
}
foreach($inputPath in @($EvidenceManifest,$RunDir,$HarnessExe)) {
  if (-not [IO.Path]::IsPathFullyQualified($inputPath)) { throw "Absolute path required: $inputPath" }
}
if ($Finding -notmatch '^(crashes|hangs)/id_[A-Za-z0-9_.+,-]+$') {
  throw 'Finding must name an inventoried crashes/id_* or hangs/id_* artifact'
}
if (-not (Test-Path -LiteralPath $EvidenceManifest -PathType Leaf)) { throw 'Evidence manifest missing' }
if (-not (Test-Path -LiteralPath $RunDir -PathType Container)) { throw 'Campaign directory missing' }
if (-not (Test-Path -LiteralPath $HarnessExe -PathType Leaf)) { throw 'Real harness executable missing' }

$evidence = Get-Content -LiteralPath $EvidenceManifest -Raw | ConvertFrom-Json
if ($evidence.source_commit -ne '16c59fde8b824ab54c56f23aef910a6fdd874ad0') {
  throw 'Evidence does not match pinned SumatraPDF source'
}
$collection = if ($Finding.StartsWith('crashes/')) { @($evidence.crashes) } else { @($evidence.hangs) }
$matches = @($collection | Where-Object { $_.path -ceq $Finding })
if ($matches.Count -ne 1 -or $matches[0].classification -ne 'untriaged') {
  throw "Finding is not an authentic untriaged sample in the evidence inventory: $Finding"
}
$record = $matches[0]
$root = [IO.Path]::GetFullPath($RunDir).TrimEnd('\') + '\'
$artifact = [IO.Path]::GetFullPath((Join-Path $RunDir ($Finding -replace '/','\')))
if (-not $artifact.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Finding path escapes campaign' }
# Check lexical parents before reading the sample. Resolving first could hide a junction.
$directory = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($artifact))
while ($null -ne $directory) {
  if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Reparse-point directory is prohibited: $($directory.FullName)"
  }
  $directory = $directory.Parent
}
if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw 'Recorded finding file missing' }
$attributes = [IO.File]::GetAttributes($artifact)
if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse-point finding files are prohibited' }
if ((Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash -ne $record.sha256) {
  throw 'Finding SHA-256 mismatch: sample changed since evidence collection'
}
if ((Get-FileHash -LiteralPath $HarnessExe -Algorithm SHA256).Hash -ne $evidence.binary_hashes.harness) {
  throw 'Harness SHA-256 mismatch: executable changed since the campaign'
}

foreach ($name in @('PdfFilter.dll','libmupdf.dll')) {
  $parser = Join-Path ([IO.Path]::GetDirectoryName($HarnessExe)) $name
  if (-not (Test-Path -LiteralPath $parser -PathType Leaf)) { throw "Parser binary missing: $name" }
  $expected = $evidence.binary_hashes.PSObject.Properties[$name]
  if ($null -eq $expected -or (Get-FileHash -LiteralPath $parser -Algorithm SHA256).Hash -ne $expected.Value) {
    throw "Parser SHA-256 mismatch: $name changed since the campaign"
  }
}

$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Replay must run as a nonadministrator inside an isolated Windows x64 environment'
}
# Direct argv invocation, no shell interpolation and no exception masking.
& $HarnessExe $artifact
$exitCode=$LASTEXITCODE
Write-Output "Untriaged $Finding replay exit code: $exitCode (0=parsed, 1=rejected, other=investigate)"
if ($exitCode -ne 0 -and $exitCode -ne 1) { throw "Unexpected replay termination (untriaged): exit code $exitCode" }
