#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [Parameter(Mandatory)][string]$WorldWriteSentinel,
    [Parameter(Mandatory)][string]$AuthenticatedWriteSentinel,
    [Parameter(Mandatory)][string]$WorldLowWriteSentinel,
    [Parameter(Mandatory)][string]$AuthenticatedLowWriteSentinel
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'AppContainer API feasibility probe is Windows-only' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'AppContainer API feasibility probe requires an ordinary nonadministrator identity'
}
if (-not [IO.Path]::IsPathFullyQualified($RepoRoot)) { throw 'RepoRoot must be absolute' }
foreach ($path in @($WorldWriteSentinel, $AuthenticatedWriteSentinel, $WorldLowWriteSentinel, $AuthenticatedLowWriteSentinel)) {
    if (-not [IO.Path]::IsPathFullyQualified($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'AppContainer broad-ACL sentinel fixture is missing'
    }
}
$probe = Join-Path $RepoRoot 'build/worker-supervisor/Debug/process_probe.exe'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) { throw 'Native AppContainer probe executable is missing' }
$output = Join-Path $env:TEMP ('appcontainer-output-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $output
try {
    & $probe --appcontainer-probe $output $WorldWriteSentinel $AuthenticatedWriteSentinel $WorldLowWriteSentinel $AuthenticatedLowWriteSentinel
    if ($LASTEXITCODE -ne 0) { throw "AppContainer API feasibility probe failed: exit $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath (Join-Path $output 'appcontainer-probe-result') -PathType Leaf)) {
        throw 'AppContainer did not create its isolated per-run output marker'
    }
    Write-Output 'Verified nonadministrator AppContainer API probe; native output records profile and temp paths'
} finally {
    if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Recurse -Force }
}
