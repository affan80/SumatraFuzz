#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot,
    [switch]$Child
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'Ephemeral Windows x64 GitHub runner required'
}
if (-not [IO.Path]::IsPathFullyQualified($RepoRoot)) { throw 'RepoRoot must be absolute' }
if ($Child) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Supervisor containment check requires a nonadministrator process'
    }
    Set-Location -LiteralPath $RepoRoot
    Write-Output "Verified standard-user supervisor check: $($identity.Name)"
    & (Join-Path $RepoRoot 'scripts/windows/tests/appcontainer-probe.ps1') -RepoRoot $RepoRoot `
      -WorldWriteSentinel $env:SUMATRAFUZZ_WORLD_WRITE_PROBE `
      -AuthenticatedWriteSentinel $env:SUMATRAFUZZ_AUTHENTICATED_WRITE_PROBE `
      -WorldLowWriteSentinel $env:SUMATRAFUZZ_WORLD_LOW_WRITE_PROBE `
      -AuthenticatedLowWriteSentinel $env:SUMATRAFUZZ_AUTHENTICATED_LOW_WRITE_PROBE
    $node = (Get-Command node -ErrorAction Stop).Source
    & $node --test test/supervisor-windows.check.cjs
    if ($LASTEXITCODE -ne 0) { throw "Supervisor containment check failed: exit $LASTEXITCODE" }
    exit 0
}
$account = 'sf-probe-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$password = ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'aA1!') -AsPlainText -Force
$temp = Join-Path $RepoRoot "runs/$account"
$protected = Join-Path $temp 'protected'
# Resource admission requires trusted ownership/metadata ACLs all the way to
# the volume root. The checkout is runner-owned and is not such a boundary.
$resourceRoot = Join-Path ([IO.Path]::GetPathRoot($RepoRoot)) "sf-resources-$account"
$credentialSentinel = Join-Path $protected 'credential-sentinel'
$worldWriteSentinel = Join-Path $temp 'world-write-sentinel'
$authenticatedWriteSentinel = Join-Path $temp 'authenticated-write-sentinel'
$worldLowWriteSentinel = Join-Path $temp 'world-low-write-sentinel'
$authenticatedLowWriteSentinel = Join-Path $temp 'authenticated-low-write-sentinel'
$proc = $null
$started = $false
try {
    $user = New-LocalUser -Name $account -Password $password -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $user
    $null = New-Item -ItemType Directory -Path $temp -Force
    & icacls $temp /setintegritylevel '(OI)(CI)L'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot provision low-integrity output fixture' }
    & icacls $RepoRoot /grant "${account}:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant supervisor user read access' }
    & icacls $temp /grant "${account}:(OI)(CI)M"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant supervisor user temporary storage access' }
    $volumeRoot = [IO.Path]::GetPathRoot($RepoRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $ancestor = [IO.Path]::GetFullPath((Split-Path -Parent $RepoRoot))
    while ($true) {
      & icacls $ancestor /grant '*S-1-5-12:(X)'
      if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare restricted-code traversal for the containment fixture' }
      if ([IO.Path]::GetFullPath($ancestor).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq $volumeRoot) { break }
      $ancestor = Split-Path -Parent $ancestor
      if (-not $ancestor) { throw 'Cannot reach the volume root for the containment fixture' }
    }
    & icacls $RepoRoot /grant '*S-1-5-12:(X)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare restricted-code traversal for the containment fixture' }
    $runsRoot = Join-Path $RepoRoot 'runs'
    & icacls $runsRoot /grant '*S-1-5-12:(X)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare restricted-code traversal for the containment fixture' }
    & icacls $temp /grant '*S-1-5-12:(RX)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the restricted-code ancestor traversal fixture' }
    Set-Content -LiteralPath $worldWriteSentinel -Value 'world-write access probe' -NoNewline
    Set-Content -LiteralPath $authenticatedWriteSentinel -Value 'authenticated-users write access probe' -NoNewline
    Set-Content -LiteralPath $worldLowWriteSentinel -Value 'world low-integrity write access probe' -NoNewline
    Set-Content -LiteralPath $authenticatedLowWriteSentinel -Value 'authenticated low-integrity write access probe' -NoNewline
    foreach ($fixture in @($worldWriteSentinel, $authenticatedWriteSentinel, $worldLowWriteSentinel, $authenticatedLowWriteSentinel)) {
      & icacls $fixture /inheritance:r
      if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the broad-ACL write probe fixture' }
      & icacls $fixture /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
      if ($LASTEXITCODE -ne 0) { throw 'Cannot grant administrator cleanup access to the write probe fixture' }
      $integrity = if ($fixture -like '*-low-*') { 'L' } else { 'M' }
      & icacls $fixture /setintegritylevel $integrity
      if ($LASTEXITCODE -ne 0) { throw 'Cannot set the broad-ACL write probe integrity level' }
    }
    & icacls $worldWriteSentinel /grant '*S-1-1-0:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the World-writable probe fixture' }
    & icacls $authenticatedWriteSentinel /grant '*S-1-5-11:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the Authenticated Users writable probe fixture' }
    & icacls $worldLowWriteSentinel /grant '*S-1-1-0:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the low-integrity World-writable probe fixture' }
    & icacls $authenticatedLowWriteSentinel /grant '*S-1-5-11:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the low-integrity Authenticated Users writable probe fixture' }
    $null = New-Item -ItemType Directory -Path $protected -Force
    Set-Content -LiteralPath $credentialSentinel -Value 'service-only trust and DPAPI sentinel' -NoNewline
    $standardUser = "$env:COMPUTERNAME\$account"
    $null = New-Item -ItemType Directory -Path $resourceRoot
    & icacls $resourceRoot /inheritance:r
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect resource admission fixture' }
    & icacls $resourceRoot /grant:r "${standardUser}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set resource admission fixture ACL' }
    & icacls $resourceRoot /setowner '*S-1-5-32-544'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set trusted resource fixture owner' }
    & icacls $resourceRoot /setintegritylevel '(OI)(CI)L'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set resource fixture integrity' }
    & icacls $protected /grant:r "${standardUser}:(RX)" '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant standard-user access to inspect the protected fixture' }
    & icacls $credentialSentinel /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot restrict supervisor credential fixture to SYSTEM and administrators' }
    & icacls $protected /inheritance:r
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect supervisor credential fixture directory' }
    & icacls $credentialSentinel /inheritance:r
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect supervisor credential fixture file' }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = (Get-Command pwsh -ErrorAction Stop).Source
    $info.WorkingDirectory = $RepoRoot
    $info.UseShellExecute = $false
    $info.UserName = $account
    $info.Domain = $env:COMPUTERNAME
    $info.Password = $password
    $info.LoadUserProfile = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in @('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-RepoRoot',$RepoRoot,'-Child')) {
        $info.ArgumentList.Add($arg)
    }
    foreach ($name in @('GITHUB_TOKEN','GH_TOKEN','ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN')) {
        [void]$info.Environment.Remove($name)
    }
    $info.Environment['SUMATRAFUZZ_PROTECTED_DIR'] = $protected
    $info.Environment['SUMATRAFUZZ_WORLD_WRITE_PROBE'] = $worldWriteSentinel
    $info.Environment['SUMATRAFUZZ_AUTHENTICATED_WRITE_PROBE'] = $authenticatedWriteSentinel
    $info.Environment['SUMATRAFUZZ_WORLD_LOW_WRITE_PROBE'] = $worldLowWriteSentinel
    $info.Environment['SUMATRAFUZZ_AUTHENTICATED_LOW_WRITE_PROBE'] = $authenticatedLowWriteSentinel
    $info.Environment['SUMATRAFUZZ_RESOURCE_ROOT'] = $resourceRoot
    $info.Environment['TEMP'] = $temp
    $info.Environment['TMP'] = $temp
    $proc = [Diagnostics.Process]::new()
    $proc.StartInfo = $info
    $started = $proc.Start()
    if (-not $started) { throw 'Nonadministrator supervisor check failed to start' }
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit(120000)) {
        $proc.Kill($true)
        [void]$proc.WaitForExit(30000)
        throw 'Nonadministrator supervisor check exceeded two minutes'
    }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    Write-Output $out
    if ($err) { Write-Output $err }
    if ($proc.ExitCode -ne 0) { throw "Nonadministrator supervisor check failed: exit $($proc.ExitCode)" }
} finally {
    if ($proc) {
        if ($started -and -not $proc.HasExited) { $proc.Kill($true); [void]$proc.WaitForExit(30000) }
        $proc.Dispose()
    }
    if (Test-Path -LiteralPath $resourceRoot) { Remove-Item -LiteralPath $resourceRoot -Recurse -Force }
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $account }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    $password.Dispose()
}
