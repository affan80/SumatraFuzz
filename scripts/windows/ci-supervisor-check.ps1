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
    $node = (Get-Command node -ErrorAction Stop).Source
    & $node --test test/supervisor-windows.check.cjs
    if ($LASTEXITCODE -ne 0) { throw "Supervisor containment check failed: exit $LASTEXITCODE" }
    exit 0
}
$account = 'sf-probe-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$password = ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'aA1!') -AsPlainText -Force
$temp = Join-Path $RepoRoot "runs/$account"
$protected = Join-Path $temp 'protected'
$credentialSentinel = Join-Path $protected 'credential-sentinel'
$worldWriteSentinel = Join-Path $temp 'world-write-sentinel'
$authenticatedWriteSentinel = Join-Path $temp 'authenticated-write-sentinel'
$proc = $null
$started = $false
try {
    $user = New-LocalUser -Name $account -Password $password -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $user
    $null = New-Item -ItemType Directory -Path $temp -Force
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
    foreach ($fixture in @($worldWriteSentinel, $authenticatedWriteSentinel)) {
      & icacls $fixture /inheritance:r
      if ($LASTEXITCODE -ne 0) { throw 'Cannot protect the broad-ACL write probe fixture' }
      & icacls $fixture /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
      if ($LASTEXITCODE -ne 0) { throw 'Cannot grant administrator cleanup access to the write probe fixture' }
    }
    & icacls $worldWriteSentinel /grant '*S-1-1-0:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the World-writable probe fixture' }
    & icacls $authenticatedWriteSentinel /grant '*S-1-5-11:(M)'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare the Authenticated Users writable probe fixture' }
    $null = New-Item -ItemType Directory -Path $protected -Force
    Set-Content -LiteralPath $credentialSentinel -Value 'service-only trust and DPAPI sentinel' -NoNewline
    $standardUser = "$env:COMPUTERNAME\$account"
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
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $account }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    $password.Dispose()
}
