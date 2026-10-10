#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true') { throw 'Ephemeral Windows GitHub runner required' }
if (-not [IO.Path]::IsPathFullyQualified($RepoRoot)) { throw 'RepoRoot must be absolute' }
$account = 'sf-native-' + [guid]::NewGuid().ToString('N').Substring(0,8)
$password = ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'aA1!') -AsPlainText -Force
$proc = $null
$started = $false
try {
    $user = New-LocalUser -Name $account -Password $password -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $user
    $runs = Join-Path $RepoRoot 'runs'
    $temp = Join-Path $runs 'native-user-temp'
    $null = New-Item -ItemType Directory -Path $temp -Force
    & icacls $RepoRoot /grant "${account}:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant native user read access' }
    & icacls $runs /grant "${account}:(OI)(CI)M"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant native user evidence access' }
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
    foreach ($arg in @('-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'verify-native-gate.ps1'),'-RepoRoot',$RepoRoot)) {
        $info.ArgumentList.Add($arg)
    }
    foreach ($name in @('GITHUB_TOKEN','GH_TOKEN','ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN')) {
        [void]$info.Environment.Remove($name)
    }
    $info.Environment['TEMP'] = $temp
    $info.Environment['TMP'] = $temp
    $info.Environment['PYTHONDONTWRITEBYTECODE'] = '1'
    $proc = [Diagnostics.Process]::new()
    $proc.StartInfo = $info
    $started = $proc.Start()
    if (-not $started) { throw 'Nonadministrator verification process failed to start' }
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit(1200000)) {
        $proc.Kill($true)
        [void]$proc.WaitForExit(30000)
        throw 'Nonadministrator native gate exceeded 20 minutes'
    }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    $out | Set-Content -LiteralPath (Join-Path $runs 'native-gate.stdout.log') -Encoding utf8
    $err | Set-Content -LiteralPath (Join-Path $runs 'native-gate.stderr.log') -Encoding utf8
    Write-Output $out
    if ($err) { Write-Output $err }
    if ($proc.ExitCode -ne 0) { throw "Nonadministrator native gate failed: exit $($proc.ExitCode)" }
} finally {
    if ($proc) {
        if ($started -and -not $proc.HasExited) { $proc.Kill($true); [void]$proc.WaitForExit(30000) }
        $proc.Dispose()
    }
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $account }
    $password.Dispose()
}
