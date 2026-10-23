#requires -Version 7.0
[CmdletBinding()]
param(
  [string]$ConfigurationPath,
  [string]$WorkerCredentialsPath,
  [string]$PairingBundlePath,
  [string]$TrustOperationPath,
  [switch]$Live,
  [ValidateRange(1, 300)][int]$StartTimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'worker-service-config.psm1') -Force

if (-not ('SumatraFuzz.NamedPipeIdentity' -as [type])) {
  Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace SumatraFuzz {
  public static class NamedPipeIdentity {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);
  }
}
'@
}

function Read-ProtectedSource {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][long]$MaximumBytes)

  if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path.StartsWith('\\')) {
    throw 'Provisioning inputs must use an absolute local path'
  }
  $full = [IO.Path]::GetFullPath($Path)
  $parsed = [IO.Path]::GetPathRoot($full)
  $current = $parsed
  foreach ($part in $full.Substring($parsed.Length).Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
    $current = Join-Path $current $part
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      throw 'Provisioning inputs cannot traverse a reparse point'
    }
  }
  $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
  if ($item.PSIsContainer -or $item.Length -lt 1 -or $item.Length -gt $MaximumBytes) {
    throw 'Provisioning input is not a bounded regular file'
  }

  $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
  if ($owner -ne $adminSid -and $owner -ne $identity -and $owner -ne $systemSid) {
    throw 'Provisioning input owner is not an administrator, SYSTEM, or the current operator'
  }
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.IdentityReference -notin @($adminSid, $systemSid, $identity)) {
      throw 'Provisioning input ACL grants access outside the current administrator context'
    }
  }
  $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) {
      throw 'Provisioning input is not a bounded regular file'
    }
    $bytes = [byte[]]::new([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($count -le 0) { throw 'Provisioning input changed while being read' }
      $offset += $count
    }
    if ($stream.Position -ne $stream.Length) { throw 'Provisioning input changed while being read' }
    return $bytes
  } finally {
    $stream.Dispose()
  }
}

function Write-ProtectedDestination {
  param(
    [Parameter(Mandatory)][byte[]]$Bytes,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid,
    [Parameter(Mandatory)][ValidateSet('Read', 'ReadDelete')][string]$ServiceAccess
  )
  $temporary = Join-Path (Split-Path -Parent $Destination) ('.' + [IO.Path]::GetFileName($Destination) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllBytes($temporary, $Bytes)
    Set-WorkerProtectedAcl -Path $temporary -ServiceSid $ServiceSid -ServiceAccess $ServiceAccess
    [IO.File]::Move($temporary, $Destination, $true)
    Assert-WorkerProtectedAcl -Path $Destination -ServiceSid $ServiceSid -AllowServiceWrite:($ServiceAccess -eq 'ReadDelete')
  } finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  }
}

function Read-PipeBytesExactly {
  param(
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][int]$Count,
    [Parameter(Mandatory)][Threading.CancellationToken]$CancellationToken
  )
  $bytes = [byte[]]::new($Count)
  $offset = 0
  try {
    while ($offset -lt $Count) {
      $read = $Stream.ReadAsync($bytes, $offset, $Count - $offset, $CancellationToken).GetAwaiter().GetResult()
      if ($read -le 0) { throw 'Worker returned an invalid local trust response' }
      $offset += $read
    }
    return ,$bytes
  } catch {
    [Array]::Clear($bytes, 0, $bytes.Length)
    throw
  }
}

function Write-PipeBytesWithTimeout {
  param(
    [Parameter(Mandatory)][IO.Stream]$Stream,
    [Parameter(Mandatory)][byte[]]$Bytes,
    [ValidateRange(1, 120000)][int]$TimeoutMilliseconds = 10000
  )
  $timeout = [Threading.CancellationTokenSource]::new($TimeoutMilliseconds)
  try {
    $Stream.WriteAsync($Bytes, 0, $Bytes.Length, $timeout.Token).GetAwaiter().GetResult()
  } finally {
    $timeout.Dispose()
  }
}

function Invoke-LiveTrustOperation {
  param(
    [Parameter(Mandatory)][byte[]]$Bundle,
    [Parameter(Mandatory)][ValidateSet(16, 18)][byte]$Opcode,
    [Parameter(Mandatory)][uint32]$ExpectedServerProcessId,
    [Parameter(Mandatory)][string]$ExpectedHostPath
  )
  if ($Bundle.Length -lt 1 -or $Bundle.Length -gt 1048576) { throw 'Signed trust input exceeds its byte limit' }
  $payload = [byte[]]::new($Bundle.Length + 1)
  $lengthBytes = $null
  $responseLength = $null
  $response = $null
  $receiptTimeout = $null
  $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SumatraFuzzWorker-trust', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
  try {
    $payload[0] = $Opcode
    [Array]::Copy($Bundle, 0, $payload, 1, $Bundle.Length)
    $lengthBytes = [BitConverter]::GetBytes([uint32]$payload.Length)
    if (-not [BitConverter]::IsLittleEndian) { throw 'Unsupported local host byte order' }
    $pipe.Connect(10000)
    [uint32]$serverProcessId = 0
    if (-not [SumatraFuzz.NamedPipeIdentity]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$serverProcessId) -or
        $serverProcessId -eq 0 -or $serverProcessId -ne $ExpectedServerProcessId) {
      throw 'Connected pipe is not owned by the installed worker service'
    }
    $liveService = Get-WorkerServiceCim
    if (-not $liveService -or $liveService.State -ne 'Running' -or
        [uint32]$liveService.ProcessId -ne $serverProcessId) {
      throw 'Connected pipe is not owned by the running worker service'
    }
    $serverProcess = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$serverProcessId" -ErrorAction Stop
    if (-not $serverProcess -or [IO.Path]::GetFullPath([string]$serverProcess.ExecutablePath) -ine [IO.Path]::GetFullPath($ExpectedHostPath)) {
      throw 'Connected pipe server executable does not match the protected worker host'
    }
    Write-PipeBytesWithTimeout -Stream $pipe -Bytes $lengthBytes
    Write-PipeBytesWithTimeout -Stream $pipe -Bytes $payload

    $receiptTimeout = [Threading.CancellationTokenSource]::new(75000)
    $responseLength = Read-PipeBytesExactly -Stream $pipe -Count 4 -CancellationToken $receiptTimeout.Token
    if ([BitConverter]::ToUInt32($responseLength, 0) -ne 1) { throw 'Worker returned an invalid local trust response' }
    $response = Read-PipeBytesExactly -Stream $pipe -Count 1 -CancellationToken $receiptTimeout.Token
    Write-PipeBytesWithTimeout -Stream $pipe -Bytes ([byte[]]@(0xa5))
    if ($response[0] -ne 0) { throw 'Worker rejected the signed trust operation' }
    Write-Output 'Live trust operation applied.'
  } catch {
    if ($_.Exception.Message -like 'Worker rejected the signed trust operation' -or
        $_.Exception.Message -like 'Worker returned an invalid local trust response' -or
        $_.Exception.Message -like 'Signed trust input exceeds its byte limit' -or
        $_.Exception.Message -like 'Unsupported local host byte order') { throw }
    throw 'Unable to apply the live trust operation through the protected worker channel'
  } finally {
    if ($receiptTimeout) { $receiptTimeout.Dispose() }
    if ($pipe) { $pipe.Dispose() }
    foreach ($bytes in @($payload, $lengthBytes, $responseLength, $response)) {
      if ($bytes -is [byte[]]) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
  }
}

function Assert-ConfigurationMatchesInstall {
  param([Parameter(Mandatory)][object]$Configuration, [Parameter(Mandatory)][object]$Marker)
  if ($Configuration.schema -ne 1 -or
      $Configuration.bind.mode -cne $Marker.bind_mode.ToLowerInvariant() -or
      $Configuration.bind.address -cne $Marker.bind_address -or
      [int]$Configuration.bind.port -ne [int]$Marker.port -or
      ($Marker.bind_mode -eq 'Remote' -and ([guid]$Configuration.bind.adapterGuid) -ne ([guid]$Marker.adapter_guid)) -or
      (@($Configuration.bind.peerCidrs) -join ',') -cne (@($Marker.peer_cidrs) -join ',') -or
      [IO.Path]::GetFullPath($Configuration.storage.root) -ine [IO.Path]::GetFullPath($Marker.data_root) -or
      (Get-WorkerVolumeGuid $Configuration.storage.volumeId) -ne (Get-WorkerVolumeGuid $Marker.volume_id) -or
      [long]$Configuration.storage.diskLimitBytes -ne [long]$Marker.quota_bytes -or
      [long]$Configuration.policy.maxLimits.max_disk_bytes -ne [long]$Marker.quota_bytes -or
      [IO.Path]::GetFullPath($Configuration.trust.organizationSigningPublicKeyPath) -ine [IO.Path]::GetFullPath($Marker.signing_key_path) -or
      [IO.Path]::GetFullPath($Configuration.credentials.protectedBundlePath) -ine [IO.Path]::GetFullPath($Marker.credentials_path)) {
    throw 'Worker configuration does not match the protected installation policy'
  }
  if ($Marker.bind_mode -eq 'Local' -and
      (([guid]$Configuration.bind.adapterGuid) -ne [guid]::Empty -or @($Configuration.bind.peerCidrs).Count -ne 0)) {
    throw 'Local worker configuration cannot select a remote adapter or peer range'
  }
}

Assert-WorkerPlatform -RequireElevation
$hasPairing = -not [string]::IsNullOrWhiteSpace($PairingBundlePath)
$hasTrustOperation = -not [string]::IsNullOrWhiteSpace($TrustOperationPath)
$hasCredentials = -not [string]::IsNullOrWhiteSpace($WorkerCredentialsPath)
if (($hasPairing -and $hasTrustOperation) -or (-not $hasPairing -and -not $hasTrustOperation) -or
    ($hasCredentials -and -not $hasPairing) -or
    ($Live -and ($hasCredentials -or -not [string]::IsNullOrWhiteSpace($ConfigurationPath)))) {
  throw 'Provide worker credentials with a signed pairing bundle, or one signed trust-operation transaction'
}

$marker = Get-WorkerInstallMarker
if (-not $marker -or $marker.state -ne 'Installed') { throw 'An installed, protected worker service is required before provisioning' }
$service = Get-WorkerServiceCim
if (-not $service) { throw 'The protected worker service does not exist' }
Assert-WorkerServiceMatchesMarker $marker
$serviceSid = Resolve-WorkerSid 'NT SERVICE\SumatraFuzzWorker'
$dataRoot = [string]$marker.data_root
$stagingRoot = Join-Path $dataRoot 'staging'
[void](Assert-WorkerDataMountPoint -DataRoot $dataRoot -InstallRoot ([string]$marker.install_root) -ExpectedVolumeId ([string]$marker.volume_id))
$stagingItem = Get-Item -LiteralPath $stagingRoot -Force -ErrorAction Stop
if (-not $stagingItem.PSIsContainer -or ($stagingItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
  throw 'Protected worker provisioning path is missing or redirected'
}

$configBytes = $null
$credentialBytes = $null
$pairingBytes = $null
$trustOperationBytes = $null
try {
  $installedConfigurationPath = Join-Path $dataRoot 'worker-config.json'
  if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    $configBytes = Read-ProtectedSource -Path $ConfigurationPath -MaximumBytes 65536
  } else {
    $configBytes = [IO.File]::ReadAllBytes($installedConfigurationPath)
    if ($configBytes.Length -lt 1) { throw 'Initial provisioning requires an explicit worker configuration input' }
    if ($configBytes.Length -gt 65536) { throw 'Worker configuration exceeds its byte limit' }
  }
  $utf8 = [Text.UTF8Encoding]::new($false, $true)
  $configuration = ConvertFrom-Json -InputObject $utf8.GetString($configBytes) -AsHashtable -Depth 32 -ErrorAction Stop
  Assert-ConfigurationMatchesInstall -Configuration $configuration -Marker $marker

  if ($hasPairing) {
    $pairingBytes = Read-ProtectedSource -Path $PairingBundlePath -MaximumBytes 1048576
    if ($hasCredentials) { $credentialBytes = Read-ProtectedSource -Path $WorkerCredentialsPath -MaximumBytes 1048576 }
  } else {
    $trustOperationBytes = Read-ProtectedSource -Path $TrustOperationPath -MaximumBytes 1048576
  }

  $useLive = [bool]$Live -or
    ($service.State -eq 'Running' -and -not $hasCredentials -and [string]::IsNullOrWhiteSpace($ConfigurationPath))
  if ($useLive) {
    if ($service.State -ne 'Running') { throw 'Live trust operations require the installed worker service to be running' }
    $liveService = Get-WorkerServiceCim
    if (-not $liveService -or $liveService.State -ne 'Running' -or [uint32]$liveService.ProcessId -eq 0) {
      throw 'Live trust operations require the installed worker service to be running'
    }
    if ($hasPairing) {
      Invoke-LiveTrustOperation -Bundle $pairingBytes -Opcode 18 -ExpectedServerProcessId ([uint32]$liveService.ProcessId) -ExpectedHostPath ([string]$marker.host_path)
    } else {
      Invoke-LiveTrustOperation -Bundle $trustOperationBytes -Opcode 16 -ExpectedServerProcessId ([uint32]$liveService.ProcessId) -ExpectedHostPath ([string]$marker.host_path)
    }
    return
  }

  if ($hasCredentials -and (Get-Item -LiteralPath $marker.credentials_path -Force).Length -eq 0 -and [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    throw 'Initial activation requires an explicit protected worker configuration input'
  }
  if ($service.State -ne 'Stopped') {
    Stop-Service -Name 'SumatraFuzzWorker' -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
      Start-Sleep -Milliseconds 250
      $service = Get-WorkerServiceCim
    } while ($service -and $service.State -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
    if (-not $service -or $service.State -ne 'Stopped') { throw 'Worker service did not stop within the bounded provisioning interval' }
  }

  if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    Write-ProtectedDestination -Bytes $configBytes -Destination $installedConfigurationPath -ServiceSid $serviceSid -ServiceAccess Read
  }
  if ($hasPairing) {
    Write-ProtectedDestination -Bytes $pairingBytes -Destination (Join-Path $stagingRoot 'worker-pairing.sfpair') -ServiceSid $serviceSid -ServiceAccess ReadDelete
    if ($hasCredentials) {
      Write-ProtectedDestination -Bytes $credentialBytes -Destination (Join-Path $stagingRoot 'worker-credentials.json') -ServiceSid $serviceSid -ServiceAccess ReadDelete
    }
  } else {
    Write-ProtectedDestination -Bytes $trustOperationBytes -Destination (Join-Path $stagingRoot 'worker-trust-operation.sftxn') -ServiceSid $serviceSid -ServiceAccess ReadDelete
  }

  Set-Service -Name 'SumatraFuzzWorker' -StartupType Automatic -ErrorAction Stop
  Start-Service -Name 'SumatraFuzzWorker' -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddSeconds($StartTimeoutSeconds)
  do {
    Start-Sleep -Milliseconds 250
    $service = Get-WorkerServiceCim
  } while ($service -and $service.State -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
  if (-not $service -or $service.State -ne 'Running') {
    throw 'Worker service did not become ready; protected staging is retained for operator recovery'
  }
} finally {
  foreach ($bytes in @($configBytes, $credentialBytes, $pairingBytes, $trustOperationBytes)) {
    if ($bytes -is [byte[]]) { [Array]::Clear($bytes, 0, $bytes.Length) }
  }
}
