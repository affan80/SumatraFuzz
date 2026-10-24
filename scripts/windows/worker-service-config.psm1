#requires -Version 7.0
Set-StrictMode -Version Latest

$script:WorkerServiceName = 'SumatraFuzzWorker'
$script:WorkerServiceAccount = 'NT SERVICE\SumatraFuzzWorker'
$script:WorkerMinimumDiskLimitBytes = 67108864
$script:WorkerMaximumDiskLimitBytes = 1099511627776
$script:WorkerDataRoot = Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'ProgramData\SumatraFuzz\Worker'
$script:WorkerInstallStateRoot = Join-Path (Split-Path -Parent $script:WorkerDataRoot) 'InstallState'
$script:WorkerSigningKeyRelativePath = 'config\organization-signing-public-key.pem'
$script:WorkerFirewallNamePrefix = 'SumatraFuzzWorker-'

function Get-WorkerPlatformFacts {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return [pscustomobject]@{
    IsWindows = [bool]$IsWindows
    Architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
}

function Assert-WorkerPlatform {
  [CmdletBinding()]
  param([switch]$RequireElevation)

  $facts = Get-WorkerPlatformFacts
  if (-not $facts.IsWindows -or $facts.Architecture -ne 'X64') {
    throw 'Windows x64 is required for worker service provisioning'
  }
  if ($RequireElevation -and -not $facts.Elevated) {
    throw 'Worker service provisioning requires elevation'
  }
}

function Resolve-WorkerInstallLayout {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$InstallRoot)

  if (-not [IO.Path]::IsPathFullyQualified($InstallRoot)) { throw 'InstallRoot must be an absolute path' }
  $root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ([IO.Path]::GetFileName($root) -ine 'SumatraFuzz') { throw 'InstallRoot must be the fixed SumatraFuzz directory expected by the native service host' }
  $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
  if (-not $rootItem -or -not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Worker install root is missing, redirected, or not a directory' }
  $paths = [ordered]@{
    Root = $root
    Host = Join-Path $root 'service\SumatraFuzzWorkerHost.exe'
    Node = Join-Path $root 'runtime\node.exe'
    Entry = Join-Path $root 'apps\worker-service\dist\src\service-entry.js'
    SigningKey = Join-Path $root $script:WorkerSigningKeyRelativePath
    InstallScript = Join-Path $root 'provisioning\install-worker-service.ps1'
    ProvisionScript = Join-Path $root 'provisioning\provision-worker-service.ps1'
    UninstallScript = Join-Path $root 'provisioning\uninstall-worker-service.ps1'
    ConfigModule = Join-Path $root 'provisioning\worker-service-config.psm1'
    ProvisioningReadme = Join-Path $root 'provisioning\README.md'
  }
  foreach ($name in @('Host', 'Node', 'Entry', 'SigningKey', 'InstallScript', 'ProvisionScript', 'UninstallScript', 'ConfigModule', 'ProvisioningReadme')) {
    $item = Get-Item -LiteralPath $paths[$name] -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "Worker install layout is missing a regular fixed-path file: $name"
    }
  }
  foreach ($relative in @('service', 'runtime', 'apps', 'apps\worker-service', 'apps\worker-service\dist', 'apps\worker-service\dist\src', 'config', 'provisioning')) {
    $directory = Get-Item -LiteralPath (Join-Path $root $relative) -Force -ErrorAction SilentlyContinue
    if (-not $directory -or -not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "Worker install layout contains a missing or redirected directory: $relative"
    }
  }
  return [pscustomobject]$paths
}

function Assert-WorkerProtectedInstallAncestors {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$InstallRoot)
  $fullPath = [IO.Path]::GetFullPath($InstallRoot)
  $volumeRoot = [IO.Path]::GetPathRoot($fullPath)
  if (-not $volumeRoot -or $fullPath.StartsWith('\\')) {
    throw 'Worker install path must be on a local drive'
  }
  $volumeRoot = $volumeRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $current = $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ($current -eq $volumeRoot) { $current = $volumeRoot + [IO.Path]::DirectorySeparatorChar }
  while ($true) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Worker install ancestor is redirected or is not a directory'
    }
    Assert-WorkerHostCompatibleDacl -Path $current -RequireTrustedOwner -AllowCurrentAdministratorOwner
    if ([IO.Path]::GetFullPath($current).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -eq $volumeRoot) {
      break
    }
    $parent = Split-Path -Parent $current
    if (-not $parent -or $parent -eq $current) { throw 'Worker install ancestor chain is incomplete' }
    $current = $parent
  }
}

function ConvertTo-WorkerIpAddress {
  param([Parameter(Mandatory)][string]$Address)
  $parsed = $null
  if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed)) { throw 'Worker address is invalid' }
  return $parsed
}

function Test-WorkerPrivateAddress {
  [CmdletBinding()]
  param([Parameter(Mandatory)][Net.IPAddress]$Address)

  if ([Net.IPAddress]::IsLoopback($Address)) { return $false }
  $bytes = $Address.GetAddressBytes()
  if ($bytes.Length -eq 4) {
    return ($bytes[0] -eq 10) -or
      ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
      ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
      ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127)
  }
  if ($bytes.Length -eq 16) { return (($bytes[0] -band 0xFE) -eq 0xFC) }
  return $false
}

function Test-WorkerCidr {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Cidr)

  $parts = $Cidr.Split('/')
  if ($parts.Count -ne 2) { return $false }
  $address = $null
  $prefix = 0
  if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or
      -not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
  $bytes = $address.GetAddressBytes()
  if (($bytes.Length -eq 4 -and ($prefix -lt 1 -or $prefix -gt 32)) -or
      ($bytes.Length -eq 16 -and ($prefix -lt 1 -or $prefix -gt 128)) -or
      ($bytes.Length -notin @(4, 16))) { return $false }

  # Require both ends of the CIDR to be private; this rejects broad ranges
  # that start inside a private block but extend into public address space.
  $network = [byte[]]::new($bytes.Length)
  $last = [byte[]]::new($bytes.Length)
  $remaining = $prefix
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bits = [Math]::Min(8, $remaining)
    $mask = if ($bits -le 0) { 0 } else { (0xFF -shl (8 - $bits)) -band 0xFF }
    $network[$i] = [byte]($bytes[$i] -band $mask)
    $last[$i] = [byte]($network[$i] -bor (0xFF -bxor $mask))
    $remaining -= $bits
  }
  return (Test-WorkerPrivateAddress ([Net.IPAddress]::new($network))) -and
    (Test-WorkerPrivateAddress ([Net.IPAddress]::new($last)))
}

function Assert-WorkerBindConfiguration {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Local', 'Remote')][string]$Mode,
    [Parameter(Mandatory)][string]$Address,
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
    [string]$AdapterGuid,
    [string[]]$PeerCidrs = @()
  )

  $addressValue = ConvertTo-WorkerIpAddress $Address
  if ($Mode -eq 'Local') {
    if (-not [Net.IPAddress]::IsLoopback($addressValue) -or $AdapterGuid -or $PeerCidrs.Count -gt 0) {
      throw 'Local worker mode accepts only an explicit loopback address and no remote adapter or peer ranges'
    }
    return
  }
  if (-not (Test-WorkerPrivateAddress $addressValue)) { throw 'Remote worker bind address must be private or VPN-scoped' }
  $adapter = [guid]::Empty
  if (-not [guid]::TryParse($AdapterGuid, [ref]$adapter) -or $adapter -eq [guid]::Empty) {
    throw 'Remote worker mode requires an exact adapter GUID'
  }
  if ($PeerCidrs.Count -lt 1 -or $PeerCidrs.Count -gt 32) { throw 'Remote worker mode requires 1 to 32 peer CIDRs' }
  foreach ($peer in $PeerCidrs) {
    if (-not (Test-WorkerCidr $peer)) { throw 'Remote worker peer CIDR is malformed or includes public addresses' }
  }

  $matching = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
      try { ([guid]$_.InterfaceGuid) -eq $adapter } catch { $false }
    })
  if ($matching.Count -ne 1 -or $matching[0].Status -ne 'Up') { throw 'Configured remote network adapter is unavailable or ambiguous' }
  $assigned = @(Get-NetIPAddress -InterfaceIndex $matching[0].InterfaceIndex -ErrorAction Stop | Where-Object {
      try { [Net.IPAddress]::Parse($_.IPAddress).Equals($addressValue) } catch { $false }
    })
  if ($assigned.Count -ne 1) { throw 'Configured remote address is not assigned to the selected adapter' }
  $profile = @(Get-NetConnectionProfile -InterfaceIndex $matching[0].InterfaceIndex -ErrorAction SilentlyContinue |
      Where-Object { $_.NetworkCategory -in @('DomainAuthenticated', 'Private') })
  if ($profile.Count -lt 1) { throw 'Remote worker adapter must have an active Domain or Private firewall profile' }
}

function Get-WorkerVolumeGuid {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$UniqueId)
  $match = [regex]::Match($UniqueId, '(?i)volume\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}')
  if (-not $match.Success) { throw 'Worker data volume must have a stable volume GUID' }
  return "volume{$($match.Groups[1].Value.ToLowerInvariant())}"
}

function Assert-WorkerDataMountPoint {
  [CmdletBinding()]
  param(
    [string]$DataRoot = $script:WorkerDataRoot,
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$ExpectedVolumeId
  )
  $fullDataRoot = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
  if ($fullDataRoot -ine [IO.Path]::GetFullPath($script:WorkerDataRoot).TrimEnd('\')) {
    throw 'Worker data must use the fixed dedicated-volume mount point'
  }
  $rootItem = Get-Item -LiteralPath $fullDataRoot -Force -ErrorAction Stop
  if (-not $rootItem.PSIsContainer -or -not ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Worker data root must be a dedicated-volume mount point'
  }
  $ancestor = Split-Path -Parent $fullDataRoot
  while ($ancestor) {
    $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Worker data ancestor is missing or redirected'
    }
    $parent = Split-Path -Parent $ancestor
    if ($parent -eq $ancestor) { break }
    $ancestor = $parent
  }
  $expectedGuid = Get-WorkerVolumeGuid $ExpectedVolumeId
  $volumeMatches = @(Get-Volume -ErrorAction Stop | Where-Object { try { (Get-WorkerVolumeGuid $_.UniqueId) -eq $expectedGuid } catch { $false } })
  if ($volumeMatches.Count -ne 1) { throw 'Expected worker data volume is unavailable or ambiguous' }
  $volume = $volumeMatches[0]
  if ($volume.FileSystem -ne 'NTFS') { throw 'Worker data volume is not the expected NTFS volume' }
  $mountedVolume = Get-Volume -FilePath $fullDataRoot -ErrorAction Stop
  # MSFT_Volume.Path is a GUID path; registered mounted folders are partition AccessPaths.
  $partitions = @(Get-Partition -ErrorAction Stop)
  $mountPaths = @(
    $partitions |
      ForEach-Object { $_.AccessPaths } |
      Where-Object { $_ } |
      ForEach-Object {
        $candidate = [IO.Path]::GetFullPath($_).TrimEnd('\')
        try {
          $candidateVolume = Get-Volume -FilePath $candidate -ErrorAction Stop
          if ((Get-WorkerVolumeGuid $candidateVolume.UniqueId) -eq $expectedGuid) { $candidate }
        } catch {
          # An unavailable or ambiguous access path cannot prove mount ownership.
        }
      }
  )
  if ((Get-WorkerVolumeGuid $mountedVolume.UniqueId) -ne $expectedGuid -or $fullDataRoot -notin $mountPaths) {
    throw 'Worker data reparse point is not the exact configured dedicated-volume mount point'
  }
  foreach ($protectedPath in @($InstallRoot, $env:SystemRoot)) {
    $protectedVolume = Get-Volume -FilePath $protectedPath -ErrorAction Stop
    if ((Get-WorkerVolumeGuid $protectedVolume.UniqueId) -eq $expectedGuid) {
      throw 'Worker data must use a dedicated volume separate from installed code and Windows'
    }
  }
  return $volume
}

function Assert-WorkerDataVolume {
  [CmdletBinding()]
  param(
    [string]$DataRoot = $script:WorkerDataRoot,
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$ExpectedVolumeId
  )
  $volume = Assert-WorkerDataMountPoint -DataRoot $DataRoot -InstallRoot $InstallRoot -ExpectedVolumeId $ExpectedVolumeId
  $allowedSystemNames = @('$RECYCLE.BIN', 'System Volume Information')
  $expectedTop = @('worker-config.json', 'credentials.dpapi', 'staging', 'trust', 'runs', 'evidence', 'tmp', 'state', 'security', 'inputs', 'outputs')
  foreach ($entry in @(Get-ChildItem -LiteralPath $DataRoot -Force -ErrorAction Stop)) {
    if ($entry.Name -notin $allowedSystemNames -and $entry.Name -notin $expectedTop) {
      throw 'Worker data volume contains unrelated top-level data'
    }
  }
  $dataParent = Split-Path -Parent $DataRoot
  $parentEntries = @(Get-ChildItem -LiteralPath $dataParent -Force -ErrorAction Stop | Where-Object { $_.Name -notin @('Worker', 'InstallState') })
  if ($parentEntries.Count -gt 0) { throw 'Worker data parent contains unrelated SumatraFuzz data' }
  return $volume
}

function Get-WorkerQuotaSetting {
  param([Parameter(Mandatory)][string]$VolumePath, [Parameter(Mandatory)][string]$VolumeId)
  $volumeGuid = Get-WorkerVolumeGuid $VolumeId
  $settings = @(Get-CimInstance -ClassName Win32_QuotaSetting -ErrorAction Stop | Where-Object {
      $pathMatch = ([string]$_.VolumePath).TrimEnd('\') -ieq $VolumePath.TrimEnd('\')
      $guidMatch = try { (Get-WorkerVolumeGuid ([string]$_.VolumePath)) -eq $volumeGuid } catch { $false }
      $pathMatch -or $guidMatch
    })
  if ($settings.Count -ne 1) { throw 'NTFS quota state could not be identified for the worker volume' }
  return $settings[0]
}

function Get-WorkerServiceQuotaRecord {
  param([Parameter(Mandatory)][string]$VolumeId)
  $records = @(Get-CimInstance -ClassName Win32_VolumeUserQuota -ErrorAction Stop | Where-Object {
      $volume = $_.Volume
      $account = $_.Account
      $volume -and $account -and
        ([string]$volume.DeviceID).TrimEnd('\') -ieq $VolumeId.TrimEnd('\') -and
        [string]$account.Name -ieq $script:WorkerServiceName -and
        [string]$account.Domain -ieq 'NT SERVICE'
    })
  if ($records.Count -gt 1) { throw 'Worker service quota is ambiguous' }
  if ($records.Count -eq 0) { return $null }
  return $records[0]
}

function Assert-WorkerQuota {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$VolumeId, [Parameter(Mandatory)][long]$LimitBytes)
  if ($LimitBytes -lt $script:WorkerMinimumDiskLimitBytes -or $LimitBytes -gt $script:WorkerMaximumDiskLimitBytes) { throw 'Worker quota is outside supported bounds' }
  $volumeGuid = Get-WorkerVolumeGuid $VolumeId
  $volume = Get-Volume | Where-Object { try { (Get-WorkerVolumeGuid $_.UniqueId) -eq $volumeGuid } catch { $false } }
  if (-not $volume -or $volume.FileSystem -ne 'NTFS') { throw 'Worker NTFS volume is unavailable' }
  $mount = @($volume.Path | Where-Object { $_ } | Select-Object -First 1)[0]
  $setting = Get-WorkerQuotaSetting -VolumePath $mount -VolumeId $volume.UniqueId
  if ([int]$setting.State -ne 2) { throw 'Worker NTFS quota enforcement is not active' }
  $record = Get-WorkerServiceQuotaRecord -VolumeId $volume.UniqueId
  if (-not $record -or [long]$record.Limit -ne $LimitBytes) { throw 'Worker service hard quota does not match the configured disk limit' }
}

function Invoke-WorkerFsutil {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$ArgumentList)
  $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
  & $fsutil @ArgumentList *> $null
  if ($LASTEXITCODE -ne 0) { throw 'NTFS worker quota operation failed' }
}

function Set-WorkerQuota {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$VolumeId, [Parameter(Mandatory)][long]$LimitBytes)
  $volumeGuid = Get-WorkerVolumeGuid $VolumeId
  if ($LimitBytes -lt $script:WorkerMinimumDiskLimitBytes -or $LimitBytes -gt $script:WorkerMaximumDiskLimitBytes) { throw 'Worker quota is outside supported bounds' }
  $volume = Get-Volume | Where-Object { try { (Get-WorkerVolumeGuid $_.UniqueId) -eq $volumeGuid } catch { $false } }
  if (-not $volume -or $volume.FileSystem -ne 'NTFS') { throw 'Worker NTFS volume is unavailable' }
  $mount = @($volume.Path | Where-Object { $_ } | Select-Object -First 1)[0]
  $setting = Get-WorkerQuotaSetting -VolumePath $mount -VolumeId $volume.UniqueId
  $existingRecord = Get-WorkerServiceQuotaRecord -VolumeId $volume.UniqueId
  if ([int]$setting.State -eq 2 -and $existingRecord -and [long]$existingRecord.Limit -eq $LimitBytes) {
    Assert-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $LimitBytes
    return $false
  }
  if ([int]$setting.State -ne 0 -or $existingRecord) {
    throw 'Worker volume quota state is already configured and is not owned by this installation'
  }
  $changed = $false
  try {
    Invoke-WorkerFsutil @('quota', 'track', $mount)
    $changed = $true
    Invoke-WorkerFsutil @('quota', 'modify', $mount, '0', [string]$LimitBytes, $script:WorkerServiceAccount)
    Invoke-WorkerFsutil @('quota', 'enforce', $mount)
    Assert-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $LimitBytes
  } catch {
    if ($changed) {
      try {
        Invoke-WorkerFsutil @('quota', 'modify', $mount, '0', '-1', $script:WorkerServiceAccount)
        Invoke-WorkerFsutil @('quota', 'disable', $mount)
      } catch { throw 'Worker quota provisioning failed and dedicated-volume quota rollback also failed' }
    }
    throw
  }
  return $true
}

function Restore-WorkerQuota {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$VolumeId)
  $volumeGuid = Get-WorkerVolumeGuid $VolumeId
  $volume = Get-Volume | Where-Object { try { (Get-WorkerVolumeGuid $_.UniqueId) -eq $volumeGuid } catch { $false } }
  if (-not $volume -or $volume.FileSystem -ne 'NTFS') { throw 'Worker NTFS volume is unavailable for quota rollback' }
  $mount = @($volume.Path | Where-Object { $_ } | Select-Object -First 1)[0]
  Invoke-WorkerFsutil @('quota', 'modify', $mount, '0', '-1', $script:WorkerServiceAccount)
  Invoke-WorkerFsutil @('quota', 'disable', $mount)
}

function Resolve-WorkerSid {
  param([Parameter(Mandatory)][string]$Account)
  return ([Security.Principal.NTAccount]::new($Account)).Translate([Security.Principal.SecurityIdentifier])
}

function Set-WorkerProtectedAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid,
    [ValidateSet('Read', 'ReadDelete', 'Modify', 'AdminOnly')][string]$ServiceAccess = 'Read',
    [switch]$RestrictedRead,
    [switch]$RestrictedExecute,
    [switch]$RestrictedTraverse,
    [switch]$Directory
  )

  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
  $acl.SetOwner($adminSid)
  $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
  $propagation = [Security.AccessControl.PropagationFlags]::None
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Allow))
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($adminSid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Allow))
  if ($ServiceAccess -ne 'AdminOnly') {
    $rights = switch ($ServiceAccess) {
      'Modify' { [Security.AccessControl.FileSystemRights]::Modify; break }
      'ReadDelete' { [Security.AccessControl.FileSystemRights]::ReadData -bor [Security.AccessControl.FileSystemRights]::ReadAttributes -bor [Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::Delete; break }
      default { [Security.AccessControl.FileSystemRights]::ReadAndExecute }
    }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ServiceSid, $rights, $inheritance, $propagation, [Security.AccessControl.AccessControlType]::Allow))
  }
  $restrictedModes = @()
  if ($RestrictedRead) { $restrictedModes += 'read' }
  if ($RestrictedExecute) { $restrictedModes += 'execute' }
  if ($RestrictedTraverse) { $restrictedModes += 'traverse' }
  if ($restrictedModes.Count -gt 1) { throw 'Restricted ACL modes are mutually exclusive' }
  if ($RestrictedRead -or $RestrictedExecute -or $RestrictedTraverse) {
    # Restricted children must pass the normal service-identity ACL check and
    # the Restricted Code SID check. Input files receive read-only access;
    # only installed code receives execute rights. The native supervisor adds
    # its random per-run SID only on the current output directory.
    $restrictedCodeSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-12')
    $restrictedRights = if ($RestrictedExecute) {
      [Security.AccessControl.FileSystemRights]::ReadAndExecute
    } elseif ($RestrictedRead -and $Directory) {
      [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Traverse
    } elseif ($RestrictedRead) {
      [Security.AccessControl.FileSystemRights]::Read
    } else {
      [Security.AccessControl.FileSystemRights]::Traverse
    }
    # ACL every accepted object explicitly. Inheriting a directory RX ACE onto
    # its children would give parser inputs ExecuteFile through the inherited ACE.
    $restrictedInheritance = [Security.AccessControl.InheritanceFlags]::None
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($restrictedCodeSid, $restrictedRights, $restrictedInheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Set-WorkerProtectedTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid,
    [ValidateSet('Read', 'Modify')][string]$ServiceAccess = 'Read',
    [switch]$RestrictedRead,
    [switch]$RestrictedExecute
  )
  $items = @(Get-WorkerProtectedTreeInventory -Path $Path)
  # Validation is deliberately complete before the first DACL mutation. In
  # particular, do not repair the root and then discover an unsafe owner or
  # writable descendant: an owner can change the DACL through WRITE_DAC even
  # when its explicit ACEs look harmless.
  Set-WorkerProtectedAcl -Path $Path -ServiceSid $ServiceSid -ServiceAccess $ServiceAccess -RestrictedRead:$RestrictedRead -RestrictedExecute:$RestrictedExecute -Directory
  foreach ($item in $items) {
    Set-WorkerProtectedAcl -Path $item.FullName -ServiceSid $ServiceSid -ServiceAccess $ServiceAccess -RestrictedRead:$RestrictedRead -RestrictedExecute:$RestrictedExecute -Directory:$item.PSIsContainer
  }
}

function Get-WorkerProtectedTreeInventory {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )
  # This path-based preflight closes the untrusted-user repair window by
  # refusing unsafe owners/ACEs and reparse points before ACL changes. As with
  # Windows ACL APIs generally, it cannot revoke an already-open handle held
  # by a trusted administrator, SYSTEM, or TrustedInstaller.
  $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Worker protected tree root is redirected or is not a directory'
  }
  Assert-WorkerHostCompatibleDacl -Path $Path -RequireTrustedOwner -AllowCurrentAdministratorOwner
  $items = [System.Collections.Generic.List[object]]::new()
  $pending = [System.Collections.Generic.Stack[string]]::new()
  $pending.Push($Path)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | Sort-Object FullName)) {
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Worker protected tree contains a reparse point'
      }
      Assert-WorkerHostCompatibleDacl -Path $item.FullName -RequireTrustedOwner -AllowCurrentAdministratorOwner
      $items.Add($item)
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
  return $items.ToArray()
}

function Protect-WorkerRuntimeTree {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid,
    [switch]$RestrictedRead,
    [switch]$RestrictedTraverse
  )
  $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Worker runtime tree root is redirected or is not a directory'
  }
  # Validate before changing ACLs: unsafe legacy state may have been changed by
  # a local user. Then lock each directory before enumerating it, and apply an
  # explicit protected ACL to every accepted descendant.
  Assert-WorkerHostCompatibleDacl -Path $Path -ServiceSid $ServiceSid -AllowServiceWrite -RequireTrustedOwner -AllowCurrentAdministratorOwner
  Set-WorkerProtectedAcl -Path $Path -ServiceSid $ServiceSid -ServiceAccess Modify -RestrictedRead:$RestrictedRead -RestrictedTraverse:$RestrictedTraverse -Directory
  $pending = [System.Collections.Generic.Stack[string]]::new()
  $pending.Push($Path)
  while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop | Sort-Object FullName)) {
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Worker runtime state contains a reparse point'
      }
      Assert-WorkerHostCompatibleDacl -Path $item.FullName -ServiceSid $ServiceSid -AllowServiceWrite -RequireTrustedOwner -AllowCurrentAdministratorOwner
      Set-WorkerProtectedAcl -Path $item.FullName -ServiceSid $ServiceSid -ServiceAccess Modify -RestrictedRead:$RestrictedRead -Directory:$item.PSIsContainer
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
}

function Set-WorkerOutputLowIntegrity {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Worker output root must be an ordinary directory before applying its integrity label'
  }
  $icacls = Join-Path $env:SystemRoot 'System32/icacls.exe'
  & $icacls $Path '/setintegritylevel' '(OI)(CI)L' '/T' '/C'
  if ($LASTEXITCODE -ne 0) { throw 'Could not apply low-integrity no-write-up label to worker outputs' }
}

function Assert-WorkerNoReparseTree {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [switch]$AllowWorkerDataVolumeRoot)
  $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    if (-not $AllowWorkerDataVolumeRoot -or
        [IO.Path]::GetFullPath($Path).TrimEnd('\') -ine [IO.Path]::GetFullPath($script:WorkerDataRoot).TrimEnd('\')) {
      throw 'Worker data root is redirected'
    }
  }
  foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker data contains a reparse point; refusing recursive deletion' }
  }
}

function Assert-WorkerProtectedAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$ServiceSid, [switch]$AllowServiceWrite)
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (-not $acl.AreAccessRulesProtected) { throw 'Worker path ACL inherits untrusted access rules' }
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  if (-not $acl.Owner.Translate([Security.Principal.SecurityIdentifier]).Equals($adminSid)) { throw 'Worker path owner is not Builtin Administrators' }
  $trustedInstallerSid = try { ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
  foreach ($rule in $acl.Access) {
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($rule.FileSystemRights -band $writeRights) -ne 0 -and
        $sid.Value -notin @('S-1-5-18', 'S-1-5-32-544', $trustedInstallerSid) -and
        -not ($AllowServiceWrite -and $sid.Equals($ServiceSid))) {
      throw 'An untrusted principal can modify a protected worker path'
    }
  }
  $serviceRules = @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Equals($ServiceSid) })
  if ($serviceRules.Count -eq 0) { throw 'Worker service identity lacks an explicit protected-path ACL' }
}

function Get-WorkerInstallMarker {
  [CmdletBinding()]
  param()
  $path = Join-Path $script:WorkerInstallStateRoot 'worker-service.json'
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  $item = Get-Item -LiteralPath $path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker installation marker is redirected' }
  $stateRootItem = Get-Item -LiteralPath $script:WorkerInstallStateRoot -Force -ErrorAction Stop
  if ($stateRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker installation marker directory is redirected' }
  Assert-WorkerAdminOnlyAcl -Path $path
  Assert-WorkerAdminOnlyAcl -Path $script:WorkerInstallStateRoot
  $marker = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
  $owner = [guid]::Empty
  $validState = $marker.state -in @('Installing', 'Installed', 'RollbackRequired', 'Uninstalled')
  if ($marker.schema -ne 1 -or $marker.service_name -cne $script:WorkerServiceName -or
      -not [guid]::TryParse([string]$marker.owner_id, [ref]$owner) -or
      $marker.firewall_name -cne "$($script:WorkerFirewallNamePrefix)$($owner.ToString('D'))" -or
      $marker.firewall_group -cne "SumatraFuzz Worker $($owner.ToString('D'))" -or
      [IO.Path]::GetFullPath([string]$marker.data_root) -ine [IO.Path]::GetFullPath($script:WorkerDataRoot) -or
      [IO.Path]::GetFullPath([string]$marker.config_path) -ine [IO.Path]::GetFullPath((Join-Path $script:WorkerDataRoot 'worker-config.json')) -or
      [IO.Path]::GetFullPath([string]$marker.credentials_path) -ine [IO.Path]::GetFullPath((Join-Path $script:WorkerDataRoot 'credentials.dpapi')) -or
      -not $validState) {
    throw 'Worker installation marker is invalid'
  }
  return $marker
}

function Assert-WorkerAdminOnlyAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (-not $acl.AreAccessRulesProtected) { throw 'Worker ownership marker ACL inherits external permissions' }
  $ownerSid = $acl.Owner.Translate([Security.Principal.SecurityIdentifier]).Value
  if ($ownerSid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Worker ownership marker owner is not SYSTEM or Builtin Administrators' }
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    if (($rule.FileSystemRights -band $writeRights) -ne 0 -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Worker ownership marker is writable by an untrusted principal' }
  }
}

function Assert-WorkerHostCompatibleDacl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Security.Principal.SecurityIdentifier]$ServiceSid,
    [switch]$AllowServiceWrite,
    [switch]$RequireTrustedOwner,
    [switch]$AllowCurrentAdministratorOwner
  )
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedInstallerSid = try { ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
  $allowed = @('S-1-5-18', 'S-1-5-32-544', $trustedInstallerSid)
  if ($AllowServiceWrite -and $ServiceSid) { $allowed += $ServiceSid.Value }
  if ($RequireTrustedOwner) {
    $ownerReference = $acl.Owner
    if ($ownerReference -is [Security.Principal.SecurityIdentifier]) {
      $ownerSid = $ownerReference.Value
    } elseif ($ownerReference -is [Security.Principal.IdentityReference]) {
      $ownerSid = $ownerReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } else {
      $ownerSid = ([Security.Principal.NTAccount]::new([string]$ownerReference)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $ownerAllowed = $ownerSid -in $allowed
    if (-not $ownerAllowed -and $AllowCurrentAdministratorOwner) {
      $facts = Get-WorkerPlatformFacts
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $ownerAllowed = $facts.IsWindows -and $facts.Elevated -and $identity.User.Value -eq $ownerSid
    }
    if (-not $ownerAllowed) { throw 'Worker runtime path owner is not a trusted service or administrator identity' }
  }
  $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::FullControl -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if (($rule.FileSystemRights -band $writeRights) -ne 0 -and $sid -notin $allowed) { throw "Native host rejects writable principal on protected path: $Path" }
  }
}

function Write-WorkerInstallMarker {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$Marker)
  $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $stateParent = Split-Path -Parent $script:WorkerInstallStateRoot
  if (-not (Test-Path -LiteralPath $stateParent)) { [void](New-Item -ItemType Directory -Path $stateParent -Force) }
  Set-WorkerProtectedAcl -Path $stateParent -ServiceSid $admins -ServiceAccess AdminOnly -Directory
  if (-not (Test-Path -LiteralPath $script:WorkerInstallStateRoot)) { [void](New-Item -ItemType Directory -Path $script:WorkerInstallStateRoot -Force) }
  Set-WorkerProtectedAcl -Path $script:WorkerInstallStateRoot -ServiceSid $admins -ServiceAccess AdminOnly -Directory
  $path = Join-Path $script:WorkerInstallStateRoot 'worker-service.json'
  $temp = "$path.$([guid]::NewGuid().ToString('N')).tmp"
  $json = $Marker | ConvertTo-Json -Depth 8
  [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
  Set-WorkerProtectedAcl -Path $temp -ServiceSid $admins -ServiceAccess AdminOnly
  [IO.File]::Move($temp, $path, $true)
}

function Get-WorkerServiceCim {
  param()
  return Get-CimInstance -ClassName Win32_Service -Filter "Name='$script:WorkerServiceName'" -ErrorAction SilentlyContinue
}

function Invoke-WorkerSc {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$ArgumentList)
  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  & $sc @ArgumentList *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Windows Service Control Manager operation failed' }
}

function Assert-WorkerServiceMatchesMarker {
  param([Parameter(Mandatory)][object]$Marker)
  $service = Get-WorkerServiceCim
  if (-not $service -or [IO.Path]::GetFullPath($service.PathName.Trim('"')) -ine [IO.Path]::GetFullPath([string]$Marker.host_path) -or
      $service.StartName -ine $script:WorkerServiceAccount) {
    throw 'Existing worker service does not match the protected installation marker'
  }
}

function Set-WorkerServiceSecurityDescriptor {
  # Only SYSTEM and administrators may reconfigure, stop, or delete this service.
  $descriptor = 'D:P(A;;CCLCSWRPWPDTLOCRRCSDWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRRCSDWDWO;;;BA)'
  Invoke-WorkerSc @('sdset', $script:WorkerServiceName, $descriptor)
}

function Ensure-WorkerFirewallRule {
  param([Parameter(Mandatory)][object]$Marker, [Parameter(Mandatory)][object]$Layout, [string]$AdapterAlias)
  if ($Marker.bind_mode -eq 'Local') { return $false }
  $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $Marker.firewall_name -ErrorAction SilentlyContinue)
  $created = $false
  if ($existing.Count -eq 0) {
    $null = New-NetFirewallRule -PolicyStore PersistentStore -Name $Marker.firewall_name -DisplayName 'SumatraFuzz Worker (scoped)' -Group $Marker.firewall_group -Enabled True -Direction Inbound -Action Allow -Program $Layout.Host -Protocol TCP -LocalAddress $Marker.bind_address -LocalPort $Marker.port -RemoteAddress @($Marker.peer_cidrs) -InterfaceAlias $AdapterAlias -Profile Domain,Private -EdgeTraversalPolicy Block -ErrorAction Stop
    $created = $true
    $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $Marker.firewall_name -ErrorAction Stop)
  }
  if ($existing.Count -ne 1 -or $existing[0].Group -ne $Marker.firewall_group -or $existing[0].Enabled -ne 'True' -or $existing[0].Direction -ne 'Inbound' -or $existing[0].Action -ne 'Allow' -or @($existing[0].Profile | Where-Object { $_ -in @('Domain', 'Private') }).Count -ne 2 -or $existing[0].EdgeTraversalPolicy -ne 'Block') {
    throw 'Effective worker firewall rule does not match the requested scoped policy'
  }
  $addressFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
  $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
  $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
  $interfaceFilter = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $existing[0] -ErrorAction Stop
  $expectedPeers = @($Marker.peer_cidrs | Sort-Object -Unique)
  $actualPeers = @($addressFilter.RemoteAddress | Sort-Object -Unique)
  if (@($Marker.peer_cidrs).Count -ne $expectedPeers.Count -or
      @($addressFilter.LocalAddress).Count -ne 1 -or $addressFilter.LocalAddress[0] -ne $Marker.bind_address -or
      ($actualPeers -join ',') -cne ($expectedPeers -join ',') -or
      @($portFilter.LocalPort).Count -ne 1 -or $portFilter.LocalPort[0] -ne [string]$Marker.port -or
      $portFilter.Protocol -ne 'TCP' -or $appFilter.Program -ine $Layout.Host -or
      @($interfaceFilter.InterfaceAlias).Count -ne 1 -or $interfaceFilter.InterfaceAlias[0] -ine $AdapterAlias) {
    throw 'Effective worker firewall filters are broader than the requested policy'
  }
  return $created
}

function Remove-WorkerFirewallRule {
  param([Parameter(Mandatory)][object]$Marker)
  $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Marker.firewall_name -ErrorAction SilentlyContinue)
  if ($rules.Count -eq 0) { return }
  if ($rules.Count -ne 1 -or $rules[0].Group -ne $Marker.firewall_group) { throw 'Worker firewall ownership check failed; rule was retained' }
  Remove-NetFirewallRule -InputObject $rules[0] -ErrorAction Stop
}

function New-WorkerServiceMarker {
  param([Parameter(Mandatory)][object]$Layout, [Parameter(Mandatory)][object]$Volume, [Parameter(Mandatory)][long]$LimitBytes, [Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$Port, [string]$AdapterGuid, [string[]]$PeerCidrs)
  $owner = [guid]::NewGuid().ToString('D')
  return [pscustomobject]@{
    schema = 1; state = 'Installing'; owner_id = $owner; service_name = $script:WorkerServiceName
    install_root = $Layout.Root; host_path = $Layout.Host; node_path = $Layout.Node; entry_path = $Layout.Entry
    config_path = (Join-Path $script:WorkerDataRoot 'worker-config.json'); credentials_path = (Join-Path $script:WorkerDataRoot 'credentials.dpapi')
    signing_key_path = $Layout.SigningKey; data_root = $script:WorkerDataRoot
    volume_id = $Volume.UniqueId; quota_bytes = $LimitBytes; bind_mode = $Mode; bind_address = $Address
    port = $Port; adapter_guid = $AdapterGuid; peer_cidrs = @($PeerCidrs)
    firewall_name = "$($script:WorkerFirewallNamePrefix)$owner"; firewall_group = "SumatraFuzz Worker $owner"
  }
}

function Assert-WorkerMarkerMatchesRequest {
  param([Parameter(Mandatory)][object]$Marker, [Parameter(Mandatory)][object]$Layout, [Parameter(Mandatory)][object]$Volume, [long]$LimitBytes, [string]$Mode, [string]$Address, [int]$Port, [string]$AdapterGuid, [string[]]$PeerCidrs)
  $samePeers = (@($Marker.peer_cidrs) -join ',') -ceq (@($PeerCidrs) -join ',')
  if ([IO.Path]::GetFullPath($Marker.install_root) -ine $Layout.Root -or
      (Get-WorkerVolumeGuid $Marker.volume_id) -ne (Get-WorkerVolumeGuid $Volume.UniqueId) -or
      [long]$Marker.quota_bytes -ne $LimitBytes -or $Marker.bind_mode -cne $Mode -or
      $Marker.bind_address -cne $Address -or [int]$Marker.port -ne $Port -or
      $Marker.adapter_guid -ine $AdapterGuid -or -not $samePeers) {
    throw 'Requested worker service configuration differs from its protected installation marker'
  }
}

function Install-SumatrafuzzWorkerService {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][string]$ExpectedDataVolumeId,
    [Parameter(Mandatory)][ValidateRange(67108864, 1099511627776)][long]$WorkerDiskLimitBytes,
    [ValidateSet('Local', 'Remote')][string]$BindMode = 'Local',
    [string]$BindAddress = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 8443,
    [string]$AdapterGuid,
    [string[]]$PeerCidrs = @()
  )
  Assert-WorkerPlatform -RequireElevation
  $layout = Resolve-WorkerInstallLayout $InstallRoot
  # Protect every ancestor, since DELETE_CHILD/rename rights above the immediate
  # parent can replace the service executable tree despite a protected root DACL.
  Assert-WorkerProtectedInstallAncestors -InstallRoot $layout.Root
  [void](Get-WorkerProtectedTreeInventory -Path $layout.Root)
  Assert-WorkerHostCompatibleDacl -Path (Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'ProgramData')
  Assert-WorkerBindConfiguration -Mode $BindMode -Address $BindAddress -Port $Port -AdapterGuid $AdapterGuid -PeerCidrs $PeerCidrs
  $volume = Assert-WorkerDataVolume -InstallRoot $layout.Root -ExpectedVolumeId $ExpectedDataVolumeId
  $marker = Get-WorkerInstallMarker
  $service = Get-WorkerServiceCim
  if (-not $marker -and $service) { throw 'An unowned service with the worker service name already exists' }
  if (-not $marker) {
    $marker = New-WorkerServiceMarker -Layout $layout -Volume $volume -LimitBytes $WorkerDiskLimitBytes -Mode $BindMode -Address $BindAddress -Port $Port -AdapterGuid $AdapterGuid -PeerCidrs $PeerCidrs
    Write-WorkerInstallMarker $marker
  } else {
    Assert-WorkerMarkerMatchesRequest -Marker $marker -Layout $layout -Volume $volume -LimitBytes $WorkerDiskLimitBytes -Mode $BindMode -Address $BindAddress -Port $Port -AdapterGuid $AdapterGuid -PeerCidrs $PeerCidrs
    if ($service) { Assert-WorkerServiceMatchesMarker $marker }
  }

  $createdService = $false
  $createdFirewall = $false
  $quotaAttempted = $false
  try {
    if (-not $service) {
      # Keep an unprovisioned service from entering a boot-time restart loop.
      # The explicit provisioning command enables automatic startup only after
      # protected config, credentials, and signed pairing have been staged.
      Invoke-WorkerSc @('create', $script:WorkerServiceName, 'binPath=', ('"' + $layout.Host + '"'), 'obj=', $script:WorkerServiceAccount, 'password=', '', 'start=', 'demand', 'DisplayName=', 'SumatraFuzz Worker')
      $createdService = $true
    }
    Invoke-WorkerSc @('sidtype', $script:WorkerServiceName, 'unrestricted')
    # The service SID is provisioned by SCM; resolve it only after the service
    # exists (or after confirming an existing owned service above).
    $serviceSid = Resolve-WorkerSid $script:WorkerServiceAccount
    if (-not (Test-Path -LiteralPath $script:WorkerDataRoot)) { [void](New-Item -ItemType Directory -Path $script:WorkerDataRoot -Force) }
    $dataParent = Split-Path -Parent $script:WorkerDataRoot
    if (-not (Test-Path -LiteralPath $dataParent)) { [void](New-Item -ItemType Directory -Path $dataParent -Force) }
    $parentItem = Get-Item -LiteralPath $dataParent -Force -ErrorAction Stop
    if ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker data parent contains a reparse point' }
    [void](Assert-WorkerDataMountPoint -DataRoot $script:WorkerDataRoot -InstallRoot $layout.Root -ExpectedVolumeId $volume.UniqueId)
    Set-WorkerProtectedAcl -Path $dataParent -ServiceSid $serviceSid -ServiceAccess AdminOnly -Directory
    # Keep the fixed data-root directory read-only to the service so its
    # DELETE_CHILD right cannot replace the administrator-provisioned config
    # or DPAPI credential files. Mutable state lives in explicit child dirs.
    Set-WorkerProtectedAcl -Path $script:WorkerDataRoot -ServiceSid $serviceSid -ServiceAccess Read -Directory
    foreach ($directory in @('trust', 'runs', 'evidence', 'tmp', 'state', 'security', 'security\audit', 'inputs', 'outputs')) {
      $path = Join-Path $script:WorkerDataRoot $directory
      if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path -Force) }
      if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker data subdirectory contains a reparse point' }
      # Existing trust stores and SQLite sidecars are security state. Only the
      # runtime directory ACL is repaired; descendants must already be safe,
      # since adopting writable state would trust content a local user could
      # have changed before this installation.
      Protect-WorkerRuntimeTree -Path $path -ServiceSid $serviceSid -RestrictedRead:([bool]($directory -eq 'inputs')) -RestrictedTraverse:([bool]($directory -eq 'outputs'))
      if ($directory -eq 'outputs') { Set-WorkerOutputLowIntegrity -Path $path }
    }
    foreach ($file in @($marker.config_path, $marker.credentials_path)) {
      if (-not (Test-Path -LiteralPath $file)) { [IO.File]::WriteAllBytes($file, [byte[]]@()) }
      if ((Get-Item -LiteralPath $file -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker protected runtime file is redirected' }
      $access = if ($file -ieq $marker.credentials_path) { 'Modify' } else { 'Read' }
      Set-WorkerProtectedAcl -Path $file -ServiceSid $serviceSid -ServiceAccess $access
      Assert-WorkerProtectedAcl -Path $file -ServiceSid $serviceSid -AllowServiceWrite:($access -eq 'Modify')
    }
    $stagingRoot = Join-Path $script:WorkerDataRoot 'staging'
    if (-not (Test-Path -LiteralPath $stagingRoot)) { [void](New-Item -ItemType Directory -Path $stagingRoot -Force) }
    if ((Get-Item -LiteralPath $stagingRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker staging path is redirected' }
    Set-WorkerProtectedAcl -Path $stagingRoot -ServiceSid $serviceSid -ServiceAccess Read -Directory
    foreach ($stagedName in @('worker-credentials.json', 'worker-pairing.sfpair', 'worker-trust-operation.sftxn')) {
      $stagedPath = Join-Path $stagingRoot $stagedName
      if (-not (Test-Path -LiteralPath $stagedPath)) { [IO.File]::WriteAllBytes($stagedPath, [byte[]]@()) }
      if ((Get-Item -LiteralPath $stagedPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Worker staging file is redirected' }
      Set-WorkerProtectedAcl -Path $stagedPath -ServiceSid $serviceSid -ServiceAccess ReadDelete
      Assert-WorkerProtectedAcl -Path $stagedPath -ServiceSid $serviceSid -AllowServiceWrite
    }
    Assert-WorkerHostCompatibleDacl -Path $dataParent
    Assert-WorkerHostCompatibleDacl -Path $script:WorkerDataRoot -ServiceSid $serviceSid -AllowServiceWrite
    if (-not $marker.signing_key_path -or -not (Test-Path -LiteralPath $marker.signing_key_path)) { throw 'Organization signing public key is not staged at the fixed protected path' }
    Set-WorkerProtectedTree -Path $layout.Root -ServiceSid $serviceSid -RestrictedExecute
    Set-WorkerProtectedAcl -Path $layout.SigningKey -ServiceSid $serviceSid -ServiceAccess Read
    Assert-WorkerProtectedAcl -Path $layout.SigningKey -ServiceSid $serviceSid

    if ($marker.state -eq 'Installed') { Assert-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $WorkerDiskLimitBytes }
    else { $quotaAttempted = [bool](Set-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $WorkerDiskLimitBytes) }

    Assert-WorkerBindConfiguration -Mode $BindMode -Address $BindAddress -Port $Port -AdapterGuid $AdapterGuid -PeerCidrs $PeerCidrs
    $adapterAlias = $null
    if ($BindMode -eq 'Remote') { $adapterAlias = (Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { ([guid]$_.InterfaceGuid) -eq [guid]$AdapterGuid }).Name }
    $createdFirewall = Ensure-WorkerFirewallRule -Marker $marker -Layout $layout -AdapterAlias $adapterAlias
    Set-WorkerServiceSecurityDescriptor
    $wasRunning = $service -and $service.State -eq 'Running'
    $marker.state = 'Installed'
    Write-WorkerInstallMarker $marker
    $hasRuntimeInputs = (Get-Item -LiteralPath $marker.config_path).Length -gt 0 -and (Get-Item -LiteralPath $marker.credentials_path).Length -gt 0
    if ($wasRunning -and -not $hasRuntimeInputs) { throw 'Running worker service lacks provisioned protected runtime configuration or credentials' }
    if (-not $wasRunning -and $hasRuntimeInputs) { Invoke-WorkerSc @('start', $script:WorkerServiceName) }
  } catch {
    $originalError = $_
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    if ($createdFirewall) { try { Remove-WorkerFirewallRule $marker } catch { $rollbackErrors.Add('firewall') } }
    if ($createdService) {
      try {
        $current = Get-WorkerServiceCim
        if ($current -and [IO.Path]::GetFullPath($current.PathName.Trim('"')) -ieq [IO.Path]::GetFullPath($layout.Host)) {
          Invoke-WorkerSc @('stop', $script:WorkerServiceName)
          Invoke-WorkerSc @('delete', $script:WorkerServiceName)
        }
      } catch { $rollbackErrors.Add('service') }
    }
    if ($quotaAttempted -and -not $service) { try { Restore-WorkerQuota -VolumeId $volume.UniqueId } catch { $rollbackErrors.Add('quota') } }
    if ($rollbackErrors.Count -eq 0 -and -not $service) {
      Remove-Item -LiteralPath (Join-Path $script:WorkerInstallStateRoot 'worker-service.json') -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $marker.config_path -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $marker.credentials_path -Force -ErrorAction SilentlyContinue
    } else {
      $marker.state = 'RollbackRequired'
      try { Write-WorkerInstallMarker $marker } catch { $rollbackErrors.Add('marker') }
    }
    if ($rollbackErrors.Count -gt 0) { throw 'Worker service install failed and rollback is incomplete; protected install marker retained for operator recovery' }
    throw $originalError
  }
}

function Uninstall-SumatrafuzzWorkerService {
  [CmdletBinding()]
  param([switch]$DeleteData)
  Assert-WorkerPlatform -RequireElevation
  $marker = Get-WorkerInstallMarker
  if (-not $marker) { throw 'No protected worker installation marker exists; refusing to remove resources' }
  $service = Get-WorkerServiceCim
  if ($service) { Assert-WorkerServiceMatchesMarker $marker }
  $firewall = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $marker.firewall_name -ErrorAction SilentlyContinue)
  if ($firewall.Count -gt 1 -or ($firewall.Count -eq 1 -and $firewall[0].Group -ne $marker.firewall_group)) { throw 'Worker firewall ownership check failed; resources were retained' }
  if ($service) {
    if ($service.State -ne 'Stopped') {
      Invoke-WorkerSc @('stop', $script:WorkerServiceName)
      $deadline = [DateTime]::UtcNow.AddSeconds(60)
      do {
        Start-Sleep -Milliseconds 250
        $service = Get-WorkerServiceCim
      } while ($service -and $service.State -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
      if ($service -and $service.State -ne 'Stopped') { throw 'Worker service did not stop within the bounded drain interval' }
    }
    Invoke-WorkerSc @('delete', $script:WorkerServiceName)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
      Start-Sleep -Milliseconds 250
      $service = Get-WorkerServiceCim
    } while ($service -and [DateTime]::UtcNow -lt $deadline)
    if ($service) { throw 'Worker service deletion is still pending' }
  }
  Remove-WorkerFirewallRule $marker
  if ($DeleteData) {
    $dataRoot = [string]$marker.data_root
    if ([IO.Path]::GetFullPath($dataRoot) -ine [IO.Path]::GetFullPath($script:WorkerDataRoot)) { throw 'Worker data deletion path does not match the fixed service data root' }
    [void](Assert-WorkerDataVolume -DataRoot $dataRoot -InstallRoot ([string]$marker.install_root) -ExpectedVolumeId ([string]$marker.volume_id))
    Assert-WorkerNoReparseTree -Path $dataRoot -AllowWorkerDataVolumeRoot
    Restore-WorkerQuota -VolumeId ([string]$marker.volume_id)
    foreach ($item in @(Get-ChildItem -LiteralPath $dataRoot -Force -ErrorAction Stop)) {
      Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
    }
  }
  $marker.state = 'Uninstalled'
  Write-WorkerInstallMarker $marker
}

Export-ModuleMember -Function Get-WorkerPlatformFacts, Assert-WorkerPlatform, Resolve-WorkerInstallLayout, Assert-WorkerProtectedInstallAncestors, Test-WorkerPrivateAddress, Test-WorkerCidr, Assert-WorkerBindConfiguration, Assert-WorkerDataMountPoint, Assert-WorkerDataVolume, Get-WorkerQuotaSetting, Get-WorkerServiceQuotaRecord, Assert-WorkerQuota, Set-WorkerQuota, Restore-WorkerQuota, Invoke-WorkerFsutil, Resolve-WorkerSid, Set-WorkerProtectedAcl, Set-WorkerProtectedTree, Protect-WorkerRuntimeTree, Set-WorkerOutputLowIntegrity, Assert-WorkerProtectedAcl, Assert-WorkerAdminOnlyAcl, Assert-WorkerHostCompatibleDacl, Assert-WorkerNoReparseTree, Get-WorkerInstallMarker, Write-WorkerInstallMarker, Invoke-WorkerSc, Get-WorkerServiceCim, Assert-WorkerServiceMatchesMarker, Install-SumatrafuzzWorkerService, Uninstall-SumatrafuzzWorkerService
