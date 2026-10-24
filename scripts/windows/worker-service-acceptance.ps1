#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$RepoRoot,
  [string]$PackageRoot = (Join-Path $RepoRoot 'release/worker-service/SumatraFuzz'),
  [string]$FixtureRoot = (Join-Path $env:RUNNER_TEMP 'sf-worker-service-fixture')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable Windows GitHub runner required' }
if (-not [IO.Path]::IsPathFullyQualified($RepoRoot) -or -not [IO.Path]::IsPathFullyQualified($PackageRoot)) { throw 'Acceptance roots must be absolute paths' }
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'Installed worker acceptance requires Windows x64' }
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Security.Principal.WindowsPrincipal]::new($currentIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Only disposable service installation and configuration may run elevated'
}

$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)
$PackageRoot = [IO.Path]::GetFullPath($PackageRoot)
$DataRoot = Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'ProgramData\SumatraFuzz\Worker'
$ProgramDataRoot = Split-Path -Parent $DataRoot
$InstallStateRoot = Join-Path $ProgramDataRoot 'InstallState'
$InstallRoot = Join-Path $env:ProgramFiles 'SumatraFuzz'
$FixtureRoot = [IO.Path]::GetFullPath($FixtureRoot)
$VhdPath = Join-Path $env:RUNNER_TEMP ('sf-worker-' + [guid]::NewGuid().ToString('N') + '.vhdx')
$VolumeLabel = 'SFWorker' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$DiskLimitBytes = 1GB
$Mounted = $false
$Installed = $false
$Module = Join-Path $RepoRoot 'scripts/windows/worker-service-config.psm1'
Import-Module $Module -Force

function Protect-AcceptanceDirectory {
  param([Parameter(Mandatory)][string]$Path)
  [void](New-Item -ItemType Directory -Path $Path -Force)
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $objects = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
  foreach ($item in $objects) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Acceptance fixture tree contains a reparse point' }
    $acl = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($adminSid)
    $inheritance = if ($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sidText in @('S-1-5-18', $adminSid.Value, $identity.Value)) {
      $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
      $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
      [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $item.FullName -AclObject $acl
  }
}

function Invoke-PwshFile {
  param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string[]]$Arguments)
  & (Get-Command pwsh -ErrorAction Stop).Source -NoProfile -NonInteractive -File $File @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Windows worker service acceptance command failed: $([IO.Path]::GetFileName($File))" }
}

function Build-InstalledPolicy {
  param([Parameter(Mandatory)][string]$VolumeId)
  $sourceLockPath = Join-Path $RepoRoot 'external/native-tools/locks/target-lock.json'
  $sourceManifestPath = Join-Path $RepoRoot 'runs/a4/debug-evidence/a4-confirmed.json'
  $sourceBinaryRoot = Join-Path $RepoRoot 'build/a3/Release'
  $targetLock = Get-Content -LiteralPath $sourceLockPath -Raw | ConvertFrom-Json -AsHashtable
  $manifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json -AsHashtable
  $engineRoot = Join-Path $InstallRoot 'engine'
  $toolRoot = Join-Path $InstallRoot 'tools'
  $configRoot = Join-Path $InstallRoot 'config'
  $dynamoRoot = Join-Path $toolRoot 'dynamorio'
  $winaflRoot = Join-Path $toolRoot 'winafl'
  foreach ($directory in @($engineRoot, $toolRoot, $dynamoRoot, $winaflRoot, $configRoot)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
  foreach ($file in @('sumatrafuzz-harness.exe', 'PdfFilter.dll', 'libmupdf.dll')) {
    Copy-Item -LiteralPath (Join-Path $sourceBinaryRoot $file) -Destination (Join-Path $engineRoot $file) -Force
  }
  $drrunSource = [IO.Path]::GetFullPath([string]$targetLock.tools.drrun.path)
  $drrunParent = Split-Path -Parent $drrunSource
  $drrunRelative = [IO.Path]::GetRelativePath((Join-Path $RepoRoot 'external/native-tools/dynamorio'), $drrunParent)
  $drrunDestination = Join-Path $dynamoRoot $drrunRelative
  [void](New-Item -ItemType Directory -Path $drrunDestination -Force)
  Copy-Item -Path (Join-Path $drrunParent '*') -Destination $drrunDestination -Recurse -Force
  $aflSource = [IO.Path]::GetFullPath([string]$targetLock.tools.afl_fuzz.path)
  $winaflSource = [IO.Path]::GetFullPath([string]$targetLock.tools.winafl_client.path)
  Copy-Item -LiteralPath $aflSource -Destination (Join-Path $winaflRoot 'afl-fuzz.exe') -Force
  Copy-Item -LiteralPath $winaflSource -Destination (Join-Path $winaflRoot 'winafl.dll') -Force
  $nativeToolsRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'external/native-tools')).TrimEnd('\') + '\'
  $runtimeDependencies = @()
  $runtimeEntries = @()
  if ($targetLock.ContainsKey('runtime_dependencies')) { $runtimeEntries = @($targetLock.runtime_dependencies) }
  foreach ($dependency in $runtimeEntries) {
    $source = [IO.Path]::GetFullPath([string]$dependency.path)
    if (-not $source.StartsWith($nativeToolsRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $source -PathType Leaf) -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$dependency.sha256) {
      throw 'Pinned Microsoft runtime dependency is missing, outside the tool root, or changed'
    }
    $destination = Join-Path $winaflRoot (Split-Path $source -Leaf)
    Copy-Item -LiteralPath $source -Destination $destination -Force
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$dependency.sha256) {
      throw 'Copied Microsoft runtime dependency failed hash verification'
    }
    $dependency.path = $destination
    $runtimeDependencies += $dependency
  }

  $targetLock.tools.drrun.path = Join-Path $drrunDestination ([IO.Path]::GetFileName($drrunSource))
  $targetLock.tools.afl_fuzz.path = Join-Path $winaflRoot 'afl-fuzz.exe'
  $targetLock.tools.winafl_client.path = Join-Path $winaflRoot 'winafl.dll'
  $targetLock.runtime_dependencies = $runtimeDependencies
  $installedLockPath = Join-Path $configRoot 'target-lock.json'
  $lockJson = ConvertTo-Json -InputObject $targetLock -Depth 12
  [IO.File]::WriteAllText($installedLockPath, $lockJson + "`n", [Text.UTF8Encoding]::new($false))
  $lockHash = (Get-FileHash -LiteralPath $installedLockPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifest.toolchain_lock_sha256 = $lockHash
  $installedManifestPath = Join-Path $configRoot 'a4-confirmed.json'
  $manifestJson = ConvertTo-Json -InputObject $manifest -Depth 12
  [IO.File]::WriteAllText($installedManifestPath, $manifestJson + "`n", [Text.UTF8Encoding]::new($false))
  $manifestHash = (Get-FileHash -LiteralPath $installedManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $volumeGuid = Get-WorkerVolumeGuid $VolumeId
  $workerId = (Get-Content -LiteralPath (Join-Path $FixtureRoot 'fixture-summary.json') -Raw | ConvertFrom-Json).workerId
  $config = [ordered]@{
    schema = 1
    workerId = $workerId
    bind = [ordered]@{ mode = 'local'; address = '127.0.0.1'; port = 18443; adapterGuid = ''; peerCidrs = @() }
    storage = [ordered]@{ root = $DataRoot; volumeId = $volumeGuid; diskLimitBytes = $DiskLimitBytes }
    trust = [ordered]@{ organizationSigningPublicKeyPath = Join-Path $InstallRoot 'config/organization-signing-public-key.pem' }
    credentials = [ordered]@{ protectedBundlePath = Join-Path $DataRoot 'credentials.dpapi' }
    policy = [ordered]@{
      maxLimits = [ordered]@{ max_duration_s = 600; max_memory_bytes = 4GB; max_disk_bytes = $DiskLimitBytes; max_cpu_percent = 75 }
      pinnedTargetLockSha256 = $lockHash
      pinnedA4ManifestSha256 = $manifestHash
      targetLockPath = $installedLockPath
      a4ManifestPath = $installedManifestPath
      harnessPath = Join-Path $engineRoot 'sumatrafuzz-harness.exe'
      allowedBinaryRoot = $engineRoot
      allowedToolRoot = $toolRoot
      allowedInputRoot = Join-Path $DataRoot 'inputs'
      outputRoot = Join-Path $DataRoot 'outputs'
    }
    audit = [ordered]@{ maxBytes = 16MB; maxSegmentBytes = 1MB; maxSegments = 16 }
  }
  $configPath = Join-Path $FixtureRoot 'worker-config.json'
  [IO.File]::WriteAllText($configPath, (ConvertTo-Json -InputObject $config -Depth 16) + "`n", [Text.UTF8Encoding]::new($false))
  return $configPath
}

function Assert-OrdinaryUserDenials {
  param([Parameter(Mandatory)][string]$SigningKeyPath)
  $account = 'sf-read-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
  $password = ConvertTo-SecureString ([Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'aA1!') -AsPlainText -Force
  $dpapiProbePath = Join-Path $FixtureRoot 'dpapi-envelope-user-test.bin'
  $process = $null
  try {
    $user = New-LocalUser -Name $account -Password $password -AccountNeverExpires -PasswordNeverExpires
    Add-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')) -Member $user
    [IO.File]::WriteAllBytes($dpapiProbePath, [IO.File]::ReadAllBytes((Join-Path $DataRoot 'credentials.dpapi')))
    $userSid = $user.SID
    $rootAcl = Get-Acl -LiteralPath $FixtureRoot
    $rootAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      $userSid, [Security.AccessControl.FileSystemRights]::Traverse,
      [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $FixtureRoot -AclObject $rootAcl
    $envelopeAcl = Get-Acl -LiteralPath $dpapiProbePath
    $envelopeAcl.SetAccessRuleProtection($true, $false)
    $envelopeAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544', $currentIdentity.User.Value)) {
      $envelopeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($sidText), [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
      ))
    }
    $envelopeAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
      $userSid, [Security.AccessControl.FileSystemRights]::Read,
      [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $dpapiProbePath -AclObject $envelopeAcl
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command pwsh -ErrorAction Stop).Source
    $start.WorkingDirectory = $RepoRoot
    $start.UseShellExecute = $false
    $start.UserName = $account
    $start.Domain = $env:COMPUTERNAME
    $start.Password = $password
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @(
      '-NoProfile', '-NonInteractive', '-File', (Join-Path $RepoRoot 'scripts/windows/assert-worker-files-denied.ps1'),
      '-ConfigurationPath', (Join-Path $DataRoot 'worker-config.json'),
      '-CredentialsPath', (Join-Path $DataRoot 'credentials.dpapi'),
      '-SigningKeyPath', $SigningKeyPath,
      '-RuntimePath', (Join-Path $InstallRoot 'runtime/node.exe'),
      '-DpapiEnvelopePath', $dpapiProbePath,
      '-SupervisorModulePath', (Join-Path $RepoRoot 'native/worker-supervisor/build/Release/worker_supervisor.node')
    )) { $start.ArgumentList.Add($argument) }
    foreach ($name in @('GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')) {
      [void]$start.Environment.Remove($name)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Could not start ordinary-user worker access probe' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(15000)) {
      $process.Kill($true)
      [void]$process.WaitForExit(5000)
      throw 'Ordinary-user worker access probe exceeded its deadline'
    }
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
      throw "Ordinary-user worker access probe failed (exit=$($process.ExitCode)): $out $err"
    }
  } finally {
    if ($process) {
      if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) }
      $process.Dispose()
    }
    if (Get-LocalUser -Name $account -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $account }
    $password.Dispose()
    Remove-Item -LiteralPath $dpapiProbePath -Force -ErrorAction SilentlyContinue
  }
}

try {
  if (Test-Path -LiteralPath $DataRoot) {
    $existing = @(Get-ChildItem -LiteralPath $DataRoot -Force -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) { throw 'Disposable worker data mount point is already in use' }
  } else {
    [void](New-Item -ItemType Directory -Path $DataRoot -Force)
  }
  foreach ($path in @($InstallRoot, $InstallStateRoot)) {
    if (Test-Path -LiteralPath $path) { throw 'Disposable worker installation path is already in use' }
  }
  if (Test-Path -LiteralPath $ProgramDataRoot) {
    $unrelated = @(Get-ChildItem -LiteralPath $ProgramDataRoot -Force | Where-Object { $_.Name -notin @('Worker', 'InstallState') })
    if ($unrelated.Count -gt 0) { throw 'Disposable worker ProgramData parent contains unrelated data' }
  }

  if (-not (Test-Path -LiteralPath (Join-Path $FixtureRoot 'fixture-summary.json') -PathType Leaf)) {
    node (Join-Path $RepoRoot 'scripts/windows/create-worker-service-fixture.mjs') $FixtureRoot
    if ($LASTEXITCODE -ne 0) { throw 'Could not create ephemeral TLS and signed-pairing fixtures' }
  }
  Protect-AcceptanceDirectory -Path $FixtureRoot
  $env:WORKER_SERVICE_FIXTURE_ROOT = $FixtureRoot

  $diskpartPath = Join-Path $FixtureRoot 'create-worker-vhd.txt'
  @(
    "create vdisk file=`"$VhdPath`" maximum=2048 type=expandable"
    "select vdisk file=`"$VhdPath`""
    'attach vdisk'
  ) | Set-Content -LiteralPath $diskpartPath -Encoding ascii
  & diskpart.exe /s $diskpartPath *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create and attach the disposable NTFS worker volume' }
  $image = Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
  $disk = $image | Get-Disk -ErrorAction Stop
  if (-not $disk.IsOffline) { Set-Disk -Number $disk.Number -IsOffline $false -IsReadOnly $false }
  if ($disk.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null }
  $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize
  $volume = Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel $VolumeLabel -Confirm:$false
  Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath ($DataRoot + '\')
  $Mounted = $true
  $volume = Get-Volume -FileSystemLabel $VolumeLabel -ErrorAction Stop
  if ($volume.FileSystem -ne 'NTFS') { throw 'Disposable worker data volume is not NTFS' }

  [void](New-Item -ItemType Directory -Path $InstallRoot -Force)
  Copy-Item -Path (Join-Path $PackageRoot '*') -Destination $InstallRoot -Recurse -Force
  $publicKey = Join-Path $InstallRoot 'config/organization-signing-public-key.pem'
  Copy-Item -LiteralPath (Join-Path $FixtureRoot 'organization-public.pem') -Destination $publicKey -Force
  $configPath = Build-InstalledPolicy -VolumeId $volume.UniqueId
  $installScript = Join-Path $InstallRoot 'provisioning/install-worker-service.ps1'
  $provisionScript = Join-Path $InstallRoot 'provisioning/provision-worker-service.ps1'
  $uninstallScript = Join-Path $InstallRoot 'provisioning/uninstall-worker-service.ps1'
  Invoke-PwshFile -File $installScript -Arguments @(
    '-InstallRoot', $InstallRoot,
    '-ExpectedDataVolumeId', $volume.UniqueId,
    '-WorkerDiskLimitBytes', [string]$DiskLimitBytes,
    '-BindMode', 'Local',
    '-BindAddress', '127.0.0.1',
    '-Port', '18443'
  )
  $Installed = $true
  Invoke-PwshFile -File $provisionScript -Arguments @(
    '-ConfigurationPath', $configPath,
    '-WorkerCredentialsPath', (Join-Path $FixtureRoot 'worker-credentials.json'),
    '-PairingBundlePath', (Join-Path $FixtureRoot 'controller-1.sfpair')
  )
  Invoke-PwshFile -File $provisionScript -Arguments @(
    '-PairingBundlePath', (Join-Path $FixtureRoot 'controller-2.sfpair'),
    '-Live'
  )
  $installedService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SumatraFuzzWorker'" -ErrorAction Stop
  if (-not $installedService -or $installedService.StartName -ine 'NT SERVICE\SumatraFuzzWorker' -or $installedService.State -ne 'Running') {
    throw 'Installed worker service does not run under its dedicated service identity'
  }
  $listeningAddresses = @(Get-NetTCPConnection -State Listen -LocalPort 18443 -ErrorAction Stop | Select-Object -ExpandProperty LocalAddress -Unique)
  if ($listeningAddresses.Count -ne 1 -or $listeningAddresses[0] -ne '127.0.0.1') { throw 'Local worker listener escaped its loopback-only binding' }
  $marker = Get-WorkerInstallMarker
  if (Get-NetFirewallRule -PolicyStore PersistentStore -Name $marker.firewall_name -ErrorAction SilentlyContinue) {
    throw 'Loopback-only worker installation created an inbound firewall allow rule'
  }
  Assert-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $DiskLimitBytes
  $mismatchedQuotaExit = 0
  & (Get-Command pwsh -ErrorAction Stop).Source -NoProfile -NonInteractive -File $installScript `
    -InstallRoot $InstallRoot -ExpectedDataVolumeId $volume.UniqueId -WorkerDiskLimitBytes ($DiskLimitBytes + 1) `
    -BindMode Local -BindAddress 127.0.0.1 -Port 18443
  $mismatchedQuotaExit = $LASTEXITCODE
  if ($mismatchedQuotaExit -eq 0) { throw 'Installed worker accepted a disk quota that differs from its protected marker' }
  Assert-WorkerQuota -VolumeId $volume.UniqueId -LimitBytes $DiskLimitBytes
  Assert-OrdinaryUserDenials -SigningKeyPath $publicKey

  $env:WORKER_SERVICE_DATA_ROOT = $DataRoot
  $env:WORKER_SERVICE_PROVISIONER_PATH = Join-Path $InstallRoot 'provisioning/provision-worker-service.ps1'
  $env:WORKER_SERVICE_ACCEPTANCE_CLEANUP = 'false'
  node --experimental-strip-types (Join-Path $RepoRoot 'scripts/windows/worker-service-acceptance.ts')
  if ($LASTEXITCODE -ne 0) { throw 'Installed-service mTLS and genuine native acceptance failed' }

  $forcedRunPath = Join-Path $FixtureRoot 'forced-termination-run.json'
  if (-not (Test-Path -LiteralPath $forcedRunPath -PathType Leaf)) { throw 'Forced-termination run marker is missing' }
  $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SumatraFuzzWorker'" -ErrorAction Stop
  if (-not $service -or $service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) { throw 'Worker service is unavailable before forced-stop acceptance' }
  $serviceProcessId = [uint32]$service.ProcessId
  $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
  $byParent = @{}
  foreach ($process in $processes) {
    $parent = [uint32]$process.ParentProcessId
    if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = [System.Collections.Generic.List[object]]::new() }
    $byParent[$parent].Add($process)
  }
  $pending = [System.Collections.Generic.Queue[uint32]]::new()
  $pending.Enqueue($serviceProcessId)
  $seen = [System.Collections.Generic.HashSet[uint32]]::new()
  while ($pending.Count -gt 0) {
    $parent = $pending.Dequeue()
    if (-not $seen.Add($parent)) { continue }
    foreach ($child in $byParent[$parent]) { $pending.Enqueue([uint32]$child.ProcessId) }
  }
  if ($seen.Count -lt 3) { throw 'Active parser descendants were not present for forced-stop acceptance' }
  $tree = @($processes | Where-Object { $seen.Contains([uint32]$_.ProcessId) } | ForEach-Object {
      [ordered]@{ process_id = [uint32]$_.ProcessId; creation_date = [string]$_.CreationDate }
    })
  Stop-Process -Id $serviceProcessId -Force -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddSeconds(20)
  $remainingTree = @($tree)
  do {
    Start-Sleep -Milliseconds 250
    $liveProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $remainingTree = @($tree | Where-Object {
        $expected = $_
        @($liveProcesses | Where-Object {
            [uint32]$_.ProcessId -eq [uint32]$expected.process_id -and [string]$_.CreationDate -eq $expected.creation_date
          }).Count -gt 0
      })
  } while ($remainingTree.Count -gt 0 -and [DateTime]::UtcNow -lt $deadline)
  if ($remainingTree.Count -gt 0) { throw 'Forced service termination left a worker or parser descendant alive' }
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do {
    Start-Sleep -Milliseconds 250
    $service = Get-Service -Name 'SumatraFuzzWorker' -ErrorAction SilentlyContinue
  } while ($service -and $service.Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
  if (-not $service -or $service.Status -ne 'Stopped') { throw 'SCM did not observe forced worker-host termination' }
  [IO.File]::WriteAllText(
    (Join-Path $FixtureRoot 'forced-termination-tree-verified.json'),
    (ConvertTo-Json -InputObject @{ descendantsTerminated = $true } -Compress) + "`n",
    [Text.UTF8Encoding]::new($false)
  )
  Start-Service -Name 'SumatraFuzzWorker' -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do {
    Start-Sleep -Milliseconds 250
    $service = Get-Service -Name 'SumatraFuzzWorker' -ErrorAction SilentlyContinue
  } while ($service -and $service.Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
  if (-not $service -or $service.Status -ne 'Running') { throw 'Worker service did not recover after forced termination' }
  $env:WORKER_SERVICE_VERIFY_FORCED_TERMINATION = 'true'
  node --experimental-strip-types (Join-Path $RepoRoot 'scripts/windows/worker-service-acceptance.ts')
  if ($LASTEXITCODE -ne 0) { throw 'Forced service termination recovery acceptance failed' }
  Remove-Item Env:\WORKER_SERVICE_VERIFY_FORCED_TERMINATION -ErrorAction SilentlyContinue

  $env:WORKER_SERVICE_VERIFY_REVOCATION = 'true'
  node --experimental-strip-types (Join-Path $RepoRoot 'scripts/windows/worker-service-acceptance.ts')
  if ($LASTEXITCODE -ne 0) { throw 'Installed-service live revocation acceptance failed' }
  Remove-Item Env:\WORKER_SERVICE_VERIFY_REVOCATION -ErrorAction SilentlyContinue

  Stop-Service -Name 'SumatraFuzzWorker' -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddSeconds(75)
  do { Start-Sleep -Milliseconds 250; $service = Get-Service -Name 'SumatraFuzzWorker' -ErrorAction SilentlyContinue }
  while ($service -and $service.Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
  if (-not $service -or $service.Status -ne 'Stopped') { throw 'Installed worker service did not stop within its bounded deadline' }
  Start-Service -Name 'SumatraFuzzWorker' -ErrorAction Stop
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  do { Start-Sleep -Milliseconds 250; $service = Get-Service -Name 'SumatraFuzzWorker' -ErrorAction SilentlyContinue }
  while ($service -and $service.Status -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
  if (-not $service -or $service.Status -ne 'Running') { throw 'Installed worker service did not restart from DPAPI and durable trust state' }
  $env:WORKER_SERVICE_VERIFY_REVOCATION = 'true'
  node --experimental-strip-types (Join-Path $RepoRoot 'scripts/windows/worker-service-acceptance.ts')
  if ($LASTEXITCODE -ne 0) { throw 'Installed-service trust recovery after restart failed' }
  Remove-Item Env:\WORKER_SERVICE_VERIFY_REVOCATION -ErrorAction SilentlyContinue

  $acceptance = Join-Path $RepoRoot 'runs/worker-native/acceptance-summary.json'
  if (-not (Test-Path -LiteralPath $acceptance -PathType Leaf)) { throw 'Sanitized installed-service acceptance evidence is missing' }
  $evidence = Get-Content -LiteralPath $acceptance -Raw | ConvertFrom-Json
  if ($evidence.executions_done -lt 1000 -or $evidence.process_tree_verified_as_service_sid -ne $true) { throw 'Installed-service evidence does not meet the acceptance gate' }
  $dataEvidence = Join-Path $DataRoot 'state/runs.sqlite'
  if (-not (Test-Path -LiteralPath $dataEvidence -PathType Leaf)) { throw 'Worker evidence was not retained before uninstall' }

  Invoke-PwshFile -File $uninstallScript -Arguments @()
  $Installed = $false
  if (-not (Test-Path -LiteralPath $dataEvidence -PathType Leaf)) { throw 'Worker uninstall deleted retained evidence' }
  Write-Output 'Verified installed-service mTLS, controller ownership, live revocation, DPAPI restart, quotas, and retained journal.'
} finally {
  Remove-Item Env:\WORKER_SERVICE_VERIFY_FORCED_TERMINATION -ErrorAction SilentlyContinue
  Remove-Item Env:\WORKER_SERVICE_VERIFY_REVOCATION -ErrorAction SilentlyContinue
  Remove-Item Env:\WORKER_SERVICE_ACCEPTANCE_CLEANUP -ErrorAction SilentlyContinue
  Remove-Item Env:\WORKER_SERVICE_FIXTURE_ROOT -ErrorAction SilentlyContinue
  Remove-Item Env:\WORKER_SERVICE_DATA_ROOT -ErrorAction SilentlyContinue
  Remove-Item Env:\WORKER_SERVICE_PROVISIONER_PATH -ErrorAction SilentlyContinue
  if ($Installed) {
    try { Invoke-PwshFile -File (Join-Path $InstallRoot 'provisioning/uninstall-worker-service.ps1') -Arguments @() } catch { Write-Error 'Worker service acceptance cleanup could not uninstall the test service' }
  }
  if ($Mounted) {
    try {
      $disk = (Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop) | Get-Disk
      $partition = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.AccessPaths -contains ($DataRoot + '\') }
      if ($partition) { Remove-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath ($DataRoot + '\') }
      Dismount-DiskImage -ImagePath $VhdPath -ErrorAction Stop
    } catch { Write-Error 'Worker service acceptance cleanup could not detach the test volume' }
  }
  Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $InstallStateRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $DataRoot -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $VhdPath -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}
