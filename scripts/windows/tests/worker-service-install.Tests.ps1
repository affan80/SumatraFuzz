#requires -Version 7.0
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../worker-service-config.psm1') -Force
}

Describe 'Worker service policy validation' {
  It 'checks every install-root ancestor so a writable higher parent cannot replace the service tree' {
    $root = Join-Path $TestDrive 'writable-parent\SumatraFuzz'
    [void](New-Item -ItemType Directory -Path $root -Force)
    $script:installAncestorChecks = [System.Collections.Generic.List[string]]::new()
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {
      $script:installAncestorChecks.Add([IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar))
      if ([IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar) -eq
          [IO.Path]::GetFullPath((Split-Path -Parent $root)).TrimEnd([IO.Path]::DirectorySeparatorChar)) {
        throw 'An untrusted principal can replace an ancestor of the protected install root'
      }
    }

    { Assert-WorkerProtectedInstallAncestors -InstallRoot $root } | Should -Throw '*replace an ancestor*'
    $script:installAncestorChecks | Should -Contain ([IO.Path]::GetFullPath((Split-Path -Parent $root)).TrimEnd([IO.Path]::DirectorySeparatorChar))
    $script:installAncestorChecks | Should -Contain ([IO.Path]::GetPathRoot($root).TrimEnd([IO.Path]::DirectorySeparatorChar))
  }

  It 'parses the protected provisioning entrypoint and live-pipe identity check' {
    $scriptPath = Join-Path $PSScriptRoot '../provision-worker-service.ps1'
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
    $parseErrors | Should -BeNullOrEmpty
    $source = [IO.File]::ReadAllText($scriptPath)
    $source | Should -Match 'GetNamedPipeServerProcessId'
    $source | Should -Match '\$serverProcessId\s+-ne\s+\$ExpectedServerProcessId'
    $source | Should -Match '\$useLive\s*=\s*\[bool\]\$Live\s*-or'
  }

  It 'locks the runtime root and validates every existing descendant before service startup' {
    $root = Join-Path $TestDrive 'runtime-state'
    $nested = Join-Path $root 'security'
    [void](New-Item -ItemType Directory -Path $nested -Force)
    $database = Join-Path $nested 'trust.sqlite'
    [IO.File]::WriteAllBytes($database, [byte[]]@(1, 2, 3))
    $script:workerAclCalls = [System.Collections.Generic.List[object]]::new()
    $script:workerPathChecks = [System.Collections.Generic.List[string]]::new()
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config {
      $script:workerAclCalls.Add([pscustomobject]@{
          Path = $Path; ServiceAccess = $ServiceAccess; Directory = [bool]$Directory
        })
    }
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config { $script:workerPathChecks.Add($Path) }

    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
    Protect-WorkerRuntimeTree -Path $root -ServiceSid $sid

    $script:workerAclCalls.Count | Should -Be 3
    ($script:workerAclCalls | Where-Object Path -EQ $root).ServiceAccess | Should -Be 'Modify'
    $script:workerPathChecks.Count | Should -Be 3
    $script:workerPathChecks | Should -Contain $nested
    $script:workerPathChecks | Should -Contain $database
    ($script:workerAclCalls | Where-Object Path -EQ $nested).Directory | Should -BeTrue
    ($script:workerAclCalls | Where-Object Path -EQ $database).Directory | Should -BeFalse
    Should -Invoke Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config -Times 3 -Exactly -ParameterFilter { $AllowServiceWrite }
  }

  It 'refuses existing runtime state with an untrusted writable ACL' {
    $root = Join-Path $TestDrive 'unsafe-runtime-state'
    [void](New-Item -ItemType Directory -Path $root -Force)
    $database = Join-Path $root 'trust.sqlite'
    [IO.File]::WriteAllBytes($database, [byte[]]@(1, 2, 3))
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config {}
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {
      if ($Path -eq $database) { throw 'An untrusted principal can modify a protected worker path' }
    }

    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
    { Protect-WorkerRuntimeTree -Path $root -ServiceSid $sid } | Should -Throw '*untrusted principal*'
    Should -Invoke Set-WorkerProtectedAcl -ModuleName worker-service-config -Times 1 -Exactly -ParameterFilter { $Path -eq $root }
    Should -Invoke Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config -Times 1 -Exactly -ParameterFilter { $Path -eq $database }
  }

  It 'rejects an unsafe install-tree descendant owner before repairing the root DACL' {
    $root = Join-Path $TestDrive 'unsafe-install\SumatraFuzz'
    $nested = Join-Path $root 'runtime'
    [void](New-Item -ItemType Directory -Path $nested -Force)
    [IO.File]::WriteAllBytes((Join-Path $nested 'node.exe'), [byte[]]@(1))
    $unsafeFile = Join-Path $nested 'node.exe'
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config {}
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {
      $script:installTreeChecks.Add([pscustomobject]@{ Path = $Path; TrustedOwner = [bool]$RequireTrustedOwner })
      if ($Path -eq $unsafeFile) { throw 'Worker runtime path owner is not a trusted service or administrator identity' }
    }
    $script:installTreeChecks = [System.Collections.Generic.List[object]]::new()
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    { Set-WorkerProtectedTree -Path $root -ServiceSid $sid } | Should -Throw '*owner is not a trusted*'
    Should -Invoke Set-WorkerProtectedAcl -ModuleName worker-service-config -Times 0 -Exactly
    $script:installTreeChecks.Count | Should -Be 3
    ($script:installTreeChecks | Where-Object { -not $_.TrustedOwner }).Count | Should -Be 0
  }

  It 'rejects a writable install-tree descendant before repairing the root DACL' {
    $root = Join-Path $TestDrive 'writable-install\SumatraFuzz'
    $nested = Join-Path $root 'runtime'
    [void](New-Item -ItemType Directory -Path $nested -Force)
    $unsafeFile = Join-Path $nested 'node.exe'
    [IO.File]::WriteAllBytes($unsafeFile, [byte[]]@(1))
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config {}
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {
      if ($Path -eq $unsafeFile) { throw 'Native host rejects writable principal on protected path' }
    }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    { Set-WorkerProtectedTree -Path $root -ServiceSid $sid } | Should -Throw '*writable principal*'
    Should -Invoke Set-WorkerProtectedAcl -ModuleName worker-service-config -Times 0 -Exactly
  }

  It 'accepts a freshly protected Program Files code tree and hardens only after complete validation' {
    $root = Join-Path $TestDrive 'Program Files\SumatraFuzz'
    $nested = Join-Path $root 'service'
    [void](New-Item -ItemType Directory -Path $nested -Force)
    [IO.File]::WriteAllBytes((Join-Path $nested 'SumatraFuzzWorkerHost.exe'), [byte[]]@(1))
    $script:installTreeChecks = [System.Collections.Generic.List[object]]::new()
    $script:installTreeAclCalls = [System.Collections.Generic.List[object]]::new()
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config { $script:installTreeChecks.Add([pscustomobject]@{ Path = $Path; TrustedOwner = [bool]$RequireTrustedOwner }) }
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config { $script:installTreeAclCalls.Add([pscustomobject]@{ Path = $Path; Directory = [bool]$Directory; RestrictedExecute = [bool]$RestrictedExecute }) }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    { Set-WorkerProtectedTree -Path $root -ServiceSid $sid -RestrictedExecute } | Should -Not -Throw
    $script:installTreeChecks.Count | Should -Be 3
    ($script:installTreeChecks | Where-Object { -not $_.TrustedOwner }).Count | Should -Be 0
    $script:installTreeAclCalls.Count | Should -Be 3
    ($script:installTreeAclCalls | Where-Object Path -EQ $root).Directory | Should -BeTrue
    ($script:installTreeAclCalls | Where-Object { $_.RestrictedExecute }).Count | Should -Be 3
  }

  It 'grants restricted-code reads to input trees and traversal only to the output root' {
    $root = Join-Path $TestDrive 'worker-inputs'
    [void](New-Item -ItemType Directory -Path (Join-Path $root 'bundle') -Force)
    [IO.File]::WriteAllBytes((Join-Path $root 'bundle\seed.pdf'), [byte[]]@(1, 2, 3))
    $script:restrictedAclCalls = [System.Collections.Generic.List[object]]::new()
    Mock Set-WorkerProtectedAcl -ModuleName worker-service-config {
      $script:restrictedAclCalls.Add([pscustomobject]@{
          Path = $Path; RestrictedRead = [bool]$RestrictedRead; RestrictedExecute = [bool]$RestrictedExecute; RestrictedTraverse = [bool]$RestrictedTraverse; Directory = [bool]$Directory
        })
    }
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {}
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    Protect-WorkerRuntimeTree -Path $root -ServiceSid $sid -RestrictedRead
    ($script:restrictedAclCalls | Where-Object { -not $_.RestrictedRead -or $_.RestrictedExecute -or $_.RestrictedTraverse }).Count | Should -Be 0
    $seedAcl = $script:restrictedAclCalls | Where-Object Path -EQ (Join-Path $root 'bundle\seed.pdf')
    $seedAcl.Directory | Should -BeFalse
    $seedAcl.RestrictedRead | Should -BeTrue

    $script:restrictedAclCalls.Clear()
    Protect-WorkerRuntimeTree -Path $root -ServiceSid $sid -RestrictedTraverse
    ($script:restrictedAclCalls | Where-Object { $_.Path -eq $root -and $_.RestrictedTraverse }).Count | Should -Be 1
    ($script:restrictedAclCalls | Where-Object { $_.Path -ne $root -and $_.RestrictedTraverse }).Count | Should -Be 0
    ($script:restrictedAclCalls | Where-Object { $_.Path -ne $root -and $_.RestrictedRead }).Count | Should -Be 0
  }

  It 'does not grant the Restricted Code SID execute rights on input PDFs' {
    $path = Join-Path $TestDrive 'input-seed.pdf'
    [IO.File]::WriteAllBytes($path, [byte[]]@(1, 2, 3))
    $global:sumatraCapturedRestrictedAcl = $null
    Mock Set-Acl -ModuleName worker-service-config { $global:sumatraCapturedRestrictedAcl = $AclObject }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    Set-WorkerProtectedAcl -Path $path -ServiceSid $sid -ServiceAccess Modify -RestrictedRead
    $rule = $global:sumatraCapturedRestrictedAcl.Access | Where-Object { try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-12' } catch { $false } }
    $rule | Should -Not -BeNullOrEmpty
    ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ReadData) | Should -Not -Be 0
    ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ExecuteFile) | Should -Be 0
    $rule.InheritanceFlags | Should -Be ([Security.AccessControl.InheritanceFlags]::None)
  }

  It 'grants input directories traversal explicitly without inheriting execute onto inputs' {
    $path = Join-Path $TestDrive 'inputs'
    [void](New-Item -ItemType Directory -Path $path)
    $global:sumatraCapturedRestrictedAcl = $null
    Mock Set-Acl -ModuleName worker-service-config { $global:sumatraCapturedRestrictedAcl = $AclObject }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    Set-WorkerProtectedAcl -Path $path -ServiceSid $sid -ServiceAccess Modify -RestrictedRead -Directory
    $rule = $global:sumatraCapturedRestrictedAcl.Access | Where-Object { try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-12' } catch { $false } }
    $rule | Should -Not -BeNullOrEmpty
    ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Read) | Should -Not -Be 0
    ([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Traverse) | Should -Not -Be 0
    $rule.InheritanceFlags | Should -Be ([Security.AccessControl.InheritanceFlags]::None)
  }

  It 'grants execute only to installed code and traversal only to the output root' {
    $path = Join-Path $TestDrive 'worker.exe'
    [IO.File]::WriteAllBytes($path, [byte[]]@(1, 2, 3))
    $global:sumatraCapturedRestrictedAcl = $null
    Mock Set-Acl -ModuleName worker-service-config { $global:sumatraCapturedRestrictedAcl = $AclObject }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    Set-WorkerProtectedAcl -Path $path -ServiceSid $sid -ServiceAccess Read -RestrictedExecute
    $executeRule = $global:sumatraCapturedRestrictedAcl.Access | Where-Object { try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-12' } catch { $false } }
    ([int]$executeRule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ExecuteFile) | Should -Not -Be 0
    $executeRule.InheritanceFlags | Should -Be ([Security.AccessControl.InheritanceFlags]::None)

    $global:sumatraCapturedRestrictedAcl = $null
    Set-WorkerProtectedAcl -Path $TestDrive -ServiceSid $sid -ServiceAccess Modify -RestrictedTraverse -Directory
    $traverseRule = $global:sumatraCapturedRestrictedAcl.Access | Where-Object { try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-12' } catch { $false } }
    ([int]$traverseRule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::Traverse) | Should -Not -Be 0
    ([int]$traverseRule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::WriteData) | Should -Be 0
    $traverseRule.InheritanceFlags | Should -Be ([Security.AccessControl.InheritanceFlags]::None)
  }

  It 'rejects runtime descendants owned by an untrusted identity even without writable allow ACEs' {
    $owner = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-111-222-333-1001')
    Mock Get-Acl -ModuleName worker-service-config { [pscustomobject]@{ Owner = $owner; Access = @() } }
    $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')

    { Assert-WorkerHostCompatibleDacl -Path 'C:\runtime\trust.sqlite' -ServiceSid $sid -AllowServiceWrite -RequireTrustedOwner } |
      Should -Throw '*owner is not a trusted*'
  }

  It 'fails closed for a non-Windows operating system' {
    Mock Get-WorkerPlatformFacts -ModuleName worker-service-config { [pscustomobject]@{ IsWindows = $false; Architecture = 'X64'; Elevated = $true } }
    { Assert-WorkerPlatform } | Should -Throw
  }

  It 'fails closed for a non-x64 architecture' {
    Mock Get-WorkerPlatformFacts -ModuleName worker-service-config { [pscustomobject]@{ IsWindows = $true; Architecture = 'Arm64'; Elevated = $true } }
    { Assert-WorkerPlatform } | Should -Throw
  }

  It 'requires elevation for provisioning' {
    Mock Get-WorkerPlatformFacts -ModuleName worker-service-config { [pscustomobject]@{ IsWindows = $true; Architecture = 'X64'; Elevated = $false } }
    { Assert-WorkerPlatform -RequireElevation } | Should -Throw '*elevation*'
  }

  It 'requires Windows x64 and supports installer elevation checks' {
    { Assert-WorkerPlatform -RequireElevation:$false } | Should -Not -Throw
  }

  It 'rejects wildcard and non-loopback local binds' {
    { Assert-WorkerBindConfiguration -Mode Local -Address '0.0.0.0' -Port 8443 } | Should -Throw
    { Assert-WorkerBindConfiguration -Mode Local -Address '192.168.1.4' -Port 8443 } | Should -Throw
    { Assert-WorkerBindConfiguration -Mode Local -Address '127.0.0.1' -Port 8443 } | Should -Not -Throw
  }

  It 'rejects public addresses and malformed peer ranges' {
    { Assert-WorkerBindConfiguration -Mode Remote -Address '8.8.8.8' -Port 8443 -AdapterGuid '11111111-1111-1111-1111-111111111111' -PeerCidrs @('10.0.0.0/8') } | Should -Throw
    { Assert-WorkerBindConfiguration -Mode Remote -Address '10.0.0.2' -Port 8443 -AdapterGuid '11111111-1111-1111-1111-111111111111' -PeerCidrs @('0.0.0.0/0') } | Should -Throw
    { Assert-WorkerBindConfiguration -Mode Remote -Address '10.0.0.2' -Port 8443 -AdapterGuid '11111111-1111-1111-1111-111111111111' -PeerCidrs @('10.0.0.0/8') } | Should -Throw
  }

  It 'accepts a private remote endpoint only when adapter, assigned address and profile match' {
    Mock Get-NetAdapter -ModuleName worker-service-config { [pscustomobject]@{ InterfaceGuid = '{11111111-1111-1111-1111-111111111111}'; InterfaceIndex = 7; Name = 'VPN'; Status = 'Up' } }
    Mock Get-NetIPAddress -ModuleName worker-service-config { [pscustomobject]@{ IPAddress = '10.0.0.2'; InterfaceIndex = 7 } }
    Mock Get-NetConnectionProfile -ModuleName worker-service-config { [pscustomobject]@{ NetworkCategory = 'Private' } }
    { Assert-WorkerBindConfiguration -Mode Remote -Address '10.0.0.2' -Port 8443 -AdapterGuid '11111111-1111-1111-1111-111111111111' -PeerCidrs @('10.0.0.0/8') } | Should -Not -Throw
  }

  It 'rejects adapter identity or address drift' {
    Mock Get-NetAdapter -ModuleName worker-service-config { [pscustomobject]@{ InterfaceGuid = '{22222222-2222-2222-2222-222222222222}'; InterfaceIndex = 7; Name = 'VPN'; Status = 'Up' } }
    Mock Get-NetIPAddress -ModuleName worker-service-config { [pscustomobject]@{ IPAddress = '10.0.0.2'; InterfaceIndex = 7 } }
    { Assert-WorkerBindConfiguration -Mode Remote -Address '10.0.0.2' -Port 8443 -AdapterGuid '11111111-1111-1111-1111-111111111111' -PeerCidrs @('10.0.0.0/8') } | Should -Throw
    Should -Invoke Get-NetAdapter -ModuleName worker-service-config -Times 1 -Exactly
  }

  It 'fails closed when the quota record is missing, unenforced, or mismatched' {
    Mock Get-CimInstance -ModuleName worker-service-config { @() }
    { Assert-WorkerQuota -VolumeId 'volume{11111111-1111-1111-1111-111111111111}' -LimitBytes 536870912 } | Should -Throw
  }

  It 'uses the same 64 MiB through 1 TiB worker quota bounds as the service runtime' {
    { Assert-WorkerQuota -VolumeId 'volume{11111111-1111-1111-1111-111111111111}' -LimitBytes (64MB - 1) } | Should -Throw '*outside supported bounds*'
    { Assert-WorkerQuota -VolumeId 'volume{11111111-1111-1111-1111-111111111111}' -LimitBytes (1TB + 1) } | Should -Throw '*outside supported bounds*'
  }

  It 'rolls back only its quota changes when quota enforcement fails' {
    $global:workerFsutilCalls = 0
    Mock Get-Volume -ModuleName worker-service-config { [pscustomobject]@{ UniqueId = 'volume{11111111-1111-1111-1111-111111111111}'; FileSystem = 'NTFS'; Path = @('D:\') } }
    Mock Get-WorkerQuotaSetting -ModuleName worker-service-config { [pscustomobject]@{ State = 0 } }
    Mock Get-WorkerServiceQuotaRecord -ModuleName worker-service-config { $null }
    Mock Invoke-WorkerFsutil -ModuleName worker-service-config {
      $global:workerFsutilCalls++
      if ($global:workerFsutilCalls -eq 2) { throw 'simulated quota modify failure' }
    }
    { Set-WorkerQuota -VolumeId 'volume{11111111-1111-1111-1111-111111111111}' -LimitBytes 536870912 } | Should -Throw
    $global:workerFsutilCalls | Should -Be 4
    Remove-Variable workerFsutilCalls -Scope Global -ErrorAction SilentlyContinue
  }

  It 'rejects data volumes that are not the requested NTFS volume' {
    Mock Get-Volume -ModuleName worker-service-config { [pscustomobject]@{ UniqueId = 'volume{22222222-2222-2222-2222-222222222222}'; FileSystem = 'NTFS'; Path = @('D:\') } }
    { Assert-WorkerDataVolume -DataRoot 'D:\ProgramData\SumatraFuzz\Worker' -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId 'volume{11111111-1111-1111-1111-111111111111}' } | Should -Throw
  }

  It 'accepts only the exact dedicated-volume mount at the fixed worker data root' {
    $dataRoot = Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'ProgramData\SumatraFuzz\Worker'
    $installRoot = Join-Path $TestDrive 'Program Files\SumatraFuzz'
    [void](New-Item -ItemType Directory -Path $installRoot -Force)
    $expected = [pscustomobject]@{ UniqueId = 'volume{11111111-1111-1111-1111-111111111111}'; FileSystem = 'NTFS'; Path = '\\?\Volume{11111111-1111-1111-1111-111111111111}\' }
    $system = [pscustomobject]@{ UniqueId = 'volume{22222222-2222-2222-2222-222222222222}'; FileSystem = 'NTFS'; Path = @((Split-Path -Qualifier $installRoot) + '\') }
    Mock Get-Volume -ModuleName worker-service-config {
      if ($FilePath -eq $dataRoot) { return $expected }
      if ($FilePath) { return $system }
      return @($expected)
    }
    Mock Get-Partition -ModuleName worker-service-config { [pscustomobject]@{ AccessPaths = @(($dataRoot + '\'), $expected.Path) } }
    Mock Get-Item -ModuleName worker-service-config {
      $attributes = [IO.FileAttributes]::Directory
      if ($LiteralPath -eq $dataRoot) { $attributes = $attributes -bor [IO.FileAttributes]::ReparsePoint }
      [pscustomobject]@{ PSIsContainer = $true; Attributes = $attributes }
    }
    Mock Get-ChildItem -ModuleName worker-service-config { @() }

    (Assert-WorkerDataVolume -DataRoot $dataRoot -InstallRoot $installRoot -ExpectedVolumeId $expected.UniqueId).UniqueId | Should -Be $expected.UniqueId
  }

  It 'rejects install layouts with any missing fixed executable' {
    $root = Join-Path $TestDrive 'SumatraFuzz'
    [void](New-Item -ItemType Directory -Path $root -Force)
    { Resolve-WorkerInstallLayout -InstallRoot $root } | Should -Throw '*missing a regular fixed-path file*'
  }

  It 'requires the fixed native-host install root name' {
    { Resolve-WorkerInstallLayout -InstallRoot 'C:\Program Files\OtherName' } | Should -Throw '*fixed SumatraFuzz directory*'
  }
}

Describe 'Exact worker data mount policy shared by installation and provisioning' {
  BeforeEach {
    $script:mountDataRoot = Join-Path ([IO.Path]::GetPathRoot($env:SystemRoot)) 'ProgramData\SumatraFuzz\Worker'
    $script:mountVolume = [pscustomobject]@{ UniqueId = 'volume{11111111-1111-1111-1111-111111111111}'; FileSystem = 'NTFS'; Path = '\\?\Volume{11111111-1111-1111-1111-111111111111}\' }
    $script:mountSystem = [pscustomobject]@{ UniqueId = 'volume{22222222-2222-2222-2222-222222222222}'; FileSystem = 'NTFS' }
    $script:mountAccessPaths = @(($script:mountDataRoot + '\'), $script:mountVolume.Path)
    $script:mountRootAttributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
    Mock Get-Volume -ModuleName worker-service-config {
      if (-not $FilePath -or $FilePath -eq $script:mountDataRoot) { return $script:mountVolume }
      return $script:mountSystem
    }
    Mock Get-Partition -ModuleName worker-service-config { [pscustomobject]@{ AccessPaths = $script:mountAccessPaths } }
    Mock Get-Item -ModuleName worker-service-config {
      $attributes = if ($LiteralPath -eq $script:mountDataRoot) { $script:mountRootAttributes } else { [IO.FileAttributes]::Directory }
      [pscustomobject]@{ PSIsContainer = $true; Attributes = $attributes }
    }
  }

  It 'allows the exact registered mount and returns its verified NTFS volume' {
    (Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId).UniqueId | Should -Be 'volume{11111111-1111-1111-1111-111111111111}'
  }

  It 'rejects a normal directory even when volume metadata claims the expected volume' {
    $script:mountRootAttributes = [IO.FileAttributes]::Directory
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*mount point*'
  }

  It 'rejects an ordinary junction that is not a registered volume access path' {
    $script:mountAccessPaths = @('D:\', $script:mountVolume.Path)
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*exact configured*'
  }

  It 'rejects a volume mounted at the parent instead of the exact worker root' {
    $script:mountAccessPaths = @((Split-Path -Parent $script:mountDataRoot) + '\')
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*exact configured*'
  }

  It 'rejects an unavailable expected GUID' {
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId 'volume{33333333-3333-3333-3333-333333333333}' } | Should -Throw '*unavailable or ambiguous*'
  }

  It 'rejects a non-NTFS data volume' {
    $script:mountVolume.FileSystem = 'ReFS'
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*NTFS*'
  }

  It 'rejects a mount redirected to another volume after enumeration' {
    Mock Get-Volume -ModuleName worker-service-config {
      if ($FilePath) { return $script:mountSystem }
      return $script:mountVolume
    }
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*exact configured*'
  }

  It 'rejects data on the Windows or installed-code volume' {
    $script:mountSystem = $script:mountVolume
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*separate*'
  }

  It 'rejects a redirected ancestor of the fixed worker root' {
    Mock Get-Item -ModuleName worker-service-config { [pscustomobject]@{ PSIsContainer = $true; Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint } }
    { Assert-WorkerDataMountPoint -DataRoot $script:mountDataRoot -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*ancestor*'
  }

  It 'rejects an alternate data-root path' {
    { Assert-WorkerDataMountPoint -DataRoot 'D:\Worker' -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedVolumeId $script:mountVolume.UniqueId } | Should -Throw '*fixed*'
  }
}

Describe 'Worker service installer transaction' {
  It 'refuses an unowned preexisting service without changing it' {
    $installRoot = Join-Path $TestDrive 'Program Files\SumatraFuzz'
    [void](New-Item -ItemType Directory -Path $installRoot -Force)
    Mock Assert-WorkerPlatform -ModuleName worker-service-config {}
    Mock Resolve-WorkerInstallLayout -ModuleName worker-service-config { [pscustomobject]@{ Root = $installRoot; Host = (Join-Path $installRoot 'service\SumatraFuzzWorkerHost.exe'); Node = (Join-Path $installRoot 'runtime\node.exe'); Entry = (Join-Path $installRoot 'apps\worker-service\dist\src\service-entry.js'); SigningKey = (Join-Path $installRoot 'config\organization-signing-public-key.pem') } }
    Mock Assert-WorkerBindConfiguration -ModuleName worker-service-config {}
    Mock Assert-WorkerHostCompatibleDacl -ModuleName worker-service-config {}
    Mock Resolve-WorkerSid -ModuleName worker-service-config { throw 'Service SID must not be resolved before SCM creates the service' }
    Mock Assert-WorkerDataVolume -ModuleName worker-service-config { [pscustomobject]@{ UniqueId = 'volume{11111111-1111-1111-1111-111111111111}'; FileSystem = 'NTFS'; Path = 'D:\' } }
    Mock Get-WorkerInstallMarker -ModuleName worker-service-config { $null }
    Mock Get-WorkerServiceCim -ModuleName worker-service-config { [pscustomobject]@{ Name = 'SumatraFuzzWorker'; State = 'Stopped'; PathName = 'C:\unowned.exe'; StartName = 'LocalSystem' } }
    Mock Invoke-WorkerSc -ModuleName worker-service-config {}
    { Install-SumatrafuzzWorkerService -InstallRoot 'C:\Program Files\SumatraFuzz' -ExpectedDataVolumeId 'volume{11111111-1111-1111-1111-111111111111}' -WorkerDiskLimitBytes 536870912 } | Should -Throw
    Should -Invoke Invoke-WorkerSc -ModuleName worker-service-config -Times 0 -Exactly
    Should -Invoke Resolve-WorkerSid -ModuleName worker-service-config -Times 0 -Exactly
  }

  It 'retains worker data and credentials by default on uninstall' {
    $marker = [pscustomobject]@{
      schema = 1; state = 'Installed'; owner_id = '00000000-0000-0000-0000-000000000001'
      firewall_name = 'SumatraFuzzWorker-test'; firewall_group = 'SumatraFuzz Worker test'
      data_root = Join-Path $env:SystemRoot 'ProgramData\SumatraFuzz\Worker'
      volume_id = 'volume{11111111-1111-1111-1111-111111111111}'
    }
    Mock Assert-WorkerPlatform -ModuleName worker-service-config {}
    Mock Get-WorkerInstallMarker -ModuleName worker-service-config { $marker }
    Mock Get-WorkerServiceCim -ModuleName worker-service-config { $null }
    Mock Get-NetFirewallRule -ModuleName worker-service-config { @() }
    Mock Write-WorkerInstallMarker -ModuleName worker-service-config {}
    Mock Remove-Item -ModuleName worker-service-config {}
    Uninstall-SumatrafuzzWorkerService
    Should -Invoke Remove-Item -ModuleName worker-service-config -Times 0 -Exactly
    Should -Invoke Write-WorkerInstallMarker -ModuleName worker-service-config -Times 1 -Exactly
    $marker.state | Should -Be 'Uninstalled'
  }
}
