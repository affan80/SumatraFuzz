#requires -Version 7.0
[CmdletBinding()]
param(
  [string]$InstallRoot = (Join-Path $env:ProgramFiles 'SumatraFuzz'),
  [Parameter(Mandatory)][string]$ExpectedDataVolumeId,
  [Parameter(Mandatory)][ValidateRange(67108864, 1099511627776)][long]$WorkerDiskLimitBytes,
  [ValidateSet('Local', 'Remote')][string]$BindMode = 'Local',
  [string]$BindAddress = '127.0.0.1',
  [ValidateRange(1, 65535)][int]$Port = 8443,
  [string]$AdapterGuid,
  [string[]]$PeerCidrs = @()
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'worker-service-config.psm1') -Force
Install-SumatrafuzzWorkerService -InstallRoot $InstallRoot -ExpectedDataVolumeId $ExpectedDataVolumeId -WorkerDiskLimitBytes $WorkerDiskLimitBytes -BindMode $BindMode -BindAddress $BindAddress -Port $Port -AdapterGuid $AdapterGuid -PeerCidrs $PeerCidrs
