#requires -Version 7.0
[CmdletBinding()]
param([switch]$DeleteData)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'worker-service-config.psm1') -Force
Uninstall-SumatrafuzzWorkerService -DeleteData:$DeleteData
