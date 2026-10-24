#requires -Version 7.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='SumatraFuzzWorker'" -ErrorAction Stop
if (-not $service -or $service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
  throw 'Installed worker service is not running'
}
$processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
$byParent = @{}
foreach ($process in $processes) {
  $parent = [uint32]$process.ParentProcessId
  if (-not $byParent.ContainsKey($parent)) { $byParent[$parent] = [System.Collections.Generic.List[object]]::new() }
  $byParent[$parent].Add($process)
}
$pending = [System.Collections.Generic.Queue[uint32]]::new()
$pending.Enqueue([uint32]$service.ProcessId)
$seen = [System.Collections.Generic.HashSet[uint32]]::new()
while ($pending.Count -gt 0) {
  $parent = $pending.Dequeue()
  if (-not $seen.Add($parent)) { continue }
  foreach ($child in $byParent[$parent]) { $pending.Enqueue([uint32]$child.ProcessId) }
}
if ($seen.Count -lt 3) { throw 'Installed worker campaign process tree was not observed' }
foreach ($processId in $seen) {
  $process = $processes | Where-Object { [uint32]$_.ProcessId -eq $processId } | Select-Object -First 1
  if (-not $process) { throw 'Installed worker process tree changed during identity verification' }
  $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
  if ($owner.ReturnValue -ne 0 -or "$($owner.Domain)\$($owner.User)" -ine 'NT SERVICE\SumatraFuzzWorker') {
    throw 'Installed worker descendant is not running under the dedicated service identity'
  }
}
Write-Output "Verified $($seen.Count) worker service processes run as the dedicated service identity."
