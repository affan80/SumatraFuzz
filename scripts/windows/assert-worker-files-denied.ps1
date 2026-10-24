#requires -Version 7.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ConfigurationPath,
  [Parameter(Mandatory)][string]$CredentialsPath,
  [Parameter(Mandatory)][string]$SigningKeyPath,
  [Parameter(Mandatory)][string]$RuntimePath,
  [Parameter(Mandatory)][string]$DpapiEnvelopePath,
  [Parameter(Mandatory)][string]$SupervisorModulePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($path in @($ConfigurationPath, $CredentialsPath, $SigningKeyPath)) {
  try {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $stream.Dispose()
    throw 'Ordinary user read a protected worker file'
  } catch [UnauthorizedAccessException] {
    # Expected: worker configuration, DPAPI credentials and organization key are protected.
  }
}

$node = (Get-Command node -ErrorAction Stop).Source
$dpapiProbe = "const supervisor=require(process.argv[1]);const sealed=require('node:fs').readFileSync(process.argv[2]);try{const clear=supervisor.unprotectSecret(sealed);clear.fill(0);process.exit(2)}catch{process.exit(0)}"
& $node -e $dpapiProbe $SupervisorModulePath $DpapiEnvelopePath
if ($LASTEXITCODE -ne 0) { throw 'DPAPI ciphertext was readable by an identity other than the worker service' }

try {
  $stream = [IO.File]::Open($RuntimePath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
  $stream.Dispose()
  throw 'Ordinary user opened the worker runtime for writing'
} catch [UnauthorizedAccessException] {
  # Expected: the service can read/execute fixed runtime files, but cannot replace them.
}

$pipe = [IO.Pipes.NamedPipeClientStream]::new('.', 'SumatraFuzzWorker-trust', [IO.Pipes.PipeDirection]::InOut)
try {
  try {
    $pipe.Connect(3000)
    throw 'Ordinary user connected to the administrator-only worker trust pipe'
  } catch [UnauthorizedAccessException] {
    # Expected: the named-pipe DACL rejects ordinary users.
  } catch [IO.IOException] {
    if (($_.Exception.HResult -band 0xffff) -ne 5) {
      throw 'Worker trust pipe was unavailable instead of denying the ordinary user'
    }
  }
} finally {
  $pipe.Dispose()
}

Write-Output 'Ordinary-user protected-file and trust-pipe denials verified.'
