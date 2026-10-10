#requires -Version 7.0
BeforeAll {
  $script:replay = (Resolve-Path (Join-Path $PSScriptRoot '../replay-input.ps1')).Path
  function New-ReplayFixture([string]$root) {
    $null = New-Item -ItemType Directory -Path $root -Force
    $run = Join-Path $root 'run dir with spaces'
    $hangs = Join-Path $run 'hangs'
    $null = New-Item -ItemType Directory -Path $hangs -Force
    $sample = Join-Path $hangs 'id_000001'
    Set-Content -LiteralPath $sample -Value '%PDF-malformed'
    $harness = Join-Path $root 'sumatrafuzz-harness.exe'
    Set-Content -LiteralPath $harness -Value 'test-only nonexecutable fixture'
    $relative = 'hangs/id_000001'
    $manifest = Join-Path $root 'evidence.json'
    @{
      source_commit='16c59fde8b824ab54c56f23aef910a6fdd874ad0'
      binary_hashes=@{harness=(Get-FileHash -LiteralPath $harness -Algorithm SHA256).Hash}
      crashes=@()
      hangs=@(@{
        path=$relative
        classification='untriaged'
        sha256=(Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
      })
    } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $manifest
    return @{ EvidenceManifest=$manifest; RunDir=$run; HarnessExe=$harness; Finding=$relative; Sample=$sample }
  }
}
Describe 'Real finding replay fails closed before executing native samples' -Skip:(!$IsWindows) {
  BeforeEach { $script:f=New-ReplayFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) }
  It 'rejects an input absent from the evidence inventory' {
    $replayParams=@{EvidenceManifest=$f.EvidenceManifest;RunDir=$f.RunDir;HarnessExe=$f.HarnessExe;Finding='hangs/id_999999'}
    { & $script:replay @replayParams } | Should -Throw '*not an authentic untriaged sample*'
  }
  It 'rejects sample mutation after original hash collection' {
    Add-Content -LiteralPath $f.Sample -Value 'changed'
    $replayParams=@{EvidenceManifest=$f.EvidenceManifest;RunDir=$f.RunDir;HarnessExe=$f.HarnessExe;Finding=$f.Finding}
    { & $script:replay @replayParams } | Should -Throw '*Finding SHA-256 mismatch*'
  }
  It 'rejects harness mutation after native run' {
    Add-Content -LiteralPath $f.HarnessExe -Value 'changed'
    $replayParams=@{EvidenceManifest=$f.EvidenceManifest;RunDir=$f.RunDir;HarnessExe=$f.HarnessExe;Finding=$f.Finding}
    { & $script:replay @replayParams } | Should -Throw '*Harness SHA-256 mismatch*'
  }
  It 'rejects path traversal syntax' {
    $replayParams=@{EvidenceManifest=$f.EvidenceManifest;RunDir=$f.RunDir;HarnessExe=$f.HarnessExe;Finding='hangs/../outside.pdf'}
    { & $script:replay @replayParams } | Should -Throw '*Finding must name*'
  }
}
