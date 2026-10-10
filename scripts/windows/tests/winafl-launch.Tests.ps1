#requires -Version 7.0
BeforeAll {
  $script:runner=(Join-Path $PSScriptRoot '../run-winafl-smoke.ps1')
  function New-CampaignFixture([string]$root) {
    [void](New-Item -ItemType Directory -Path $root -Force)
    $input=Join-Path $root 'valid seeds'
    [void](New-Item -ItemType Directory -Path $input -Force)
    Set-Content -LiteralPath (Join-Path $input 'seed.pdf') -Value '%PDF-1.4'
    $harness=Join-Path $root 'sumatrafuzz-harness.exe'
    $bin=Join-Path $root 'tool.bin'
    Set-Content -LiteralPath $harness -Value 'harness'
    Set-Content -LiteralPath $bin -Value 'binary'
    $sha=(Get-FileHash $bin -Algorithm SHA256).Hash
    $lock=Join-Path $root 'lock.json'
    @{architecture='x64';winafl_commit='fd85f38548b14352f4b70ad414f364ea6dc1a769';dynamorio_release='cronbuild-11.91.20735';dynamorio_bin64=$root;tools=@{
      drrun=@{path=$bin;sha256=$sha};winafl_client=@{path=$bin;sha256=$sha};afl_fuzz=@{path=$bin;sha256=$sha}
    }} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $lock
    $debug=Join-Path $root 'debug.json'
    @{source='observed-dynamorio-debug';target_module='sumatrafuzz-harness.exe';target_method='fuzz_one_file';
      nargs=1;iterations=10;nonzero_coverage_slots=1;
      observed_modules=@('PdfFilter.dll');harness_sha256=(Get-FileHash $harness -Algorithm SHA256).Hash.ToLowerInvariant();
      toolchain_lock_sha256=(Get-FileHash $lock -Algorithm SHA256).Hash.ToLowerInvariant()} |
      ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $debug
    return @{ToolchainLock=$lock;DebugEvidence=$debug;HarnessExe=$harness;InputDir=$input;OutputDir=(Join-Path $root 'fresh runs')}
  }
}
Describe 'WinAFL campaign launcher preflight must fail closed' -Skip:(!$IsWindows) {
  BeforeEach { $script:f=New-CampaignFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) }
  It 'rejects reused output directory' {
    [void](New-Item -Type Directory -Path $f.OutputDir -Force)
    { & $script:runner @f } | Should -Throw '*already exists*'
  }
  It 'rejects missing debug evidence' {
    Remove-Item -LiteralPath $f.DebugEvidence
    { & $script:runner @f } | Should -Throw '*debug evidence*'
  }
  It 'rejects a tampered binary hash' {
    Add-Content -LiteralPath ((Get-Content $f.ToolchainLock -Raw | ConvertFrom-Json).tools.afl_fuzz.path) -Value 'tampered'
    { & $script:runner @f } | Should -Throw '*checksum*'
  }
  It 'rejects changed harness after genuine debug run' {
    Add-Content -LiteralPath $f.HarnessExe -Value 'changed'
    { & $script:runner @f } | Should -Throw '*harness checksum*'
  }
  It 'rejects unsupported source of module observations' {
    $x=Get-Content $f.DebugEvidence -Raw | ConvertFrom-Json
    $x.source='manual-candidate-list'
    $x | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $f.DebugEvidence
    { & $script:runner @f } | Should -Throw '*DynamoRIO*'
  }
}
