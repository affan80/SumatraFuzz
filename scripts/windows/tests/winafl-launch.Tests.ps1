#requires -Version 7.0
BeforeAll {
  $script:runner=(Join-Path $PSScriptRoot '../run-winafl-smoke.ps1')
  function New-CampaignFixture([string]$root) {
    [void](New-Item -ItemType Directory -Path $root -Force)
    $input=Join-Path $root 'valid seeds'
    [void](New-Item -ItemType Directory -Path $input -Force)
    Set-Content -LiteralPath (Join-Path $input 'seed.pdf') -Value '%PDF-1.4'
    Set-Content -LiteralPath (Join-Path $input 'second.pdf') -Value '%PDF-1.4'
    $harness=Join-Path $root 'sumatrafuzz-harness.exe'
    $bin=Join-Path $root 'tool.bin'
    Set-Content -LiteralPath $harness -Value 'harness'
    Set-Content -LiteralPath $bin -Value 'binary'
    $sha=(Get-FileHash $bin -Algorithm SHA256).Hash
    $lock=Join-Path $root 'lock.json'
    @{architecture='x64';source_commit='16c59fde8b824ab54c56f23aef910a6fdd874ad0';tools=@{
      drrun=@{path=$bin;sha256=$sha};winafl_client=@{path=$bin;sha256=$sha};afl_fuzz=@{path=$bin;sha256=$sha}
    }} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $lock
    $debug=Join-Path $root 'debug.json'
    foreach ($name in @('PdfFilter.dll','libmupdf.dll')) { Set-Content -LiteralPath (Join-Path $root $name) -Value 'parser fixture' }
    @{target_commit='16c59fde8b824ab54c56f23aef910a6fdd874ad0';target_module='sumatrafuzz-harness.exe';target_method='fuzz_one_file';
      cycles=10;confirmed_map_nonzero_bytes=1;
      confirmed_modules=@('PdfFilter.dll','libmupdf.dll');harness_sha256=(Get-FileHash $harness -Algorithm SHA256).Hash.ToLowerInvariant();
      pdf_filter_sha256=(Get-FileHash (Join-Path $root 'PdfFilter.dll') -Algorithm SHA256).Hash;
      mupdf_sha256=(Get-FileHash (Join-Path $root 'libmupdf.dll') -Algorithm SHA256).Hash;
      toolchain_lock_sha256=(Get-FileHash $lock -Algorithm SHA256).Hash.ToLowerInvariant()} |
      ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $debug
    return @{ToolchainLock=$lock;A4Manifest=$debug;HarnessExe=$harness;InputDir=$input;OutputDir=(Join-Path $root 'fresh runs')}
  }
}
Describe 'WinAFL campaign launcher preflight must fail closed' -Skip:(!$IsWindows) {
  BeforeEach { $script:f=New-CampaignFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) }
  It 'rejects reused output directory' {
    [void](New-Item -Type Directory -Path $f.OutputDir -Force)
    { & $script:runner @f } | Should -Throw '*overwrite WinAFL campaign*'
  }
  It 'rejects missing debug evidence' {
    Remove-Item -LiteralPath $f.A4Manifest
    { & $script:runner @f } | Should -Throw '*does not exist*'
  }
  It 'rejects a tampered binary hash' {
    Add-Content -LiteralPath ((Get-Content $f.ToolchainLock -Raw | ConvertFrom-Json).tools.afl_fuzz.path) -Value 'tampered'
    { & $script:runner @f } | Should -Throw '*Tool binary hash mismatch*'
  }
  It 'rejects changed harness after genuine debug run' {
    Add-Content -LiteralPath $f.HarnessExe -Value 'changed'
    { & $script:runner @f } | Should -Throw '*Parser binary changed since A4*'
  }
  It 'rejects evidence for a different pinned source' {
    $x=Get-Content $f.A4Manifest -Raw | ConvertFrom-Json
    $x.target_commit='unverified'
    $x | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $f.A4Manifest
    { & $script:runner @f } | Should -Throw '*A4 instrumented run evidence missing*'
  }
}
