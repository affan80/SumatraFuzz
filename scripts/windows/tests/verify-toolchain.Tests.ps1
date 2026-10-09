#requires -Version 7.0
BeforeAll {
  $script:scriptPath = (Resolve-Path (Join-Path $PSScriptRoot '../verify-toolchain.ps1')).Path
  function New-PE([string]$Path,[UInt16]$Machine=0x8664) {
    $b=[byte[]]::new(512); $b[0]=77; $b[1]=90
    [BitConverter]::GetBytes([int]128).CopyTo($b,0x3c)
    $b[128]=80; $b[129]=69
    [BitConverter]::GetBytes($Machine).CopyTo($b,132)
    [IO.File]::WriteAllBytes($Path,$b)
  }
  function New-Fixture([string]$Root) {
    [void](New-Item -ItemType Directory -Path $Root -Force)
    $src=Join-Path $Root 'source with spaces'
    $bin=Join-Path $Root 'tools with spaces'
    [void](New-Item -ItemType Directory -Path $src,$bin -Force)
    Set-Content -LiteralPath (Join-Path $src 'file') -Value x
    & git -C $src init -q
    & git -C $src add file
    & git -C $src -c user.name=Test -c user.email=test@example.invalid commit -qm test
    & git -C $src tag 3.6.1rel
    $sha=(& git -C $src rev-parse HEAD).Trim()
    $cfg=Join-Path $Root 'target.json'
    @{target_id='sumatrapdf-3.6.1rel';source_repository='https://github.com/sumatrapdfreader/sumatrapdf';source_tag='3.6.1rel';source_commit=$sha;architecture='x64';harness_entry='fuzz_one_file';nargs=1} | ConvertTo-Json | Set-Content -LiteralPath $cfg
    $afl=Join-Path $bin 'afl-fuzz.exe'
    $dll=Join-Path $bin 'winafl.dll'
    $dr=Join-Path $bin 'drrun.exe'
    New-PE $afl; New-PE $dll; New-PE $dr
    return @{SumatraSource=$src;WinAflExe=$afl;WinAflDll=$dll;DrrunExe=$dr;Workspace=(Join-Path $Root 'work dir');TargetConfig=$cfg}
  }
}
Describe 'Windows toolchain validation' -Skip:(!$IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  BeforeEach { $script:fixture=New-Fixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) }
  It 'allows spaces and saves hashes' {
    { & $script:scriptPath @fixture } | Should -Not -Throw
    $lock=Get-Content -LiteralPath (Join-Path $fixture.Workspace 'target-lock.json') -Raw | ConvertFrom-Json
    $lock.tools.drrun.sha256 | Should -Match '^[0-9a-f]{64}$'
    $lock.source_commit | Should -Be ((& git -C $fixture.SumatraSource rev-parse HEAD).Trim())
  }
  It 'rejects missing binary' {
    Remove-Item -LiteralPath $fixture.DrrunExe
    { & $script:scriptPath @fixture } | Should -Throw '*DrrunExe*'
  }
  It 'rejects x86 PE' {
    New-PE $fixture.WinAflDll 0x14c
    { & $script:scriptPath @fixture } | Should -Throw '*x64*'
  }
  It 'rejects corrupt PE' {
    Set-Content -LiteralPath $fixture.WinAflExe -Value corrupt
    { & $script:scriptPath @fixture } | Should -Throw '*PE*'
  }
  It 'rejects relative path' {
    $fixture.Workspace='relative'
    { & $script:scriptPath @fixture } | Should -Throw '*absolute*'
  }
  It 'rejects modified source' {
    Set-Content -LiteralPath (Join-Path $fixture.SumatraSource 'file') -Value changed
    { & $script:scriptPath @fixture } | Should -Throw '*modified*'
  }
  It 'rejects source drift' {
    Set-Content -LiteralPath (Join-Path $fixture.SumatraSource 'file') -Value changed
    & git -C $fixture.SumatraSource add file
    & git -C $fixture.SumatraSource -c user.name=Test -c user.email=test@example.invalid commit -qm drift
    { & $script:scriptPath @fixture } | Should -Throw '*drift*'
  }
  It 'rejects workspace file' {
    Set-Content -LiteralPath $fixture.Workspace -Value blocking
    { & $script:scriptPath @fixture } | Should -Throw '*Workspace*'
  }
}
