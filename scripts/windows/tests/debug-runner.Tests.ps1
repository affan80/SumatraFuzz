#requires -Version 7.0
BeforeAll {
    $script:runner = (Resolve-Path (Join-Path $PSScriptRoot '../run-dynamorio-debug.ps1')).Path
    function New-DebugFixture([string]$root) {
        [void](New-Item -ItemType Directory -Path $root -Force)
        $bin=Join-Path $root 'tools with spaces'
        [void](New-Item -ItemType Directory -Path $bin -Force)
        $exe=Join-Path $root 'sumatrafuzz-harness.exe'
        $pdf=Join-Path $root 'valid pdf.pdf'
        $tool=Join-Path $bin 'tool.bin'
        Set-Content -LiteralPath $exe -Value 'fake-harness'
        Set-Content -LiteralPath $pdf -Value '%PDF-1.4'
        Set-Content -LiteralPath $tool -Value 'fake-tool'
        $hash=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
        $lock=Join-Path $root 'lock.json'
        @{
            architecture='x64'
            source_commit='16c59fde8b824ab54c56f23aef910a6fdd874ad0'
            harness_entry='fuzz_one_file'; nargs=1
            acquisition=@{winafl_source_commit='fd85f38548b14352f4b70ad414f364ea6dc1a769';dynamorio_release='cronbuild-11.91.20735'}
            tools=@{
                drrun=@{path=$tool;sha256=$hash}
                afl_fuzz=@{path=$tool;sha256=$hash}
                winafl_client=@{path=$tool;sha256=$hash}
            }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $lock
        return @{ToolchainLock=$lock;HarnessExe=$exe;InputPdf=$pdf;OutputDir=(Join-Path $root 'log dir')}
    }
}
Describe 'Real DynamoRIO launcher rejects invalid inputs before execution' -Skip:(!$IsWindows) {
    BeforeEach { $script:fixture=New-DebugFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) }
    It 'rejects relative log directory' {
        $fixture.OutputDir='relative-path'
        { & $script:runner @fixture } | Should -Throw '*absolute*'
    }
    It 'rejects wrong target module executable' {
        $new=Join-Path (Split-Path -Parent $fixture.HarnessExe) 'other-harness.exe'
        Copy-Item $fixture.HarnessExe $new
        $fixture.HarnessExe=$new
        { & $script:runner @fixture } | Should -Throw '*target module*'
    }
    It 'rejects corrupted client SHA-256' {
        Add-Content -LiteralPath ((Get-Content $fixture.ToolchainLock -Raw | ConvertFrom-Json).tools.winafl_client.path) -Value tamper
        { & $script:runner @fixture } | Should -Throw '*Hash mismatch*'
    }
    It 'rejects unknown runtime provenance' {
        $x=Get-Content $fixture.ToolchainLock -Raw | ConvertFrom-Json
        $x.acquisition.dynamorio_release='unverified'
        $x | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $fixture.ToolchainLock
        { & $script:runner @fixture } | Should -Throw '*Unrecognized toolchain*'
    }
}
