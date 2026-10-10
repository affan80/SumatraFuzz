#requires -Version 7.0
BeforeAll {
    $script:gate = Join-Path $PSScriptRoot '../verify-native-gate.ps1'
}
Describe 'Native campaign privilege boundary' -Skip:(!$IsWindows) {
    It 'rejects administrator execution before invoking any native input' {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Set-ItResult -Skipped -Because 'This negative test requires the hosted administrator context'
            return
        }
        { & $script:gate -RepoRoot (Split-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) -Parent) } |
            Should -Throw '*nonadministrator*'
    }
}
