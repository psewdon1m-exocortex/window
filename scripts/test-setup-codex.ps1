$ErrorActionPreference = 'Stop'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('window-setup-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$oldPath = $env:PATH
$oldSshLog = $env:WINDOW_TEST_SSH_LOG
$oldCodexLog = $env:WINDOW_TEST_CODEX_LOG
try {
    Set-Content -LiteralPath (Join-Path $scratch 'ssh-keygen.cmd') -Encoding ascii -Value "@echo off`r`nexit /b 0"
    Set-Content -LiteralPath (Join-Path $scratch 'ssh.cmd') -Encoding ascii -Value "@echo off`r`necho %* > `"%WINDOW_TEST_SSH_LOG%`"`r`nexit /b 0"
    Set-Content -LiteralPath (Join-Path $scratch 'codex.cmd') -Encoding ascii -Value "@echo off`r`necho %* > `"%WINDOW_TEST_CODEX_LOG%`"`r`nexit /b 0"
    $env:PATH = "$scratch;$oldPath"
    $env:WINDOW_TEST_SSH_LOG = Join-Path $scratch 'ssh.log'
    $env:WINDOW_TEST_CODEX_LOG = Join-Path $scratch 'codex.log'
    $key = Join-Path $scratch 'client-key'
    Set-Content -LiteralPath $key -Value 'test private key placeholder'
    Set-Content -LiteralPath "$key.pub" -Value 'ssh-ed25519 AAAAexample window-test'
    $setup = Join-Path $PSScriptRoot 'setup-codex.ps1'

    & $setup -HostName example.com -KeyPath $key -PairingMethod Password -OperatorUser deploy | Out-Null
    $sshCall = Get-Content -LiteralPath $env:WINDOW_TEST_SSH_LOG -Raw
    $codexCall = Get-Content -LiteralPath $env:WINDOW_TEST_CODEX_LOG -Raw
    if ($sshCall -notmatch 'PubkeyAuthentication=no' -or $sshCall -notmatch 'deploy@example\.com' -or $sshCall -notmatch 'window pair --key-base64 AAAAexample') {
        throw "Password pairing did not use the protected first-time SSH path: $sshCall"
    }
    if ($codexCall -notmatch 'mcp add window' -or $codexCall -notmatch 'BatchMode=yes') {
        throw "Codex was not configured for later key-based MCP reads: $codexCall"
    }

    Remove-Item -LiteralPath $env:WINDOW_TEST_SSH_LOG
    & $setup -HostName example.com -KeyPath $key -PairingMethod Tui | Out-Null
    if (Test-Path -LiteralPath $env:WINDOW_TEST_SSH_LOG) {
        throw 'Manual TUI pairing unexpectedly opened an SSH connection.'
    }
    Write-Host 'Window setup password and TUI pairing modes passed.'
} finally {
    $env:PATH = $oldPath
    $env:WINDOW_TEST_SSH_LOG = $oldSshLog
    $env:WINDOW_TEST_CODEX_LOG = $oldCodexLog
    $resolved = [IO.Path]::GetFullPath($scratch)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and $resolved -ne $temporaryRoot) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
