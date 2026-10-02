param(
    [Parameter(Mandatory = $true)][string]$HostName,
    [int]$Port = 22,
    [string]$KeyPath = (Join-Path $env:USERPROFILE '.ssh\exocortex-window'),
    [ValidateSet('Password', 'Tui')][string]$PairingMethod,
    [string]$OperatorUser
)

$ErrorActionPreference = 'Stop'
if ($HostName -notmatch '^[A-Za-z0-9.-]+$' -or $Port -lt 1 -or $Port -gt 65535) {
    throw 'Enter a DNS name or IPv4 address and a valid SSH port.'
}
$ssh = Get-Command ssh -ErrorAction Stop
$sshKeygen = Get-Command ssh-keygen -ErrorAction Stop
$knownName = if ($Port -eq 22) { $HostName } else { "[$HostName]:$Port" }
& $sshKeygen.Source -F $knownName *> $null
if ($LASTEXITCODE -ne 0) {
    throw "The SSH host key for $knownName is not trusted yet. Verify its fingerprint out of band and add it to known_hosts before setup."
}
$keyDirectory = Split-Path -Parent $KeyPath
New-Item -ItemType Directory -Path $keyDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $KeyPath)) {
    Write-Host 'Create a dedicated Window SSH key. A passphrase requires a running ssh-agent for unattended MCP startup.'
    & $sshKeygen.Source -t ed25519 -f $KeyPath -C 'exocortex-window'
    if ($LASTEXITCODE -ne 0) { throw 'SSH key generation failed.' }
}
$publicKeyPath = "$KeyPath.pub"
if (-not (Test-Path -LiteralPath $publicKeyPath)) { throw 'The Window public key is missing.' }
$publicKey = (Get-Content -LiteralPath $publicKeyPath -Raw).Trim()
if ($publicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?$') { throw 'The Window key is not ssh-ed25519.' }
$keyBlob = ($publicKey -split '\s+')[1]

if (-not $PairingMethod) {
    Write-Host 'Pair this development PC with Window:'
    Write-Host '  1. Enter the server operator password once (SSH and possibly sudo)'
    Write-Host '  2. Paste the public key into Updater TUI'
    $choice = Read-Host 'Choose 1 or 2'
    switch ($choice) {
        '1' { $PairingMethod = 'Password' }
        '2' { $PairingMethod = 'Tui' }
        default { throw 'Choose 1 or 2, or pass -PairingMethod Password/Tui.' }
    }
}

if ($PairingMethod -eq 'Password') {
    if (-not $OperatorUser) {
        $OperatorUser = Read-Host 'Server Window operator username [windowops]'
        if (-not $OperatorUser) { $OperatorUser = 'windowops' }
    }
    if ($OperatorUser -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') { throw 'Enter a valid server operator username.' }
    Write-Host 'OpenSSH will prompt for the server password; sudo may prompt again. Neither password is stored by this script.'
    $pairArguments = @('-tt', '-p', [string]$Port,
        '-o', 'BatchMode=no', '-o', 'PubkeyAuthentication=no',
        '-o', 'PreferredAuthentications=keyboard-interactive,password',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes',
        "$OperatorUser@$HostName", 'sudo', '/usr/bin/updater', 'window', 'pair', '--key-base64', $keyBlob)
    & $ssh.Source @pairArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Window pairing failed. Check that windowops has a login password or SSH key, the restricted sudoers rule is installed, and Window is installed. You can rerun with -PairingMethod Tui.'
    }
}

$arguments = @('-T', '-p', [string]$Port, '-i', $KeyPath,
    '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'IdentitiesOnly=yes', '-o', 'ClearAllForwardings=yes',
    "window@$HostName")
$codex = Get-Command codex -ErrorAction SilentlyContinue
if ($codex) {
    & $codex.Source mcp add window -- $ssh.Source @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Codex MCP registration failed. Review any existing window server entry.' }
    Write-Host 'Codex MCP server window registered. Restart Codex to load it.'
} else {
    Write-Host 'Codex CLI is unavailable. Add a STDIO MCP server named window in Codex Settings:'
    Write-Host "Command: $($ssh.Source)"
    Write-Host "Arguments: $($arguments -join ' ')"
}
if ($PairingMethod -eq 'Tui') {
    Write-Host 'Paste this public key into sudo updater tui --window-only > Pair development PC:'
    Write-Output $publicKey
} else {
    Write-Host 'Pairing complete. Open the timed Window grant in Updater TUI when needed.'
}
