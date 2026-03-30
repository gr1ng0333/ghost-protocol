## Ghost VPS SSH Setup — passwordless login
## Run once: .\setup_vps_ssh.ps1
## After that, just: ssh ghost-vps

$VPS_HOST = "94.156.122.66"
$VPS_USER = "root"

# 1. Copy public key to VPS (will ask password ONE last time)
Write-Host "Copying SSH key to $VPS_USER@$VPS_HOST ..." -ForegroundColor Cyan
Write-Host "Enter the VPS password when prompted (last time!):" -ForegroundColor Yellow

$pubKey = Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" -Raw
$cmd = "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$($pubKey.Trim())' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'KEY_INSTALLED_OK'"
ssh -o StrictHostKeyChecking=no "${VPS_USER}@${VPS_HOST}" $cmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to copy key. Check password and try again." -ForegroundColor Red
    exit 1
}

# 2. Add SSH config alias
$sshConfig = "$env:USERPROFILE\.ssh\config"
$aliasBlock = @"

Host ghost-vps
    HostName $VPS_HOST
    User $VPS_USER
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
"@

$existingConfig = ""
if (Test-Path $sshConfig) {
    $existingConfig = Get-Content $sshConfig -Raw
}

if ($existingConfig -notmatch "ghost-vps") {
    Add-Content -Path $sshConfig -Value $aliasBlock
    Write-Host "Added 'ghost-vps' alias to SSH config." -ForegroundColor Green
} else {
    Write-Host "'ghost-vps' alias already exists in SSH config." -ForegroundColor Yellow
}

# 3. Test passwordless connection
Write-Host "`nTesting passwordless login..." -ForegroundColor Cyan
ssh ghost-vps "echo 'SUCCESS: connected as $(whoami) on $(hostname)'"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nDone! Now you can connect with:" -ForegroundColor Green
    Write-Host "  ssh ghost-vps" -ForegroundColor White
} else {
    Write-Host "`nKey was copied but test failed. Try manually: ssh ghost-vps" -ForegroundColor Yellow
}
