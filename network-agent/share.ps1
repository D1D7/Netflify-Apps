# Make a ZIP of NetAgent to give to someone else: code, scripts and docs only.
# Never included: .env (API keys, passwords), data\ (app password, 2FA, PIN, history),
# inventory\devices.yaml (your devices), backups\, exports\, logs\, .venv\.
# Result: NetAgent-share-<date>.zip on your Desktop.
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$stage = Join-Path $env:TEMP "netagent-share-$stamp"
$dest = Join-Path $stage "NetAgent"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$dirs = @("netagent", "docs", "tests")
$files = @("requirements.txt", "requirements-dev.txt", ".env.example", "README.md", "PLAN.md", "Dockerfile",
           "docker-compose.yml", ".gitattributes", ".gitignore", "netagent-background.vbs", "share.ps1",
           "inventory\devices.example.yaml", "inventory\golden.example.yaml", "lab\mikrotik-chr.ps1")

foreach ($d in $dirs) {
    $src = Join-Path $Root $d
    if (Test-Path $src) { Copy-Item -Recurse -Force $src (Join-Path $dest $d) }
}
foreach ($f in $files) {
    $src = Join-Path $Root $f
    if (Test-Path $src) {
        $target = Join-Path $dest $f
        New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
        Copy-Item -Force $src $target
    }
}
Get-ChildItem -Path $Root -Filter *.bat -File | ForEach-Object { Copy-Item -Force $_.FullName (Join-Path $dest $_.Name) }

# Safety net: remove anything private that might have slipped in.
Get-ChildItem -Path $dest -Recurse -Force -Directory |
    Where-Object { $_.Name -in @("__pycache__", ".pytest_cache", "data", ".venv", "backups", "exports", "logs") } |
    Sort-Object FullName -Descending | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $dest -Recurse -Force -File |
    Where-Object { $_.Name -eq ".env" -or $_.Name -eq "devices.yaml" -or $_.Name -eq "golden.yaml" -or $_.Extension -in @(".pem", ".pyc") } |
    Remove-Item -Force

$zip = Join-Path ([Environment]::GetFolderPath("Desktop")) "NetAgent-share-$stamp.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $dest -DestinationPath $zip
Remove-Item -Recurse -Force $stage

Write-Host ""
Write-Host "  ZIP ready: $zip" -ForegroundColor Green
Write-Host "  Inside: code and scripts only. No .env, no passwords, no devices.yaml, no data." -ForegroundColor Green
Write-Host "  The other person: unzip -> install.bat -> own API key in .env -> setup-password.bat -> start.bat (or demo.bat)"
