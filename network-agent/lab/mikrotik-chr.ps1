# NetAgent lab: a real MikroTik RouterOS (CHR, free) in VirtualBox, added to NetAgent automatically.
#
#   lab-mikrotik.bat            create + start the VM, first-time setup, add to inventory
#   lab-mikrotik.bat -Stop      power the VM off
#   lab-mikrotik.bat -Reset     delete the VM and start from scratch
#
# CHR without a license runs at 1 Mbit/s per interface - plenty for a management lab.
param(
    [switch]$Reset,
    [switch]$Stop,
    [int]$SshPort = 2230,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path -Parent $PSScriptRoot
$VmName = "NetAgent-CHR"
$LabDir = Join-Path $Root "lab\chr"
$Py = Join-Path $Root ".venv\Scripts\python.exe"
New-Item -ItemType Directory -Force -Path $LabDir | Out-Null

function Say($text, $color = "Gray") { Write-Host "  $text" -ForegroundColor $color }

function Find-VBoxManage {
    $cmd = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) {
            $p = Join-Path $base "Oracle\VirtualBox\VBoxManage.exe"
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

$VBox = Find-VBoxManage
if (-not $VBox) {
    Say "VirtualBox is not installed - installing it with winget (accept the Windows prompt)..." Yellow
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Say "winget is missing. Install VirtualBox from https://www.virtualbox.org/wiki/Downloads and run this again." Red
        exit 1
    }
    winget install --id Oracle.VirtualBox -e --accept-source-agreements --accept-package-agreements
    $VBox = Find-VBoxManage
    if (-not $VBox) {
        Say "VirtualBox install did not finish. Restart the PC and run lab-mikrotik.bat again." Red
        exit 1
    }
}

function VBox {
    & $VBox @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

function VmExists { return [bool]((& $VBox list vms) -match "^`"$VmName`" ") }
function VmRunning { return [bool]((& $VBox list runningvms) -match "^`"$VmName`" ") }

if ($Stop -or $Reset) {
    if (VmRunning) {
        Say "Powering off $VmName..."
        VBox controlvm $VmName poweroff | Out-Null
        Start-Sleep -Seconds 3
    }
    if ($Stop) { Say "Stopped." Green; exit 0 }
    if (VmExists) {
        Say "Deleting $VmName..."
        VBox unregistervm $VmName --delete | Out-Null
    }
}

$fresh = $false
if (-not (VmExists)) {
    if (-not $Version) {
        try {
            $Version = ((New-Object System.Net.WebClient).DownloadString("https://upgrade.mikrotik.com/routeros/NEWESTa7.stable").Trim() -split "\s+")[0]
        } catch {
            $Version = "7.16.1"
            Say "Could not ask MikroTik for the newest version, using $Version" Yellow
        }
    }
    $zip = Join-Path $LabDir "chr-$Version.vdi.zip"
    if (-not (Test-Path $zip)) {
        $url = "https://download.mikrotik.com/routeros/$Version/chr-$Version.vdi.zip"
        Say "Downloading RouterOS CHR $Version (~50 MB)..."
        (New-Object System.Net.WebClient).DownloadFile($url, $zip)
    }
    $extract = Join-Path $LabDir "extract"
    if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
    Expand-Archive -Path $zip -DestinationPath $extract
    $src = Get-ChildItem -Path $extract -Filter *.vdi -Recurse | Select-Object -First 1
    if (-not $src) { throw "No .vdi inside $zip" }
    $vdi = Join-Path $LabDir "$VmName.vdi"
    if (Test-Path $vdi) { Remove-Item -Force $vdi }
    Move-Item $src.FullName $vdi
    Remove-Item -Recurse -Force $extract
    VBox internalcommands sethduuid $vdi | Out-Null   # fresh disk id, so a re-created VM never clashes

    Say "Creating VM $VmName (256 MB RAM, 1 CPU)..."
    VBox createvm --name $VmName --ostype Linux26_64 --basefolder $LabDir --register | Out-Null
    VBox modifyvm $VmName --memory 256 --cpus 1 --boot1 disk --nic1 nat | Out-Null
    VBox modifyvm $VmName --natpf1 "ssh,tcp,127.0.0.1,$SshPort,,22" | Out-Null
    VBox modifyvm $VmName --natpf1 "winbox,tcp,127.0.0.1,8291,,8291" | Out-Null
    VBox storagectl $VmName --name SATA --add sata --controller IntelAhci --portcount 1 | Out-Null
    VBox storageattach $VmName --storagectl SATA --port 0 --device 0 --type hdd --medium $vdi | Out-Null
    $fresh = $true
}

if (-not (VmRunning)) {
    Say "Starting $VmName in the background (no window)..."
    VBox startvm $VmName --type headless | Out-Null
}

if ($fresh) {
    Say "First-time setup (new admin password goes straight into .env)..."
    & $Py -m netagent.demo.chr_init --host 127.0.0.1 --port $SshPort --wait 240
    if ($LASTEXITCODE -ne 0) { Say "Setup failed - see the message above. Retry: lab-mikrotik.bat -Reset" Red; exit 1 }
} else {
    Say "$VmName is already set up." Green
}

Write-Host ""
Say "MikroTik lab is running:" Green
Say "  SSH     127.0.0.1:$SshPort  (user admin, password = LAB_PASS in .env)"
Say "  Winbox  127.0.0.1:8291"
Say "  NetAgent device name: CHR-Lab  ->  restart start.bat, then try /status or /health CHR-Lab"
Say "  Stop the VM: lab-mikrotik.bat -Stop"
