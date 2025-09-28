# FINAL & COMPLETE SCRIPT - Uninstalls Suricata, Npcap, and cleans up all leftover folders.
# MUST BE RUN AS ADMINISTRATOR

Write-Host "--- Starting Total Silent Uninstall ---" -ForegroundColor Cyan

# Step 1: Kill any running Suricata process to unlock files
Write-Host "Stopping any suricata.exe process..."
Stop-Process -Name "suricata" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Step 2: Change directory to C:\ to prevent folder locks
Set-Location C:\

# Step 3: Forcefully delete the entire Suricata directory
$suricataDir = "C:\Program Files\Suricata"
if (Test-Path $suricataDir) {
    Write-Host "Deleting Suricata directory..."
    Remove-Item -Path $suricataDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 4: Silently run the Npcap uninstaller
$npcapUninstaller = "C:\Program Files\Npcap\uninstall.exe"
if (Test-Path $npcapUninstaller) {
    Write-Host "Running Npcap silent uninstaller..."
    Start-Process -FilePath $npcapUninstaller -ArgumentList "/S" -Wait
}

# Step 5: Forcefully delete the leftover Npcap directory
$npcapDir = "C:\Program Files\Npcap"
if (Test-Path $npcapDir) {
    Write-Host "Cleaning up leftover Npcap directory..."
    Remove-Item -Path $npcapDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 6: Final Verification
if ((-not (Test-Path $suricataDir)) -and (-not (Test-Path $npcapDir))) {
    Write-Host "SUCCESS: Suricata and Npcap have been totally removed." -ForegroundColor Green
} else {
    Write-Host "WARNING: Some files may remain. A system reboot may be required to unlock them." -ForegroundColor Yellow
}

Write-Host "--- Process Complete ---" -ForegroundColor Cyan