# Uninstalls Suricata, Npcap, and cleans up all leftover folders.
# MUST BE RUN AS ADMINISTRATOR

# Repository configuration
$WAZUH_SURICATA_REPO_REF = if ($env:WAZUH_SURICATA_REPO_REF) { $env:WAZUH_SURICATA_REPO_REF } else { "v0.2.0-rc.5" }
$WAZUH_SURICATA_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/$WAZUH_SURICATA_REPO_REF"

$TEMP_DIR = Join-Path $env:TEMP "wazuh-suricata-install"
if (-not (Test-Path $TEMP_DIR)) {
    New-Item -Path $TEMP_DIR -ItemType Directory | Out-Null
}

try {
    $ChecksumsURL = "$WAZUH_SURICATA_REPO_URL/checksums.sha256"
    $UtilsURL = "$WAZUH_SURICATA_REPO_URL/scripts/shared/utils.ps1"
    
    $global:ChecksumsPath = Join-Path $TEMP_DIR "checksums.sha256"
    $UtilsPath = Join-Path $TEMP_DIR "utils.ps1"

    Invoke-WebRequest -Uri $ChecksumsURL -OutFile $ChecksumsPath -ErrorAction Stop
    Invoke-WebRequest -Uri $UtilsURL -OutFile $UtilsPath -ErrorAction Stop

    # Verification function (bootstrap)
    function Get-FileChecksum-Bootstrap {
        param([string]$FilePath)
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    }

    $ExpectedHash = (Select-String -Path $ChecksumsPath -Pattern "scripts/shared/utils.ps1").Line.Split(" ")[0]
    $ActualHash = Get-FileChecksum-Bootstrap -FilePath $UtilsPath

    if ([string]::IsNullOrWhiteSpace($ExpectedHash) -or ($ActualHash -ne $ExpectedHash.ToLower())) {
        Write-Error "Checksum verification failed for utils.ps1"
        Write-Error "Expected: $ExpectedHash"
        Write-Error "Got:      $ActualHash"
        exit 1
    }

    . $UtilsPath
}
catch {
    Write-Error "Failed to initialize utilities: $($_.Exception.Message)"
    exit 1
}

# Global configuration
$global:Config = @{
    TaskName = "SuricataStartup"
}

function Remove-SuricataScheduledTask {
    try {
        $task = Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue
        if ($task) {
            try {
                Stop-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue
                InfoMessage "Stopped Suricata scheduled task."
            } catch {
                WarnMessage "Could not stop Suricata scheduled task (it may not be running). $_"
            }
            Unregister-ScheduledTask -TaskName $global:Config.TaskName -Confirm:$false
            InfoMessage "Removed Suricata scheduled task."
        } else {
            WarnMessage "No Suricata scheduled task found."
        }
    } catch {
        ErrorMessage "Error while removing scheduled task: $_"
    }
}

Write-Host "--- Starting Total Silent Uninstall ---" -ForegroundColor Cyan

# Step 1: Remove Suricata scheduled task
Write-Host "Removing Suricata scheduled task..."
Remove-SuricataScheduledTask

# Step 2: Kill any running Suricata process to unlock files
Write-Host "Stopping any suricata.exe process..."
Stop-Process -Name "suricata" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Step 3: Change directory to C:\ to prevent folder locks
Set-Location C:\

# Step 4: Forcefully delete the entire Suricata directory
$suricataDir = "C:\Program Files\Suricata"
if (Test-Path $suricataDir) {
    Write-Host "Deleting Suricata directory..."
    Remove-Item -Path $suricataDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 5: Silently run the Npcap uninstaller
$npcapUninstaller = "C:\Program Files\Npcap\uninstall.exe"
if (Test-Path $npcapUninstaller) {
    Write-Host "Running Npcap silent uninstaller..."
    Start-Process -FilePath $npcapUninstaller -ArgumentList "/S" -Wait
}

# Step 6: Forcefully delete the leftover Npcap directory
$npcapDir = "C:\Program Files\Npcap"
if (Test-Path $npcapDir) {
    Write-Host "Cleaning up leftover Npcap directory..."
    Remove-Item -Path $npcapDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 7: Final Verification
if ((-not (Test-Path $suricataDir)) -and (-not (Test-Path $npcapDir))) {
    Write-Host "SUCCESS: Suricata and Npcap have been totally removed." -ForegroundColor Green
} else {
    Write-Host "WARNING: Some files may remain. A system reboot may be required to unlock them." -ForegroundColor Yellow
}

Write-Host "--- Process Complete ---" -ForegroundColor Cyan