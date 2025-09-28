# Uninstalls Suricata, Npcap, and cleans up all leftover folders.
# MUST BE RUN AS ADMINISTRATOR

# Global configuration
$global:Config = @{
    TaskName = "SuricataStartup"
}

# Function to handle logging
function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}

# Logging helpers with colors
function InfoMessage {
    param ([string]$Message)
    Log "[INFO]" $Message "White"
}

function WarnMessage {
    param ([string]$Message)
    Log "[WARNING]" $Message "Yellow"
}

function ErrorMessage {
    param ([string]$Message)
    Log "[ERROR]" $Message "Red"
}

function SuccessMessage {
    param ([string]$Message)
    Log "[SUCCESS]" $Message "Green"
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