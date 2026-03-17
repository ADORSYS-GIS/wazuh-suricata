# uninstall.ps1 - Uninstall Suricata, Npcap, rules, and scheduled task

# Logging helpers (reuse from install.ps1)
function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}
function InfoMessage { param([string]$Message) Log "[INFO]" $Message "White" }
function WarnMessage { param([string]$Message) Log "[WARNING]" $Message "Yellow" }
function ErrorMessage { param([string]$Message) Log "[ERROR]" $Message "Red" }
function SuccessMessage { param([string]$Message) Log "[SUCCESS]" $Message "Green" }

# Global config (reuse from install.ps1)
$global:Config = @{
    SuricataDir         = "C:\Program Files\Suricata"
    SuricataExePath     = "C:\Program Files\Suricata\suricata.exe"
    NpcapPath           = "C:\Program Files\Npcap"
    NpcapUninstallPath  = "C:\Program Files\Npcap\uninstall.exe"
    RulesDir            = "C:\Program Files\Suricata\rules"
    SuricataConfigPath  = "C:\Program Files\Suricata\suricata.yaml"
    SuricataLogDir      = "C:\Program Files\Suricata\log"
    TaskName            = "SuricataStartup"
}

function Remove-SystemPath {
    param (
        [string]$PathToRemove
    )
    try {
        $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
        $pathArray = $currentPath -split ';'
        if ($pathArray -contains $PathToRemove) {
            InfoMessage "The path '$PathToRemove' exists in the system Path. Proceeding to remove it."
            $updatedPathArray = $pathArray | Where-Object { $_ -ne $PathToRemove }
            $updatedPath = ($updatedPathArray -join ';').TrimEnd(';')
            [System.Environment]::SetEnvironmentVariable("Path", $updatedPath, [System.EnvironmentVariableTarget]::Machine)
            InfoMessage "Successfully removed '$PathToRemove' from the system Path."
        } else {
            WarnMessage "The path '$PathToRemove' does not exist in the system Path. No changes were made."
        }
    } catch {
        ErrorMessage "Failed to update system Path: $_"
    }
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

function Uninstall-Suricata {
    try {
        $suricataProduct = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Suricata*" }
        if ($suricataProduct) {
            $suricataProduct.Uninstall() | Out-Null
            InfoMessage "Uninstalled Suricata via MSI."
        } else {
            WarnMessage "Suricata MSI product not found. Attempting manual removal."
        }
        if (Test-Path $global:Config.SuricataDir) {
            Remove-Item -Path $global:Config.SuricataDir -Recurse -Force -ErrorAction Stop
            InfoMessage "Removed Suricata directory."
        } else {
            WarnMessage "Suricata directory not found."
        }
        Remove-SystemPath $global:Config.SuricataDir
    } catch {
        ErrorMessage "Failed to uninstall Suricata: $_"
    }
}

function Uninstall-NpCap {
    InfoMessage "Uninstalling Npcap"
    try {
        if (-Not (Test-Path $global:Config.NpcapUninstallPath)) {
            WarnMessage "Npcap uninstaller not found: $($global:Config.NpcapUninstallPath). Skipping."
        } else {
            Start-Process -FilePath $global:Config.NpcapUninstallPath -NoNewWindow -Wait
            InfoMessage "Successfully removed Npcap."
        }
        Remove-SystemPath $global:Config.NpcapPath
        if (Test-Path $global:Config.NpcapPath) {
            Remove-Item -Path $global:Config.NpcapPath -Recurse -Force -ErrorAction Stop
            InfoMessage "Removed Npcap directory."
        } else {
            WarnMessage "Npcap directory not found."
        }
    } catch {
        ErrorMessage "Failed to uninstall Npcap: $_"
    }
}

function Uninstall-All {
    try {
        InfoMessage "=== Removing Suricata scheduled task ==="
        Remove-SuricataScheduledTask
        InfoMessage "=== Uninstalling Suricata ==="
        Uninstall-Suricata
        InfoMessage "=== Uninstalling Npcap ==="
        Uninstall-NpCap
        SuccessMessage "Uninstallation completed!"
    } catch {
        ErrorMessage "Uninstallation failed: $_"
        exit 1
    }
}

Uninstall-All
