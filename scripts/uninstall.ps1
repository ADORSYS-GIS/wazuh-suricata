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
    NpcapUninstallPath = "C:\Program Files\Npcap\uninstall.exe"
    RulesDir            = "C:\Program Files\Suricata\rules"
    SuricataConfigPath  = "C:\Program Files\Suricata\suricata.yaml"
    SuricataLogDir      = "C:\Program Files\Suricata\log"
    TaskName            = "SuricataStartup"
}

function Remove-SystemPath {
    param (
        [string]$PathToRemove
    )

    # Get the current system Path
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)

    # Split the Path into an array
    $pathArray = $currentPath -split ';'

    # Check if the specified path exists
    if ($pathArray -contains $PathToRemove) {
        InfoMessage "The path '$PathToRemove' exists in the system Path. Proceeding to remove it."

        # Remove the specified path
        $updatedPathArray = $pathArray | Where-Object { $_ -ne $PathToRemove }

        # Join the array back into a single string
        $updatedPath = ($updatedPathArray -join ';').TrimEnd(';')

        # Update the system Path
        [System.Environment]::SetEnvironmentVariable("Path", $updatedPath, [System.EnvironmentVariableTarget]::Machine)

        InfoMessage "Successfully removed '$PathToRemove' from the system Path."
    } else {
        WarnMessage "The path '$PathToRemove' does not exist in the system Path. No changes were made."
    }
}

function Remove-SuricataScheduledTask {
    if (Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue) {
	Stop-ScheduledTask -TaskName $global:Config.TaskName
        Unregister-ScheduledTask -TaskName $global:Config.TaskName -Confirm:$false
        InfoMessage "Removed Suricata scheduled task."
    } else {
        WarnMessage "No Suricata scheduled task found."
    }
}

function Uninstall-Suricata {
    # Remove Suricata via MSI if possible
    $suricataProduct = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Suricata*" }
    if ($suricataProduct) {
        $suricataProduct.Uninstall() | Out-Null
        InfoMessage "Uninstalled Suricata via MSI."
    } else {
        WarnMessage "Suricata MSI product not found. Attempting manual removal."
    }
    if (Test-Path $global:Config.SuricataDir) {
        Remove-Item -Path $global:Config.SuricataDir -Recurse -Force
        InfoMessage "Removed Suricata directory."
    }
    
    Remove-SystemPath $global:Config.SuricataDir
}
function Uninstall-NpCap {

    InfoMessage "Uninstalling NpCap"

    if (-Not (Test-Path $global:Config.NpcapUninstallPath)) {
        WarnMessage "Npcap uninstaller not found: $global:Config.NpcapUninstallPath" skipping
        return
    }

    Start-Process -FilePath $global:Config.NpcapUninstallPath -NoNewWindow -Wait
    InfoMessage "Succesfully removed NpCap"
    Remove-SystemPath $global:Config.NpcapPath

    if (Test-Path $global:Config.NpcapPath) {
        Remove-Item -Path $global:Config.NpcapPath -Recurse -Force
        InfoMessage "Removed Npcap directory."
    }
}


function Uninstall-All {
    try {
        InfoMessage "=== Removing Suricata scheduled task ==="
        Remove-SuricataScheduledTask
        InfoMessage "=== Uninstalling Suricata ==="
        Uninstall-Suricata
        InfoMessage "=== Uninstalling Npcap ==="
        Uninstall-Npcap
        SuccessMessage "Uninstallation completed!"
    } catch {
        ErrorMessage "Uninstallation failed: $_"
        exit 1
    }
}

Uninstall-All
