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
    RulesDir            = "C:\Program Files\Suricata\rules"
    SuricataConfigPath  = "C:\Program Files\Suricata\suricata.yaml"
    SuricataLogDir      = "C:\Program Files\Suricata\log"
    TaskName            = "SuricataStartup"
}

function Remove-SuricataScheduledTask {
    if (Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue) {
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
}

function Uninstall-Npcap {
    $npcapProduct = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Npcap*" }
    if ($npcapProduct) {
        $npcapProduct.Uninstall() | Out-Null
        InfoMessage "Uninstalled Npcap via MSI."
    } else {
        WarnMessage "Npcap MSI product not found. Attempting manual removal."
    }
    if (Test-Path $global:Config.NpcapPath) {
        Remove-Item -Path $global:Config.NpcapPath -Recurse -Force
        InfoMessage "Removed Npcap directory."
    }
}

function Remove-SuricataRules {
    if (Test-Path $global:Config.RulesDir) {
        Remove-Item -Path $global:Config.RulesDir -Recurse -Force
        InfoMessage "Removed Suricata rules directory."
    } else {
        WarnMessage "Suricata rules directory not found."
    }
}

function Remove-SuricataLogs {
    if (Test-Path $global:Config.SuricataLogDir) {
        Remove-Item -Path $global:Config.SuricataLogDir -Recurse -Force
        InfoMessage "Removed Suricata log directory."
    } else {
        WarnMessage "Suricata log directory not found."
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
        InfoMessage "=== Removing Suricata rules ==="
        Remove-SuricataRules
        InfoMessage "=== Removing Suricata logs ==="
        Remove-SuricataLogs
        SuccessMessage "Uninstallation completed!"
    } catch {
        ErrorMessage "Uninstallation failed: $_"
        exit 1
    }
}

Uninstall-All
