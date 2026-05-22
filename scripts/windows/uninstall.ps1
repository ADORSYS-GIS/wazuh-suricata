
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
