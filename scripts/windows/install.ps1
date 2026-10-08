# Repository configuration
$WAZUH_SURICATA_REPO_REF = if ($env:WAZUH_SURICATA_REPO_REF) { $env:WAZUH_SURICATA_REPO_REF } else { "v0.2.2" }
$WAZUH_SURICATA_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/$WAZUH_SURICATA_REPO_REF"

$TEMP_DIR = Join-Path $env:TEMP "wazuh-suricata-install"
if (-not (Test-Path $TEMP_DIR)) { New-Item -Path $TEMP_DIR -ItemType Directory -Force | Out-Null }

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

# Default version configuration
$SURICATA_VERSION = if ($env:SURICATA_VERSION) { $env:SURICATA_VERSION } else { "8.0.4" }

# Global configuration
$global:Config = @{
    TempDir                 = $TEMP_DIR
    SuricataInstallerUrl    = "https://www.openinfosecfoundation.org/download/windows/Suricata-$SURICATA_VERSION-1-64bit.msi"
    SuricataInstallerPath   = Join-Path $TEMP_DIR "Suricata_Installer.msi"
    NpcapInstallerUrl       = "https://npcap.com/dist/npcap-1.79.exe"
    NpcapInstallerPath      = Join-Path $TEMP_DIR "Npcap_Installer.exe"
    SuricataDir             = "C:\Program Files\Suricata"
    SuricataExePath         = "C:\Program Files\Suricata\suricata.exe"
    NpcapPath               = "C:\Program Files\Npcap"
    RulesDir                = "C:\Program Files\Suricata\rules"
    SuricataConfigPath      = "C:\Program Files\Suricata\suricata.yaml"
    TaskName                = "SuricataStartup"
}

# ====================== FUNCTIONS ======================

function Run-SuricataUpdate {
    InfoMessage "Running manual Suricata rules update..."

    $rulesUrl = "https://rules.emergingthreats.net/open/suricata-$SURICATA_VERSION/emerging.rules.tar.gz"
    $tempFile = Join-Path $global:Config.TempDir "emerging.rules.tar.gz"
    $rulesDir = $global:Config.RulesDir

    try {
        if (-not (Test-Path $rulesDir)) {
            New-Item -Path $rulesDir -ItemType Directory -Force | Out-Null
        }

        InfoMessage "Downloading Emerging Threats rules..."
        Invoke-WebRequest -Uri $rulesUrl -OutFile $tempFile -UseBasicParsing

        InfoMessage "Extracting rules to $rulesDir..."
        tar -xzf $tempFile -C $rulesDir

        InfoMessage "Unblocking downloaded rule files..."
        Get-ChildItem -Path $rulesDir -Recurse -File | Unblock-File

        InfoMessage "Setting permissions on rules directory..."
        icacls $rulesDir /grant "Wazuh:(OI)(CI)F" /T | Out-Null

        SuccessMessage "Manual rules update completed successfully."
        return $true
    }
    catch {
        ErrorMessage "Manual rules update failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
    }
}

function Install-SuricataSoftware {
    if (Test-Path $global:Config.SuricataExePath) {
        WarnMessage "Suricata already installed. Skipping."
        return
    }

    $installerPath = $global:Config.SuricataInstallerPath
    if (-not (Test-Path $installerPath)) {
        InfoMessage "Downloading Suricata installer..."
        Download-File -Url $global:Config.SuricataInstallerUrl -Destination $installerPath -Description "Suricata Installer"
    }

    InfoMessage "Installing Suricata..."
    Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /quiet" -Wait
    SuccessMessage "Suricata installed."
}

function Install-NpcapSoftware {
    if (Test-Path $global:Config.NpcapPath) {
        WarnMessage "Npcap is already installed."
        return
    }

    $installerPath = $global:Config.NpcapInstallerPath
    if (-not (Test-Path $installerPath)) {
        InfoMessage "Downloading Npcap..."
        Download-File -Url $global:Config.NpcapInstallerUrl -Destination $installerPath -Description "Npcap Installer"
    }

    InfoMessage "Installing Npcap... (Follow on-screen instructions)"
    Start-Process -FilePath $installerPath -Wait

    # Verify if Npcap installation succeeded or if user cancelled GUI
    $sys32NpcapDll = Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll"
    $sys32Dll = Join-Path $env:SystemRoot "System32\wpcap.dll"
    if ((Test-Path $global:Config.NpcapPath) -or (Test-Path $sys32NpcapDll) -or (Test-Path $sys32Dll)) {
        SuccessMessage "Npcap installation verified."
    } else {
        WarnMessage "Npcap installation was not completed. Suricata requires Npcap (wpcap.dll) to capture packets."
    }
}

function Update-EnvironmentVariables {
    $envPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $npcapSys32 = Join-Path $env:SystemRoot "System32\Npcap"
    
    $pathsToAdd = @($global:Config.SuricataDir, $global:Config.NpcapPath, $npcapSys32)
    $newPath = $envPath

    foreach ($p in $pathsToAdd) {
        if ($newPath -notlike "*$p*") {
            $newPath = "$newPath;$p"
        }
    }

    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path = "$env:Path;$($global:Config.SuricataDir);$($global:Config.NpcapPath);$npcapSys32"
    InfoMessage "PATH environment variable updated."
}

function Configure-SuricataYaml {
    $yamlPath = $global:Config.SuricataConfigPath
    if (-not (Test-Path $yamlPath)) { WarnMessage "suricata.yaml not found."; return }

    InfoMessage "Configuring suricata.yaml for Windows..."
    $content = Get-Content $yamlPath -Raw

    $content = $content -replace 'HOME_NET:.*', 'HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"'
    $content = $content -replace 'EXTERNAL_NET:.*', 'EXTERNAL_NET: "any"'

    $content = $content -replace '(?s)rule-files:.*?(default-rule-path:|$)', @'
rule-files:
  - emerging.rules
default-rule-path: C:\Program Files\Suricata\rules
'@

    Set-Content -Path $yamlPath -Value $content -Encoding UTF8
    SuccessMessage "suricata.yaml updated."
}

function Get-PrimaryAdapter {
    InfoMessage "Detecting primary network adapter using default route..."

    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                    Sort-Object RouteMetric |
                    Select-Object -First 1

    if (-not $defaultRoute) {
        ErrorMessage "No default IPv4 route found. Falling back to first Up adapter."
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
        if ($adapter) {
            return "\Device\NPF_$($adapter.InterfaceGuid)"
        }
        return $null
    }

    $adapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue

    if ($adapter -and $adapter.Status -eq 'Up') {
        InfoMessage "Using primary adapter: $($adapter.Name) - $($adapter.InterfaceDescription)"
        return "\Device\NPF_$($adapter.InterfaceGuid)"
    }

    ErrorMessage "Default route adapter is not available."
    return $null
}

function Register-SuricataScheduledTask {
    $adapterName = Get-PrimaryAdapter
    if (-not $adapterName) {
        ErrorMessage "No suitable network adapter found."
        return
    }

    InfoMessage "Using adapter: $adapterName"

    $exePath = $global:Config.SuricataExePath
    $arguments = "-c `"$($global:Config.SuricataConfigPath)`" -i `"$adapterName`" -l `"C:\Program Files\Suricata\log`""

    $action = New-ScheduledTaskAction -Execute $exePath -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    if (Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $global:Config.TaskName -Confirm:$false
    }

    Register-ScheduledTask -TaskName $global:Config.TaskName `
                           -Action $action `
                           -Trigger $trigger `
                           -Settings $settings `
                           -User "SYSTEM" `
                           -RunLevel Highest | Out-Null

    SuccessMessage "Suricata registered to run at startup."
}

# ====================== MAIN EXECUTION ======================

function Install-Suricata {
    try {
        InfoMessage "=== Starting Suricata Installation ==="

        InfoMessage "=== Installing Npcap ==="
        Install-NpcapSoftware

        InfoMessage "=== Installing Suricata ==="
        Install-SuricataSoftware

        InfoMessage "=== Updating Environment Variables ==="
        Update-EnvironmentVariables

        InfoMessage "=== Configuring Suricata Yaml ==="
        Configure-SuricataYaml

        InfoMessage "=== Running Suricata Rules Update ==="
        Run-SuricataUpdate

        # Clean up temporary files.
        try {
            Remove-Item -Path $global:Config.TempDir -Recurse -Force -ErrorAction Stop
            InfoMessage "Cleaned up temporary directory: $($global:Config.TempDir)"
        } catch {
            WarnMessage "Could not clean up temporary directory: $($global:Config.TempDir). $_"
        }

        InfoMessage "=== Registering Suricata Scheduled Task ==="
        Register-SuricataScheduledTask

        SuccessMessage "=== Installation Completed Successfully! ==="
    } catch {
        ErrorMessage "Installation failed: $($_.Exception.Message)"
        exit 1
    }
}

# Validate that Suricata has been installed and configured correctly.
function Validate-Installation {
    try {
        InfoMessage "=== Validating Suricata installation ==="
        $validationFailed = $false

        # Validate the Suricata configuration file
        if (Test-Path $global:Config.SuricataConfigPath) {
            SuccessMessage "Suricata configuration file exists: $($global:Config.SuricataConfigPath)"
        }
        else {
            ErrorMessage "Suricata configuration file is missing: $($global:Config.SuricataConfigPath)"
            $validationFailed = $true
        }

        # Check Npcap / wpcap.dll presence before running suricata.exe to avoid Windows System Error popup
        $wpcapDll1 = Join-Path $env:SystemRoot "System32\wpcap.dll"
        $wpcapDll2 = Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll"
        $hasWpcap = (Test-Path $wpcapDll1) -or (Test-Path $wpcapDll2) -or (Test-Path $global:Config.NpcapPath)

        if (-not $hasWpcap) {
            ErrorMessage "Npcap (wpcap.dll) is missing. Suricata requires Npcap driver to run."
            ErrorMessage "Please run Npcap installer and ensure WinPcap API compatibility is selected."
            $validationFailed = $true
        }

        # Validate the Suricata executable exists and can run
        if (Test-Path $global:Config.SuricataExePath) {
            if ($hasWpcap) {
                $versionOutput = $null
                try {
                    $versionOutput = & $global:Config.SuricataExePath --version 2>$null | Select-Object -First 1
                    if (-not $versionOutput) {
                        $versionOutput = & $global:Config.SuricataExePath -V 2>$null | Select-Object -First 1
                    }
                } catch {
                    $versionOutput = $null
                }

                if ($versionOutput) {
                    SuccessMessage "Suricata version installed: $versionOutput"
                    SuccessMessage "Suricata executable validated at: $($global:Config.SuricataExePath)"
                } else {
                    ErrorMessage "Suricata executable exists but version check failed: $($global:Config.SuricataExePath)"
                    $validationFailed = $true
                }
            } else {
                ErrorMessage "Skipping suricata.exe execution check because Npcap (wpcap.dll) is not installed."
            }
        }
        else {
            ErrorMessage "Suricata executable not found at: $($global:Config.SuricataExePath)"
            $validationFailed = $true
        }

        # Validate rules presence (at least one .rules file)
        if (Test-Path $global:Config.RulesDir) {
            $rulesFiles = Get-ChildItem -Path $global:Config.RulesDir -Filter "*.rules" -File -ErrorAction SilentlyContinue
            if ($rulesFiles -and $rulesFiles.Count -gt 0) {
                SuccessMessage "Suricata rules present in: $($global:Config.RulesDir)"
            } else {
                WarnMessage "Rules directory exists but no .rules files found: $($global:Config.RulesDir)"
                $validationFailed = $true
            }
        } else {
            ErrorMessage "Suricata rules directory is missing: $($global:Config.RulesDir)"
            $validationFailed = $true
        }

        # Validate scheduled task exists
        try {
            $task = Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue
            if ($task) {
                SuccessMessage "Scheduled task exists: $($global:Config.TaskName)"
            } else {
                WarnMessage "Scheduled task not found: $($global:Config.TaskName)"
                $validationFailed = $true
            }
        } catch {
            WarnMessage "Could not validate scheduled task: $_"
            $validationFailed = $true
        }

        if (-not $validationFailed) {
            SuccessMessage "Suricata installation and configuration validation completed successfully."
        } else {
            ErrorMessage "Suricata installation and configuration validation failed."
            exit 1
        }
    }
    catch {
        ErrorMessage "Installation validation failed: $_"
        exit 1
    }
}

# Execute the main installation and validation functions.
Install-Suricata
Validate-Installation
