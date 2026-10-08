# Optimized Suricata Installation Script for Silent Windows Server Environments
# This version replaces manual Npcap installation with automated installation
# Based on the original wazuh-suricata v0.1.4 script with improvements


#Requires -RunAsAdministrator


# Repository configuration
$WAZUH_SURICATA_REPO_REF = if ($env:WAZUH_SURICATA_REPO_REF) { $env:WAZUH_SURICATA_REPO_REF } else { "v0.2.2" }
$WAZUH_SURICATA_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/$WAZUH_SURICATA_REPO_REF"

$TEMP_DIR = Join-Path $env:TEMP "wazuh-suricata-install"
if (-not (Test-Path $TEMP_DIR)) {
    New-Item -Path $TEMP_DIR -ItemType Directory | Out-Null
}

try {
    $ChecksumsURL = "$WAZUH_SURICATA_REPO_URL/checksums.sha256"
    $UtilsURL = "$WAZUH_SURICATA_REPO_URL/scripts/shared/utils.ps1"

    $script:ChecksumsPath = Join-Path $TEMP_DIR "checksums.sha256"
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

# Set global checksums path for Download-And-VerifyFile
$script:ChecksumsPath = $script:ChecksumsPath

# Default version configuration
$SURICATA_VERSION = if ($env:SURICATA_VERSION) { $env:SURICATA_VERSION } else { "7.0.10-1" }
$RULES_VERSION = if ($env:RULES_VERSION) { $env:RULES_VERSION } else { "7.0.3" }

# Global configuration
$script:Config = @{
    TempDir                 = $TEMP_DIR
    SuricataInstallerUrl    = "https://www.openinfosecfoundation.org/download/windows/Suricata-$SURICATA_VERSION-64bit.msi"
    SuricataInstallerPath   = Join-Path $TEMP_DIR "Suricata_Installer.msi"
    SuricataDir             = "C:\Program Files\Suricata"
    SuricataExePath         = "C:\Program Files\Suricata\suricata.exe"
    NpcapPath               = "C:\Program Files\Npcap"
    RulesDir                = "C:\Program Files\Suricata\rules"
    SuricataConfigPath      = "C:\Program Files\Suricata\suricata.yaml"
    SuricataLogDir          = "C:\Program Files\Suricata\log"
    TaskName                = "SuricataStartup"
}


# Install Suricata (only run once)
function Install-SuricataSoftware {
    $installerPath = $script:Config.SuricataInstallerPath
    $arguments = "/i `"$installerPath`" /quiet /norestart"  # OPTIMIZED: Added silent installation flags


    if (Test-Path $script:Config.SuricataExePath) {
        WarnMessage "Suricata is already installed. Skipping installation."
    }
    else {
        if (Test-Path $installerPath) {
            InfoMessage "Installing Suricata silently..."
            $process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                SuccessMessage "Suricata installed successfully"
            } else {
                ErrorMessage "Suricata installation failed with exit code: $($process.ExitCode)"
            }
        }
        else {
            InfoMessage "Downloading Suricata installer..."
            Download-File -Url $script:Config.SuricataInstallerUrl -Destination $installerPath -Description "Suricata Installer"
            InfoMessage "Installing Suricata silently..."
            $process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                SuccessMessage "Suricata installed successfully"
            } else {
                ErrorMessage "Suricata installation failed with exit code: $($process.ExitCode)"
            }
        }
    }
}


# OPTIMIZED: Install Npcap using our automated script instead of manual GUI
function Install-NpcapSoftware {
    if (Test-Path $script:Config.NpcapPath) {
        WarnMessage "Npcap is already installed. Skipping installation."
        return
    }


    InfoMessage "Installing Npcap using AUTOMATED installation (no GUI interaction required)..."

    # Get the path to our optimized Npcap installation script
    $npcapScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "install-npcap-automated.ps1"

    if (Test-Path $npcapScriptPath) {
        InfoMessage "Using local optimized Npcap installation script..."
        try {
            & $npcapScriptPath
            if (Test-Path $script:Config.NpcapPath) {
                SuccessMessage "Npcap installed successfully via automated script"
                return  # Added return to avoid falling through to manual fallback
            } else {
                ErrorExit "Npcap installation failed - directory not found. Suricata cannot function without Npcap."
            }
        } catch {
            ErrorExit "Failed to run automated Npcap installation: $_"
        }
    } else {
        InfoMessage "Local script not found, downloading optimized Npcap installation script..."
        $tempNpcapScript = Join-Path -Path $script:Config.TempDir -ChildPath "install-npcap-automated.ps1"

        try {
            # Download our optimized script from the same repository
            $scriptUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/$WAZUH_SURICATA_REPO_REF/scripts/windows/install-npcap-automated.ps1"
            Download-And-VerifyFile -Url $scriptUrl -Destination $tempNpcapScript -ChecksumPattern "scripts/windows/install-npcap-automated.ps1" -FileName "install-npcap-automated.ps1" -ChecksumUrl $WAZUH_SURICATA_REPO_URL/checksums.sha256

            InfoMessage "Running automated Npcap installation..."
            & $tempNpcapScript

            if (Test-Path $script:Config.NpcapPath) {
                SuccessMessage "Npcap installed successfully via automated script"
                return  # Added return to avoid falling through to manual fallback
            } else {
                ErrorExit "Npcap installation failed - directory not found. Suricata cannot function without Npcap."
            }
        } catch {
            ErrorExit "Failed to download or run automated Npcap installation: $_"
        }

            # Fallback to original method with warning
            WarnMessage "Falling back to manual installation method..."
            InfoMessage "Installing Npcap manually - GUI interaction may be required..."

            $npcapInstallerPath = Join-Path -Path $script:Config.TempDir -ChildPath "npcap-1.79.exe"
            Download-File -Url "https://npcap.com/dist/npcap-1.79.exe" -Destination $npcapInstallerPath -Description "Npcap Installer"

            if (Test-Path $npcapInstallerPath) {
                Start-Process -FilePath $npcapInstallerPath -Wait
                WarnMessage "Please complete the Npcap installation manually if a GUI appeared"
            }
    }
}


# Update local.rules file.
function Update-RulesFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param()
    $zipUrl = "https://rules.emergingthreats.net/open/suricata-$RULES_VERSION/emerging.rules.zip"
    $zipPath = Join-Path -Path $script:Config.TempDir -ChildPath "emerging.rules.zip"
    $extractPath = $script:Config.SuricataDir


    try {
        Download-File -Url $zipUrl -Destination $zipPath -Description "Emerging Threats Rules"
        if (Test-Path $zipPath) {
            Ensure-Directory -Path $extractPath
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
            SuccessMessage "Suricata rules updated successfully"
        } else {
            ErrorMessage "Failed to download emerging.rules.zip."
        }
    } catch {
        ErrorMessage "Failed to update rules files: $_"
    } finally {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    }
}


# Get the Network Adapter GUID.
function Get-AdapterName {
    try {
        $adapter = Get-NetAdapter | Select-Object -First 1 -ExpandProperty InterfaceGuid
        if ($adapter) {
            $adapterName = "\Device\NPF_$adapter"
            return $adapterName
        } else {
            ErrorMessage "No network adapter GUID found."
            return $null
        }
    } catch {
        ErrorMessage "Failed to get network adapter GUID: $_"
        return $null
    }
}


# Register Suricata as a scheduled task to run at startup.
function Register-SuricataScheduledTask {
    $adapterName = Get-AdapterName
    if (-not $adapterName) {
        ErrorMessage "Cannot register Suricata scheduled task without a valid adapter name."
        return
    }


    InfoMessage "Adapter Name: $adapterName"


    # Build the action in clear, separate steps:
    $exePath   = $script:Config.SuricataExePath
    $cfgPath   = $script:Config.SuricataConfigPath
    # This is the one string PowerShell sees as the arguments to suricata.exe.
    # Backtick-quote (`") around each path ensures paths with spaces are passed correctly.
    $arguments = "-c `"$cfgPath`" -i `"$adapterName`""


    $taskAction   = New-ScheduledTaskAction  -Execute $exePath    -Argument $arguments
    $taskTrigger  = New-ScheduledTaskTrigger -AtStartup
    $taskSettings = New-ScheduledTaskSettingsSet -Hidden `
                                                  -AllowStartIfOnBatteries `
                                                  -DontStopIfGoingOnBatteries `
                                                  -StartWhenAvailable `
                                                  -RunOnlyIfNetworkAvailable


    if ( Get-ScheduledTask -TaskName $script:Config.TaskName -ErrorAction SilentlyContinue ) {
        Unregister-ScheduledTask -TaskName $script:Config.TaskName -Confirm:$false
        WarnMessage "Scheduled Task already exists; unregistering so we can update it."
    }


    Register-ScheduledTask -TaskName  $script:Config.TaskName `
                           -Action    $taskAction       `
                           -Trigger   $taskTrigger      `
                           -Settings  $taskSettings     `
                           -User      "SYSTEM"          `
                           -RunLevel  Highest


    SuccessMessage "Registered Suricata to run at startup as SYSTEM."
}


# Main function that runs the installation and configuration steps.
function Install-Suricata {
    try {
        InfoMessage "=== OPTIMIZED Suricata Installation for Silent Windows Server ==="
        InfoMessage "This version uses automated Npcap installation (no GUI required)"

        # Ensure the temporary directory exists.
        Ensure-Directory -Path $script:Config.TempDir


        InfoMessage "=== Installing Npcap (Automated) ==="
        Install-NpcapSoftware


        InfoMessage "=== Installing Suricata (Silent) ==="
        Install-SuricataSoftware


        InfoMessage "=== Updating Environment Variables ==="
        Update-EnvironmentVariable


        InfoMessage "=== Updating local.rules file ==="
        Update-RulesFile


        InfoMessage "=== Registering Scheduled Task ==="
        Register-SuricataScheduledTask


        # Clean up temporary files.
        try {
            Remove-Item -Path $script:Config.TempDir -Recurse -Force -ErrorAction Stop
            InfoMessage "Cleaned up temporary directory: $($script:Config.TempDir)"
        } catch {
            WarnMessage "Could not clean up temporary directory: $($script:Config.TempDir). $_"
        }


        SuccessMessage "OPTIMIZED Suricata installation and configuration completed successfully!"
        InfoMessage "Suricata is now configured to run automatically at startup"
    } catch {
        ErrorMessage "Installation failed: $_"
        exit 1
    }
}

# Execute the main installation and validation functions.
Install-Suricata
Test-Installation