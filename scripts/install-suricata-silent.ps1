# Optimized Suricata Installation Script for Silent Windows Server Environments
# This version replaces manual Npcap installation with automated installation
# Based on the original wazuh-suricata v0.1.4 script with improvements


#Requires -RunAsAdministrator


# Global configuration
$global:Config = @{
    TempDir            = "C:\Temp"
    SuricataInstallerUrl  = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.10-1-64bit.msi"
    SuricataInstallerPath = "C:\Temp\Suricata_Installer.msi"
    SuricataDir       = "C:\Program Files\Suricata"
    SuricataExePath       = "C:\Program Files\Suricata\suricata.exe"
    NpcapPath          = "C:\Program Files\Npcap"
    RulesDir           = "C:\Program Files\Suricata\rules"
    SuricataConfigPath    = "C:\Program Files\Suricata\suricata.yaml"
    LocalRulesUrl      = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules"
    SuricataLogDir        = "C:\Program Files\Suricata\log"
    TaskName           = "SuricataStartup"
}


# Function to handle logging
function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"  # Default color
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


function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log "[STEP]" "Step ${StepNumber}: $Message" "White"
}


# Helper: Create a directory if it doesn't exist.
function Ensure-Directory {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-Not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        InfoMessage "Created directory: $Path"
    }
}


# Helper: Download a file from a URL.
function Download-File {
    param (
        [Parameter(Mandatory)]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    try {
        # Set TLS protocols for download (Windows Server 2022 compatibility)
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -Headers @{"User-Agent"="Mozilla/5.0"} -ErrorAction Stop
        InfoMessage "Downloaded file from $Url to $OutputPath"
    }
    catch {
        ErrorMessage "Failed to download file from $Url. $_"
    }
}


# Install Suricata (only run once)
function Install-SuricataSoftware {
    $installerPath = $global:Config.SuricataInstallerPath
    $arguments = "/i `"$installerPath`" /quiet /norestart"  # OPTIMIZED: Added silent installation flags


    if (Test-Path $global:Config.SuricataExePath) {
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
            Download-File -Url $global:Config.SuricataInstallerUrl -OutputPath $installerPath
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
    if (Test-Path $global:Config.NpcapPath) {
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
            if (Test-Path $global:Config.NpcapPath) {
                SuccessMessage "Npcap installed successfully via automated script"
            } else {
                ErrorMessage "Npcap installation failed - directory not found"
            }
        } catch {
            ErrorMessage "Failed to run automated Npcap installation: $_"
        }
    } else {
        InfoMessage "Local script not found, downloading optimized Npcap installation script..."
        $tempNpcapScript = Join-Path -Path $global:Config.TempDir -ChildPath "install-npcap-automated.ps1"
        
        try {
            # Download our optimized script from the same repository
            $scriptUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-server/feature/silent-windows-server-scripts/scripts/install-npcap-automated.ps1"
            Download-File -Url $scriptUrl -OutputPath $tempNpcapScript
            
            InfoMessage "Running automated Npcap installation..."
            & $tempNpcapScript
            
            if (Test-Path $global:Config.NpcapPath) {
                SuccessMessage "Npcap installed successfully via automated script"
            } else {
                ErrorMessage "Npcap installation failed - directory not found"
            }
            
            # Cleanup
            if (Test-Path $tempNpcapScript) {
                Remove-Item $tempNpcapScript -Force
            }
        } catch {
            ErrorMessage "Failed to download or run automated Npcap installation: $_"
            
            # Fallback to original method with warning
            WarnMessage "Falling back to manual installation method..."
            InfoMessage "Installing Npcap manually - GUI interaction may be required..."
            
            $npcapInstallerPath = Join-Path -Path $global:Config.TempDir -ChildPath "npcap-1.79.exe"
            Download-File -Url "https://npcap.com/dist/npcap-1.79.exe" -OutputPath $npcapInstallerPath
            
            if (Test-Path $npcapInstallerPath) {
                Start-Process -FilePath $npcapInstallerPath -Wait
                WarnMessage "Please complete the Npcap installation manually if a GUI appeared"
            }
        }
    }
}


# Update environment variables to include Suricata and Npcap directories.
function Update-EnvironmentVariables {
    $envPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = "$envPath;$($global:Config.SuricataDir);$($global:Config.NpcapPath)"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    InfoMessage "Environment PATH updated with Suricata and Npcap directories."
}


# Update local.rules file.
function Update-RulesFile {
    $zipUrl = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.zip"
    $zipPath = Join-Path -Path $global:Config.TempDir -ChildPath "emerging.rules.zip"
    $extractPath = $global:Config.SuricataDir


    try {
        Download-File -Url $zipUrl -OutputPath $zipPath
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
    $exePath   = $global:Config.SuricataExePath
    $cfgPath   = $global:Config.SuricataConfigPath
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


    if ( Get-ScheduledTask -TaskName $global:Config.TaskName -ErrorAction SilentlyContinue ) {
        Unregister-ScheduledTask -TaskName $global:Config.TaskName -Confirm:$false
        WarnMessage "Scheduled Task already exists; unregistering so we can update it."
    }


    Register-ScheduledTask -TaskName  $global:Config.TaskName `
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
        Ensure-Directory -Path $global:Config.TempDir


        InfoMessage "=== Installing Npcap (Automated) ===" 
        Install-NpcapSoftware


        InfoMessage "=== Installing Suricata (Silent) ==="
        Install-SuricataSoftware


        InfoMessage "=== Updating Environment Variables ==="
        Update-EnvironmentVariables


        InfoMessage "=== Updating local.rules file ==="
        Update-RulesFile


        InfoMessage "=== Registering Scheduled Task ==="
        Register-SuricataScheduledTask


        # Clean up temporary files.
        try {
            Remove-Item -Path $global:Config.TempDir -Recurse -Force -ErrorAction Stop
            InfoMessage "Cleaned up temporary directory: $($global:Config.TempDir)"
        } catch {
            WarnMessage "Could not clean up temporary directory: $($global:Config.TempDir). $_"
        }


        SuccessMessage "OPTIMIZED Suricata installation and configuration completed successfully!"
        InfoMessage "Suricata is now configured to run automatically at startup"
    } catch {
        ErrorMessage "Installation failed: $_"
        exit 1
    }
}


# Execute the main installation function.
Install-Suricata
