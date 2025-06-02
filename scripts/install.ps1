# Global configuration
$global:Config = @{
    TempDir            = "C:\Temp"
    SuricataInstallerUrl  = "https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.10-1-64bit.msi"
    SuricataInstallerPath = "C:\Temp\Suricata_Installer.msi"
    NpcapInstallerUrl  = "https://npcap.com/dist/npcap-1.79.exe"
    NpcapInstallerPath = "C:\Temp\Npcap_Installer.exe"
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
    $arguments = "/i `"$installerPath`""

    if (Test-Path $global:Config.SuricataExePath) {
        WarnMessage "Suricata is already installed. Skipping installation."
    }
    else {
        if (Test-Path $installerPath) {
            InfoMessage "Installing Suricata..."
            Start-Process msiexec.exe -ArgumentList $arguments -Wait
        }
        else {
            InfoMessage "Downloading Suricata installer..."
            Download-File -Url $global:Config.SuricataInstallerUrl -OutputPath $installerPath
            InfoMessage "Installing Suricata..."
            Start-Process msiexec.exe -ArgumentList $arguments -Wait
        }
    }
}

# Install Npcap (only run once)
function Install-NpcapSoftware {
    if (Test-Path $global:Config.NpcapPath) {
        WarnMessage "Npcap is already installed. Skipping installation."
    }
    else {
        if (Test-Path $global:Config.NpcapInstallerPath) {
            InfoMessage "Installing Npcap..."
            Start-Process -FilePath $global:Config.NpcapInstallerPath -Wait
            InfoMessage "Please follow the on-screen instructions to complete the Npcap installation."
        }
        else {
            InfoMessage "Downloading Npcap installer..."
            Download-File -Url $global:Config.NpcapInstallerUrl -OutputPath $global:Config.NpcapInstallerPath
            InfoMessage "Installing Npcap..."
            Start-Process -FilePath $global:Config.NpcapInstallerPath -Wait
            InfoMessage "Please follow the on-screen instructions to complete the Npcap installation."
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

    InfoMessage "Registered Suricata to run at startup as SYSTEM."
}



# Main function that runs the installation and configuration steps.
function Install-Suricata {
    try {
        # Ensure the temporary directory exists.
        Ensure-Directory -Path $global:Config.TempDir

        InfoMessage "=== Installing Npcap ==="
        Install-NpcapSoftware

        InfoMessage "=== Installing Suricata ==="
        Install-SuricataSoftware

        InfoMessage "=== Updating Environment Variables ==="
        Update-EnvironmentVariables

        InfoMessage "=== Updating local.rules file ==="
        Update-RulesFile

        # Clean up temporary files.
        try {
            Remove-Item -Path $global:Config.TempDir -Recurse -Force -ErrorAction Stop
            InfoMessage "Cleaned up temporary directory: $($global:Config.TempDir)"
        } catch {
            WarnMessage "Could not clean up temporary directory: $($global:Config.TempDir). $_"
        }
        InfoMessage "=== Registering Scheduled Task ==="
        Register-SuricataScheduledTask

        SuccessMessage "Installation and configuration completed!"
    } catch {
        ErrorMessage "Installation failed: $_"
        exit 1
    }
}

# Execute the main installation function.
Install-Suricata
