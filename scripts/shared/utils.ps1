# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Logging with timestamp
function Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}

function InfoMessage {
    param ([string]$Message)
    Log -Level "[INFO]" -Message $Message -Color "White"
}

function WarnMessage {
    param ([string]$Message)
    Log -Level "[WARNING]" -Message $Message -Color "Yellow"
}

function ErrorMessage {
    param ([string]$Message)
    Log -Level "[ERROR]" -Message $Message -Color "Red"
}

function SuccessMessage {
    param ([string]$Message)
    Log -Level "[SUCCESS]" -Message $Message -Color "Green"
}

function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log -Level "[STEP]" -Message "Step ${StepNumber}: $Message" -Color "White"
}

function ErrorExit {
    param ([string]$Message)
    ErrorMessage $Message
    exit 1
}

function Ensure-Admin {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param()
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        ErrorExit "This script requires administrative privileges. Please run it as Administrator."
    }
}

function Ensure-Directory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-Not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        InfoMessage "Created directory: $Path"
    }
}

function Get-FileChecksum {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
}

function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )
    $actualHash = Get-FileChecksum -FilePath $FilePath
    if ($actualHash -ne $ExpectedHash.ToLower()) {
        ErrorMessage "Checksum verification FAILED for $FilePath!"
        ErrorMessage "  Expected: $ExpectedHash"
        ErrorMessage "  Got:      $actualHash"
        return $false
    }
    return $true
}

function Download-File {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param(
        [string]$Url,
        [string]$Destination,
        [string]$Description = "file",
        [int]$MaxRetries = 3
    )

    InfoMessage "Downloading $Description..."

    $destDir = Split-Path -Parent $Destination
    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
            SuccessMessage "$Description downloaded successfully"
            return
        } catch {
            $attempt++
            if ($attempt -lt $MaxRetries) {
                WarnMessage "Download failed, retrying ($attempt/$MaxRetries)..."
                Start-Sleep -Seconds 2
            }
        }
    }

    ErrorExit "Failed to download $Description from $Url after $MaxRetries attempts"
}

function Download-And-VerifyFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    param(
        [string]$Url,
        [string]$Destination,
        [string]$ChecksumPattern,
        [string]$FileName = "Unknown file",
        [string]$ChecksumFile = $script:ChecksumsPath,
        [string]$ChecksumUrl = $null
    )

    Download-File -Url $Url -Destination $Destination -Description $FileName

    # If a direct checksum URL is provided, download it and use it as the source of truth
    if (-not [string]::IsNullOrWhiteSpace($ChecksumUrl)) {
        $tempChecksumFile = Join-Path ([System.IO.Path]::GetTempPath()) "checksums-$([System.Guid]::NewGuid().ToString()).sha256"
        Download-File -Url $ChecksumUrl -Destination $tempChecksumFile -Description "checksum file"
        $ChecksumFile = $tempChecksumFile
    }

    if (-not [string]::IsNullOrWhiteSpace($ChecksumFile) -and (Test-Path -Path $ChecksumFile)) {
        $expectedHash = (Select-String -Path $ChecksumFile -Pattern $ChecksumPattern).Line.Split(" ")[0].Trim()
        if (-not [string]::IsNullOrWhiteSpace($expectedHash)) {
            if (-not (Test-Checksum -FilePath $Destination -ExpectedHash $expectedHash)) {
                ErrorExit "$FileName checksum verification failed"
            }
            InfoMessage "$FileName checksum verification passed."
        } else {
            ErrorExit "No checksum found for $FileName in $ChecksumFile using pattern $ChecksumPattern"
        }

        # Cleanup temporary checksum file if it was downloaded from a URL
        if (-not [string]::IsNullOrWhiteSpace($ChecksumUrl) -and (Test-Path -Path $ChecksumFile)) {
            Remove-Item -Path $ChecksumFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        ErrorExit "Checksum file not found at $ChecksumFile, cannot verify $FileName"
    }

    SuccessMessage "$FileName downloaded and verified successfully."
    return $true
}

function Remove-SystemPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
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

# ---------------------------------------------------------------------------
# Shared Suricata installation helpers used by both install.ps1 and
# install-suricata-silent.ps1. They rely on $script:Config, which the calling
# installer script populates before dot-sourcing this module.
# ---------------------------------------------------------------------------

# Validate that the Suricata configuration file exists.
function Test-SuricataConfigFile {
    if (Test-Path $script:Config.SuricataConfigPath) {
        SuccessMessage "Suricata configuration file exists: $($script:Config.SuricataConfigPath)"
        return $true
    }
    ErrorMessage "Suricata configuration file is missing: $($script:Config.SuricataConfigPath)"
    return $false
}

# Validate that the Suricata executable exists and can run.
function Test-SuricataExecutable {
    if (-not (Test-Path $script:Config.SuricataExePath)) {
        ErrorMessage "Suricata executable not found at: $($script:Config.SuricataExePath)"
        return $false
    }

    # Check Npcap / wpcap.dll presence before running suricata.exe to avoid Windows System Error popup
    $wpcapDll1 = Join-Path $env:SystemRoot "System32\wpcap.dll"
    $wpcapDll2 = Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll"
    $hasWpcap = (Test-Path $wpcapDll1) -or (Test-Path $wpcapDll2) -or (Test-Path $script:Config.NpcapPath)

    if (-not $hasWpcap) {
        ErrorMessage "Npcap (wpcap.dll) is missing. Suricata requires Npcap driver to run."
        ErrorMessage "Please run Npcap installer and ensure WinPcap API compatibility is selected."
        return $false
    }

    $versionOutput = $null
    try {
        $versionOutput = & $script:Config.SuricataExePath --version 2>$null | Select-Object -First 1
        if (-not $versionOutput) {
            $versionOutput = & $script:Config.SuricataExePath -V 2>$null | Select-Object -First 1
        }
    } catch {
        $versionOutput = $null
    }

    if ($versionOutput) {
        SuccessMessage "Suricata version installed: $versionOutput"
        SuccessMessage "Suricata executable validated at: $($script:Config.SuricataExePath)"
        return $true
    }
    ErrorMessage "Suricata executable exists but version check failed: $($script:Config.SuricataExePath)"
    ErrorMessage "This usually indicates that Npcap is not correctly installed or drivers are not running."
    return $false
}

# Validate that at least one .rules file is present.
function Test-SuricataRule {
    if (-not (Test-Path $script:Config.RulesDir)) {
        ErrorMessage "Suricata rules directory is missing: $($script:Config.RulesDir)"
        return $false
    }

    $rulesFiles = Get-ChildItem -Path $script:Config.RulesDir -Filter "*.rules" -File -ErrorAction SilentlyContinue
    if ($rulesFiles -and @($rulesFiles).Count -gt 0) {
        SuccessMessage "Suricata rules present in: $($script:Config.RulesDir)"
        return $true
    }
    WarnMessage "Rules directory exists but no .rules files found: $($script:Config.RulesDir)"
    return $false
}

# Validate that the scheduled task exists.
function Test-SuricataScheduledTask {
    try {
        $task = Get-ScheduledTask -TaskName $script:Config.TaskName -ErrorAction SilentlyContinue
        if ($task) {
            SuccessMessage "Scheduled task exists: $($script:Config.TaskName)"
            return $true
        }
        WarnMessage "Scheduled task not found: $($script:Config.TaskName)"
        return $false
    } catch {
        WarnMessage "Could not validate scheduled task: $_"
        return $false
    }
}

# Validate that Suricata has been installed and configured correctly.
function Test-Installation {
    try {
        InfoMessage "=== Validating Suricata installation ==="
        $validationFailed = $false

        # Validate each aspect independently so all failures are reported.
        $checks = @(
            (Test-SuricataConfigFile),
            (Test-SuricataExecutable),
            (Test-SuricataRule),
            (Test-SuricataScheduledTask)
        )
        $validationFailed = $checks -contains $false

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

# Update the machine PATH to include Suricata and Npcap directories.
function Update-EnvironmentVariable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param()
    $envPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $npcapSys32 = Join-Path $env:SystemRoot "System32\Npcap"

    $pathsToAdd = @($script:Config.SuricataDir, $script:Config.NpcapPath, $npcapSys32)
    $newPath = $envPath

    foreach ($p in $pathsToAdd) {
        if ($newPath -notlike "*$p*") {
            $newPath = "$newPath;$p"
        }
    }

    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path = "$env:Path;$($script:Config.SuricataDir);$($script:Config.NpcapPath);$npcapSys32"
    InfoMessage "Environment PATH updated with Suricata and Npcap directories."
}
