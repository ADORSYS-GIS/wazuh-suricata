# Automated Npcap Installation using SendKeys
# This script uses keyboard automation to interact with the Npcap installer
# Designed for headless Windows Server environments where GUI interaction is required

# Requires Administrator privileges
#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms

# Global configuration
$global:NpcapConfig = @{
    TempDir = "C:\Temp"
    InstallerUrl = "https://npcap.com/dist/npcap-1.79.exe"
    InstallerPath = "C:\Temp\npcap-1.79.exe"
    InstallPath = "C:\Program Files\Npcap"
    MaxWaitTime = 45  # Maximum wait time in seconds (reduced from 120)
}

# Logging functions with colors
function Log {
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

# Helper function to send keyboard input with delay
function Send-KeysToWindow {
    param(
        [string]$Keys, 
        [int]$DelayMs = 500
    )
    Start-Sleep -Milliseconds $DelayMs
    try {
        [System.Windows.Forms.SendKeys]::SendWait($Keys)
        InfoMessage "Sent keys: $Keys"
    }
    catch {
        WarnMessage "Failed to send keys: $Keys - $_"
    }
}

# Ensure temp directory exists
function Ensure-TempDirectory {
    if (-not (Test-Path $global:NpcapConfig.TempDir)) {
        New-Item -ItemType Directory -Path $global:NpcapConfig.TempDir -Force | Out-Null
        InfoMessage "Created temp directory: $($global:NpcapConfig.TempDir)"
    }
}

# Download Npcap installer
function Download-NpcapInstaller {
    $installerPath = $global:NpcapConfig.InstallerPath
    
    if (Test-Path $installerPath) {
        InfoMessage "Npcap installer already exists at $installerPath"
        return $installerPath
    }
    
    InfoMessage "Downloading Npcap installer from $($global:NpcapConfig.InstallerUrl)..."
    try {
        Invoke-WebRequest -Uri $global:NpcapConfig.InstallerUrl -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
        
        if (Test-Path $installerPath) {
            SuccessMessage "Npcap installer downloaded successfully"
            return $installerPath
        } else {
            ErrorMessage "Failed to download Npcap installer"
            return $null
        }
    } catch {
        ErrorMessage "Failed to download Npcap installer: $($_.Exception.Message)"
        return $null
    }
}

# Check if Npcap is functionally installed and working
function Test-NpcapInstalled {
    InfoMessage "Checking Npcap installation status..."
    
    # PRIORITY 1: Check if Npcap drivers are running (most important)
    $driversRunning = $false
    $drivers = Get-WmiObject Win32_SystemDriver -Filter "Name LIKE 'npf%' OR Name LIKE 'npcap%'" -ErrorAction SilentlyContinue
    
    if ($drivers) {
        $runningDrivers = $drivers | Where-Object { $_.State -eq "Running" }
        $driversRunning = ($runningDrivers.Count -gt 0)
        InfoMessage "Found $($drivers.Count) Npcap driver(s), $($runningDrivers.Count) running"
        
        if ($driversRunning) {
            InfoMessage "✓ Npcap drivers are running - this is the key indicator"
        } else {
            WarnMessage "✗ Npcap drivers exist but are not running"
        }
    } else {
        InfoMessage "✗ No Npcap drivers found"
    }
    
    # PRIORITY 2: Check essential files (secondary validation)
    $hasEssentialFiles = $false
    if (Test-Path $global:NpcapConfig.InstallPath) {
        $essentialFiles = @(
            "npcap.sys",     # Most critical - the driver
            "NPFInstall.exe", # Installer
            "npcap.inf"      # Driver info
        )
        
        $foundFiles = 0
        $missingFiles = @()
        foreach ($file in $essentialFiles) {
            $filePath = Join-Path $global:NpcapConfig.InstallPath $file
            if (Test-Path $filePath) {
                $foundFiles++
            } else {
                $missingFiles += $file
            }
        }
        
        $hasEssentialFiles = ($foundFiles -eq $essentialFiles.Count)
        InfoMessage "Essential files: $foundFiles/$($essentialFiles.Count) found"
        
        if ($missingFiles.Count -gt 0) {
            WarnMessage "Missing essential files: $($missingFiles -join ', ')"
        }
        
        # Check if directory only contains install.log (failed installation indicator)
        $allFiles = Get-ChildItem $global:NpcapConfig.InstallPath -ErrorAction SilentlyContinue
        if ($allFiles.Count -le 2 -and ($allFiles | Where-Object { $_.Name -like "*install.log*" })) {
            WarnMessage "Directory contains only install logs - indicates failed installation"
            $hasEssentialFiles = $false
        }
    } else {
        InfoMessage "Npcap installation directory not found"
    }
    
    # PRIORITY 3: Registry check (tertiary validation)
    $hasRegistry = $false
    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($regPath in $registryPaths) {
        $npcapEntry = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | 
                      Where-Object { $_.DisplayName -like "*npcap*" }
        if ($npcapEntry) {
            $hasRegistry = $true
            InfoMessage "✓ Registry entry found: $($npcapEntry.DisplayName)"
            break
        }
    }
    
    # DECISION LOGIC: Prioritize functional checks
    if ($driversRunning -and $hasEssentialFiles) {
        SuccessMessage "✓ Npcap is fully functional (drivers running + files present)"
        InfoMessage "Installation status summary:"
        InfoMessage "  - Drivers Running: ✓"
        InfoMessage "  - Essential Files: ✓" 
        InfoMessage "  - Registry Entry: $(if ($hasRegistry) { '✓' } else { '✗' })"
        return $true
    } 
    elseif ($driversRunning -and -not $hasEssentialFiles) {
        WarnMessage "⚠ Drivers running but files missing - unusual state"
        InfoMessage "Will reinstall to ensure complete installation"
        return $false
    }
    elseif (-not $driversRunning -and $hasEssentialFiles) {
        WarnMessage "⚠ Files present but drivers not running - installation incomplete"
        InfoMessage "Will clean up and reinstall"
        return $false
    }
    else {
        InfoMessage "✗ Npcap not functionally installed"
        InfoMessage "Installation status summary:"
        InfoMessage "  - Drivers Running: ✗"
        InfoMessage "  - Essential Files: ✗"
        InfoMessage "  - Registry Entry: $(if ($hasRegistry) { '✓' } else { '✗' })"
        return $false
    }
}

# Remove partial Npcap installation
function Remove-PartialNpcapInstallation {
    WarnMessage "Cleaning up partial Npcap installation..."
    
    # Stop and remove drivers
    $drivers = Get-WmiObject Win32_SystemDriver -Filter "Name LIKE 'npf%' OR Name LIKE 'npcap%'" -ErrorAction SilentlyContinue
    foreach ($driver in $drivers) {
        try {
            if ($driver.State -eq "Running") {
                $driver.StopService()
                WarnMessage "Stopped driver: $($driver.Name)"
            }
        } catch {
            WarnMessage "Could not stop driver: $($driver.Name) - $($_.Exception.Message)"
        }
    }
    
    # Remove installation directory if exists
    if (Test-Path $global:NpcapConfig.InstallPath) {
        try {
            Remove-Item $global:NpcapConfig.InstallPath -Recurse -Force -ErrorAction Stop
            InfoMessage "Removed partial installation directory"
        } catch {
            WarnMessage "Could not remove installation directory: $($_.Exception.Message)"
        }
    }
}

# Comprehensive installation verification
function Verify-NpcapInstallation {
    InfoMessage "Performing comprehensive Npcap installation verification..."
    
    $checks = @{
        "Installation Directory" = Test-Path $global:NpcapConfig.InstallPath
        "Sufficient Files" = if (Test-Path $global:NpcapConfig.InstallPath) { 
            (Get-ChildItem $global:NpcapConfig.InstallPath -ErrorAction SilentlyContinue | Measure-Object).Count -gt 5 
        } else { $false }
        "Driver Status" = $null -ne (Get-WmiObject Win32_SystemDriver -Filter "Name LIKE 'npf%' OR Name LIKE 'npcap%'" -ErrorAction SilentlyContinue)
    }
    
    $allPassed = $true
    foreach ($check in $checks.GetEnumerator()) {
        if ($check.Value) {
            SuccessMessage "[PASS] $($check.Key): OK"
        } else {
            ErrorMessage "[FAIL] $($check.Key): MISSING"
            $allPassed = $false
        }
    }
    
    return $allPassed
}

# Wait for installer processes to complete
function Wait-ForInstallerCompletion {
    InfoMessage "Waiting for Npcap installer to complete..."
    
    $waitTime = 0
    $maxWait = $global:NpcapConfig.MaxWaitTime
    
    while ($waitTime -lt $maxWait) {
        # Check for Npcap installer processes
        $installerProcesses = Get-Process | Where-Object { 
            $_.ProcessName -like "*npcap*" -or 
            $_.ProcessName -like "*setup*" -or
            $_.MainWindowTitle -like "*Npcap*"
        }
        
        if ($installerProcesses.Count -eq 0) {
            SuccessMessage "Npcap installer processes have completed"
            return $true
        }
        
        InfoMessage "Installer still running... ($($waitTime)/$($maxWait) seconds)"
        Start-Sleep -Seconds 5
        $waitTime += 5
    }
    
    WarnMessage "Timeout reached while waiting for installer completion"
    return $false
}

# Force close any remaining installer processes
function Stop-InstallerProcesses {
    $processes = Get-Process | Where-Object { 
        $_.ProcessName -like "*npcap*" -or 
        $_.ProcessName -like "*setup*"
    }
    
    foreach ($process in $processes) {
        try {
            $process.Kill()
            WarnMessage "Force closed process: $($process.ProcessName)"
        } catch {
            ErrorMessage "Could not force close process: $($process.ProcessName)"
        }
    }
}

# Perform automated Npcap installation with retry logic
function Install-NpcapAutomated {
    InfoMessage "Starting automated Npcap installation..."
    
    # Function-first detection - check if Npcap is actually working
    if (Test-NpcapInstalled) {
        SuccessMessage "Functional Npcap installation detected. Skipping installation."
        return $true
    }
    
    # If we get here, Npcap is either not installed or not working properly
    InfoMessage "Npcap is not functional - proceeding with installation"
    
    # Always clean up any existing installation (including failed ones with just logs)
    if (Test-Path $global:NpcapConfig.InstallPath) {
        WarnMessage "Removing existing Npcap installation directory..."
        Remove-PartialNpcapInstallation
    }
    
    # Ensure temp directory exists
    Ensure-TempDirectory
    
    # Download installer
    $installerPath = Download-NpcapInstaller
    if (-not $installerPath) {
        ErrorMessage "Cannot proceed without Npcap installer"
        return $false
    }
    
    InfoMessage "Starting Npcap installer with keyboard automation..."
    InfoMessage "This will automatically navigate through the installer using SendKeys"
    
    try {
        # Start the installer process
        $process = Start-Process -FilePath $installerPath -PassThru -ErrorAction Stop
        InfoMessage "Npcap installer started (PID: $($process.Id))"
        
        # Wait for installer window to appear and stabilize
        InfoMessage "Waiting for installer window to load..."
        Start-Sleep -Seconds 8
        
        # Step 1: Accept license agreement (Alt+A or Enter)
        InfoMessage "Step 1: Accepting license agreement..."
        Send-KeysToWindow -Keys "%a" -DelayMs 1000  # Alt+A for "I Agree"
        Start-Sleep -Seconds 2
        
        # Fallback: Try Enter if Alt+A doesn't work
        Send-KeysToWindow -Keys "{ENTER}" -DelayMs 1000
        Start-Sleep -Seconds 3
        
        # Step 2: Navigate through options (use default settings)
        InfoMessage "Step 2: Proceeding with default options..."
        Send-KeysToWindow -Keys "{ENTER}" -DelayMs 1000  # Next button
        Start-Sleep -Seconds 25  # Wait 25 seconds before next step
        
        # Step 3: Start installation
        InfoMessage "Step 3: Starting installation..."
        Send-KeysToWindow -Keys "{ENTER}" -DelayMs 1000  # Install button
        Start-Sleep -Seconds 10  # Wait 10 seconds before next step
        
        # Step 4: Handle any additional prompts
        InfoMessage "Step 4: Handling installation prompts..."
        Send-KeysToWindow -Keys "{ENTER}" -DelayMs 1000  # Continue/Next
        Start-Sleep -Seconds 10  # Wait 10 seconds before next step
        
        # Step 5: Complete installation
        InfoMessage "Step 5: Completing installation..."
        Send-KeysToWindow -Keys "{ENTER}" -DelayMs 1000  # Finish button
        Start-Sleep -Seconds 10  # Wait 10 seconds for completion
        
        # Wait for installation to complete
        $completed = Wait-ForInstallerCompletion
        
        if (-not $completed) {
            WarnMessage "Installation may not have completed properly. Forcing cleanup..."
            Stop-InstallerProcesses
        }
        
        # Enhanced verification with comprehensive checks
        InfoMessage "Waiting for installation to complete..."
        Start-Sleep -Seconds 10  # Allow more time for files to be written
        
        if (Verify-NpcapInstallation) {
            SuccessMessage "Npcap installation completed and verified successfully!"
            
            # Additional driver status info
            $drivers = Get-WmiObject Win32_SystemDriver -Filter "Name LIKE 'npf%' OR Name LIKE 'npcap%'" -ErrorAction SilentlyContinue
            if ($drivers) {
                SuccessMessage "Npcap drivers are loaded and running!"
                $drivers | ForEach-Object { 
                    InfoMessage "  - Driver: $($_.Name) - Status: $($_.State)" 
                }
            }
            
            return $true
        } else {
            ErrorMessage "Npcap installation verification failed!"
            return $false
        }
        
    } catch {
        ErrorMessage "Failed to start Npcap installer: $($_.Exception.Message)"
        return $false
    } finally {
        # Cleanup installer file
        if (Test-Path $installerPath) {
            try {
                Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
                InfoMessage "Cleaned up installer file"
            } catch {
                WarnMessage "Could not remove installer file: $installerPath"
            }
        }
    }
}

# Install Npcap with retry logic
function Install-NpcapWithRetry {
    $maxRetries = 2
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        InfoMessage "Installation attempt $attempt of $maxRetries"
        
        if (Install-NpcapAutomated) {
            return $true
        }
        
        if ($attempt -lt $maxRetries) {
            WarnMessage "Installation failed. Cleaning up and retrying..."
            Remove-PartialNpcapInstallation
            Start-Sleep -Seconds 10
        }
    }
    
    ErrorMessage "All installation attempts failed"
    return $false
}

# Main execution
function Main {
    InfoMessage "=== Automated Npcap Installation Script ==="
    InfoMessage "This script will install Npcap using keyboard automation"
    InfoMessage "Designed for headless Windows Server environments with enhanced detection"
    
    try {
        $result = Install-NpcapWithRetry
        
        if ($result) {
            SuccessMessage "Npcap installation process completed successfully!"
            InfoMessage "Npcap is now ready for use with Suricata and other network monitoring tools"
            exit 0
        } else {
            ErrorMessage "Npcap installation failed after all retry attempts!"
            exit 1
        }
    } catch {
        ErrorMessage "Script execution failed: $($($_.Exception.Message))"
        exit 1
    }
}

# Execute main function if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    Main
}
