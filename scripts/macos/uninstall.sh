#!/usr/bin/env bash

#=============================================================================
# Modern Suricata Uninstallation Script for macOS
# Removes Suricata packages installed via the new package-based installation
# Handles installations in /opt/wazuh/suricata
#=============================================================================

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"
}
warn_message() {
    log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"
}
error_message() {
    log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"
}
success_message() {
    log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"
}

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# OS Detection for macOS
OS="darwin"
CONFIG_DIR="/etc/suricata"
LOG_DIR="/var/log/suricata"
RULES_DIR="/var/lib/suricata"
OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"

# Remote script URLs and temporary directory
LEGACY_UNINSTALL_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/refs/tags/v0.1.5/scripts/uninstall.sh"
TMP_DIR=$(mktemp -d)

# Cleanup function for temporary directory
cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if sudo is available or if the script is run as root
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command_exists sudo; then
            sudo "$@"
        else
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# macOS sed function
sed_inplace() {
    maybe_sudo sed -i '' "$@" 2>/dev/null || true
}

# Detect system architecture
detect_architecture() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)
            echo "amd64"
            ;;
        arm64|aarch64)
            echo "arm64"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Detect Suricata installations - check for both legacy and modern
detect_suricata_installation() {
    local has_legacy=0
    local has_modern=0
    local has_softlink=0
    
    # Check for legacy installation in /opt/suricata
    if [ -d "/opt/suricata" ]; then
        has_legacy=1
    fi
    
    # Check for modern installation in /opt/wazuh/suricata
    if [ -d "/opt/wazuh/suricata" ]; then
        has_modern=1
    fi
    
    # Check for softlink in /usr/local/bin/suricata
    if [ -L "/usr/local/bin/suricata" ] || [ -f "/usr/local/bin/suricata" ]; then
        has_softlink=1
    fi
    
    # Check for Homebrew installation
    if command_exists brew && brew list suricata >/dev/null 2>&1; then
        has_modern=1
    fi
    
    # Return result as "legacy,modern,softlink" format
    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Download and execute legacy cleanup script
run_legacy_cleanup_script() {
    local cleanup_script="$TMP_DIR/legacy-uninstall.sh"
    
    info_message "Downloading legacy uninstall script..."
    
    if ! curl -fsSL -o "$cleanup_script" "$LEGACY_UNINSTALL_URL" 2>/dev/null; then
        warn_message "Failed to download legacy uninstall script from $LEGACY_UNINSTALL_URL"
        warn_message "Attempting manual legacy cleanup..."
        
        # Fallback: Manual cleanup of legacy installation
        if [ -d "/opt/suricata" ]; then
            info_message "Removing legacy Suricata directory: /opt/suricata"
            if maybe_sudo rm -rf "/opt/suricata"; then
                success_message "Legacy directory removed successfully"
            else
                warn_message "Failed to remove legacy directory"
            fi
        fi
        
        # Remove legacy symlinks
        for link in "/usr/local/bin/suricata" "/usr/bin/suricata"; do
            if [ -L "$link" ] || [ -f "$link" ]; then
                info_message "Removing legacy symlink: $link"
                maybe_sudo rm -f "$link" 2>/dev/null || true
            fi
        done
        
        success_message "Manual legacy cleanup completed"
        return 0
    fi
    
    chmod +x "$cleanup_script"
    
    info_message "Running legacy uninstall script..."
    if bash "$cleanup_script" --silent 2>/dev/null || bash "$cleanup_script" 2>/dev/null; then
        success_message "Legacy cleanup completed successfully"
        return 0
    else
        error_message "Legacy uninstall script failed"
        return 1
    fi
}

# Restart Wazuh agent
restart_wazuh_agent() {
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart >/dev/null 2>&1; then
        success_message "Wazuh agent restarted successfully."
    else
        warn_message "Could not restart Wazuh agent (may not be running)."
    fi
}

# Stop Suricata services
stop_suricata_services() {
    info_message "Stopping Suricata services..."
    
    local plist_file="/Library/LaunchDaemons/com.suricata.suricata.plist"
    if [ -f "$plist_file" ]; then
        info_message "Unloading Suricata LaunchDaemon..."
        maybe_sudo launchctl unload "$plist_file" 2>/dev/null || warn_message "Failed to unload Suricata LaunchDaemon"
        maybe_sudo rm -f "$plist_file"
        success_message "Suricata LaunchDaemon removed"
    else
        info_message "No Suricata LaunchDaemon found"
    fi
}

# Remove Suricata packages installed via package managers
remove_suricata_packages() {
    info_message "Removing Suricata packages..."
    local removed=0
    
    # Check for Homebrew installation
    if command_exists brew && brew list suricata >/dev/null 2>&1; then
        info_message "Detected Homebrew-installed Suricata"
        brew unpin suricata 2>/dev/null || true
        if brew uninstall --force suricata; then
            success_message "Removed Suricata via Homebrew"
            removed=1
        fi
    else
        info_message "No Homebrew-installed Suricata found"
    fi
    
    return 0
}

# Remove custom Suricata installation from /opt/wazuh/suricata
remove_custom_suricata_installation() {
    info_message "Removing custom Suricata installation..."
    local removed=0
    
    # Remove Suricata binary directory
    local suricata_install_dir="/opt/wazuh/suricata"
    if [ -d "$suricata_install_dir" ]; then
        info_message "Removing Suricata installation directory: $suricata_install_dir"
        if maybe_sudo rm -rf "$suricata_install_dir"; then
            success_message "Removed Suricata installation directory"
            removed=1
        else
            error_message "Failed to remove Suricata installation directory"
        fi
    else
        info_message "Suricata installation directory not found: $suricata_install_dir"
    fi
    
    # Remove symbolic links
    local symlinks=("/usr/local/bin/suricata" "/usr/bin/suricata")
    for suricata_symlink in "${symlinks[@]}"; do
        if [ -L "$suricata_symlink" ] || [ -f "$suricata_symlink" ]; then
            info_message "Removing Suricata symlink: $suricata_symlink"
            if maybe_sudo rm -f "$suricata_symlink"; then
                success_message "Removed Suricata symlink"
                removed=1
            else
                warn_message "Failed to remove Suricata symlink"
            fi
        fi
    done
    
    # Remove PATH configuration
    if [ -f "/etc/profile.d/suricata.sh" ]; then
        info_message "Removing PATH configuration: /etc/profile.d/suricata.sh"
        if maybe_sudo rm -f "/etc/profile.d/suricata.sh"; then
            success_message "Removed PATH configuration"
            removed=1
        else
            warn_message "Failed to remove PATH configuration"
        fi
    fi
    
    if [ $removed -eq 0 ]; then
        info_message "No custom Suricata installation found"
    fi
}

# Remove Suricata configuration and data directories
remove_suricata_directories() {
    info_message "Removing Suricata configuration and data directories..."
    local removed_count=0
    
    local dirs_to_remove=(
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$RULES_DIR"
        "/var/run/suricata"
        "/usr/lib/suricata"
        "/usr/local/lib/suricata"
    )
    
    for dir in "${dirs_to_remove[@]}"; do
        if [ -d "$dir" ]; then
            info_message "Removing directory: $dir"
            if maybe_sudo rm -rf "$dir"; then
                removed_count=$((removed_count + 1))
            else
                warn_message "Failed to remove directory: $dir"
            fi
        fi
    done
    
    if [ $removed_count -gt 0 ]; then
        success_message "Removed $removed_count directory(ies)"
    else
        info_message "No Suricata directories found"
    fi
}

# Validate complete removal
validate_removal() {
    info_message "Validating Suricata removal..."
    local found_items=0
    
    # Check if Suricata command is still available
    if command_exists suricata; then
        local suricata_path
        suricata_path=$(command -v suricata)
        warn_message "Suricata command still available at: $suricata_path"
        found_items=$((found_items + 1))
    fi
    
    # Check custom installation path
    if [ -d "/opt/wazuh/suricata" ]; then
        warn_message "Suricata installation directory still exists: /opt/wazuh/suricata"
        found_items=$((found_items + 1))
    fi
    
    # Check symlink
    if [ -L "/usr/local/bin/suricata" ] || [ -f "/usr/local/bin/suricata" ]; then
        warn_message "Suricata binary/symlink still exists: /usr/local/bin/suricata"
        found_items=$((found_items + 1))
    fi
    
    # Check configuration directory
    if [ -d "$CONFIG_DIR" ]; then
        warn_message "Suricata configuration directory still exists: $CONFIG_DIR"
        found_items=$((found_items + 1))
    fi
    
    # Check rules directory
    if [ -d "$RULES_DIR" ]; then
        warn_message "Suricata rules directory still exists: $RULES_DIR"
        found_items=$((found_items + 1))
    fi
    
    # Check log directory
    if [ -d "$LOG_DIR" ]; then
        warn_message "Suricata log directory still exists: $LOG_DIR"
        found_items=$((found_items + 1))
    fi
    
    if [ $found_items -eq 0 ]; then
        success_message "Suricata has been completely removed from the system"
        return 0
    else
        warn_message "Found $found_items Suricata component(s) still present"
        warn_message "Manual cleanup may be required for complete removal"
        return 0
    fi
}

# Main uninstallation function
main() {
    info_message "Starting Suricata uninstallation for macOS..."
    info_message "Detected OS: ${OS}"
    
    # Cleanup any legacy leftover directories from old installers (before delegation)
    if [ -d "${HOME}/suricata-install" ]; then
        info_message "Removing leftover directory from legacy installer: ${HOME}/suricata-install"
        rm -rf "${HOME}/suricata-install"
    fi
    
    # Special case: macOS Intel (amd64) - delegate to v0.1.5 uninstaller
    if [ "$(detect_architecture)" = "amd64" ]; then
        info_message "macOS Intel detected. Delegating to v0.1.5 uninstaller."
        local remote_uninstaller="$TMP_DIR/legacy-uninstall.sh"
        if ! curl -fsSL -o "$remote_uninstaller" "$LEGACY_UNINSTALL_URL"; then
            error_message "Failed to download legacy uninstaller from $LEGACY_UNINSTALL_URL"
            exit 1
        fi
        chmod +x "$remote_uninstaller"
        # Run the legacy uninstaller
        bash "$remote_uninstaller" "$@"
        exit $?
    fi
    
    # Detect existing Suricata installations
    local detection_result
    detection_result=$(detect_suricata_installation)
    
    # Parse the detection result
    IFS=',' read -r has_legacy has_modern has_softlink <<<"$detection_result"
    
    # Display detection results
    if [ "$has_legacy" -eq 1 ] || [ "$has_modern" -eq 1 ] || [ "$has_softlink" -eq 1 ]; then
        echo ""
        warn_message "Existing Suricata installation(s) detected!"
        
        # Check for legacy installation in /opt/suricata
        if [ -d "/opt/suricata" ]; then
            info_message "Found Suricata in path: /opt/suricata"
        fi
        
        # Check for modern installation in /opt/wazuh/suricata
        if [ -d "/opt/wazuh/suricata" ]; then
            info_message "Found Suricata in path: /opt/wazuh/suricata"
        fi
        
        # Check for softlink in /usr/local/bin/suricata
        if [ -L "/usr/local/bin/suricata" ] || [ -f "/usr/local/bin/suricata" ]; then
            info_message "Found Suricata in path: /usr/local/bin/suricata"
        fi
        echo ""
    else
        info_message "No Suricata installation detected"
        success_message "Nothing to uninstall"
        exit 0
    fi
    
    # Handle uninstallation based on what was detected
    # Case 1: Both legacy and modern installations exist
    if [ "$has_legacy" -eq 1 ] && [ "$has_modern" -eq 1 ]; then
        info_message "Removing Suricata found in path: /opt/wazuh/suricata"
        stop_suricata_services
        remove_custom_suricata_installation
        
        info_message "Removing Suricata found in path: /opt/suricata"
        if ! run_legacy_cleanup_script; then
            error_message "Failed to remove legacy Suricata installation"
            exit 1
        fi
    # Case 2: Only modern installation exists
    elif [ "$has_modern" -eq 1 ]; then
        info_message "Removing Suricata found in path: /opt/wazuh/suricata"
        stop_suricata_services
        remove_custom_suricata_installation
    # Case 3: Only legacy installation exists
    elif [ "$has_legacy" -eq 1 ]; then
        info_message "Removing Suricata found in path: /opt/suricata"
        if ! run_legacy_cleanup_script; then
            error_message "Failed to remove legacy Suricata installation"
            exit 1
        fi
    fi
    
    # Clean up any remaining softlinks in /usr/local/bin/suricata
    if [ -L "/usr/local/bin/suricata" ] || [ -f "/usr/local/bin/suricata" ]; then
        info_message "Cleaning up softlink: /usr/local/bin/suricata"
        maybe_sudo rm -f "/usr/local/bin/suricata" || warn_message "Failed to remove softlink"
    fi
    
    # Remove package manager installations
    remove_suricata_packages
    
    #Remove configuration and data directories
    remove_suricata_directories
    
    # Validate removal
    validate_removal
    
    # macOS specific: Cleanup legacy leftover directory in home
    if [ -d "${HOME}/suricata-install" ]; then
        info_message "Removing leftover directory from legacy installer: ${HOME}/suricata-install"
        rm -rf "${HOME}/suricata-install"
    fi
    
    echo ""
    success_message "Suricata uninstallation process completed!"
}

# Execute main function
main "$@"