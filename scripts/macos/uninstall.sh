#!/usr/bin/env bash

#=============================================================================
# Modern Suricata Uninstallation Script for macOS
# Removes Suricata packages installed via the new package-based installation
# Handles installations in /opt/wazuh/suricata
#=============================================================================

# Set shell options based on shell type
if [[ -n "${BASH_VERSION:-}" ]]; then
    set -euo pipefail
else
    set -eu
fi

# OS guard
if [[ "$(uname -s)" != "Darwin" ]]; then
    printf "%s\n" "[ERROR] This uninstallation script is intended for macOS systems." >&2
    exit 1
fi

# Variables
WAZUH_SURICATA_REPO_REF=${WAZUH_SURICATA_REPO_REF:-"v0.2.0-rc2"}
WAZUH_SURICATA_REPO_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/${WAZUH_SURICATA_REPO_REF}"

# OS Detection for macOS
OS="darwin"
CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
RULES_DIR="/opt/wazuh/suricata/var/lib/suricata"
OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"

TMP_DIR=$(mktemp -d)

# Source shared utilities
if ! curl -fsSL "${WAZUH_SURICATA_REPO_URL}/scripts/shared/utils.sh" -o "$TMP_DIR/utils.sh"; then
    echo "Failed to download utils.sh"
    exit 1
fi

# Function to calculate SHA256 (bootstrap)
calculate_sha256_bootstrap() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    else
        shasum -a 256 "$file" | awk '{print $1}'
    fi
}

# Download checksums and verify utils.sh
if ! curl -fsSL "${WAZUH_SURICATA_REPO_URL}/checksums.sha256" -o "$TMP_DIR/checksums.sha256"; then
    echo "Failed to download checksums.sha256"
    exit 1
fi

EXPECTED_HASH=$(grep "scripts/shared/utils.sh" "$TMP_DIR/checksums.sha256" | awk '{print $1}')
ACTUAL_HASH=$(calculate_sha256_bootstrap "$TMP_DIR/utils.sh")

if [[ -z "$EXPECTED_HASH" ]] || [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
    echo "Error: Checksum verification failed for utils.sh" >&2
    exit 1
fi

# shellcheck disable=SC1091
. "$TMP_DIR/utils.sh"

# Register cleanup to run on exit
trap cleanup EXIT

# Set up global checksums file
export CHECKSUMS_FILE="$TMP_DIR/checksums.sha256"

# Detect architecture is handled by utils.sh

# Remote script URLs
LEGACY_UNINSTALL_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/refs/tags/v0.1.5/scripts/uninstall.sh"

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
    
    if ! download_file "$LEGACY_UNINSTALL_URL" "$cleanup_script" "legacy uninstall script"; then
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
    
    maybe_sudo chmod +x "$cleanup_script"
    
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
        if ! download_file "$LEGACY_UNINSTALL_URL" "$remote_uninstaller" "legacy uninstall script"; then
            exit 1
        fi
        maybe_sudo chmod +x "$remote_uninstaller"
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
    
    echo ""
    success_message "Suricata uninstallation process completed!"
}

# Execute main function
main "$@"