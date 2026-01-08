#!/usr/bin/env bash

#=============================================================================
# Modern Suricata Uninstallation Script
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

# OS Detection
case "$(uname)" in
Linux)
    OS="linux"
    CONFIG_DIR="/etc/suricata"
    LOG_DIR="/var/log/suricata"
    RULES_DIR="/var/lib/suricata"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    ;;
Darwin)
    OS="darwin"
    CONFIG_DIR="/etc/suricata"
    LOG_DIR="/var/log/suricata"
    RULES_DIR="/var/lib/suricata"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
    ;;
*)
    error_message "Unsupported operating system: $(uname)"
    exit 1
    ;;
esac

# Detect Linux Distribution
if [ "$OS" = "linux" ]; then
    detect_distro() {
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo "$ID"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/debian_version ]; then
            echo "debian"
        else
            error_message "Unable to detect Linux distribution"
            exit 1
        fi
    }
    DISTRO=$(detect_distro)
fi

# Remote script URLs and temporary directory
LEGACY_UNINSTALL_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/v1.5.0/scripts/uninstall.sh"
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

# Cross-platform sed function
sed_inplace() {
    if [ "$OS" = "darwin" ]; then
        maybe_sudo sed -i '' "$@" 2>/dev/null || true
    else
        maybe_sudo sed -i "$@" 2>/dev/null || true
    fi
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
    
    # Check if Suricata is installed via package manager (modern)
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                if command_exists rpm && rpm -q suricata >/dev/null 2>&1; then
                    has_modern=1
                fi
                ;;
            ubuntu|debian)
                if command_exists dpkg && dpkg -s suricata >/dev/null 2>&1; then
                    has_modern=1
                fi
                ;;
        esac
    fi
    
    # Return result as "legacy,modern,softlink" format
    echo "${has_legacy},${has_modern},${has_softlink}"
}

# Download and execute legacy cleanup script
run_legacy_cleanup_script() {
    local cleanup_script="$TMP_DIR/legacy-uninstall.sh"
    
    info_message "Downloading legacy uninstall script..."
    
    if ! curl -fsSL -o "$cleanup_script" "$LEGACY_UNINSTALL_URL" 2>/dev/null; then
        error_message "Failed to download legacy uninstall script from $LEGACY_UNINSTALL_URL"
        return 1
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
    
    if [ "$OS" = "linux" ]; then
        if command_exists systemctl; then
            if maybe_sudo systemctl is-active --quiet suricata 2>/dev/null; then
                info_message "Stopping Suricata systemd service..."
                maybe_sudo systemctl stop suricata 2>/dev/null || warn_message "Failed to stop Suricata service"
                maybe_sudo systemctl disable suricata 2>/dev/null || warn_message "Failed to disable Suricata service"
                success_message "Suricata service stopped and disabled"
            else
                info_message "Suricata service is not running"
            fi
        fi
    elif [ "$OS" = "darwin" ]; then
        local plist_file="/Library/LaunchDaemons/com.suricata.suricata.plist"
        if [ -f "$plist_file" ]; then
            info_message "Unloading Suricata LaunchDaemon..."
            maybe_sudo launchctl unload "$plist_file" 2>/dev/null || warn_message "Failed to unload Suricata LaunchDaemon"
            maybe_sudo rm -f "$plist_file"
            success_message "Suricata LaunchDaemon removed"
        else
            info_message "No Suricata LaunchDaemon found"
        fi
    fi
}

# Remove Suricata packages installed via package managers
remove_suricata_packages() {
    info_message "Removing Suricata packages..."
    local removed=0
    
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                # Check if Suricata is installed via RPM
                if command_exists rpm && rpm -q suricata >/dev/null 2>&1; then
                    info_message "Detected RPM-installed Suricata package"
                    if command_exists dnf; then
                        if maybe_sudo dnf remove -y suricata; then
                            success_message "Removed Suricata via dnf"
                            removed=1
                        fi
                    elif command_exists yum; then
                        if maybe_sudo yum remove -y suricata; then
                            success_message "Removed Suricata via yum"
                            removed=1
                        fi
                    fi
                else
                    info_message "No RPM-installed Suricata package found"
                fi
                ;;
            ubuntu|debian)
                # Check if Suricata is installed via DEB
                if command_exists dpkg && dpkg -s suricata >/dev/null 2>&1; then
                    info_message "Detected DEB-installed Suricata package"
                    if maybe_sudo apt-get remove -y suricata; then
                        maybe_sudo apt-get autoremove -y
                        success_message "Removed Suricata via apt"
                        removed=1
                    fi
                else
                    info_message "No DEB-installed Suricata package found"
                fi
                ;;
            *)
                warn_message "Unsupported Linux distribution for package removal: $DISTRO"
                ;;
        esac
    elif [ "$OS" = "darwin" ]; then
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
    
    # Remove library configuration
    if [ "$OS" = "linux" ] && [ -f "/etc/ld.so.conf.d/suricata.conf" ]; then
        info_message "Removing library configuration: /etc/ld.so.conf.d/suricata.conf"
        if maybe_sudo rm -f "/etc/ld.so.conf.d/suricata.conf"; then
            maybe_sudo ldconfig
            success_message "Removed library configuration"
            removed=1
        else
            warn_message "Failed to remove library configuration"
        fi
    fi
    
    
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

# Remove systemd service files (Linux only)
remove_systemd_service_files() {
    if [ "$OS" = "linux" ]; then
        info_message "Removing systemd service files..."
        local removed_count=0
        
        local service_files=(
            "/etc/systemd/system/suricata.service"
            "/usr/lib/systemd/system/suricata.service"
            "/lib/systemd/system/suricata.service"
        )
        
        for service_file in "${service_files[@]}"; do
            if [ -f "$service_file" ]; then
                info_message "Removing service file: $service_file"
                if maybe_sudo rm -f "$service_file"; then
                    removed_count=$((removed_count + 1))
                fi
            fi
        done
        
        if [ $removed_count -gt 0 ]; then
            maybe_sudo systemctl daemon-reload 2>/dev/null || true
            success_message "Removed systemd service files"
        else
            info_message "No systemd service files found"
        fi
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
    info_message "Starting Suricata uninstallation..."
    info_message "Detected OS: ${OS}"
    
    if [ "$OS" = "linux" ]; then
        info_message "Detected Linux distribution: ${DISTRO}"
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
    
    # Remove systemd service files (Linux only)
    remove_systemd_service_files
    
    # Validate removal
    validate_removal
    
    echo ""
    success_message "Suricata uninstallation process completed!"
}

# Execute main function
main "$@"