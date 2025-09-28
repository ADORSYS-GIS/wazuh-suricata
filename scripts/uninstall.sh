#!/bin/bash

# Suricata Uninstallation Script
# This script removes all components installed by install.sh including:
# - Suricata packages (via package managers or prebuilt binaries)
# - Configuration files and directories (/etc/suricata, /var/lib/suricata, /var/log/suricata)
# - Runtime directories (/var/lib/suricata/cache, /var/log/suricata/certs, etc.)
# - System service files (systemd units, LaunchDaemon plists)
# - Repository configurations (PPAs, COPR repos)
# - Dependencies (yq, Homebrew packages)
# - IPS mode configurations (UFW rules, drop.conf)
# - Symlinks and PATH modifications

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

SURICATA_VERSION=${SURICATA_VERSION:-"7.0"}
MODE=""
LOGGED_IN_USER=""
TAP_NAME="adorsys-gis/tools"
VERSION="${1:-7.0.10}"
FORMULA="$TAP_NAME/suricata@$VERSION"

if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<<"show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
fi

# Text Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Logging Utilities
log() { echo -e "$(date +"%Y-%m-%d %H:%M:%S") $1 $2"; }
info_message() { log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"; }
success_message() { log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"; }
warn_message() { log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"; }
error_message() { log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"; }

# Error Handler
error_exit() {
    error_message "$1"
    exit 1
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Execute with Root Privileges
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 && sudo "$@" || error_exit "This script requires root privileges. Run as root or use sudo."
    else
        "$@"
    fi
}

sed_alternative() {
    if command_exists gsed; then
        maybe_sudo gsed "$@"
    else
        maybe_sudo sed "$@"
    fi
}

brew_command() {
    sudo -u "$LOGGED_IN_USER" brew "$@"
}

# OS Detection
case "$(uname)" in
Linux)
    OS="linux"
    CONFIG_DIR="/etc/suricata"
    LOG_DIR="/var/log/suricata"
    RULES_DIR="/var/lib/suricata"
    USR_LIB_DIR="/usr/lib/suricata"
    SURICATA_DEFAULT_FILE="/etc/default/suricata"
    UFW_DEFAULT_FILE="/etc/default/ufw"
    UFW_BEFORE_RULES="/etc/ufw/before.rules"
    
    # Detect Linux Distribution
    detect_distro() {
        if [ -f /etc/os-release ]; then . /etc/os-release; echo "$ID"
        elif [ -f /etc/redhat-release ]; then echo "redhat"
        elif [ -f /etc/debian_version ]; then echo "debian"
        else echo "unknown"; fi
    }
    DISTRO=$(detect_distro)
    
    # Set package manager
    case "$DISTRO" in
      ubuntu|debian) PACKAGE_MANAGER="apt" ;;
      centos|fedora|rhel) 
          if command_exists dnf; then
              PACKAGE_MANAGER="dnf"
          else
              PACKAGE_MANAGER="yum"
          fi
          ;;
      *) PACKAGE_MANAGER="unknown" ;;
    esac
    ;;
Darwin)
    OS="darwin"
    BREW_PREFIX=$(brew --prefix)
    CONFIG_DIR="$BREW_PREFIX/etc/suricata"
    LOG_DIR="$BREW_PREFIX/var/log/suricata"
    RULES_DIR="$BREW_PREFIX/var/lib/suricata/rules"
    USR_LIB_DIR="$BREW_PREFIX/usr/lib/suricata"
    CELLAR_DIR="$BREW_PREFIX/Cellar/suricata@7.0.10/7.0.10"
    LAUNCH_AGENT_FILE="/Library/LaunchDaemons/com.suricata.suricata.plist"
    ;;
*)
    error_exit "Unsupported operating system: $(uname)"
    ;;
esac

# Get installation profile
if [ "$(uname -s)" = "Linux" ]; then
    if [ -f "$SURICATA_DEFAULT_FILE" ]; then
        info_message "Starting Suricata uninstallation process..."
        if maybe_sudo grep -q "LISTENMODE=nfqueue" "$SURICATA_DEFAULT_FILE"; then
            info_message "Suricata is running in IPS mode."
            MODE="ips"
        else
            info_message "Suricata is running in IDS mode."
            MODE="ids"
        fi
    fi
fi

# Stop Suricata service
if [ "$OS" = "linux" ]; then
    if command_exists suricata && command_exists systemctl; then
        info_message "Stopping Suricata service..."
        maybe_sudo systemctl stop suricata || warn_message "Failed to stop Suricata service."
        maybe_sudo systemctl disable suricata || warn_message "Failed to disable Suricata service."
    fi
elif [ "$OS" = "darwin" ]; then
    if [ -f "$LAUNCH_AGENT_FILE" ]; then
        info_message "Unloading Suricata plist..."
        maybe_sudo launchctl unload "$LAUNCH_AGENT_FILE" || warn_message "Failed to unload Suricata plist."
        maybe_sudo rm -f "$LAUNCH_AGENT_FILE"
    fi
fi

# Uninstall yq if installed
if command_exists yq; then
    info_message "Uninstalling yq..."
    if [ "$OS" = "linux" ]; then
        maybe_sudo rm -f /usr/bin/yq || warn_message "Failed to uninstall yq."
    elif [ "$OS" = "darwin" ]; then
        # Check both Homebrew and manual installation locations
        if brew_command list yq >/dev/null 2>&1; then
            brew_command uninstall yq || warn_message "Failed to uninstall yq via Homebrew."
        fi
        # Also remove manual installation
        maybe_sudo rm -f /usr/local/bin/yq || warn_message "Failed to remove manually installed yq."
    fi
else
    info_message "yq is not installed. Skipping uninstallation."
fi

# Remove Suricata dependencies on macOS (always check regardless of installation method)
if [ "$OS" = "darwin" ] && command_exists brew; then
    info_message "Checking for Suricata dependencies to remove..."
    deps=("jansson" "libmagic" "libnet" "libyaml" "lz4" "pcre2")
    
    for dep in "${deps[@]}"; do
        if brew_command list "$dep" >/dev/null 2>&1; then
            info_message "Attempting to remove $dep..."
            
            # Check if the package has dependents before attempting removal
            dependents=$(brew_command uses --installed "$dep" 2>/dev/null || echo "")
            if [ -n "$dependents" ] && [ "$dependents" != "" ]; then
                info_message "Skipping $dep - still required by: $(echo "$dependents" | tr '\n' ' ')"
            else
                if brew_command uninstall "$dep" 2>/dev/null; then
                    success_message "$dep removed successfully"
                else
                    warn_message "Could not remove $dep - may be required by system or other packages"
                fi
            fi
        else
            info_message "$dep is not installed - skipping"
        fi
    done
fi

# Removing suricata repository from local package list...
if [ "$OS" = "linux" ]; then
    case "$DISTRO" in
        ubuntu|debian)
            if grep -q "oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
                info_message "Removing Suricata stable PPA repository..."
                maybe_sudo add-apt-repository --remove "ppa:oisf/suricata-stable" -y
            elif grep -q "oisf/suricata-$SURICATA_VERSION" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
                info_message "Removing Suricata $SURICATA_VERSION PPA repository..."
                maybe_sudo add-apt-repository --remove "ppa:oisf/suricata-$SURICATA_VERSION" -y
            fi
            ;;
        centos|fedora|rhel)
            # Remove OISF COPR repository
            if maybe_sudo "$PACKAGE_MANAGER" copr list --enabled 2>/dev/null | grep -q "@oisf/suricata-$SURICATA_VERSION"; then
                info_message "Disabling OISF Suricata $SURICATA_VERSION COPR repository..."
                maybe_sudo "$PACKAGE_MANAGER" copr disable "@oisf/suricata-$SURICATA_VERSION" -y || warn_message "Failed to disable COPR repository"
            fi

            # Note: We don't automatically remove EPEL repository as it may be used by other software
            # Users can remove it manually if desired: sudo dnf remove epel-release
            ;;
    esac
fi

# Function to remove residual Suricata files from Homebrew Cellar
remove_suricata_residuals() {
    local paths_to_check=(
        "/opt/homebrew/Cellar/suricata/7.0.10"  # Apple Silicon
        "/usr/local/Cellar/suricata/7.0.10"     # Intel
    )

    for path in "${paths_to_check[@]}"; do
        if [ -e "$path" ]; then
            info_message "Found residual Suricata files at $path. Deleting..."
            if ! maybe_sudo rm -rf "$path"; then
                warn_message "Failed to remove residual files at $path. This may require manual cleanup."
            fi
        fi
    done
}

# Function to detect and remove prebuilt binary installation
remove_prebuilt_suricata() {
    info_message "Checking for prebuilt Suricata installation..."
    
    # Check if /opt/suricata exists (prebuilt installation)
    if [ -d "/opt/suricata" ]; then
        info_message "Found prebuilt Suricata installation at /opt/suricata. Removing..."
        
        # Remove the entire /opt/suricata directory
        maybe_sudo rm -rf "/opt/suricata" || warn_message "Failed to remove /opt/suricata directory."
        
        # Remove symlinks from /usr/local/bin
        if [ -L "/usr/local/bin/suricata" ]; then
            info_message "Removing Suricata symlink from /usr/local/bin..."
            maybe_sudo rm -f "/usr/local/bin/suricata" || warn_message "Failed to remove Suricata symlink."
        fi
        
        if [ -e "/usr/local/bin/suricata-update" ]; then
            info_message "Removing suricata-update from /usr/local/bin..."
            maybe_sudo rm -f "/usr/local/bin/suricata-update" || warn_message "Failed to remove suricata-update."
        fi
        
        # Update paths for prebuilt installation cleanup
        CONFIG_DIR="/etc/suricata"
        LOG_DIR="/var/log/suricata" 
        RULES_DIR="/var/lib/suricata"
        
        success_message "Prebuilt Suricata installation removed."
        return 0
    else
        info_message "No prebuilt Suricata installation found at /opt/suricata."
        return 1
    fi
}

# Try to remove prebuilt installation first, then fall back to package managers
if ! remove_prebuilt_suricata; then
    # If no prebuilt installation found, try package managers
    if command_exists suricata; then
        info_message "Uninstalling Suricata using the package manager..."
        if [ "$OS" = "linux" ]; then
            case "$DISTRO" in
                ubuntu|debian)
                    info_message "Removing Suricata using apt..."
                    maybe_sudo apt remove --purge -y suricata || warn_message "Failed to uninstall Suricata using apt."

                    # Remove systemd service file if it exists (can be created by install.sh on some systems)
                    if [ -f "/usr/lib/systemd/system/suricata.service" ]; then
                        info_message "Removing Suricata systemd service file..."
                        maybe_sudo rm -f "/usr/lib/systemd/system/suricata.service" || warn_message "Failed to remove systemd service file."
                        maybe_sudo systemctl daemon-reload || warn_message "Failed to reload systemd daemon."
                    fi
                    ;;
                centos|fedora|rhel)
                    info_message "Removing Suricata using $PACKAGE_MANAGER..."
                    maybe_sudo "$PACKAGE_MANAGER" remove -y suricata || warn_message "Failed to uninstall Suricata using $PACKAGE_MANAGER."

                    # Remove dependencies that were installed specifically for Suricata
                    info_message "Removing Suricata-related dependencies..."
                    maybe_sudo "$PACKAGE_MANAGER" remove -y hyperscan hyperscan-devel yum-plugin-copr curl wget || warn_message "Some dependencies could not be removed."

                    # Remove systemd service file if it exists
                    if [ -f "/usr/lib/systemd/system/suricata.service" ]; then
                        info_message "Removing Suricata systemd service file..."
                        maybe_sudo rm -f "/usr/lib/systemd/system/suricata.service" || warn_message "Failed to remove systemd service file."
                        maybe_sudo systemctl daemon-reload || warn_message "Failed to reload systemd daemon."
                    fi
                    ;;
                *)
                    warn_message "Unsupported Linux distribution: $DISTRO. Skipping Suricata uninstallation."
                    ;;
            esac
        elif [ "$OS" = "darwin" ]; then
            if  brew_command list "$FORMULA" >/dev/null 2>&1; then
                brew_command uninstall "$FORMULA" || {
                    warn_message "Failed to remove $FORMULA"
                }
            else
                brew_command unpin suricata
                brew_command uninstall suricata || {
                    warn_message "Failed to remove Homebrew default Suricata"
                }
            fi
            remove_suricata_residuals
            
            
            # Clean up PATH modifications made by our installer
            if [ -f "/etc/paths.d/100-usr-local-bin" ]; then
                info_message "Removing custom PATH configuration..."
                maybe_sudo rm -f "/etc/paths.d/100-usr-local-bin" || warn_message "Failed to remove PATH configuration"
            fi

            # Remove Homebrew taps that might have been added for Suricata
            if brew_command tap | grep -q "adorsys-gis/tools"; then
                info_message "Removing adorsys-gis/tools Homebrew tap..."
                brew_command untap adorsys-gis/tools || warn_message "Failed to remove adorsys-gis/tools tap"
            fi
        fi
    else
        info_message "Suricata is not installed. Skipping uninstallation."
    fi
fi

# Delete Suricata configuration folder after uninstallation

# Remove Suricata configuration and data directories
if [ -d "$CONFIG_DIR" ]; then
    info_message "Removing Suricata configuration folder..."
    maybe_sudo rm -rf "$CONFIG_DIR" || warn_message "Failed to remove Suricata configuration folder."
fi

if [ -d "$LOG_DIR" ]; then
    info_message "Removing Suricata log folder..."
    maybe_sudo rm -rf "$LOG_DIR" || warn_message "Failed to remove Suricata log folder."
fi

if [ -d "$RULES_DIR" ]; then
    info_message "Removing Suricata rules folder..."
    maybe_sudo rm -rf "$RULES_DIR" || warn_message "Failed to remove Suricata rules folder."
fi

if [ -d "$USR_LIB_DIR" ]; then
    info_message "Removing Suricata lib folder..."
    maybe_sudo rm -rf "$USR_LIB_DIR" || warn_message "Failed to remove Suricata lib folder."
fi

if [ "$OS" = "darwin" ] && [ -d "$CELLAR_DIR" ]; then
    info_message "Removing Suricata cellar folder..."
    maybe_sudo rm -rf "$CELLAR_DIR" || warn_message "Failed to remove Suricata cellar folder."
fi

# Remove runtime directories created by install.sh
runtime_dirs=(
    "/var/lib/suricata/cache"
    "/var/lib/suricata/cache/sgh"
    "/var/lib/suricata/data"
    "/var/log/suricata/certs"
    "/var/log/suricata/files"
    "/var/run/suricata"
)

for runtime_dir in "${runtime_dirs[@]}"; do
    if [ -d "$runtime_dir" ]; then
        info_message "Removing runtime directory: $runtime_dir"
        maybe_sudo rm -rf "$runtime_dir" || warn_message "Failed to remove $runtime_dir"
    fi
done

# Remove IPS mode configuration files that may have been created
drop_conf_locations=(
    "/etc/suricata/drop.conf"
    "$CONFIG_DIR/drop.conf"
)

for drop_conf in "${drop_conf_locations[@]}"; do
    if [ -f "$drop_conf" ]; then
        info_message "Removing drop.conf file: $drop_conf"
        maybe_sudo rm -f "$drop_conf" || warn_message "Failed to remove $drop_conf"
    fi
done

# Only run on Linux
if [ "$(uname -s)" = "Linux" ] && [ "$MODE" = "ips" ]; then
    if [ -f "$SURICATA_DEFAULT_FILE" ]; then
        info_message "Removing Suricata default file..."
        maybe_sudo rm -f "$SURICATA_DEFAULT_FILE" || warn_message "Failed to remove Suricata default file."
    fi

    # Revert IPS mode-specific configurations
    if [ -f "$UFW_DEFAULT_FILE" ]; then
        info_message "Restoring DEFAULT_INPUT_POLICY to DROP in $UFW_DEFAULT_FILE..."
        sed_alternative -i "s|DEFAULT_INPUT_POLICY=\"ACCEPT\"|DEFAULT_INPUT_POLICY=\"DROP\"|" "$UFW_DEFAULT_FILE" || warn_message "Failed to restore DEFAULT_INPUT_POLICY in $UFW_DEFAULT_FILE."
    fi

    if [ -f "$UFW_BEFORE_RULES" ]; then
        info_message "Removing NFQUEUE rules from $UFW_BEFORE_RULES..."
        sed_alternative -i "/^-I INPUT -j NFQUEUE/d" "$UFW_BEFORE_RULES" || warn_message "Failed to remove INPUT NFQUEUE rule from $UFW_BEFORE_RULES."
        sed_alternative -i "/^-I OUTPUT -j NFQUEUE/d" "$UFW_BEFORE_RULES" || warn_message "Failed to remove OUTPUT NFQUEUE rule from $UFW_BEFORE_RULES."
    fi

    # Restart UFW service after reverting IPS mode-specific changes
    if command_exists ufw; then
        info_message "Restarting UFW service to apply changes..."
        maybe_sudo ufw disable || warn_message "Failed to disable UFW service."
        maybe_sudo ufw enable || warn_message "Failed to enable UFW service."
    fi
fi

success_message "Suricata uninstallation process completed successfully."