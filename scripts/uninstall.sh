#!/bin/bash

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

SURICATA_VERSION=${SURICATA_VERSION:-"7.0"}
MODE=""
LOGGED_IN_USER=""

if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
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
    ;;
Darwin)
    OS="darwin"
    BREW_PREFIX=$(brew --prefix)
    CONFIG_DIR="$BREW_PREFIX/etc/suricata"
    LOG_DIR="$BREW_PREFIX/var/log/suricata"
    RULES_DIR="$BREW_PREFIX/var/lib/suricata/rules"
    USR_LIB_DIR="$BREW_PREFIX/usr/lib/suricata"
    LAUNCH_AGENT_FILE="/Library/LaunchDaemons/com.suricata.suricata.plist"
    ;;
*)
    error_exit "Unsupported operating system: $(uname)"
    ;;
esac

# Uninstall Process
info_message "Starting Suricata uninstallation process..."

if maybe_sudo grep -q "LISTENMODE=nfqueue" "$SURICATA_DEFAULT_FILE"; then
    info_message "Suricata is running in IPS mode."
    MODE=ips
else
    info_message "Suricata is running in IDS mode."
    MODE=ids
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

#Uninstall yq if installed
if command_exists yq; then
    info_message "Uninstalling yq..."
    if [ "$OS" = "linux" ]; then
        maybe_sudo rm -f /usr/bin/yq || warn_message "Failed to uninstall yq."
    elif [ "$OS" = "darwin" ]; then
        brew_command uninstall yq || warn_message "Failed to uninstall yq."
    fi
else
    info_message "yq is not installed. Skipping uninstallation."
fi

# Uninstall Suricata using package managers

if command_exists suricata; then
    info_message "Uninstalling Suricata using the package manager..."
    if [ "$OS" = "linux" ]; then
        if command_exists apt; then
            maybe_sudo add-apt-repository --remove "ppa:oisf/suricata-$SURICATA_VERSION" -y
            maybe_sudo apt remove --purge -y suricata || warn_message "Failed to uninstall Suricata using apt-get."
        elif command_exists yum; then
            maybe_sudo yum remove -y suricata || warn_message "Failed to uninstall Suricata using yum."
        else
            warn_message "No supported package manager found. Skipping Suricata uninstallation."
        fi
    elif [ "$OS" = "darwin" ]; then
        brew_command uninstall suricata || warn_message "Failed to uninstall Suricata using Homebrew."
    fi
else
    info_message "Suricata is not installed. Skipping uninstallation."
fi

# Delete Suricata configuration folder after uninstallation

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
    maybe_sudo rm -rf "$USR_LIB_DIR" || warn_message "Failed to remove Suricata rules folder."
fi

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