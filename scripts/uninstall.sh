#!/bin/bash

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Text Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Logging Utilities
log() { echo -e "$(date +"%Y-%m-%d %H:%M:%S") $1 $2"; }
info_message() { log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"; }
success_message() { log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"; }
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

# OS Detection
case "$(uname)" in
Linux)
    OS="linux"
    CONFIG_DIR="/etc/suricata"
    LOG_DIR="/var/log/suricata"
    ;;
Darwin)
    OS="darwin"
    BREW_PREFIX=$(brew --prefix)
    CONFIG_DIR="$BREW_PREFIX/etc/suricata"
    LOG_DIR="$BREW_PREFIX/var/log/suricata"
    LAUNCH_AGENT_FILE="/Library/LaunchDaemons/com.suricata.suricata.plist"
    ;;
*)
    error_exit "Unsupported operating system: $(uname)"
    ;;
esac

# Uninstall Process
info_message "Starting Suricata uninstallation process..."

# Stop Suricata service
if [ "$OS" = "linux" ]; then
    if command_exists systemctl; then
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

# Uninstall Suricata using package managers
info_message "Uninstalling Suricata using the package manager..."
if [ "$OS" = "linux" ]; then
    if command_exists apt-get; then
        maybe_sudo apt-get remove --purge -y suricata || warn_message "Failed to uninstall Suricata using apt-get."
    elif command_exists yum; then
        maybe_sudo yum remove -y suricata || warn_message "Failed to uninstall Suricata using yum."
    else
        warn_message "No supported package manager found. Skipping Suricata uninstallation."
    fi
elif [ "$OS" = "darwin" ]; then
    if command_exists brew; then
        maybe_sudo brew uninstall suricata || warn_message "Failed to uninstall Suricata using Homebrew."
    fi
fi

# Delete Suricata configuration folder after uninstallation
info_message "Removing Suricata configuration folder..."
maybe_sudo rm -rf "$CONFIG_DIR" || warn_message "Failed to remove Suricata configuration folder."

# Remove logs
info_message "Removing Suricata logs..."
maybe_sudo rm -rf "$LOG_DIR" || warn_message "Failed to remove logs."

success_message "Suricata uninstallation process completed successfully."