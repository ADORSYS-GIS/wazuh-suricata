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
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Logging Utilities
log() { echo -e "$(date +"%Y-%m-%d %H:%M:%S") $1 $2"; }
info_message() { log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"; }
warn_message() { log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"; }
error_message() { log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"; }
success_message() { log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"; }
print_step_header() { echo -e "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"; }

# Error Handler
error_exit() {
    error_message "$1"
    exit 1
}

LOGGED_IN_USER=""
SURICATA_VERSION_MACOS=${SURICATA_VERSION_MACOS:-"7.0.10"}
# Create Downloads directory for source builds
DOWNLOADS_DIR="${HOME}/suricata-install"

if [ "$(uname -s)" = "Darwin" ]; then
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
fi

# Command Existence Check
command_exists() { command -v "$1" >/dev/null 2>&1; }

# Execute with Root Privileges
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        command_exists sudo && sudo "$@" || error_exit "This script requires root privileges. Run as root or use sudo."
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

mkdir -p "$DOWNLOADS_DIR"

get_current_suricata_version() {
    if command_exists suricata; then
        maybe_sudo suricata -V | awk '{print $5}' | head -n1
    else
        echo ""
    fi
}

# Environment Variables
SURICATA_USER=${SURICATA_USER:-"root"}
SURICATA_VERSION=${SURICATA_VERSION:-"7.0"}
CONFIG_FILE=""
INTERFACE=""
LAUNCH_AGENT_FILE="/Library/LaunchDaemons/com.suricata.suricata.plist"

# Add options for better user experience
show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --help                Show this help message and exit
  --mode [ids|ips]      Configure Suricata in IDS (default) or IPS mode (Linux only)

Examples:
  $0 --mode ids
  $0 --mode ips
EOF
}

# Parse command-line arguments
MODE="ids"

while [[ $# -gt 0 ]]; do
    case "$1" in
    --help)
        show_help
        exit 0
        ;;
    --mode)
        if [[ "$2" =~ ^(ids|ips)$ ]]; then
            MODE="$2"
            shift
        else
            error_exit "Invalid mode: $2. Use 'ids' or 'ips'."
        fi
        ;;
    *)
        error_exit "Unknown option: $1"
        ;;
    esac
    shift
done

# OS and Architecture Detection
case "$(uname)" in
Linux)
    OS="linux"
    CONFIG_DIR="/etc/suricata"
    CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
    RULES_DIR="/var/lib/suricata/rules"
    INTERFACE="wlp0s20f3"
    ;;
Darwin)
    OS="darwin"
    BIN_FOLDER=$(brew --prefix)
    CONFIG_DIR="$BIN_FOLDER/etc/suricata"
    CONFIG_FILE="$BIN_FOLDER/etc/suricata/suricata.yaml"
    RULES_DIR="$BIN_FOLDER/var/lib/suricata/rules"
    INTERFACE="en0"
    ;;
*) error_exit "Unsupported operating system: $(uname)" ;;
esac
RULES_FILE="$RULES_DIR/suricata.rules"

ARCH=$(uname -m)
case "$ARCH" in
x86_64) ARCH="amd64" ;;
arm64 | aarch64) ARCH="arm64" ;;
*) error_exit "Unsupported architecture: $ARCH" ;;
esac

# Validate mode
if [[ "$MODE" == "ips" && "$OS" != "linux" ]]; then
    error_exit "IPS mode is only supported on Linux systems."
fi

YQ_BINARY=${YQ_BINARY:-"yq_${OS}_${ARCH}"}

# Detect Linux Distribution
if [ "$OS" = "linux" ]; then
    detect_distro() {
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            echo $ID
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/debian_version ]; then
            echo "debian"
        else
            error_exit "Unable to detect Linux distribution"
        fi
    }
    DISTRO=$(detect_distro)
    case "$DISTRO" in
    ubuntu | debian)
        PACKAGE_MANAGER="apt"
        INSTALL_CMD="install -y"
        ;;
    centos | fedora | rhel)
        PACKAGE_MANAGER="yum"
        INSTALL_CMD="install -y"
        ;;
    *) error_exit "Unsupported Linux distribution: $DISTRO" ;;
    esac
fi

# Check for systemd on Linux
if [ "$OS" = "linux" ]; then
    if ! command_exists systemctl; then
        error_exit "This script requires systemd to manage services."
    fi
fi

# General Utility Functions
create_file() {
    local filepath="$1"
    local content="$2"
    maybe_sudo bash -c "cat > \"$filepath\" <<EOF
$content
EOF"
    info_message "Created file: $filepath"
}

remove_file() {
    local filepath="$1"
    if [ -f "$filepath" ]; then
        info_message "Removing file: $filepath"
        maybe_sudo rm -f "$filepath"
    fi
}

# macOS Launchd Plist File
create_launchd_plist_file() {
    local filepath="$1"
    local suricata_bin="$2"
    info_message "Creating plist file for Suricata..."
    create_file "$filepath" "
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.suricata.suricata</string>
    <key>ProgramArguments</key>
    <array>
        <string>$suricata_bin</string>
        <string>-c</string>
        <string>$CONFIG_FILE</string>
        <string>-i</string>
        <string>$INTERFACE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"
    info_message "Unloading previous plist file (if any)..."
    maybe_sudo launchctl unload "$filepath" 2>/dev/null || true

    info_message "Loading new daemon plist file..."
    maybe_sudo launchctl load -w "$filepath" 2>/dev/null || warn_message "Loading previous plist file failed: $filepath"
    info_message "macOS Launchd plist file created and loaded: $filepath"
}

# Detect Wi-Fi Interface
detect_wifi_interface() {
    if command_exists networksetup; then
        INTERFACE=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}') || INTERFACE=""
    elif command_exists ip; then
        INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(en|eth|wl)' | head -n1) || INTERFACE=""
    elif command_exists ifconfig; then
        INTERFACE=$(ifconfig | awk -F': ' '{print $1}' | grep -E '^(en|eth|wl)' | head -n1) || INTERFACE=""
    else
        INTERFACE=""
    fi

    if [ -z "$INTERFACE" ]; then
        INTERFACE="eth0" # Default fallback
        warn_message "No Wi-Fi interface detected. Defaulting to: $INTERFACE"
    fi
    info_message "Detected interface: $INTERFACE"
}

# Download and Extract Rules
download_rules() {
    if ! command_exists suricata-update; then
        error_exit "suricata-update is required to download and manage rules. Please install it."
    fi

    # Ensure suricata-update sources are updated
    info_message "Updating suricata-update sources..."
    maybe_sudo suricata-update update-sources || error_exit "Failed to update suricata-update sources."

    # Enable the et/open source
    info_message "Enabling et/open source..."
    maybe_sudo suricata-update enable-source et/open || error_exit "Failed to enable et/open source."

    # If in IPS mode, create drop.conf
    if [[ "$MODE" == "ips" ]]; then
        DROP_CONF_PATH="$CONFIG_DIR/drop.conf"
        info_message "Creating drop.conf for IPS mode at $DROP_CONF_PATH..."
        maybe_sudo bash -c "cat > $DROP_CONF_PATH" <<EOF
# Convert specific SID to drop
#2019401
# Convert rules matching a pattern
#re:trojan
# Convert all rules in a specific group
group:emerging-attack_response # Drop ALL rules from emerging-attack_response.rules
EOF
        success_message "drop.conf created successfully."
    fi

    # Download and apply rules
    info_message "Downloading and applying rules using suricata-update..."
    maybe_sudo suricata-update || error_exit "Failed to download and apply rules."
    success_message "Suricata rules downloaded and applied successfully."

    # Add custom drop rule to suricata.rules
    if maybe_sudo test -f "$RULES_FILE"; then
        info_message "Adding custom drop rule to $RULES_FILE..."
        maybe_sudo echo 'drop tcp any any -> $HOME_NET any (msg:"TCP Scan ?"; flow:from_client;flags:S; sid:992002087;rev:1;)' | maybe_sudo tee -a "$RULES_FILE" > /dev/null
        success_message "Custom drop rule added to $RULES_FILE."
    else
        warn_message "$RULES_FILE not found. Skipping custom rule addition."
    fi
}

# Create and Update Suricata Configuration
update_config() {
    # Get the active network interface
    detect_wifi_interface

    # Replace the default eth0 value in the CONFIG_FILE with the active interface
    sed_alternative -i "s|interface: eth0|interface: $INTERFACE|" "$CONFIG_FILE" || error_exit "Failed to set active interface in $CONFIG_FILE"

    # Replace the value of community-id: from false to true
    sed_alternative -i "s|community-id: false|community-id: true|" "$CONFIG_FILE" || error_exit "Failed to enable community-id in $CONFIG_FILE"

    # Add detect-engine configuration at the end of the CONFIG_FILE if not already present
    if ! grep -q "detect-engine:" "$CONFIG_FILE"; then
        echo -e "\ndetect-engine:\n  - rule-reload: true" | maybe_sudo tee -a "$CONFIG_FILE" >/dev/null || error_exit "Failed to append detect-engine configuration to $CONFIG_FILE"
    fi

    # Use yq command to update eve-log types
    maybe_sudo yq -i '(.outputs[] | select(has("eve-log"))."eve-log".types) = ["alert"]' "$CONFIG_FILE" || error_exit "Failed to update eve-log types in $CONFIG_FILE"

    # Additional configurations for IPS mode
    if [[ "$MODE" == "ips" ]]; then
        # Replace LISTENMODE=af-packet with LISTENMODE=nfqueue in /etc/default/suricata
        SURICATA_DEFAULT_FILE="/etc/default/suricata"
        UFW_DEFAULT_FILE="/etc/default/ufw"

        if [[ -f "$SURICATA_DEFAULT_FILE" ]]; then
            sed_alternative -i "s|LISTENMODE=af-packet|LISTENMODE=nfqueue|" "$SURICATA_DEFAULT_FILE" || error_exit "Failed to set LISTENMODE to nfqueue in $SURICATA_DEFAULT_FILE"
        else
            warn_message "$SURICATA_DEFAULT_FILE not found. Skipping LISTENMODE update."
        fi

        # Replace DEFAULT_INPUT_POLICY=DROP with DEFAULT_INPUT_POLICY=ACCEPT in /etc/default/ufw
        if [[ -f "$UFW_DEFAULT_FILE" ]]; then
            sed_alternative -i "s|DEFAULT_INPUT_POLICY=\"DROP\"|DEFAULT_INPUT_POLICY=\"ACCEPT\"|" "$UFW_DEFAULT_FILE" || error_exit "Failed to set DEFAULT_INPUT_POLICY to ACCEPT in $UFW_DEFAULT_FILE"
        else
            warn_message "$UFW_DEFAULT_FILE not found. Skipping ENABLED update."
        fi

        # Add extra config to /etc/ufw/before.rules
        UFW_BEFORE_RULES="/etc/ufw/before.rules"
        if [[ -f "$UFW_BEFORE_RULES" ]]; then
            # Check if the rules already exist
            if grep -q "^-I INPUT -j NFQUEUE" "$UFW_BEFORE_RULES" &&
                grep -q "^-I OUTPUT -j NFQUEUE" "$UFW_BEFORE_RULES"; then
                info_message "NFQUEUE rules already exist in $UFW_BEFORE_RULES"
            else
                # Insert the rules after '# End required lines'
                sed_alternative -i '/# End required lines/a \
-I INPUT -j NFQUEUE\
-I OUTPUT -j NFQUEUE' "$UFW_BEFORE_RULES"
                info_message "Added NFQUEUE rules to $UFW_BEFORE_RULES."
            fi
        else
            warn_message "$UFW_BEFORE_RULES not found. Skipping NFQUEUE rules addition."
        fi
    fi

    success_message "Configuration updated successfully."
}

remove_brew_suricata() {
    # only on macOS/Homebrew
    if command_exists brew; then
        if brew_command list suricata >/dev/null 2>&1; then
            info_message "Removing Homebrew-installed Suricata package"
            brew_command uninstall --force suricata || {
                error_message "Failed to remove Homebrew-installed Suricata"
            }
            success_message "Homebrew-installed Suricata removed"
        fi
    fi
}


install_suricata_macos() {
    local version="$1"
    info_message "Installing Suricata v${version} from source on macOS" ""
    SURICATA_RB_URL="https://raw.githubusercontent.com/Homebrew/homebrew-core/1adc97dc5122276de00d8081a5497bb6b5381b0c/Formula/s/suricata.rb" #v7.0.10
    SURICATA_RP_PATH="$DOWNLOADS_DIR/suricata.rb"

    curl -SL --progress-bar "$SURICATA_RB_URL" -o "$SURICATA_RP_PATH" || {
        error_message "Failed to download suricata.rb file"
        exit 1
    }

    brew_command install --formula "$SURICATA_RP_PATH"
    brew_command pin suricata

    success_message "Suricata v${version} built and installed from source on macOS successfully"
}

install_suricata_darwin() {
    local desired_version="$1"
    local current_version=$(get_current_suricata_version)
    
    if [ -n "$current_version" ]; then
        if [ "$current_version" = "$desired_version" ]; then
            info_message "Suricata $current_version is already installed. Skipping installation."
            return 0
        else
            info_message "Updating Suricata from $current_version to $desired_version..."
            remove_brew_suricata
        fi
    fi
    
    info_message "Installing Suricata $desired_version..."
    install_suricata_macos "$desired_version"
    
    if [ -d "$DOWNLOADS_DIR" ]; then
        info_message "Cleaning up downloads directory..."
        maybe_sudo rm -rf "$DOWNLOADS_DIR"
    fi
}

# Installation Process
print_step_header 1 "Installing dependencies and Suricata"
if [ "$OS" = "linux" ]; then
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        if grep -q "oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            info_message "Removing unsupported Suricata repository..."
            maybe_sudo add-apt-repository --remove "ppa:oisf/suricata-stable" -y
            maybe_sudo "$PACKAGE_MANAGER" purge -y suricata || warn_message "Failed to remove Suricata package."
        fi
        if ! grep -q "oisf/suricata-$SURICATA_VERSION" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            info_message "Updating package lists and adding Suricata repository..."
            maybe_sudo "$PACKAGE_MANAGER" update
            maybe_sudo add-apt-repository "ppa:oisf/suricata-$SURICATA_VERSION" -y
            maybe_sudo "$PACKAGE_MANAGER" update
        else
            info_message "Suricata repository already added, updating package lists..."
        fi
        if command_exists yq; then
            info_message "yq is already installed."
        else
            info_message "Installing yq..."
            maybe_sudo curl -SL --progress-bar https://github.com/mikefarah/yq/releases/latest/download/${YQ_BINARY} -o /usr/bin/yq
            maybe_sudo chmod +x /usr/bin/yq
            info_message "yq installed at: /usr/bin/yq"
        fi
        info_message "Installing Suricata..."
        maybe_sudo $PACKAGE_MANAGER $INSTALL_CMD suricata
        SURICATA_BIN=$(command -v suricata || echo "/usr/bin/suricata")
        success_message "Suricata installed at: $SURICATA_BIN"
    fi
elif [ "$OS" = "darwin" ]; then
    info_message "Installing Suricata and yq via Homebrew..."
    install_suricata_darwin "$SURICATA_VERSION_MACOS"
    SURICATA_BIN=$(command -v suricata || echo "$BIN_FOLDER/bin/suricata")
    success_message "Suricata installed at: $SURICATA_BIN"
fi

print_step_header 2 "Downloading Suricata rules"
download_rules

print_step_header 3 "Creating and updating Suricata configuration for $MODE mode"
update_config

if [ "$OS" = "linux" ]; then
    print_step_header 4 "Restarting service(s) to include new configuration"
    if [[ "$MODE" == "ips" ]]; then
        info_message "Restarting ufw service..."
        maybe_sudo ufw disable
        maybe_sudo ufw enable
    fi
    info_message "Restarting Suricata service..."
    maybe_sudo systemctl restart suricata
elif [ "$OS" = "darwin" ]; then
    print_step_header 4 "Setting up Suricata to start at boot"
    create_launchd_plist_file "$LAUNCH_AGENT_FILE" "$SURICATA_BIN"
fi

print_step_header 5 "Validating installation"
if maybe_sudo [ -f "$CONFIG_FILE" ]; then
    success_message "Suricata configuration file exists: $CONFIG_FILE."
else
    error_exit "Suricata configuration file is missing: $CONFIG_FILE."
fi
SURICATA_BIN=$(command -v suricata || echo "not found")
if [ "$SURICATA_BIN" != "not found" ]; then
    success_message "Suricata executable found at: $SURICATA_BIN"
else
    error_exit "Suricata executable not found in PATH."
fi

success_message "Suricata installation and configuration complete!"
