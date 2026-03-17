#!/usr/bin/env bash

#=============================================================================
# Enhanced Suricata Installation Script for macOS
# Detects existing Suricata installations and performs automatic cleanup
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
print_step() {
    log "${BLUE}${BOLD}[STEP]${NORMAL}" "$1: $2"
}

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Configuration
# Default Configuration
SURICATA_VERSION="8.0.2"
MODE="ids"
INTERFACE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --version)
            SURICATA_VERSION="$2"
            shift 2
            ;;
        *)
            # Backward compatibility: if first argument is not a flag, treat as version
            if [[ "$1" != -* ]] && [[ -z "$INTERFACE" ]]; then
                 SURICATA_VERSION="$1"
                 shift
            else
                 error_message "Unknown argument: $1"
                 exit 1
            fi
            ;;
    esac
done

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
RELEASE_TAG="suricata-v0.5.2"

# Remote script URLs
UNINSTALL_MODERN_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/suricata-modular-scripts/scripts/uninstall.sh"
FALLBACK_CONFIG_URL="https://raw.githubusercontent.com/OISF/suricata/suricata-8.0.2/suricata.yaml.in"
TMP_DIR=$(mktemp -d)

# OS Detection for macOS
OS="darwin"
CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
RULES_DIR="/opt/wazuh/suricata/var/lib/suricata/rules"
LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"

# Get logged in user for Homebrew operations
LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')

# Cleanup function
cleanup() {
    info_message "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect system architecture for macOS
detect_architecture() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            error_message "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
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

# Create a file with content (helper)
create_file() {
    local filepath="$1"
    local content="$2"
    
    maybe_sudo bash -c "cat > '$filepath'" <<EOF
$content
EOF
}

# Create macOS Launchd plist
create_launchd_plist_file() {
    local filepath="$1"
    local suricata_bin="$2"
    
    # Ensure binary path is absolute
    if [[ "$suricata_bin" != /* ]]; then
        suricata_bin="/usr/local/bin/$suricata_bin"
    fi

    info_message "Creating plist file for Suricata..."
    create_file "$filepath" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
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
</plist>"

    info_message "Unloading previous plist file (if any)..."
    maybe_sudo launchctl unload "$filepath" 2>/dev/null || true

    info_message "Loading new daemon plist file..."
    maybe_sudo launchctl load -w "$filepath" 2>/dev/null || warn_message "Loading plist failed: $filepath"
    info_message "macOS Launchd plist file created and loaded: $filepath"
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Check if Suricata is already installed with the correct version
check_installed_version() {
    local installed_bin="/opt/wazuh/suricata/bin/suricata"
    
    if [ ! -x "$installed_bin" ]; then
        return 1
    fi
    
    info_message "Checking installed Suricata version..."
    
    # Get installed version
    local output
    output=$("$installed_bin" -V 2>&1 | head -n1)
    
    if [[ "$output" != *"$SURICATA_VERSION"* ]]; then
        info_message "Installed version ($output) does not match target version ($SURICATA_VERSION)"
        return 1
    else
        success_message "Suricata $SURICATA_VERSION is already installed ($output)"
        return 0
    fi
}

# Download and execute uninstall script
run_uninstall_script() {
    local uninstall_args="${1:-}"
    local download_path="$TMP_DIR/uninstall.sh"
    local local_script_path
    
    # Check if we can find the uninstall script locally (relative to install.sh)
    # This is useful for development or manual runs from the repo
    local_script_path="$(dirname "$(readlink -f "$0")")/uninstall.sh"
    
    if [ -f "$local_script_path" ]; then
        info_message "Using local uninstall script: $local_script_path"
        cp "$local_script_path" "$download_path"
    else
        info_message "Downloading uninstall script..."
        if ! curl -fsSL -o "$download_path" "$UNINSTALL_MODERN_URL" 2>/dev/null; then
            error_message "Failed to download uninstall script from $UNINSTALL_MODERN_URL"
            return 1
        fi
    fi
    
    chmod +x "$download_path"
    
    info_message "Running uninstall script with args: ${uninstall_args:-(none)}..."
    if bash "$download_path" $uninstall_args; then
        success_message "Uninstallation/Cleanup completed successfully"
        return 0
    else
        error_message "Uninstall script failed"
        return 1
    fi
}

# Pre-installation check and automatic cleanup
pre_installation_check() {
    info_message "Performing pre-installation checks..."
    
    # Check if we should skip installation
    if check_installed_version; then
        # If installed correctly, verify and skip
        info_message "Target version matches. Verified existing installation."
        
        # Set a flag to skip package installation and dependency setup
        export SKIP_INSTALL=1
        
        echo ""
        success_message "Existing modern installation verified."
        echo ""
    else
        # If not installed or wrong version, run full cleanup
        info_message "Target version not found. Running full cleanup..."
        if ! run_uninstall_script; then
            error_message "Failed to run uninstall script"
            exit 1
        fi
        
        export SKIP_INSTALL=0
        
        echo ""
        success_message "System cleaned and ready for fresh Suricata installation"
        echo ""
    fi
    
    # Brief pause to let user see the messages
    sleep 2
}

#=============================================================================
# INSTALLATION FUNCTIONS
#=============================================================================

# Install dependencies for macOS
install_dependencies() {
    info_message "Installing dependencies..."
    
    print_step 1 "Installing dependencies on macOS"
    if command_exists brew; then
        local brew_cmd=(brew install jq yq libpcap lz4 pcre2 jansson libyaml libmagic)
        if [ "$(id -u)" -eq 0 ] && [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "loginwindow" ]; then
            local brew_out=""
            brew_out=$(sudo -u "$LOGGED_IN_USER" "${brew_cmd[@]}" 2>&1) || {
                warn_message "Could not install dependencies via Homebrew"
                warn_message "Homebrew output: $brew_out"
            }
        elif [ "$(id -u)" -ne 0 ]; then
            local brew_out=""
            brew_out=$("${brew_cmd[@]}" 2>&1) || {
                warn_message "Could not install dependencies via Homebrew"
                warn_message "Homebrew output: $brew_out"
            }
        else
            warn_message "Cannot install dependencies (jq, yq, libpcap, lz4, libmagic, etc.) via Homebrew as root without a logged in user"
        fi
        
    else
        warn_message "Homebrew not found. Please install jq/yq manually."
    fi
    
    # Fix for libpcap linkage on Apple Silicon where binary expects specific path
    if [ "$(uname -m)" = "arm64" ]; then
        local expected_lib="/opt/homebrew/opt/libpcap/lib/libpcap.A.dylib"
        if [ ! -f "$expected_lib" ]; then
             local actual_lib=""
             
             # Try to find libpcap in common locations
             if command_exists brew; then
                 actual_lib=$(brew --prefix libpcap 2>/dev/null)/lib/libpcap.dylib
             fi
             
             if [ -z "$actual_lib" ] || [ ! -f "$actual_lib" ]; then
                 if [ -f "/opt/homebrew/lib/libpcap.dylib" ]; then
                     actual_lib="/opt/homebrew/lib/libpcap.dylib"
                 elif [ -f "/opt/homebrew/opt/libpcap/lib/libpcap.dylib" ]; then
                     actual_lib="/opt/homebrew/opt/libpcap/lib/libpcap.dylib"
                 elif [ -f "/usr/local/lib/libpcap.dylib" ]; then
                     actual_lib="/usr/local/lib/libpcap.dylib"
                 fi
             fi

             if [ -n "$actual_lib" ] && [ -f "$actual_lib" ]; then
                 info_message "Fixing libpcap linkage... Linking $actual_lib to $expected_lib"
                 maybe_sudo mkdir -p "$(dirname "$expected_lib")"
                 maybe_sudo ln -sf "$actual_lib" "$expected_lib"
             else
                 warn_message "Could not locate libpcap.dylib. Suricata binary might fail to run."
                 warn_message "If errors persist, please install libpcap: brew install libpcap"
             fi
        fi
    fi
    
    success_message "Dependencies installation attempted successfully"
}

# Download file with error checking
download_file() {
    local url="$1"
    local output="$2"
    local description="$3"
    
    info_message "Downloading $description..."
    local output_dir
    output_dir=$(dirname "$output")
    if ! maybe_sudo mkdir -p "$output_dir"; then
        error_message "Failed to create directory for $description: $output_dir"
        return 1
    fi
    
    # Use sudo to download the file to system directories
    if curl -fsSL "$url" | maybe_sudo tee "$output" > /dev/null; then
        success_message "$description downloaded successfully"
        return 0
    else
        error_message "Failed to download $description from $url"
        error_message "Please check your network connection and URL validity"
        return 1
    fi
}

# Download Suricata DMG for macOS based on architecture
download_suricata_macos_dmg() {
    local arch="$1"
    local url="${GITHUB_RELEASE_BASE_URL}/${RELEASE_TAG}/suricata-${SURICATA_VERSION}-macos-${arch}.dmg"
    
    print_step 1 "Downloading Suricata DMG for macOS $arch"
    download_file "$url" "$TMP_DIR/suricata.dmg" "Suricata DMG" || exit 1
}

# Install Suricata from DMG on macOS
install_suricata_macos_dmg() {
    local arch="$1"
    info_message "Installing Suricata from DMG on macOS ($arch)..."
    
    local mount_point="/Volumes/Suricata_Installer"
    
    print_step 1 "Mounting Suricata DMG"
    if ! maybe_sudo hdiutil attach "$TMP_DIR/suricata.dmg" -mountpoint "$mount_point" -quiet; then
        error_message "Failed to mount Suricata DMG"
        exit 1
    fi
    
    print_step 2 "Installing Suricata binary"
    maybe_sudo mkdir -p "/opt/wazuh/suricata/bin/"
    
    local suricata_binary=""
    if [ -f "$mount_point/suricata" ]; then
        suricata_binary="$mount_point/suricata"
    else
        suricata_binary=$(find "$mount_point" -name "suricata" -type f -perm +111 2>/dev/null | head -n 1)
    fi
    
    if [ -z "$suricata_binary" ] || [ ! -f "$suricata_binary" ]; then
        maybe_sudo hdiutil detach "$mount_point" -quiet
        error_message "Could not find Suricata binary in DMG"
        exit 1
    fi
    
    maybe_sudo cp "$suricata_binary" "/opt/wazuh/suricata/bin/"
    
    # Copy configuration file if present
    if [ -f "$mount_point/suricata.yaml" ]; then
        maybe_sudo mkdir -p "/opt/wazuh/suricata/etc/suricata/"
        maybe_sudo cp "$mount_point/suricata.yaml" "/opt/wazuh/suricata/etc/suricata/"
    fi
    
    maybe_sudo hdiutil detach "$mount_point" -quiet
    
    print_step 3 "Setting permissions"
    # Set executable permissions for all users to ensure it can be run without sudo
    maybe_sudo chmod 755 "/opt/wazuh/suricata/bin/suricata"
    maybe_sudo chown root:wheel "/opt/wazuh/suricata/bin/suricata" 2>/dev/null || \
    maybe_sudo chown root:staff "/opt/wazuh/suricata/bin/suricata" 2>/dev/null || \
    maybe_sudo chown root:root "/opt/wazuh/suricata/bin/suricata"
    
    # Ensure /usr/local/bin exists and create symlink
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo ln -sf "/opt/wazuh/suricata/bin/suricata" /usr/local/bin/suricata
    # Also ensure the symlink has proper permissions
    maybe_sudo chmod 755 /usr/local/bin/suricata
    
    success_message "Suricata installed successfully from DMG on macOS"
}

# Try to locate the Suricata binary under the managed prefix
find_suricata_binary() {
    local base="/opt/wazuh/suricata"
    # Search several common locations and a deeper scan as fallback
    local candidates=(
        "$base/bin/suricata"
        "$base/sbin/suricata"
        "$base/libexec/suricata/suricata"
        "$base/suricata"
    )
    for candidate in "${candidates[@]}"; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            echo "$candidate"; return 0
        fi
    done
    # Deep search up to depth 6 for any file named 'suricata' or starting with 'suricata'
    local found
    found=$(find "$base" -maxdepth 6 -type f \( -name 'suricata' -o -name 'suricata*' \) 2>/dev/null | sort | head -n1)
    if [ -n "$found" ] && [ -x "$found" ]; then
        echo "$found"; return 0
    fi
    return 1
}

# Create symlinks for global access
create_symlinks() {
    print_step 2 "Creating symlinks for global access"
    
    # Remove old symlinks
    maybe_sudo rm -f /usr/local/bin/suricata /usr/bin/suricata 2>/dev/null || true
    
    local target_binary="/opt/wazuh/suricata/bin/suricata"
    
    # Create /usr/local/bin symlink (standard user PATH)
    if maybe_sudo ln -sf "$target_binary" /usr/local/bin/suricata; then
        info_message "Created symlink: /usr/local/bin/suricata -> $target_binary"
    else
        warn_message "Failed to create /usr/local/bin/suricata symlink"
    fi
    
    # Verify installation
    if command -v suricata >/dev/null 2>&1; then
        success_message "Suricata is now available in your PATH"
    else
        warn_message "Suricata symlinks created but not found in PATH"
    fi
}

# Detect Network Interface for macOS
detect_wifi_interface() {
    if command_exists networksetup; then
        INTERFACE=$(networksetup -listallhardwareports | awk '/Device/ {print $2}' | while read dev; do
            if ifconfig "$dev" 2>/dev/null | grep -q "status: active"; then
                echo "$dev"
            fi
        done | head -n1) || INTERFACE=""
    else
        warn_message "networksetup command not found on macOS - setting default interface to en0"
        INTERFACE="en0"
    fi
    
    if [ -z "$INTERFACE" ]; then
        INTERFACE="en0"
        warn_message "No active interface detected. Defaulting to: $INTERFACE"
    fi
    info_message "Detected interface: $INTERFACE"
}

# Download and Extract Rules
download_rules() {
    local rules_version="$SURICATA_VERSION"
    local rules_url="https://rules.emergingthreats.net/open/suricata-${rules_version}/emerging-all.rules.tar.gz"
    local temp_dir="/tmp/suricata-rules-$$"
    local rules_archive="$temp_dir/emerging-all.rules.tar.gz"

    # Create temporary directory for downloading and extracting rules
    info_message "Creating temporary directory: $temp_dir"
    mkdir -p "$temp_dir" || {
        error_message "Failed to create temporary directory: $temp_dir"
        exit 1
    }

    # Download the rules tarball
    info_message "Downloading Suricata ${rules_version} rules from: $rules_url"
    if command_exists curl; then
        curl -L --fail --progress-bar -o "$rules_archive" "$rules_url" || {
            rm -rf "$temp_dir"
            error_message "Failed to download rules from $rules_url"
            exit 1
        }
    else
        rm -rf "$temp_dir"
        error_message "curl is required to download rules but is not installed"
        exit 1
    fi
    success_message "Rules downloaded successfully"

    # On macOS, remove quarantine attributes from the downloaded file
    info_message "Removing macOS quarantine attribute from downloaded file"
    xattr -d com.apple.quarantine "$rules_archive" 2>/dev/null || warn_message "Quarantine attribute not present"

    # Extract the rules archive
    info_message "Extracting rules archive"
    tar -xzf "$rules_archive" -C "$temp_dir" || {
        rm -rf "$temp_dir"
        error_message "Failed to extract rules archive"
        exit 1
    }

    # Ensure the rules directory exists
    info_message "Creating rules directory: $RULES_DIR"
    maybe_sudo mkdir -p "$RULES_DIR" || {
        rm -rf "$temp_dir"
        error_message "Failed to create rules directory: $RULES_DIR"
        exit 1
    }

    # Initialize suricata.rules
    local rules_file="$RULES_DIR/suricata.rules"
    info_message "Initializing $rules_file"
    maybe_sudo touch "$rules_file" || {
        rm -rf "$temp_dir"
        error_message "Failed to create $rules_file"
        exit 1
    }
    maybe_sudo chmod 644 "$rules_file" || {
        rm -rf "$temp_dir"
        error_message "Failed to set permissions on $rules_file"
        exit 1
    }

    # Combine all .rules files into suricata.rules
    info_message "Combining .rules files into $rules_file"
    local rules_files
    rules_files=$(find "$temp_dir" -type f -name "*.rules")
    if [ -n "$rules_files" ]; then
        maybe_sudo bash -c "cat $rules_files > \"$rules_file\"" || {
            rm -rf "$temp_dir"
            error_message "Failed to combine rules into $rules_file"
            exit 1
        }
        success_message "Rules combined into $rules_file successfully"
    else
        warn_message "No .rules files found in $temp_dir"
    fi

    # Clean up temporary directory
    info_message "Cleaning up temporary files"
    rm -rf "$temp_dir"
    success_message "Rules download and installation completed successfully"
}

# Create and Update Suricata Configuration
setup_suricata_config() {
    info_message "Setting up Suricata configuration..."
    
    detect_wifi_interface
    
    # Create config directory if it doesn't exist
    maybe_sudo mkdir -p "$CONFIG_DIR"
    maybe_sudo mkdir -p "$LOG_DIR"
    
    # If config file doesn't exist, create a basic one or copy from package
    if ! maybe_sudo test -f "$CONFIG_FILE"; then
        # Try to find a default config from the installation
        local default_config=""
        if [ -f "/opt/wazuh/suricata/etc/suricata/suricata.yaml" ]; then
            default_config="/opt/wazuh/suricata/etc/suricata/suricata.yaml"
        elif [ -f "/usr/share/suricata/suricata.yaml" ]; then
            default_config="/usr/share/suricata/suricata.yaml"
        fi
        
        if [ -n "$default_config" ]; then
            info_message "Copying default configuration from $default_config"
            maybe_sudo cp "$default_config" "$CONFIG_FILE"
        else
            info_message "No default configuration in package, using fallback configuration."
            info_message "Downloading configuration from fallback URL..."
            
            # Download configuration from fallback URL
            if curl -fsSL "$FALLBACK_CONFIG_URL" | maybe_sudo tee "$CONFIG_FILE" > /dev/null; then
                success_message "Configuration downloaded successfully from fallback URL"
                
                # Replace autoconf placeholders in the downloaded template
                info_message "Processing fallback configuration template..."
                
                # Define paths based on our installation
                local install_prefix="/opt/wazuh/suricata"
                local log_dir="$install_prefix/var/log/suricata"
                local sysconf_dir="$install_prefix/etc/suricata"
                local run_dir="$install_prefix/var/run/suricata"
                
                # Ensure these directories exist
                maybe_sudo mkdir -p "$log_dir" "$sysconf_dir" "$run_dir"
                
                # Replace placeholders
                sed_inplace "s|@e_logdir@|$log_dir|g" "$CONFIG_FILE"
                sed_inplace "s|@e_sysconfdir@|$sysconf_dir/|g" "$CONFIG_FILE"
                sed_inplace "s|@e_rundir@|$run_dir/|g" "$CONFIG_FILE"
                sed_inplace "s|@e_defaultruledir@|$RULES_DIR|g" "$CONFIG_FILE"
                sed_inplace "s|@MAJOR_MINOR@|8.0|g" "$CONFIG_FILE"
                sed_inplace "s|@e_enable_evelog@|yes|g" "$CONFIG_FILE"
                sed_inplace "s|@prefix@|$install_prefix|g" "$CONFIG_FILE"
                sed_inplace "s|@PACKAGE_NAME@|suricata|g" "$CONFIG_FILE"
                
                # Comment out optional features that might not be present (pfring, etc.)
                sed_inplace "s|@pfring_comment@|#|g" "$CONFIG_FILE"
                sed_inplace "s|@napatech_comment@|#|g" "$CONFIG_FILE"
                sed_inplace "s|@ndpi_comment@|#|g" "$CONFIG_FILE"
                
                success_message "Configuration template processed successfully"
            else
                error_message "Failed to download fallback configuration"
                exit 1
            fi
        fi
    fi
    
    # Update configuration if file exists
    if maybe_sudo test -f "$CONFIG_FILE"; then
        info_message "Updating Suricata configuration..."
        
        # Update interface
        sed_inplace "s|interface: eth0|interface: $INTERFACE|" "$CONFIG_FILE"
        sed_inplace "s|interface: en0|interface: $INTERFACE|" "$CONFIG_FILE"
        
        # Enable community-id
        sed_inplace "s|community-id: false|community-id: true|" "$CONFIG_FILE"

        # Ensure default-rule-path and rule-files are set to our managed rules location
        if grep -q "^\s*default-rule-path:" "$CONFIG_FILE"; then
            sed_inplace "s|^\s*default-rule-path:.*|default-rule-path: $RULES_DIR|" "$CONFIG_FILE"
        else
            maybe_sudo bash -c "echo 'default-rule-path: $RULES_DIR' >> '$CONFIG_FILE'"
        fi
        if ! grep -q "^\s*rule-files:" "$CONFIG_FILE"; then
            maybe_sudo bash -c "printf '\nrule-files:\n  - suricata.rules\n' >> '$CONFIG_FILE'"
        else
            # Ensure suricata.rules is listed
            if ! grep -q "^\s*-\s*suricata\.rules\b" "$CONFIG_FILE"; then
                maybe_sudo bash -c "awk '1; /rule-files:/ && !x{print \"  - suricata.rules\"; x=1}' '$CONFIG_FILE' > '$CONFIG_FILE.tmp' && mv '$CONFIG_FILE.tmp' '$CONFIG_FILE'"
            fi
        fi

        # Ensure eve-log types include 'alert' (tests expect this)
        if command_exists yq; then
            if maybe_sudo yq eval '.outputs[] | select(has("eve-log"))' "$CONFIG_FILE" >/dev/null 2>&1; then
                maybe_sudo yq eval -i '(.outputs[] | select(has("eve-log")) | .["eve-log"].types) |= ((. // []) + ["alert"] | unique)' "$CONFIG_FILE" >/dev/null 2>&1 || \
                    warn_message "Could not update eve-log types via yq"
            else
                maybe_sudo yq eval -i '.outputs += [{"eve-log":{"enabled":"yes","filetype":"regular","filename":"eve.json","types":["alert"]}}]' "$CONFIG_FILE" >/dev/null 2>&1 || \
                    warn_message "Could not append eve-log output via yq"
            fi
        else
            warn_message "yq not found; could not ensure eve-log includes 'alert' in configuration"
        fi
        
        success_message "Suricata configuration updated successfully"
    fi
    
    success_message "Suricata configuration setup completed"
}

# Create macOS LaunchDaemon for automatic startup
create_launchd_service() {
    info_message "Creating macOS LaunchDaemon for Suricata..."
    
    local plist_file="/Library/LaunchDaemons/com.suricata.suricata.plist"
    local suricata_bin="/opt/wazuh/suricata/bin/suricata"
    
    create_launchd_plist_file "$plist_file" "$suricata_bin"
    
    success_message "LaunchDaemon created successfully"
}

#=============================================================================
# MAIN INSTALLATION LOGIC
#=============================================================================

# Main installation function
main() {
    info_message "Starting Suricata installation for macOS..."
    info_message "Target version: $SURICATA_VERSION"
    
    # Check if Wazuh agent is installed (required dependency)
    if [ ! -d "/Library/Ossec" ]; then
        error_message "Wazuh agent not installed at /Library/Ossec"
        error_message "Please install the Wazuh agent before running this script"
        exit 1
    fi

    # Pre-installation checks and cleanup
    pre_installation_check
    
    # Skip installation if already installed correctly
    if [ "${SKIP_INSTALL:-0}" -eq 1 ]; then
        info_message "Suricata $SURICATA_VERSION is already installed. Refreshing rules..."
        download_rules
        success_message "Suricata $SURICATA_VERSION is already installed and rules updated. Exiting."
        exit 0
    fi
    
    # Install dependencies
    install_dependencies
    
    # Detect architecture
    local arch
    arch=$(detect_architecture)
    info_message "Detected architecture: $arch"
    
    # Download Suricata DMG
    download_suricata_macos_dmg "$arch"
    
    # Install Suricata from DMG
    install_suricata_macos_dmg "$arch"
    
    # Create symlinks
    create_symlinks
    
    # Download and setup rules
    download_rules
    
    # Setup configuration
    setup_suricata_config
    
    # Create LaunchDaemon for automatic startup
    create_launchd_service
    
    echo ""
    success_message "Suricata installation completed successfully!"
    info_message "Binary location: /opt/wazuh/suricata/bin/suricata"
    info_message "Configuration file: $CONFIG_FILE"
    info_message "Rules directory: $RULES_DIR"
    info_message "Log directory: $LOG_DIR"
    echo ""
    success_message "Suricata is now installed and ready to use with Wazuh!"
}

# Execute main function
main "$@"