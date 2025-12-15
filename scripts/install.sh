#!/usr/bin/env bash

#=============================================================================
# Enhanced Suricata Installation Script with Pre-Installation Detection
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
SURICATA_VERSION="${1:-8.0.2}"
INTERFACE=""

# GitHub Release configuration for packages
GITHUB_RELEASE_BASE_URL="https://github.com/ADORSYS-GIS/wazuh-plugins/releases/download"
RELEASE_TAG="suricata-v0.5.2"

# Remote script URLs
UNINSTALL_MODERN_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/suricata-modular-scripts/scripts/uninstall.sh"
LEGACY_UNINSTALL_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/v0.1.5/scripts/uninstall.sh"
REMOTE_MAC_AMD64_INSTALL_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/v0.1.5/scripts/install.sh"
FALLBACK_CONFIG_URL="https://raw.githubusercontent.com/OISF/suricata/master/suricata.yaml"

TMP_DIR=$(mktemp -d)
LOGGED_IN_USER=""

# OS and Distribution Detection
case "$(uname)" in
Linux)
    OS="linux"
    CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
    CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
    RULES_DIR="/opt/wazuh/suricata/var/lib/suricata/rules"
    LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
    OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/var/ossec/bin/wazuh-control"
    ;;
Darwin)
    OS="darwin"
    CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
    CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
    RULES_DIR="/opt/wazuh/suricata/var/lib/suricata/rules"
    LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
    OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf"
    WAZUH_CONTROL_BIN_PATH="/Library/Ossec/bin/wazuh-control"
    LOGGED_IN_USER=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ {print $3}')
    ;;
*)
    error_message "Unsupported operating system: $(uname)"
    exit 1
    ;;
esac

# Detect Linux Distribution (only on Linux)
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

# Detect system architecture (unified for Linux and macOS)
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

# Cross-platform sed function
sed_inplace() {
    if [ "$OS" = "darwin" ]; then
        maybe_sudo sed -i '' "$@" 2>/dev/null || true
    else
        maybe_sudo sed -i "$@" 2>/dev/null || true
    fi
}

#=============================================================================
# PRE-INSTALLATION CHECKS
#=============================================================================

# Detect Suricata installations - check for both legacy and modern
detect_suricata_installation() {
    local has_legacy=0
    local has_modern=0
    
    # Suppress info messages during detection to avoid interference with return values
    exec 3>&1 4>&2  # Save stdout and stderr
    exec 1>/dev/null 2>/dev/null  # Redirect stdout and stderr to /dev/null
    
    # Check for legacy installation in /opt/suricata
    if [ -d "/opt/suricata" ]; then
        has_legacy=1
    fi
    
    # Check for legacy installation in /usr/bin
    if [ -f "/usr/bin/suricata" ]; then
        has_legacy=1
    fi
    
    # Check for modern installation in /opt/wazuh/suricata
    if [ -d "/opt/wazuh/suricata" ]; then
        has_modern=1
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
    
    # Restore stdout and stderr
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    
    # Return result as "legacy,modern" format
    echo "${has_legacy},${has_modern}"
}

# Download and execute cleanup script silently
run_cleanup_script() {
    local script_url="$1"
    local script_name="$2"
    local cleanup_script="$TMP_DIR/$script_name"
    
    info_message "Downloading $script_name..."
    
    if ! curl -fsSL -o "$cleanup_script" "$script_url" 2>/dev/null; then
        error_message "Failed to download $script_name from $script_url"
        return 1
    fi
    
    chmod +x "$cleanup_script"
    
    info_message "Running $script_name silently..."
    if bash "$cleanup_script" --silent; then
        success_message "Cleanup completed successfully"
        return 0
    else
        error_message "$script_name failed"
        return 1
    fi
}

# Pre-installation check and automatic cleanup
pre_installation_check() {
    info_message "Performing pre-installation checks..."
    
    local detection_result
    detection_result=$(detect_suricata_installation)
    
    # Parse the detection result
    IFS=',' read -r has_legacy has_modern <<< "$detection_result"
    
    # Display detection results
    if [ "$has_legacy" -eq 1 ] || [ "$has_modern" -eq 1 ]; then
        echo ""
        warn_message "Existing Suricata installation(s) detected!"
        
        # Check for legacy installation in /opt/suricata
        if [ -d "/opt/suricata" ]; then
            info_message "Found legacy Suricata directory: /opt/suricata"
        fi
        
        # Check for legacy installation in /usr/bin
        if [ -f "/usr/bin/suricata" ]; then
            info_message "Found legacy Suricata binary: /usr/bin/suricata"
        fi
        
        # Check for modern installation in /opt/wazuh/suricata
        if [ -d "/opt/wazuh/suricata" ]; then
            info_message "Found modern Suricata directory: /opt/wazuh/suricata"
        fi
        
        # Check if Suricata is installed via package manager (modern)
        if [ "$OS" = "linux" ]; then
            case "$DISTRO" in
                centos|rhel|redhat|rocky|almalinux|fedora)
                    if command_exists rpm && rpm -q suricata >/dev/null 2>&1; then
                        info_message "Found Suricata installed via RPM package manager"
                    fi
                    ;;
                ubuntu|debian)
                    if command_exists dpkg && dpkg -s suricata >/dev/null 2>&1; then
                        info_message "Found Suricata installed via DEB package manager"
                    fi
                    ;;
            esac
        fi
    fi
    
    # If no installations detected, proceed with fresh install
    if [ "$has_legacy" -eq 0 ] && [ "$has_modern" -eq 0 ]; then
        success_message "No existing Suricata installation detected"
        success_message "System is ready for fresh installation"
        return 0
    fi
    
    # Automatically remove legacy installation if found
    if [ "$has_legacy" -eq 1 ]; then
        info_message "Legacy Suricata installation detected - removing automatically..."
        if ! run_cleanup_script "$LEGACY_UNINSTALL_URL" "legacy-uninstall.sh"; then
            error_message "Failed to remove legacy Suricata installation"
            exit 1
        fi 
    fi
    
    # Automatically remove modern installation if found
    if [ "$has_modern" -eq 1 ]; then
        info_message "Modern Suricata installation detected - removing automatically..."
        if ! run_cleanup_script "$UNINSTALL_MODERN_URL" "uninstall.sh"; then
            error_message "Failed to remove modern Suricata installation"
            exit 1
        fi
    fi
    
    echo ""
    success_message "Pre-installation cleanup completed"
    success_message "System is ready for fresh Suricata installation"
    echo ""
    
    # Brief pause to let user see the messages
    sleep 2
}

#=============================================================================
# INSTALLATION FUNCTIONS
#=============================================================================

# Restart Wazuh agent (show output to user)
restart_wazuh_agent() {
    info_message "Restarting Wazuh agent..."
    if maybe_sudo "$WAZUH_CONTROL_BIN_PATH" restart; then
        success_message "Wazuh agent restarted successfully."
    else
        error_message "Error occurred during Wazuh agent restart."
    fi
}

# Install dependencies based on distro
install_dependencies() {
    info_message "Installing dependencies..."
    
    if [ "$OS" = "linux" ]; then
        case "$DISTRO" in
            centos|rhel|redhat|rocky|almalinux|fedora)
                print_step 1 "Installing dependencies on RPM-based system"
                local pkg_manager=""
                if command_exists dnf; then
                    pkg_manager="dnf"
                elif command_exists yum; then
                    pkg_manager="yum"
                else
                    warn_message "Neither dnf nor yum found, skipping dependency installation"
                    return 0
                fi
                
                maybe_sudo "$pkg_manager" install -y curl wget jq 2>/dev/null || \
                warn_message "Could not install some dependencies"
                ;;
            ubuntu|debian)
                print_step 1 "Installing dependencies on DEB-based system"
                maybe_sudo apt-get update -qq
                maybe_sudo apt-get install -y curl wget jq
                ;;
            *)
                error_message "Unsupported Linux distribution: $DISTRO"
                exit 1
                ;;
        esac
    elif [ "$OS" = "darwin" ]; then
        print_step 1 "Installing dependencies on macOS"
        if command_exists brew; then
            if [ "$(id -u)" -eq 0 ] && [ -n "$LOGGED_IN_USER" ] && [ "$LOGGED_IN_USER" != "loginwindow" ]; then
                sudo -u "$LOGGED_IN_USER" brew install jq 2>/dev/null || warn_message "Could not install jq via Homebrew"
            elif [ "$(id -u)" -ne 0 ]; then
                brew install jq 2>/dev/null || warn_message "Could not install jq via Homebrew"
            else
                warn_message "Cannot install jq via Homebrew as root without a logged in user"
            fi
        else
            warn_message "Homebrew not found. Please install jq manually."
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

# Download Suricata package based on distro and architecture
download_suricata_package() {
    local distro="$1"
    local arch="$2"
    local url="" output=""
    
    case "$distro" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            print_step 1 "Downloading Suricata RPM package for $arch"
            url="${GITHUB_RELEASE_BASE_URL}/${RELEASE_TAG}/suricata-${SURICATA_VERSION}-linux-${arch}.rpm"
            output="$TMP_DIR/suricata.rpm"
            ;;
        ubuntu|debian)
            print_step 1 "Downloading Suricata DEB package for $arch"
            url="${GITHUB_RELEASE_BASE_URL}/${RELEASE_TAG}/suricata-${SURICATA_VERSION}-linux-${arch}.deb"
            output="$TMP_DIR/suricata.deb"
            ;;
        *)
            error_message "Unsupported Linux distribution: $distro"
            exit 1
            ;;
    esac
    
    download_file "$url" "$output" "Suricata package" || exit 1
}

# Download Suricata DMG for macOS based on architecture
download_suricata_macos_dmg() {
    local arch="$1"
    local url="${GITHUB_RELEASE_BASE_URL}/${RELEASE_TAG}/suricata-${SURICATA_VERSION}-macos-${arch}.dmg"
    
    print_step 1 "Downloading Suricata DMG for macOS $arch"
    download_file "$url" "$TMP_DIR/suricata.dmg" "Suricata DMG" || exit 1
}

# Install Suricata package based on distro
install_suricata_package() {
    local distro="$1"
    info_message "Installing Suricata package for $distro..."
    
    case "$distro" in
        centos|rhel|redhat|rocky|almalinux|fedora)
            print_step 1 "Installing Suricata RPM package"
            if command_exists dnf; then
                maybe_sudo dnf install -y "$TMP_DIR/suricata.rpm"
            else
                maybe_sudo yum install -y "$TMP_DIR/suricata.rpm"
            fi
            ;;
        ubuntu|debian)
            print_step 1 "Installing Suricata DEB package"
            maybe_sudo apt-get install -y "$TMP_DIR/suricata.deb"
            ;;
        *)
            error_message "Unsupported Linux distribution: $distro"
            exit 1
            ;;
    esac
    
    print_step 2 "Creating symlink to Suricata binary"
    maybe_sudo mkdir -p /usr/local/bin
    maybe_sudo ln -sf /opt/wazuh/suricata/bin/suricata /usr/local/bin/suricata
    
    # Verify symlink was created successfully
    if [ -L /usr/local/bin/suricata ]; then
        local target
        target=$(readlink /usr/local/bin/suricata 2>/dev/null || echo "unknown")
        info_message "Symlink created successfully: /usr/local/bin/suricata -> $target"
    else
        warn_message "Failed to create symlink at /usr/local/bin/suricata"
    fi
    
    print_step 3 "Configuring system library path"
    # Binaries with Linux capabilities (cap_net_admin, cap_net_raw) ignore LD_LIBRARY_PATH
    # for security. We must add the library path to the system configuration.
    if [ "$OS" = "linux" ]; then
        info_message "Adding Suricata libraries to system library path"
        echo "/opt/wazuh/suricata/lib" | maybe_sudo tee /etc/ld.so.conf.d/suricata.conf > /dev/null
        maybe_sudo ldconfig
        success_message "Library path configured successfully"
    fi
    
    print_step 4 "Setting proper permissions"
    # Set permissions so all users can read and execute
    maybe_sudo chmod -R o+rx /opt/wazuh/suricata/ 2>/dev/null || warn_message "Could not set permissions on /opt/wazuh/suricata"
    info_message "Permissions updated for all users"
    
    success_message "Suricata package installed successfully"

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

ensure_symlinks() {
    # Ensure suricata and suricata-update are available on PATH
    info_message "Ensuring Suricata symlinks exist"
    maybe_sudo mkdir -p /usr/local/bin

    local bin_path
    if bin_path=$(find_suricata_binary); then
        # Ensure it's executable
        maybe_sudo chmod +x "$bin_path" 2>/dev/null || true
        
        # Verify the binary is executable
        if [ -x "$bin_path" ]; then
            info_message "Binary is executable: $bin_path"
        else
            warn_message "Binary exists but is not executable: $bin_path"
        fi
        
        # Test execution
        if "$bin_path" --version >/dev/null 2>&1; then
            info_message "Binary execution test: SUCCESS"
        else
            warn_message "Binary execution test: FAILED"
            # Try to capture error details
            local error_output
            error_output=$("$bin_path" --version 2>&1 | head -n3 || echo "No error output")
            warn_message "Error output: $error_output"
        fi
        
        # Link to discovered binary in /usr/local/bin (user PATH)
        if [ ! -L /usr/local/bin/suricata ] || [ "$(readlink -f /usr/local/bin/suricata 2>/dev/null || true)" != "$bin_path" ]; then
            maybe_sudo ln -sf "$bin_path" /usr/local/bin/suricata || warn_message "Failed to create suricata symlink in /usr/local/bin"
        fi
        # Also provide /usr/bin symlink to satisfy sudo secure_path
        if [ -d /usr/bin ]; then
            if [ ! -L /usr/bin/suricata ] || [ "$(readlink -f /usr/bin/suricata 2>/dev/null || true)" != "$bin_path" ]; then
                if maybe_sudo ln -sf "$bin_path" /usr/bin/suricata; then
                    info_message "Symlink created: /usr/bin/suricata -> $bin_path"
                else
                    warn_message "Failed to create suricata symlink in /usr/bin"
                fi
            else
                local existing_target
                existing_target=$(readlink /usr/bin/suricata 2>/dev/null || echo "unknown")
                info_message "Symlink already exists: /usr/bin/suricata -> $existing_target"
            fi
        fi
        info_message "Suricata binary resolved at: $bin_path"
    else
        warn_message "Could not locate Suricata binary under /opt/wazuh/suricata"
    fi



# Ensure PATH fallback via profile.d
ensure_path_profile() {
    info_message "Installing PATH configuration in /etc/profile.d/suricata.sh"
    maybe_sudo bash -c 'echo "export PATH=/opt/wazuh/suricata/bin:\$PATH" > /etc/profile.d/suricata.sh'
    maybe_sudo chmod 644 /etc/profile.d/suricata.sh || true
    
    # Check if command is discoverable in current environment
    if ! command -v suricata > /dev/null 2>&1; then
        warn_message "Suricata not in current shell PATH"
        info_message "To use Suricata, restart your shell or run: exec bash"
    fi
}

# Set Linux capabilities to allow non-root usage where possible
set_linux_capabilities() {
    if [ "$(uname -s)" != "Linux" ]; then
        return 0
    fi
    if ! command -v setcap >/dev/null 2>&1; then
        return 0
    fi
    local bin_path
    if bin_path=$(find_suricata_binary); then
        # Some builds use a wrapper that execs suricata.real; set caps on both if present
        local real_path="${bin_path}.real"
        maybe_sudo setcap cap_net_admin,cap_net_raw+eip "$bin_path" 2>/dev/null || true
        if [ -f "$real_path" ]; then
            maybe_sudo setcap cap_net_admin,cap_net_raw+eip "$real_path" 2>/dev/null || true
        fi
    fi
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

# Detect Wi-Fi Interface
detect_wifi_interface() {
    if [ "$OS" = "darwin" ]; then
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
    elif [ "$OS" = "linux" ]; then
        if command_exists ip; then
            INTERFACE=$(ip -o link show | awk -F': ' '/state UP/ {print $2}' | head -n1) || INTERFACE=""
        elif command_exists ifconfig; then
            INTERFACE=$(ifconfig | awk -F': ' '{print $1}' | grep -E '^(en|eth|wl)' | head -n1) || INTERFACE=""
        else
            INTERFACE=""
        fi
    else
        INTERFACE=""
    fi
    
    if [ -z "$INTERFACE" ]; then 
        if [ "$OS" = "darwin" ]; then
            INTERFACE="en0"
        else
            INTERFACE="eth0"
        fi
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
    if [ "$OS" = "darwin" ]; then
        info_message "Removing macOS quarantine attribute from downloaded file"
        xattr -d com.apple.quarantine "$rules_archive" 2>/dev/null || warn_message "Quarantine attribute not present"
    fi

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
        elif [ -f "/Volumes/Suricata_Installer/suricata.yaml" ]; then
             default_config="/Volumes/Suricata_Installer/suricata.yaml"
        elif [ -f "/Volumes/Suricata_Installer/etc/suricata/suricata.yaml" ]; then
             default_config="/Volumes/Suricata_Installer/etc/suricata/suricata.yaml"
        fi
        
        if [ -n "$default_config" ]; then
            info_message "Copying default configuration from $default_config"
            maybe_sudo cp "$default_config" "$CONFIG_FILE"
        else
            warn_message "No default configuration found in package."
            info_message "Downloading fallback configuration from OISF..."
            if maybe_sudo curl -fsSL -o "$CONFIG_FILE" "$FALLBACK_CONFIG_URL"; then
                 success_message "Fallback configuration downloaded successfully."
            else
                 error_message "Failed to download fallback configuration."
                 warn_message "You will need to manually configure $CONFIG_FILE"
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
        
        success_message "Suricata configuration updated successfully"
    fi
}

# Validate installation
validate_installation() {
    info_message "Validating Suricata installation..."
    local validation_failed=0
    
    # Force hash table refresh to clear command cache
    hash -r 2>/dev/null || true
    
    # Try multiple methods to find and validate Suricata
    local suricata_found=0
    local actual_version=""
    local bin_path=""
    
    # Method 1: Try direct execution from /usr/local/bin (user PATH)
    if [ -x /usr/local/bin/suricata ]; then
        actual_version=$(/usr/local/bin/suricata --version 2>/dev/null | head -n1 || echo "")
        if [ -n "$actual_version" ]; then
            suricata_found=1
            bin_path="/usr/local/bin/suricata"
        fi
    fi
    
    # Method 2: Try /usr/bin symlink (sudo secure_path)
    if [ $suricata_found -eq 0 ] && [ -x /usr/bin/suricata ]; then
        actual_version=$(/usr/bin/suricata --version 2>/dev/null | head -n1 || echo "")
        if [ -n "$actual_version" ]; then
            suricata_found=1
            bin_path="/usr/bin/suricata"
        fi
    fi
    
    # Method 3: Find and execute directly from installation path
    if [ $suricata_found -eq 0 ]; then
        if bin_path=$(find_suricata_binary); then
            # Verify the found binary is executable
            if [ -x "$bin_path" ]; then
                actual_version=$("$bin_path" --version 2>/dev/null | head -n1 || echo "")
                if [ -n "$actual_version" ]; then
                    suricata_found=1
                fi
            fi
        fi
    fi
    
    # Report results
    if [ $suricata_found -eq 1 ] && [ -n "$actual_version" ]; then
        success_message "Suricata version installed: $actual_version"
        info_message "Suricata binary location: $bin_path"
    else
        # Explicit check for binaries at known locations as a last resort
        # This handles cases where 'find_suricata_binary' might fail or behave unexpectedly
        local known_bins=(
            "/usr/local/bin/suricata"
            "/usr/bin/suricata"
            "/opt/wazuh/suricata/bin/suricata"
        )
        
        warn_message "Standard validation failed. Attempting strict fallback validation..."
        
        for kbin in "${known_bins[@]}"; do
            if maybe_sudo test -x "$kbin"; then
                # Attempt version check, capturing output for debug
                local ver_output
                ver_output=$("$kbin" --version 2>&1 | head -n1 || echo "ERROR_EXEC")
                
                # If checking failed, try with sudo
                if [ "$ver_output" = "ERROR_EXEC" ] || [ -z "$ver_output" ]; then
                     ver_output=$(maybe_sudo "$kbin" --version 2>&1 | head -n1 || echo "ERROR_EXEC_SUDO")
                fi

                if [ -n "$ver_output" ] && [ "$ver_output" != "ERROR_EXEC" ] && [ "$ver_output" != "ERROR_EXEC_SUDO" ]; then
                    actual_version="$ver_output"
                    suricata_found=1
                    bin_path="$kbin"
                    success_message "Suricata version found (fallback): $actual_version"
                    info_message "Suricata binary location: $bin_path"
                    break
                else
                     warn_message "Binary found at $kbin but version check failed. Output: $ver_output"
                fi
            fi
        done
    fi
    
    if [ $suricata_found -eq 0 ]; then
        error_message "Suricata command is not available. Please check the installation."
        # Add debugging information
        warn_message "Debug: Checking for binary at expected locations:"
        if maybe_sudo test -f /usr/local/bin/suricata; then
            warn_message "  - /usr/local/bin/suricata exists"
        else
            warn_message "  - /usr/local/bin/suricata NOT found"
        fi
        if maybe_sudo test -f /usr/bin/suricata; then
            warn_message "  - /usr/bin/suricata exists"
        else
            warn_message "  - /usr/bin/suricata NOT found"
        fi
        if maybe_sudo test -f /opt/wazuh/suricata/bin/suricata; then
            warn_message "  - /opt/wazuh/suricata/bin/suricata exists"
        else
            warn_message "  - /opt/wazuh/suricata/bin/suricata NOT found"
        fi
        validation_failed=1
    fi
    
    if ! maybe_sudo test -f "$RULES_DIR/suricata.rules"; then
        warn_message "Suricata rules file not present at $RULES_DIR/suricata.rules"
        validation_failed=1
    else
        success_message "Suricata rules file exists at $RULES_DIR/suricata.rules"
    fi
    
    if [ $validation_failed -eq 0 ]; then
        success_message "Suricata installation and configuration validation completed successfully."
    else
        error_message "Suricata installation and configuration validation failed."
        exit 1
    fi
}

# Check disk space
check_disk_space() {
    local required_space=204800  # 200MB
    local available_space
    available_space=$(df /tmp | awk 'NR==2 {print $4}')
    
    if [ "$available_space" -lt "$required_space" ]; then
        error_message "Insufficient disk space. At least 200MB required in /tmp"
        error_message "Available: $((available_space / 1024)) MB"
        exit 1
    fi
    
    info_message "Sufficient disk space available: $((available_space / 1024)) MB"
}

# Main Suricata installation for Linux
suricata_installation() {
    info_message "Starting Suricata installation for Linux..."
    
    check_disk_space
    
    local arch
    arch=$(detect_architecture)
    info_message "Detected Linux distribution: $DISTRO"
    info_message "Detected system architecture: $arch"
    
    case "$DISTRO" in
        centos|rhel|redhat|rocky|almalinux|fedora|ubuntu|debian)
            info_message "Distribution $DISTRO is supported"
            ;;
        *)
            error_message "Unsupported Linux distribution: $DISTRO"
            exit 1
            ;;
    esac
    
    install_dependencies
    download_suricata_package "$DISTRO" "$arch"
    install_suricata_package "$DISTRO"
    ensure_symlinks
    ensure_path_profile
    set_linux_capabilities
    download_rules
    setup_suricata_config
    validate_installation
    restart_wazuh_agent
    
    
    success_message "Suricata installation completed successfully!"
    echo ""
    info_message "========================================="
    info_message "   How to Use Suricata"
    info_message "========================================="
    echo ""
    info_message "If 'suricata' command is not found in your current shell:"
    echo ""
    info_message "  Option 1 - Restart your shell (recommended):"
    info_message "    exec bash"
    echo ""
    info_message "  Option 2 - Use absolute path:"
    info_message "    /usr/bin/suricata -V"
    echo ""
    info_message "  Option 3 - Add to current session:"
    info_message "    export PATH=/opt/wazuh/suricata/bin:\$PATH"
    echo ""
    info_message "To verify installation:"
    info_message "    suricata -V"
    echo ""
    info_message "========================================="
    echo ""

}

# Main Suricata installation for macOS
suricata_macos_installation() {
    info_message "Starting Suricata installation for macOS..."
    
    check_disk_space
    
    local arch
    arch=$(detect_architecture)
    info_message "Detected macOS architecture: $arch"
    
    install_dependencies
    download_suricata_macos_dmg "$arch"
    install_suricata_macos_dmg "$arch"
    download_rules
    setup_suricata_config
    validate_installation
    restart_wazuh_agent
    
    success_message "Suricata installation completed successfully!"
}

# Main function
main() {
    info_message "Starting Suricata installation script v${SURICATA_VERSION}"
    info_message "Detected OS: ${OS}"
    
    # Check if Wazuh agent is installed (do this early for all platforms)
    if [ "$OS" = "darwin" ]; then
        if [ ! -d "/Library/Ossec" ]; then
            error_message "Wazuh agent not installed at /Library/Ossec"
            error_message "Please install the Wazuh agent before running this script"
            exit 1
        fi
    else
        if [ ! -d "/var/ossec" ]; then
            error_message "Wazuh agent not installed at /var/ossec"
            error_message "Please install the Wazuh agent before running this script"
            exit 1
        fi
    fi
    
    # Run pre-installation checks and automatic cleanup (BEFORE macOS Intel delegation)
    info_message "Performing pre-installation checks..."
    pre_installation_check

    # Special case: macOS Intel (amd64) should delegate entirely to v0.1.5 installer
    if [ "$OS" = "darwin" ] && [ "$(detect_architecture)" = "amd64" ]; then
        info_message "macOS Intel detected. Delegating to remote v0.1.5 installer and exiting."
        local remote_installer="$TMP_DIR/remote-install.sh"
        if ! curl -fsSL -o "$remote_installer" "$REMOTE_MAC_AMD64_INSTALL_URL"; then
            error_message "Failed to download remote installer from $REMOTE_MAC_AMD64_INSTALL_URL"
            exit 1
        fi
        chmod +x "$remote_installer"
        # Run the remote installer with the same privileges and arguments
        bash "$remote_installer" "$@"
        exit $?
    fi
    
    # Proceed with installation
    case "$OS" in
        linux)
            suricata_installation
            ;;
        darwin)
            suricata_macos_installation
            ;;
        *)
            error_message "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"



