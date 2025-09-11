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
SURICATA_GITHUB_TAG="v8.0.0-adorsys.2-rc.2"
SURICATA_VERSION_MACOS=${SURICATA_VERSION_MACOS:-"8.0.0"}
SURICATA_INSTALL_DIR="/opt/suricata"
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

brew_as_user() {
    # Run brew as the logged in user for Homebrew operations
    sudo -u "$LOGGED_IN_USER" -i brew "$@"
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

MODE="ids"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help) show_help; exit 0 ;;
        --mode)
            if [[ "${2:-}" =~ ^(ids|ips)$ ]]; then MODE="$2"; shift
            else error_exit "Invalid mode: ${2:-}. Use 'ids' or 'ips'."; fi
            ;;
        *) error_exit "Unknown option: $1" ;;
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
    BIN_FOLDER="/opt/suricata"
    CONFIG_DIR="/etc/suricata"
    CONFIG_FILE="/etc/suricata/suricata.yaml"
    RULES_DIR="/var/lib/suricata/rules"
    INTERFACE="en0"
    ;;
*) error_exit "Unsupported operating system: $(uname)";;
esac
RULES_FILE="$RULES_DIR/suricata.rules"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) error_exit "Unsupported architecture: $(uname -m)" ;;
esac

# Validate mode
if [[ "$MODE" == "ips" && "$OS" != "linux" ]]; then
    error_exit "IPS mode is only supported on Linux systems."
fi

YQ_BINARY=${YQ_BINARY:-"yq_${OS}_${ARCH}"}

# Detect Linux Distribution
if [ "$OS" = "linux" ]; then
    detect_distro() {
        if [ -f /etc/os-release ]; then . /etc/os-release; echo "$ID"
        elif [ -f /etc/redhat-release ]; then echo "redhat"
        elif [ -f /etc/debian_version ]; then echo "debian"
        else error_exit "Unable to detect Linux distribution"; fi
    }
    DISTRO=$(detect_distro)
    case "$DISTRO" in
      ubuntu|debian) PACKAGE_MANAGER="apt"; INSTALL_CMD="install -y" ;;
      centos|fedora|rhel) PACKAGE_MANAGER="yum"; INSTALL_CMD="install -y" ;;
      *) error_exit "Unsupported Linux distribution: $DISTRO" ;;
    esac
    if ! command_exists systemctl; then error_exit "This script requires systemd to manage services."; fi
fi

# General Utility Functions
create_file() {
    local filepath="$1"; local content="$2"
    maybe_sudo bash -c "cat > \"$filepath\" <<'EOF'
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
    local filepath="$1"; local suricata_bin="$2"
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
    maybe_sudo launchctl load -w "$filepath" 2>/dev/null || warn_message "Loading plist failed: $filepath"
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
    if [ -z "$INTERFACE" ]; then INTERFACE="eth0"; warn_message "No Wi-Fi interface detected. Defaulting to: $INTERFACE"; fi
    info_message "Detected interface: $INTERFACE"
}

# Build PYTHONPATH from installed tree
compute_pythonpaths() {
    local python_paths=""
    for py_dir in /opt/suricata/lib/suricata/python /opt/suricata/lib/python* /opt/suricata/lib64/python*; do
        if [ -d "$py_dir" ]; then
            if [ -z "$python_paths" ]; then python_paths="$py_dir"; else python_paths="$python_paths:$py_dir"; fi
        fi
    done
    echo "$python_paths"
}

# Download and Extract Rules
download_rules() {
    local python_paths
    python_paths="$(compute_pythonpaths)"
    if [ -n "$python_paths" ]; then
        export PYTHONPATH="$python_paths:${PYTHONPATH:-}"
        info_message "Set PYTHONPATH=$python_paths for suricata-update"
    fi

    # Determine the suricata-update command based on OS
    local suricata_update_cmd
    if [ "$OS" = "darwin" ]; then
        # On macOS, use our wrapper script
        suricata_update_cmd="/usr/local/bin/suricata-update"
        if [ ! -f "$suricata_update_cmd" ]; then
            error_exit "suricata-update is not installed at $suricata_update_cmd. Please ensure installation completed successfully."
        fi
    else
        # On Linux, use the command from PATH
        if ! command_exists suricata-update; then
            error_exit "suricata-update is required to download and manage rules. Please install it."
        fi
        suricata_update_cmd="suricata-update"
    fi

    info_message "Updating suricata-update sources..."
    maybe_sudo "$suricata_update_cmd" update-sources || error_exit "Failed to update suricata-update sources."

    info_message "Enabling et/open source..."
    maybe_sudo "$suricata_update_cmd" enable-source et/open || error_exit "Failed to enable et/open source."

    if [[ "$MODE" == "ips" ]]; then
        local DROP_CONF_PATH="$CONFIG_DIR/drop.conf"
        info_message "Creating drop.conf for IPS mode at $DROP_CONF_PATH..."
        maybe_sudo bash -c "cat > \"$DROP_CONF_PATH\" <<'EOF'
# Convert specific SID to drop
#2019401
# Convert rules matching a pattern
#re:trojan
# Convert all rules in a specific group
group:emerging-attack_response
EOF"
        success_message "drop.conf created successfully."
    fi

    info_message "Downloading and applying rules using suricata-update..."
    maybe_sudo "$suricata_update_cmd" || error_exit "Failed to download and apply rules."
    success_message "Suricata rules downloaded and applied successfully."

    if maybe_sudo test -f "$RULES_FILE"; then
        info_message "Adding custom drop rule to $RULES_FILE..."
        maybe_sudo bash -c "echo 'drop tcp any any -> \$HOME_NET any (msg:\"TCP Scan ?\"; flow:from_client;flags:S; sid:992002087;rev:1;)' >> \"$RULES_FILE\""
        success_message "Custom drop rule added to $RULES_FILE."
    else
        warn_message "$RULES_FILE not found. Skipping custom rule addition."
    fi
}

# Create and Update Suricata Configuration
update_config() {
    detect_wifi_interface

    sed_alternative -i "s|interface: eth0|interface: $INTERFACE|" "$CONFIG_FILE" || error_exit "Failed to set interface in $CONFIG_FILE"
    sed_alternative -i "s|community-id: false|community-id: true|" "$CONFIG_FILE" || error_exit "Failed to enable community-id in $CONFIG_FILE"

    if ! grep -q "detect-engine:" "$CONFIG_FILE"; then
        echo -e "\ndetect-engine:\n  - rule-reload: true" | maybe_sudo tee -a "$CONFIG_FILE" >/dev/null || error_exit "Failed to append detect-engine config"
    fi

    maybe_sudo yq -i '(.outputs[] | select(has("eve-log"))."eve-log".types) = ["alert"]' "$CONFIG_FILE" || error_exit "Failed to update eve-log types with yq"

    if [[ "$MODE" == "ips" && "$OS" == "linux" ]]; then
        local SURICATA_DEFAULT_FILE="/etc/default/suricata"
        local UFW_DEFAULT_FILE="/etc/default/ufw"
        [ -f "$SURICATA_DEFAULT_FILE" ] && sed_alternative -i "s|LISTENMODE=af-packet|LISTENMODE=nfqueue|" "$SURICATA_DEFAULT_FILE" || warn_message "$SURICATA_DEFAULT_FILE not found."
        [ -f "$UFW_DEFAULT_FILE" ] && sed_alternative -i "s|DEFAULT_INPUT_POLICY=\"DROP\"|DEFAULT_INPUT_POLICY=\"ACCEPT\"|" "$UFW_DEFAULT_FILE" || warn_message "$UFW_DEFAULT_FILE not found."
        local UFW_BEFORE_RULES="/etc/ufw/before.rules"
        if [[ -f "$UFW_BEFORE_RULES" ]]; then
            if ! grep -q "^-I INPUT -j NFQUEUE" "$UFW_BEFORE_RULES"; then
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
    if command_exists brew; then
        local suricata_found=false
        if brew_as_user list suricata >/dev/null 2>&1; then suricata_found=true; info_message "Found Homebrew-installed Suricata package"; fi
        if brew_as_user list | grep -E "suricata" >/dev/null 2>&1; then suricata_found=true; info_message "Found Suricata installed from Homebrew tap"; fi
        if [ "$suricata_found" = true ]; then
            info_message "Removing Homebrew-installed Suricata..."
            brew_as_user unpin suricata 2>/dev/null || true
            brew_as_user uninstall --force --ignore-dependencies suricata 2>/dev/null || true
            local tap_suricatas
            tap_suricatas=$(brew_as_user list | grep -E ".*suricata.*" || true)
            if [ -n "$tap_suricatas" ]; then
                for pkg in $tap_suricatas; do
                    info_message "Removing tap package: $pkg"
                    brew_as_user uninstall --force --ignore-dependencies "$pkg" 2>/dev/null || true
                done
            fi
            local brew_prefix
            brew_prefix=$(brew_as_user --prefix 2>/dev/null || echo "/usr/local")
            for dir in "$brew_prefix/etc/suricata" "$brew_prefix/var/lib/suricata" "$brew_prefix/var/log/suricata"; do
                if [ -d "$dir" ]; then
                    info_message "Removing Homebrew Suricata directory: $dir"
                    maybe_sudo rm -rf "$dir"
                fi
            done
            success_message "Homebrew Suricata cleanup complete"
        else
            info_message "No Homebrew Suricata installation found"
        fi
    fi
}

install_suricata_launcher() {
  # Normalize shebang of the packaged script
  if [ -f /opt/suricata/bin/suricata-update ]; then
    info_message "Normalizing suricata-update shebang to /usr/bin/env python3"
    if [[ "$OS" == "darwin" ]]; then
      maybe_sudo /usr/bin/sed -i '' '1s|^#!.*|#!/usr/bin/env python3|' /opt/suricata/bin/suricata-update
    else
      sed_alternative -i '1s|^#!.*|#!/usr/bin/env python3|' /opt/suricata/bin/suricata-update
    fi
  else
    warn_message "/opt/suricata/bin/suricata-update not found; skipping normalization"
    return
  fi

  # Build PYTHONPATH list
  local python_paths; python_paths=""
  for d in /opt/suricata/lib/suricata/python /opt/suricata/lib/python* /opt/suricata/lib64/python*; do
    [ -d "$d" ] && python_paths="${python_paths:+$python_paths:}$d"
  done

  # Write to a temp file first
  local tmp_launcher="/tmp/suricata-update.$$"
  maybe_sudo bash -c "cat > '$tmp_launcher' <<'EOF'
#!/bin/bash
set -euo pipefail
export PYTHONPATH="__PYTHON_PATHS__:\${PYTHONPATH:-}"
exec /usr/bin/env python3 /opt/suricata/bin/suricata-update "\$@"
EOF"
  # Inject python_paths (even if empty)
  if [[ "$OS" == "darwin" ]]; then
    maybe_sudo /usr/bin/sed -i '' "s|__PYTHON_PATHS__|$python_paths|" "$tmp_launcher"
  else
    sed_alternative -i "s|__PYTHON_PATHS__|$python_paths|" "$tmp_launcher"
  fi

  # Replace any existing symlink/file atomically
  maybe_sudo rm -f /usr/local/bin/suricata-update
  maybe_sudo mv -f "$tmp_launcher" /usr/local/bin/suricata-update
  maybe_sudo chmod +x /usr/local/bin/suricata-update

  success_message "suricata-update launcher installed at /usr/local/bin/suricata-update"
}


download_and_install_suricata_macos() {
    local tag="$1"
    local arch="$2"

    info_message "Installing Suricata ${tag} for macOS ${arch}"

    remove_brew_suricata

    local base_url="https://github.com/ADORSYS-GIS/wazuh-suricata-package/releases/download"
    local version_without_v
    version_without_v=$(echo "$tag" | sed 's/^v//')
    local filename="suricata-${version_without_v}-macos-${arch}.tar.gz"
    local download_url="${base_url}/${tag}/${filename}"
    local temp_dir="/tmp/suricata-install-$$"

    info_message "Creating temporary directory: $temp_dir"
    mkdir -p "$temp_dir" || error_exit "Failed to create temporary directory"

    info_message "Downloading Suricata from: $download_url"
    if command_exists curl; then
        curl -L --fail --progress-bar -o "${temp_dir}/${filename}" "$download_url" || { rm -rf "$temp_dir"; error_exit "Failed to download Suricata from $download_url"; }
    else
        rm -rf "$temp_dir"; error_exit "curl is required but not installed"
    fi

    success_message "Download completed successfully"

    info_message "Removing macOS quarantine attribute from downloaded file"
    xattr -d com.apple.quarantine "${temp_dir}/${filename}" 2>/dev/null || warn_message "Quarantine attribute not present"

    info_message "Extracting Suricata archive"
    tar -xzf "${temp_dir}/${filename}" -C "${temp_dir}" || { rm -rf "$temp_dir"; error_exit "Failed to extract Suricata archive"; }

    local src_dir="${temp_dir}"

    info_message "Copying configuration files to /etc"
    if [ -d "${src_dir}/etc" ]; then
        maybe_sudo rsync -av --progress "${src_dir}/etc/" /etc/ || { rm -rf "$temp_dir"; error_exit "Failed to copy configuration files to /etc"; }
    else
        warn_message "No etc directory found in archive"
    fi

    info_message "Copying Suricata files to /opt"
    if [ -d "${src_dir}/opt" ]; then
        maybe_sudo rsync -av --progress "${src_dir}/opt/" /opt/ || { rm -rf "$temp_dir"; error_exit "Failed to copy Suricata files to /opt"; }
    else
        rm -rf "$temp_dir"; error_exit "Expected opt directory not found in archive"
    fi

    info_message "Creating runtime directories under /var"
    maybe_sudo install -d -m 755 \
        /var/lib/suricata/cache/sgh \
        /var/lib/suricata/data \
        /var/log/suricata/certs \
        /var/log/suricata/files \
        /var/run/suricata || warn_message "Some runtime directories may not have been created"

    info_message "Removing macOS quarantine attributes from installed files"
    maybe_sudo xattr -dr com.apple.quarantine /opt/suricata 2>/dev/null || warn_message "Quarantine removal (opt) not needed"
    maybe_sudo xattr -dr com.apple.quarantine /etc/suricata 2>/dev/null || warn_message "Quarantine removal (etc) not needed"

    info_message "Setting executable permissions on Suricata binaries"
    maybe_sudo chmod +x /opt/suricata/bin/* || { rm -rf "$temp_dir"; error_exit "Failed to set executable permissions"; }

    info_message "Linking suricata binary to /usr/local/bin"
    maybe_sudo ln -sf /opt/suricata/bin/suricata /usr/local/bin/suricata || warn_message "Could not create symlink for suricata"

    # --- FIX: normalize shebang and create portable launcher (no recursion, no hardcoded /opt/homebrew) ---
    install_suricata_launcher

    info_message "Cleaning up temporary files"
    rm -rf "$temp_dir"

    success_message "Suricata ${tag} installed successfully"
}

# --- Installers and flow ---

print_step_header 1 "Installing dependencies and Suricata"
if [ "$OS" = "linux" ]; then
    if [ "${DISTRO:-}" = "ubuntu" ] || [ "${DISTRO:-}" = "debian" ]; then
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

        if command_exists yq; then info_message "yq is already installed."
        else
            info_message "Installing yq..."
            maybe_sudo curl -SL --progress-bar "https://github.com/mikefarah/yq/releases/latest/download/${YQ_BINARY}" -o /usr/bin/yq
            maybe_sudo chmod +x /usr/bin/yq
            info_message "yq installed at: /usr/bin/yq"
        fi

        info_message "Installing Suricata..."
        maybe_sudo $PACKAGE_MANAGER $INSTALL_CMD suricata
        # Use exact path for Linux
        SURICATA_BIN="/usr/bin/suricata"
        if [ ! -f "$SURICATA_BIN" ]; then
            # Fallback to searching in PATH if not in expected location
            SURICATA_BIN=$(command -v suricata || echo "not found")
            if [ "$SURICATA_BIN" = "not found" ]; then
                error_exit "Suricata binary not found after installation"
            fi
        fi
        success_message "Suricata installed at: $SURICATA_BIN"

        if ! command_exists pip && ! command_exists pip3; then
            info_message "Installing Python pip..."
            maybe_sudo $PACKAGE_MANAGER $INSTALL_CMD python3-pip
        fi

        info_message "Installing PyYAML for suricata-update..."
        if command_exists pip3; then maybe_sudo pip3 install pyyaml || warn_message "Failed to install pyyaml with pip3"
        elif command_exists pip; then maybe_sudo pip install pyyaml || warn_message "Failed to install pyyaml with pip"
        else warn_message "pip not found, skipping pyyaml installation"; fi
    fi
elif [ "$OS" = "darwin" ]; then
    if command_exists brew; then
        info_message "Installing required dependencies for Suricata..."
        deps=("yq" "jansson" "libmagic" "libnet" "libyaml" "lz4" "pcre2" "python@3.13")
        for dep in "${deps[@]}"; do
            if ! brew_as_user list "$dep" >/dev/null 2>&1; then
                info_message "Installing $dep..."
                brew_as_user install "$dep" || warn_message "Failed to install $dep"
            else
                info_message "$dep is already installed."
            fi
        done
    else
        if ! command_exists yq; then
            info_message "Installing yq manually..."
            maybe_sudo curl -SL --progress-bar "https://github.com/mikefarah/yq/releases/latest/download/${YQ_BINARY}" -o /usr/local/bin/yq
            maybe_sudo chmod +x /usr/local/bin/yq
        fi
        warn_message "Critical dependencies (jansson, libmagic, libnet, libyaml, lz4, pcre2, python) cannot be installed without Homebrew."
        warn_message "Suricata may not function properly. Please install Homebrew and re-run this script."
    fi

    if ! command_exists pip && ! command_exists pip3; then
        info_message "Installing Python pip..."
        if command_exists brew; then brew_as_user install python3
        else warn_message "Cannot install pip without Homebrew. Please install Python 3 manually."; fi
    fi

    info_message "Installing PyYAML for suricata-update..."
    if command_exists pip3; then
        pip3 install --user --break-system-packages pyyaml 2>/dev/null || pip3 install --user pyyaml 2>/dev/null || warn_message "Failed to install pyyaml with pip3"
    elif command_exists pip; then
        pip install --user --break-system-packages pyyaml 2>/dev/null || pip install --user pyyaml 2>/dev/null || warn_message "Failed to install pyyaml with pip"
    else
        warn_message "pip not found, skipping pyyaml installation"
    fi

    download_and_install_suricata_macos "$SURICATA_GITHUB_TAG" "$ARCH"
    # Use exact path for macOS prebuilt binary
    SURICATA_BIN="/usr/local/bin/suricata"
    if [ ! -L "$SURICATA_BIN" ] && [ ! -f "$SURICATA_BIN" ]; then
        # If symlink wasn't created, use direct path
        SURICATA_BIN="/opt/suricata/bin/suricata"
        if [ ! -f "$SURICATA_BIN" ]; then
            error_exit "Suricata binary not found after installation"
        fi
    fi
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
        maybe_sudo ufw disable || true
        maybe_sudo ufw enable || true
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
# Validate the SURICATA_BIN path that was set during installation
if [ -z "${SURICATA_BIN:-}" ]; then
    error_exit "SURICATA_BIN variable not set during installation"
elif [ ! -f "$SURICATA_BIN" ] && [ ! -L "$SURICATA_BIN" ]; then
    error_exit "Suricata executable not found at: $SURICATA_BIN"
else
    success_message "Suricata executable validated at: $SURICATA_BIN"
fi

# Bonus: show suricata-update wiring
if command_exists suricata-update; then
    info_message "suricata-update path: $(command -v suricata-update)"
    head -n 3 "$(command -v suricata-update)" || true
fi

success_message "Suricata installation and configuration complete!"
