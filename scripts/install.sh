#!/bin/bash

# Set shell options
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
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

# Environment Variables
SURICATA_USER=${SURICATA_USER:-"root"}
CONFIG_FILE=""
INTERFACE=""
LAUNCH_AGENT_FILE="/Library/LaunchDaemons/com.suricata.suricata.plist"
RULES_URL="https://rules.emergingthreats.net/open/suricata-6.0.8/emerging-all.rules.tar.gz"
TAR_PATH="/tmp/emerging-all.rules.tar.gz"

# OS and Architecture Detection
case "$(uname)" in
Linux)
    OS="linux"
    LOG_DIR="/var/log/suricata"
    CONFIG_DIR="/etc/suricata"
    CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
    RULES_DIR="/etc/suricata/rules"
    INTERFACE="wlp0s20f3"
    ;;
Darwin)
    OS="darwin"
    BIN_FOLDER=$(brew --prefix)
    LOG_DIR="$BIN_FOLDER/var/log/suricata"
    CONFIG_DIR="$BIN_FOLDER/etc/suricata"
    CONFIG_FILE="$BIN_FOLDER/etc/suricata/suricata.yaml"
    RULES_DIR="$BIN_FOLDER/etc/suricata/rules"
    INTERFACE="en0"
    ;;
*) error_exit "Unsupported operating system: $(uname)" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
x86_64) ARCH="amd64" ;;
arm64 | aarch64) ARCH="arm64" ;;
*) error_exit "Unsupported architecture: $ARCH" ;;
esac

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
        ubuntu|debian)
            PACKAGE_MANAGER="apt"
            INSTALL_CMD="install -y"
            ;;
        centos|fedora|rhel)
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
        INTERFACE=$(networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}')
    elif command_exists ip; then
        INTERFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(en|eth|wl)' | head -n1)
    elif command_exists ifconfig; then
        INTERFACE=$(ifconfig | awk -F': ' '{print $1}' | grep -E '^(en|eth|wl)' | head -n1)
    else
        warn_message "Could not detect Wi-Fi interface. Using default: $INTERFACE"
    fi
    if [ -z "$INTERFACE" ]; then
        INTERFACE="eth0" # Default fallback for environments without Wi-Fi interfaces
        warn_message "No Wi-Fi interface detected. Using default: $INTERFACE"
    fi
    info_message "Detected interface: $INTERFACE"
}

# Get HOME_NET
get_home_net() {
    if command_exists ip; then
        HOME_NET=$(ip addr show ${INTERFACE} | grep -o "inet [0-9./]*" | awk '{print $2}' | head -n1)
    elif command_exists ifconfig; then
        IP=$(ifconfig ${INTERFACE} | grep -o "inet [0-9.]*" | awk '{print $2}' | head -n1)
        MASK=$(ifconfig ${INTERFACE} | grep -o "netmask [0-9.]*" | awk '{print $2}' | head -n1)
        HOME_NET="$IP/$(mask_to_cidr ${MASK})"
    else
        HOME_NET="192.168.1.0/24" # Default fallback
        warn_message "Could not determine HOME_NET. Using default: $HOME_NET"
    fi
    if [ -z "$HOME_NET" ]; then
        HOME_NET="192.168.1.0/24" # Default fallback for environments without Wi-Fi interfaces
        warn_message "Could not determine HOME_NET. Using default: $HOME_NET"
    fi
    info_message "HOME_NET set to: $HOME_NET"
}

# Convert netmask to CIDR
mask_to_cidr() {
    local mask="$1"
    local cidr=0
    IFS='.' read -r a b c d <<< "$mask"
    for octet in $a $b $c $d; do
        while [ $octet -gt 0 ]; do
            cidr=$((cidr + (octet % 2)))
            octet=$((octet / 2))
        done
    done
    echo "$cidr"
}

# Download and Extract Rules
download_rules() {
    if ! command_exists curl; then
        error_exit "curl is required to download rules."
    fi
    maybe_sudo curl -SL --progress-bar "$RULES_URL" -o "$TAR_PATH" || error_exit "Failed to download rules from $RULES_URL"
    maybe_sudo mkdir -p "$RULES_DIR"
    maybe_sudo tar -xzf "$TAR_PATH" -C "$RULES_DIR" || error_exit "Failed to extract rules."
    maybe_sudo rm -f "$TAR_PATH"
    success_message "Suricata rules downloaded and extracted to $RULES_DIR"
}

# Create and Update Suricata Configuration
update_config() {
    CONFIG_CONTENT=$(cat <<"EOF"
%YAML 1.1
---

# Suricata configuration file for NIDS with simplified logging
# Generated by Suricata 6.0.20, tailored for minimal logs
suricata-version: "6.0"

##
## Step 1: Inform Suricata about your network
##

vars:
  address-groups:
    HOME_NET: "[HOME_NET]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

##
## Step 2: Select outputs to enable
##

default-log-dir: [LOG_DIR]

# Global stats configuration
stats:
  enabled: yes
  interval: 21600  # Log stats every 6 hours to reduce verbosity

# Configure outputs for simplified logging
outputs:
  # Fast log for concise, human-readable alerts
  - fast:
      enabled: yes
      filename: fast.log
      append: yes

  # EVE JSON log with only alert and anomaly events for simplicity
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      pcap-file: false
      community-id: false
      community-id-seed: 0
      xff:
        enabled: no
        mode: extra-data
        deployment: reverse
        header: X-Forwarded-For
      types:
        - alert
        - anomaly

  # Stats log for troubleshooting, separate from eve.json
  - stats:
      enabled: yes
      filename: stats.log
      append: yes
      totals: yes
      threads: no

  # Disable other outputs to reduce disk I/O
  - http-log:
      enabled: no
      filename: http.log
      append: yes
  - tls-log:
      enabled: no
      filename: tls.log
      append: yes
  - tls-store:
      enabled: no
  - pcap-log:
      enabled: no
      filename: log.pcap
      limit: 1000mb
      max-files: 2000
      compression: none
      mode: normal
      use-stream-depth: no
      honor-pass-rules: no
  - alert-debug:
      enabled: no
      filename: alert-debug.log
      append: yes
  - alert-prelude:
      enabled: no
      profile: suricata
      log-packet-content: no
      log-packet-header: yes
  - syslog:
      enabled: no
      facility: local5
  - file-store:
      version: 2
      enabled: no
  - tcp-data:
      enabled: no
      type: file
      filename: tcp-data.log
  - http-body-data:
      enabled: no
      type: file
      filename: http-data.log
  - lua:
      enabled: no
      scripts:

# Logging configuration for Suricata operations
logging:
  default-log-level: notice
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: suricata.log
  - syslog:
      enabled: no
      facility: local5
      format: "[%i] <%d> -- "

##
## Step 3: Configure capture settings
##

# Linux high-speed capture support
af-packet:
  - interface: [INTERFACE]
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
  - interface: default

# Cross-platform libpcap capture support
pcap:
  - interface: [INTERFACE]
  - interface: default

pcap-file:
  checksum-checks: auto

##
## Step 4: App Layer Protocol configuration
##

app-layer:
  protocols:
    rfb:
      enabled: yes
      detection-ports:
        dp: 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909
    mqtt:
      enabled: yes
    krb5:
      enabled: yes
    snmp:
      enabled: yes
    ikev2:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
    rdp:
      enabled: yes
    ssh:
      enabled: yes
    http2:
      enabled: no
      http1-rules: no
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
      inspected-tracker:
        content-limit: 100000
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    imap:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
    nfs:
      enabled: yes
    tftp:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 100kb
            decompress-depth: 100kb
        server-config:
    modbus:
      enabled: no
      detection-ports:
        dp: 502
      stream-depth: 0
    dnp3:
      enabled: no
      detection-ports:
        dp: 20000
    enip:
      enabled: no
      detection-ports:
        dp: 44818
        sp: 44818
    ntp:
      enabled: yes
    dhcp:
      enabled: yes
    sip:
      enabled: yes

asn1-max-frames: 256

datasets:
  defaults:
  rules:

##
## Advanced settings
##

security:
  lua:
host-mode: sniffer-only  # NIDS mode, no packet modification
unix-command:
  enabled: auto
legacy:
  uricontent: enabled

engine-analysis:
  rules-fast-pattern: yes
  rules: yes
pcre:
  match-limit: 3500
  match-limit-recursion: 1500

host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: []
  old-solaris: []
  solaris: []
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30
vlan:
  use-for-tracking: true
flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
    emergency-new: 5
    emergency-established: 100
    emergency-closed: 10
    emergency-bypassed: 50
  udp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50
  icmp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: no  # Disabled for NIDS
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb
decoder:
  teredo:
    enabled: true
    ports: \$TEREDO_PORTS
  vxlan:
    enabled: true
    ports: \$VXLAN_PORTS
  vntag:
    enabled: false
  geneve:
    enabled: true
    ports: \$GENEVE_PORTS

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm
  profiling:
    grouping:
      dump-to-disk: false
      include-rules: false
      include-mpm-stats: false
mpm-algo: auto
spm-algo: auto
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"
  detect-thread-ratio: 1.0
luajit:
  states: 128
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    limit: 10
    json: yes
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: yes
    filename: prefilter_perf.log
    append: yes
  rulegroups:
    enabled: yes
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes
  pcap-log:
    enabled: no
    filename: pcaplog_stats.log
    append: yes

nflog:
  - group: 2
    buffer-size: 18432
  - group: default
    qthreshold: 1
    qtimeout: 100
    max-size: 20000

capture:
netmap:
 - interface: default
pfring:
  - interface: default
ipfw:
napatech:
    streams: ["0-3"]
    enable-stream-stats: no
    auto-config: yes
    hardware-bypass: yes
    inline: no
    ports: [0-1,2-3]
    hashmode: hash5tuplesorted

# Rule configuration
default-rule-path: [RULES_DIR]
rule-files:
- "*.rules"
classification-file: [CONFIG_DIR]/classification.config
reference-config-file: [CONFIG_DIR]/reference.config
EOF
)
    create_file "$CONFIG_FILE" "$CONFIG_CONTENT"
    # Replace [HOME_NET] and [INTERFACE] in the file
    sed_alternative -i "s|\[LOG_DIR\]|${LOG_DIR}|g" "$CONFIG_FILE" || error_exit "Failed to set LOG_DIR: "$LOG_DIR" in $CONFIG_FILE"
    sed_alternative -i "s|\[HOME_NET\]|${HOME_NET}|g" "$CONFIG_FILE" || error_exit "Failed to set HOME_NET: "$HOME_NET" in $CONFIG_FILE"
    sed_alternative -i "s|\[INTERFACE\]|${INTERFACE}|g" "$CONFIG_FILE" || error_exit "Failed to set INTERFACE: "$INTERFACE" in $CONFIG_FILE"
    sed_alternative -i "s|\[RULES_DIR\]|${RULES_DIR}|g" "$CONFIG_FILE" || error_exit "Failed to set RULES_DIR: "$RULES_DIR" in $CONFIG_FILE"
    sed_alternative -i "s|\[CONFIG_DIR\]|${CONFIG_DIR}|g" "$CONFIG_FILE" || error_exit "Failed to set CONFIG_DIR: "$CONFIG_DIR" in $CONFIG_FILE"
    success_message "Suricata configuration created and updated: $CONFIG_FILE"
}

# Installation Process
print_step_header 1 "Installing dependencies and Suricata"
if [ "$OS" = "linux" ]; then
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        if ! grep -q "oisf/suricata-stable" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
            info_message "Updating package lists and adding Suricata repository..."
            maybe_sudo "$PACKAGE_MANAGER" update
            maybe_sudo add-apt-repository ppa:oisf/suricata-stable -y
            maybe_sudo "$PACKAGE_MANAGER" update
        else
            info_message "Suricata repository already added, updating package lists..."
        fi
        info_message "Installing Suricata..."
        maybe_sudo $PACKAGE_MANAGER $INSTALL_CMD suricata
        SURICATA_BIN=$(command -v suricata || echo "/usr/bin/suricata")
        success_message "Suricata installed at: $SURICATA_BIN"
fi
elif [ "$OS" = "darwin" ]; then
    info_message "Installing Suricata via Homebrew..."
    brew install suricata
    SURICATA_BIN=$(command -v suricata || echo "/usr/local/bin/suricata")
    success_message "Suricata installed at: $SURICATA_BIN"
fi

detect_wifi_interface
get_home_net

print_step_header 2 "Downloading Suricata rules"
download_rules

print_step_header 3 "Creating and updating Suricata configuration"
update_config

if [ "$OS" = "linux" ]; then
    print_step_header 4 "Restarting Suricata service to include new configuration"
    maybe_sudo systemctl restart suricata
elif [ "$OS" = "darwin" ]; then
    print_step_header 4 "Setting up Suricata to start at boot"
    create_launchd_plist_file "$LAUNCH_AGENT_FILE" "$SURICATA_BIN"
fi

print_step_header 5 "Validating installation"
if [ -f "$CONFIG_FILE" ]; then
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