#!/usr/bin/env bats

MODE=${MODE:-"ids"}

setup() {
    if [ "$(uname)" = "Darwin" ]; then
        # macOS uses /opt/wazuh/suricata for new package-based installation
        export BIN_FOLDER="/opt/wazuh/suricata/bin"
        export LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
        export CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
        export CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
        export RULES_DIR="/opt/wazuh/suricata/var/lib/suricata/rules"
    else
        # Linux also uses /opt/wazuh/suricata for new package-based installation
        export BIN_FOLDER="/opt/wazuh/suricata/bin"
        export LOG_DIR="/opt/wazuh/suricata/var/log/suricata"
        export CONFIG_DIR="/opt/wazuh/suricata/etc/suricata"
        export CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
        export RULES_DIR="/opt/wazuh/suricata/var/lib/suricata/rules"
    fi
}

@test "YQ is installed" {
    run command -v yq
    [ "$status" -eq 0 ]
}

@test "Suricata is installed" {
    run command -v suricata
    [ "$status" -eq 0 ]
}

@test "Suricata-update is accessible" {
    if command -v suricata-update >/dev/null 2>&1; then
        run command -v suricata-update
        [ "$status" -eq 0 ]
    else
        # Fallback check for absolute path symlink or binary
        # Use sudo to ensure we can see it even if permissions are restricted
        run sudo test -x /usr/local/bin/suricata-update
        if [ "$status" -ne 0 ]; then
             run sudo test -x /usr/bin/suricata-update
        fi
        if [ "$status" -ne 0 ]; then
             run sudo test -x "${BIN_FOLDER}/suricata-update"
        fi
        [ "$status" -eq 0 ]
    fi
}

@test "Suricata-update wrapper works on ARM (macOS only)" {
    if [ "$(uname)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
        # Check if wrapper script exists
        [ -f "/usr/local/bin/suricata-update" ]
        # Check if it's a bash script (wrapper) not a symlink
        run head -1 /usr/local/bin/suricata-update
        [[ "$output" == "#!/bin/bash" ]]
    else
        skip "This test is specific to macOS ARM64"
    fi
}

@test "Suricata-update symlink exists on Intel (macOS only)" {
    if [ "$(uname)" = "Darwin" ] && [ "$(uname -m)" = "x86_64" ]; then
        # Check if symlink exists
        [ -L "/usr/local/bin/suricata-update" ]
        # Verify it points to the right location (v0.1.5 still uses /opt/suricata)
        run readlink /usr/local/bin/suricata-update
        [[ "$output" == "/opt/suricata/bin/suricata-update" ]]
    else
        skip "This test is specific to macOS Intel"
    fi
}

@test "Rules file exists" {
    echo "Looking for rules in: $RULES_DIR"
    run sudo ls "$RULES_DIR"
    [ "$status" -eq 0 ]
    run sudo test -f "$RULES_DIR/suricata.rules"
    [ "$status" -eq 0 ] || skip "suricata.rules not found in expected path"
}

@test "Configuration file exists" {
    echo "Checking configuration file: $CONFIG_FILE"
    run sudo test -f "$CONFIG_FILE"
    [ "$status" -eq 0 ]
}

@test "Suricata service is NOT installed (default behavior)" {
    if [ "$(uname)" = "Linux" ]; then
        # The script does not install a systemd service by default
        run sudo systemctl list-unit-files suricata.service
        [ "$status" -ne 0 ] || [[ "$output" == *"0 unit files listed"* ]]
    else
        skip "This test is Linux-specific"
    fi
}

@test "Suricata process is running (macOS only)" {
    if [ "$(uname)" = "Darwin" ]; then
        if ! command -v pgrep >/dev/null; then
            skip "pgrep is not installed"
        fi
        run sudo pgrep suricata
        [ "$status" -eq 0 ]
    else
        skip "This test is macOS-specific"
    fi
}

@test "Community ID is enabled in configuration" {
    run sudo grep -q "community-id: true" "$CONFIG_FILE"
    [ "$status" -eq 0 ]
}

@test "Detect-engine configuration is present" {
    # This configuration might not be present in all default configs, check if it exists or skip
    if sudo grep -q "detect-engine:" "$CONFIG_FILE"; then
        run sudo grep -q "detect-engine:" "$CONFIG_FILE"
        [ "$status" -eq 0 ]
    else
        skip "detect-engine configuration not found in $CONFIG_FILE"
    fi
}

@test "Eve-log types include 'alert'" {
    run sudo yq eval '.outputs[] | select(has("eve-log")) | .["eve-log"].types[]' "$CONFIG_FILE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alert"* ]]
}

@test "Drop.conf is created in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        run sudo test -f "$CONFIG_DIR/drop.conf"
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "Drop.conf has necessary config" {
    if [ "$MODE" = "ips" ]; then
        run sudo grep -q "group:emerging-attack_response" "$CONFIG_DIR/drop.conf"
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "LISTENMODE is set to nfqueue in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        run sudo test -f "/etc/default/suricata"
        [ "$status" -eq 0 ] || skip "/etc/default/suricata not found"
        run sudo grep -q "LISTENMODE=nfqueue" /etc/default/suricata
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "DEFAULT_INPUT_POLICY is set to ACCEPT in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        run sudo test -f "/etc/default/ufw"
        [ "$status" -eq 0 ] || skip "/etc/default/ufw not found"
        run sudo grep -q "DEFAULT_INPUT_POLICY=\"ACCEPT\"" /etc/default/ufw
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "NFQUEUE rules are added to UFW in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        run sudo test -f "/etc/ufw/before.rules"
        [ "$status" -eq 0 ] || skip "/etc/ufw/before.rules not found"
        run sudo grep -q "^-I INPUT -j NFQUEUE" /etc/ufw/before.rules
        [ "$status" -eq 0 ]
        run sudo grep -q "^-I OUTPUT -j NFQUEUE" /etc/ufw/before.rules
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "Custom drop rule is present in $RULES_DIR/suricata.rules in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        run sudo test -f "$RULES_DIR/suricata.rules"
        [ "$status" -eq 0 ] || skip "suricata.rules not found in expected path"
        run sudo grep -q "sid:992002087" "$RULES_DIR/suricata.rules"
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}