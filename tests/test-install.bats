#!/usr/bin/env bats

MODE=${MODE:-"ids"}

setup() {
    if [ "$(uname)" = "Darwin" ]; then
        export BIN_FOLDER=$(brew --prefix)
        export LOG_DIR="$BIN_FOLDER/var/log/suricata"
        export CONFIG_DIR="$BIN_FOLDER/etc/suricata"
        export CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
        export RULES_DIR="$BIN_FOLDER/var/lib/suricata/rules"
    else
        export LOG_DIR="/var/log/suricata"
        export CONFIG_DIR="/etc/suricata"
        export CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
        export RULES_DIR="/var/lib/suricata/rules"
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

@test "Rules file exists" {
    echo "Looking for rules in: $RULES_DIR"
    run ls "$RULES_DIR"
    [ "$status" -eq 0 ]
    [ -f "$RULES_DIR/suricata.rules" ] || skip "suricata.rules not found in expected path"
}

@test "Configuration file exists" {
    echo "Checking configuration file: $CONFIG_FILE"
    [ -f "$CONFIG_FILE" ]
}

@test "Suricata service is running (Linux only)" {
    if [ "$(uname)" = "Linux" ]; then
        run systemctl is-active suricata
        [ "$status" -eq 0 ]
        [ "$output" = "active" ]
    else
        skip "This test is Linux-specific"
    fi
}

@test "Suricata process is running (macOS only)" {
    if [ "$(uname)" = "Darwin" ]; then
        run pgrep suricata
        [ "$status" -eq 0 ]
    else
        skip "This test is macOS-specific"
    fi
}

@test "Community ID is enabled in configuration" {
    run grep -q "community-id: true" "$CONFIG_FILE"
    [ "$status" -eq 0 ]
}

@test "Detect-engine configuration is present" {
    run grep -q "detect-engine:" "$CONFIG_FILE"
    [ "$status" -eq 0 ]
}

@test "Eve-log types include 'alert'" {
    run yq eval '.outputs[] | select(has("eve-log")) | .["eve-log"].types[]' "$CONFIG_FILE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"alert"* ]]
}

@test "Drop.conf is created in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        [ -f "$CONFIG_DIR/drop.conf" ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "Drop.conf has necessary config" {
  if [ "$MODE" = "ips" ]; then
      run grep -q "group:emerging-attack_response" "$CONFIG_DIR/drop.conf"
      [ "$status" -eq 0 ]
  else
      skip "This test is specific to IPS mode."
  fi
  
}

@test "LISTENMODE is set to nfqueue in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        [ -f "/etc/default/suricata" ] || skip "/etc/default/suricata not found"
        run grep -q "LISTENMODE=nfqueue" /etc/default/suricata
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "DEFAULT_INPUT_POLICY is set to ACCEPT in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        [ -f "/etc/default/ufw" ] || skip "/etc/default/ufw not found"
        run grep -q "DEFAULT_INPUT_POLICY=\"ACCEPT\"" /etc/default/ufw
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "NFQUEUE rules are added to UFW in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        [ -f "/etc/ufw/before.rules" ] || skip "/etc/ufw/before.rules not found"
        run grep -q "^-I INPUT -j NFQUEUE" /etc/ufw/before.rules
        [ "$status" -eq 0 ]
        run grep -q "^-I OUTPUT -j NFQUEUE" /etc/ufw/before.rules
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}

@test "Custom drop rule is present in suricata.rules in IPS mode" {
    if [ "$MODE" = "ips" ]; then
        [ -f "$RULES_DIR/suricata.rules" ] || skip "suricata.rules not found in expected path"
        run grep -q 'drop tcp any any -> \$HOME_NET !80 (msg:"TCP Scan ?"; flow:from_client;flags:S; sid:992002087;rev:1;)' "$RULES_DIR/suricata.rules"
        [ "$status" -eq 0 ]
    else
        skip "This test is specific to IPS mode."
    fi
}
