#!/usr/bin/env bats

setup() {
    # Determine the operating system
    if [ "$(uname)" = "Darwin" ]; then        
        export LOG_DIR="/var/log/suricata"
        export CONFIG_DIR="/etc/suricata"
        export CONFIG_FILE="$CONFIG_DIR/suricata.yaml"
        export RULES_DIR="/var/lib/suricata"
    else
        BIN_FOLDER=$(brew --prefix)
        export LOG_DIR="$BIN_FOLDER/var/log/suricata"
        export CONFIG_DIR="$BIN_FOLDER/etc/suricata"
        export CONFIG_FILE="$BIN_FOLDER/etc/suricata/suricata.yaml"
        export RULES_DIR="$BIN_FOLDER/var/lib/suricata"
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
  [ -f "$RULES_DIR/suricata.rules" ]
}

@test "Configuration file exists" {
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

@test "Active network interface is set in configuration" {
  run grep -q "interface: " "$CONFIG_FILE"
  [ "$status" -eq 0 ]
}

@test "Community ID is enabled in configuration" {
  run grep -q "community-id: true" "$CONFIG_FILE"
  [ "$status" -eq 0 ]
}

@test "Detect-engine configuration is present" {
  run grep -q "detect-engine:" "$CONFIG_FILE"
  [ "$status" -eq 0 ]
}

@test "Eve-log types are updated" {
  run yq eval '(.outputs[] | select(has("eve-log"))."eve-log".types) == ["alert", "anomaly"]' "$CONFIG_FILE"
  [ "$status" -eq 0 ]
}

@test "Drop.conf is created in IPS mode" {
  if [ "$MODE" = "ips" ]; then
    [ -f "$CONFIG_DIR/drop.conf" ]
  else
    skip "This test is specific to IPS mode."
  fi
}

@test "NFQUEUE rules are added to UFW in IPS mode" {
  if [ "$MODE" = "ips" ]; then
    run grep -q "-I INPUT -j NFQUEUE" /etc/ufw/before.rules
    [ "$status" -eq 0 ]
    run grep -q "-I OUTPUT -j NFQUEUE" /etc/ufw/before.rules
    [ "$status" -eq 0 ]
  else
    skip "This test is specific to IPS mode."
  fi
}