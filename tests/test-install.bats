#!/usr/bin/env bats

@test "Suricata is installed" {
  run suricata --version
  [ "$status" -eq 0 ]
  [[ "$output" =~ "6.0.8" ]] 
}

@test "Configuration file exists" {
  [ -f "/etc/suricata/suricata.yaml" ]
}

@test "Rules directory exists" {
  [ -f "/etc/suricata/rules/emerging-all.rules" ]
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