# Architecture Overview

This document explains how Suricata integrates with the Wazuh agent to monitor network traffic and send security alerts to your Wazuh manager.

## How It Works

Suricata is a network threat detection engine. It inspects network traffic passing through your computer or server. When Suricata spots malicious activity, it writes a detailed event to an alert log. The Wazuh agent reads this log in real time and sends the alerts to the Wazuh manager.

```
       Network Traffic
              │
              ▼
   ┌──────────────────────┐
   │   Suricata Engine    │  Inspects packets against rules
   └──────────┬───────────┘
              │ Writes alerts
              ▼
   ┌──────────────────────┐
   │       eve.json       │  Structured JSON log file
   └──────────┬───────────┘
              │ Reads log entries
              ▼
   ┌──────────────────────┐
   │     Wazuh Agent      │  <localfile> collector in ossec.conf
   └──────────┬───────────┘
              │ Sends alerts securely
              ▼
   ┌──────────────────────┐
   │    Wazuh Manager     │  Decodes events, triggers alerts, and shows in Dashboard
   └──────────────────────┘
```

## Step by Step Event Flow

1. **Packet Capture**: Suricata captures packets from the active network interface (such as `eth0`, `en0`, or a Windows network adapter).
2. **Rule Matching**: Suricata compares network packets with rules from the Emerging Threats open ruleset.
3. **Alert Generation**: When a packet matches a rule, Suricata records the event in `eve.json`. Every alert includes source IP, destination IP, port numbers, protocol, and a unique Community ID to correlate events across systems.
4. **Log Collection**: The Wazuh agent has a `localfile` block configured in `ossec.conf`. It monitors `eve.json` for new lines.
5. **Wazuh Processing**: The Wazuh manager receives the event, decodes the JSON payload, applies its Suricata ruleset (rules starting at ID 86600), and shows the alert in the web dashboard.

## Operating Modes

Suricata can run in two modes:

- **IDS Mode (Intrusion Detection System)**: This is the default mode. Suricata listens to network traffic in the background without modifying or slowing down connections. It alerts you when suspicious traffic is seen.
- **IPS Mode (Intrusion Prevention System)**: In this mode, traffic passes through Suricata before reaching the system. Suricata can drop bad packets directly. This mode is available on Linux using NFQueue.

## Community ID Support

Our installation automatically turns on `community-id: true` in the Suricata configuration. Community ID creates a standard hash from the flow tuple (source IP, destination IP, ports, and protocol). This makes it easy to correlate Suricata alerts with logs from other tools like Zeek, firewall logs, and Wazuh system alerts.

## Standard File Paths

| Component | Linux | macOS | Windows |
| :--- | :--- | :--- | :--- |
| **Config File** | `/opt/wazuh/suricata/etc/suricata/suricata.yaml` | `/opt/wazuh/suricata/etc/suricata/suricata.yaml` | `C:\Program Files\Suricata\suricata.yaml` |
| **Log File (`eve.json`)** | `/opt/wazuh/suricata/var/log/suricata/eve.json` | `/opt/wazuh/suricata/var/log/suricata/eve.json` | `C:\Program Files\Suricata\log\eve.json` |
| **Rules Directory** | `/opt/wazuh/suricata/var/lib/suricata/rules` | `/opt/wazuh/suricata/var/lib/suricata/rules` | `C:\Program Files\Suricata\rules` |
| **Wazuh Config** | `/var/ossec/etc/ossec.conf` | `/Library/Ossec/etc/ossec.conf` | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| **Service Name** | `suricata.service` (systemd) | `org.openinfosecfoundation.suricata` (launchd) | `Suricata` / Scheduled Task |
