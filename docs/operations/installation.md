# Installation and Setup Guide

This guide covers how to install, verify, and uninstall Suricata on Linux, macOS, and Windows using the scripts in this repository.

## Prerequisites

Before installing, make sure you have:
- Administrator or root privileges (`sudo` on Linux/macOS, Administrator prompt on Windows).
- An active internet connection to download packages and rule files.
- An installed Wazuh agent if you want to forward alerts to your Wazuh manager.

---

## 1. Linux Installation

The script has been tested on Ubuntu.

### Run the Installer

Run the install script with root privileges:

```bash
sudo ./scripts/linux/install.sh
```

### Optional Command Flags

You can pass arguments to customize the installation:

- **Mode selection**: Set whether Suricata runs in detection (`ids`) or prevention (`ips`) mode.
  ```bash
  sudo ./scripts/linux/install.sh --mode ips
  ```
- **Specific version**: Choose a different Suricata version (default is `8.0.2`).
  ```bash
  sudo ./scripts/linux/install.sh --version 8.0.2
  ```

### Verify Linux Service

Check that the systemd service is active and running:

```bash
sudo systemctl status suricata
```

View the latest alerts as they happen:

```bash
sudo tail -f /opt/wazuh/suricata/var/log/suricata/eve.json
```

### Uninstall on Linux

To completely remove Suricata and clean up all configuration files:

```bash
sudo ./scripts/linux/uninstall.sh
```

---

## 2. macOS Installation

The macOS installer supports macOS systems on both Intel (amd64) and Apple Silicon (arm64).

### Prerequisites for macOS
- [Homebrew](https://brew.sh) installed.
- Terminal with administrator permissions.

### Run the Installer

```bash
./scripts/macos/install.sh
```

The script will:
1. Detect your hardware architecture.
2. Install Suricata and required libraries using Homebrew or pre-built binaries.
3. Automatically set up Emerging Threats rules.
4. Configure network interface monitoring.
5. Register a launchd background service.

### Verify macOS Service

Check if the launchd service is loaded:

```bash
sudo launchctl list | grep suricata
```

View live alert logs:

```bash
tail -f /opt/wazuh/suricata/var/log/suricata/eve.json
```

### Uninstall on macOS

To remove Suricata and stop background services:

```bash
./scripts/macos/uninstall.sh
```

---

## 3. Windows Installation

On Windows, Suricata requires the Npcap packet capture library. The Windows installer automates both Npcap and Suricata setup.

### Run the Installer

1. Open PowerShell as **Administrator**.
2. Run the Windows installation script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\install.ps1
```

The script performs the following actions:
- Downloads and silently installs Npcap with WinPcap compatibility.
- Downloads and installs the Suricata MSI package into `C:\Program Files\Suricata`.
- Configures `suricata.yaml` and downloads current Emerging Threats rules.
- Creates a scheduled task to start Suricata automatically at system startup.

### Verify Windows Service

Check if the Suricata process is running:

```powershell
Get-Process suricata
```

Inspect the alert log:

```powershell
Get-Content -Path "C:\Program Files\Suricata\log\eve.json" -Wait -Tail 10
```

### Uninstall on Windows

To remove Suricata, the scheduled task, and related files:

```powershell
.\scripts\windows\uninstall.ps1
```

---

## 4. Connecting Suricata to Wazuh Agent

To allow the Wazuh agent to read Suricata events and forward them to your manager, add this block to your agent configuration file (`ossec.conf`):

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/opt/wazuh/suricata/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

*(For Windows, replace the location with `C:\Program Files\Suricata\log\eve.json`)*

Restart the Wazuh agent after saving the configuration:

- **Linux**: `sudo systemctl restart wazuh-agent`
- **macOS**: `sudo /Library/Ossec/bin/wazuh-control restart`
- **Windows**: `Restart-Service -Name "Wazuh"`

---

## 5. Testing Alert Generation

You can test if Suricata and Wazuh are working together by triggering a benign test signature. Run this command on your monitored machine:

```bash
curl http://testmyids.com
```

This request triggers standard alert SID `2100498` ("GPL ATTACK_RESPONSE id check returned root"). You should see a new alert appear in `eve.json` and in your Wazuh dashboard within seconds.