# wazuh-suricata

[![Suricata CI](https://github.com/ADORSYS-GIS/wazuh-suricata/actions/workflows/release.yaml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-suricata/actions/workflows/release.yaml)

## Overview

The `wazuh-suricata` project integrates the Wazuh agent with Suricata, a high-performance network intrusion detection system (NIDS). This project provides scripts and tests to automate the installation, configuration, and validation of Suricata on both Linux and macOS systems.

## Features

- Automated installation of Suricata and its dependencies.
- Configuration of Suricata for network intrusion detection.
- Download and setup of Suricata rules from Emerging Threats.
- Cross-platform support for Linux and macOS.
- Bats tests to validate the installation and configuration.
- Support for both IDS and IPS modes on Linux.

## Documentation

Full project documentation is available in the [`docs/`](./docs/README.md) directory:
- [Architecture Overview](./docs/architecture/overview.md): System design, event flow, and Wazuh integration.
- [Installation Guide](./docs/operations/installation.md): Step by step setup for Linux, macOS, and Windows.
- [Architecture Decision Records](./docs/adr/README.md): Recorded engineering and architecture choices.

## Project Structure

```
README.md
docs/
    README.md
    architecture/
        overview.md
    operations/
        installation.md
    adr/
        README.md
scripts/
    linux/
        install.sh
        uninstall.sh
    macos/
        install.sh
        uninstall.sh
    windows/
        install.ps1
        uninstall.ps1
        install-npcap-automated.ps1
        install-suricata-silent.ps1
        uninstall-automated.ps1
    shared/
        utils.sh
        utils.ps1
tests/
    test-install.bats
    test-utils.bats
    run-coverage.sh
```

- **docs/**: Project documentation organized by lifecycle phase.
- **scripts/linux/**: Scripts to install, configure, and remove Suricata on Linux.
- **scripts/macos/**: Scripts to install, configure, and remove Suricata on macOS.
- **scripts/windows/**: PowerShell scripts for automated Npcap and Suricata installation on Windows.
- **scripts/shared/**: Shared utility functions for shell and PowerShell environments.
- **tests/**: Automated Bats tests and test coverage runner.

## Prerequisites

- **Linux**: Ubuntu/Debian-based distributions with `apt` or Red Hat-based distributions with `yum`.
- **macOS**: Homebrew package manager.
- Unified install layout for both OS under `/opt/wazuh/suricata` (bin, etc/suricata, var/lib/suricata/rules, var/log/suricata).
- **Systemd**: Required for managing services on Linux.
- **Bats**: Bash Automated Testing System for running tests.

## Installation

### Linux

1. Run the Linux-specific installation script directly from the repository:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/linux/install.sh | bash
   ```

   Or download and run locally:
   ```bash
   wget https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/linux/install.sh
   chmod +x install.sh
   sudo ./install.sh
   ```

### macOS

1. Run the macOS-specific installation script directly from the repository:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/macos/install.sh | bash
   ```

   Or download and run locally:
   ```bash
   wget https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/macos/install.sh
   chmod +x install.sh
   sudo ./install.sh
   ```

### Legacy Installation (Deprecated)

The legacy unified installation script is still available but deprecated:
```bash
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/install.sh | bash
```

## Configuration

The installation script automatically configures Suricata. Key configuration details include:

- **HOME_NET**: Automatically detected based on the system's network interface.
- **Rules Directory**: `/opt/wazuh/suricata/var/lib/suricata/rules`.
- **Configuration File**: `/opt/wazuh/suricata/etc/suricata/suricata.yaml`.
- This installer manages Suricata under `/opt/wazuh/suricata` only and does not modify system-wide services or firewall settings.

## Testing

The project includes Bats tests to validate the installation and configuration of Suricata.

### Running Tests

1. Install Bats:
   ```bash
   sudo apt install -y bats
   ```
2. Run the tests:
   ```bash
   sudo bats tests/
   ```

### Test Cases

- **Suricata is installed**: Verifies that the Suricata binary is available.
- **Configuration file exists**: Checks for the presence of the Suricata configuration file.
- **Rules directory exists**: Ensures the rules directory is set up.
- **Suricata service is running (Linux)**: Confirms the Suricata service is active on Linux.
- **Suricata process is running (macOS)**: Confirms the Suricata process is running on macOS.
- **IPS mode configurations**: Validates that `LISTENMODE`, `DEFAULT_INPUT_POLICY`, and UFW rules are correctly set for IPS mode.

## Uninstallation

### Linux

To uninstall Suricata on Linux and revert all configurations, run the Linux-specific uninstall script:

```bash
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/linux/uninstall.sh | sudo bash
```

Or download and run locally:
```bash
wget https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/linux/uninstall.sh
chmod +x uninstall.sh
sudo ./uninstall.sh
```

### macOS

To uninstall Suricata on macOS and revert all configurations, run the macOS-specific uninstall script:

```bash
curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/macos/uninstall.sh | sudo bash
```

Or download and run locally:
```bash
wget https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-suricata/main/scripts/macos/uninstall.sh
chmod +x uninstall.sh
sudo ./uninstall.sh
```

### Legacy Uninstallation (Deprecated)

The legacy unified uninstallation script is still available but deprecated:
```bash
sudo ./scripts/uninstall.sh
```

The uninstallation will:
- Remove Suricata and its dependencies.
- Revert IPS mode-specific configurations (e.g., UFW rules, `LISTENMODE`).
- Delete Suricata configuration, log, and rules directories.

## Continuous Integration

The project uses GitHub Actions for CI. The workflow is defined in `.github/workflows/release.yaml` and includes:

- Running tests on `ubuntu-latest` and `macos-latest`.
- Running Bats tests that assert the `/opt/wazuh/suricata` layout.

## Troubleshooting

- **Suricata service is not running**:
  - Check the system logs: `sudo journalctl -u suricata`.
  - Ensure systemd is installed and active.
- **Rules not downloaded**:
  - Verify internet connectivity.
  - Check the rules URL in the script.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.