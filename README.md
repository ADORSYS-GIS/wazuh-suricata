# wazuh-suricata

## Overview

The `wazuh-suricata` project integrates the Wazuh agent with Suricata, a high-performance network intrusion detection system (NIDS). This project provides scripts and tests to automate the installation, configuration, and validation of Suricata on both Linux and macOS systems.

## Features

- Automated installation of Suricata and its dependencies.
- Configuration of Suricata for network intrusion detection.
- Download and setup of Suricata rules from Emerging Threats.
- Cross-platform support for Linux and macOS.
- Bats tests to validate the installation and configuration.

## Project Structure

```
README.md
scripts/
    install.sh
tests/
    test-install.bats
```

- **README.md**: Documentation for the project.
- **scripts/install.sh**: Bash script to install and configure Suricata.
- **tests/test-install.bats**: Bats tests to validate the installation and configuration of Suricata.

## Prerequisites

- **Linux**: Ubuntu/Debian-based distributions with `apt-get` or Red Hat-based distributions with `yum`.
- **macOS**: Homebrew package manager.
- **Systemd**: Required for managing services on Linux.
- **Bats**: Bash Automated Testing System for running tests.

## Installation

### Linux

1. Run the installation script directly from the repository:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/main/scripts/setup-agent.sh | bash
   ```

### macOS

1. Run the installation script directly from the repository:
   ```bash
   curl -SL --progress-bar https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/main/scripts/setup-agent.sh | bash
   ```

## Configuration

The installation script automatically configures Suricata. Key configuration details include:

- **HOME_NET**: Automatically detected based on the system's network interface.
- **Rules Directory**: `/etc/suricata/rules` (Linux) or `/usr/local/etc/suricata/rules` (macOS).
- **Configuration File**: `/etc/suricata/suricata.yaml` (Linux) or `/usr/local/etc/suricata/suricata.yaml` (macOS).

## Testing

The project includes Bats tests to validate the installation and configuration of Suricata.

### Running Tests

1. Install Bats:
   ```bash
   sudo apt-get install -y bats
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

## Continuous Integration

The project uses GitHub Actions for CI. The workflow is defined in `.github/workflows/test.yaml` and includes:

- Running tests on `ubuntu-latest` and `macos-latest`.
- Installing dependencies and running Bats tests.

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