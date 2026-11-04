# Wazuh Suricata Documentation

This repository provides automated scripts and tests to install, configure, and run Suricata on Linux, macOS, and Windows. It integrates Suricata with the Wazuh agent so network intrusion alerts flow directly into your Wazuh security monitoring dashboard.

## SDLC Map

This repository follows the organization documentation standard. The table below shows the active documentation for each phase:

| Phase | Folder | Contents |
| :--- | :--- | :--- |
| Design | [architecture/](./architecture/overview.md) | System overview, packet flow, and Wazuh agent log pipeline |
| Decision | [adr/](./adr/README.md) | Architecture Decision Records |
| Operate | [operations/](./operations/installation.md) | Step by step installation and uninstallation guides |

## Quick Links

| Area | Link | Description |
| :--- | :--- | :--- |
| Architecture Overview | [overview.md](./architecture/overview.md) | How Suricata inspects traffic and forwards logs to Wazuh |
| Installation Guide | [installation.md](./operations/installation.md) | Setup instructions for Linux, macOS, and Windows |
| Decision Records | [adr/README.md](./adr/README.md) | Index of architectural decisions |
