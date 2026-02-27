## [0.2.0-rc1] - 2026-02-27

### ⚙️ Miscellaneous Tasks

- *(ci)* Added automatic changelog and releasenotes generation
## [0.2.0] - 2026-02-25

### 🚀 Features

- Delegate macOS Intel (amd64) installation to v0.1.5 installer when no package is available.
- Add architecture detection and delegate macOS Intel uninstallation to a legacy script while cleaning old installer directories.
- Ensure rule downloads on existing Suricata installations and add the `-i` flag to macOS Homebrew dependency installations.
## [0.2.0-rc.3] - 2026-01-28

### 🚀 Features

- Remove macOS Intel delegation to remote installer and add cleanup for legacy `suricata-install` directory on macOS during install and uninstall
- Add macOS-specific cleanup for legacy `suricata-install` directory during uninstallation.
## [0.2.0-rc.2] - 2026-01-26

### 🐛 Bug Fixes

- Update legacy uninstall script URL and add a manual cleanup fallback for download failures.
- Update LEGACY_UNINSTALL_URL to use the correct tag reference.

### 🚜 Refactor

- Remove restart_wazuh_agent function

### ⚙️ Miscellaneous Tasks

- Update legacy uninstaller URL to reference the v1.5.0 tag.
## [0.2.0-rc.1] - 2026-01-08

### 🚀 Features

- *(install)* Enhance Suricata install script with pre-installation detection
- Enhance Suricata binary detection logic and add debug information to installation validation.
- Add symlink creation verification to the Suricata installation script
- Add checks for Suricata binary executability and test its basic execution.
- Add informational messages for suricata symlink creation success and existing symlinks, and refine error handling.
- Always install Suricata PATH configuration and provide clearer guidance for shell updates.
- Provide detailed post-installation instructions for Suricata usage, including PATH configuration and verification steps.
- Manage system library paths and permissions during install, and clean up associated configurations and multiple symlinks during uninstall.
- Implement automatic removal of legacy Suricata installations and update uninstall script URLs.
- Enhance Suricata binary detection in the install script and improve `suricata-update` accessibility test with fallback path checks.
- Enhance Suricata binary detection and version retrieval with fallback `sudo` checks and update related tests.
- Install suricata-update binary from DMG and update its accessibility test to skip if not found.
- Improve Suricata configuration file handling and enhance test reliability for suricata-update and process detection.
- Remove `suricata-update` installation and testing, and add a fallback download for `suricata.yaml`.
- Generate a minimal Suricata configuration file when fallback download fails
- Implement argument parsing for install script and add IPS mode configuration, while updating README to reflect unified installation paths and CI checks.
- Unify Suricata installation under `/opt/wazuh/suricata` by removing existing systemd services and configuring IPS mode.
- Implement unified `/opt/wazuh/suricata` installation layout for all OS, add `libpcap` as a macOS dependency, and update documentation and CI tests accordingly.
- Update fallback Suricata configuration URL and add libpcap linkage fix for Apple Silicon.
- Add default-log-dir configuration parameter
- Add macOS Launchd plist creation for Suricata persistence and expand Suricata configuration with new address and port groups.
- Standardize Suricata installation to `/opt/wazuh/suricata` and refactor pre-installation cleanup into `uninstall.sh`.
- Replace local fallback Suricata config generation with remote download from URL
- Enhance shell integration by adding zsh/fish PATH cleanup during uninstall and refining Suricata binary symlink management during install.
- Add lz4, pcre2, jansson, and libyaml to macOS Homebrew dependency installation.
- Add post-download processing for fallback Suricata configuration to resolve autoconf placeholders and disable optional features.
- Add libmagic to macOS Homebrew dependencies and update the related warning message.
- Add installation idempotency by verifying existing Suricata versions and skipping re-installation, and improve uninstall script handling.
- Add explicit calls to remove Suricata packages, directories, and systemd services during uninstallation.

### 🐛 Bug Fixes

- *(install)* Update Suricata install script and improve macOS handling
- *(scripts)* Remove misplaced message from install script
- *(scripts)* Correct script closing in install.sh
- *(install)* Ensure symlinks for suricata binaries on PATH
- *(scripts)* Narrow scope of Suricata uninstallation steps
- *(install)* Improve Suricata binary detection and symlink creation
- *(scripts)* Improve Suricata binary search in install script
- *(install)* Add PATH fallback setup for Suricata binary
- *(install)* Add ensure_path_profile call to suricata installation
- *(install)* Add ensure_path_profile call to suricata installation
- *(install)* Update Suricata paths and config setup for Wazuh integration
- *(scripts)* Remove duplicate Suricata validation message
- Correct conditional execution for suricata-update symlink creation.
- Enhance uninstall script to remove multiple Suricata symbolic links, library, and PATH configurations.
- Update Suricata installation paths in tests to `/opt/wazuh/suricata` for both macOS and Linux.
- Add missing closing brace to `install_suricata_binary` function.
- Update Homebrew dependency warning message to include libpcap.
- Improve libpcap detection and linkage on Apple Silicon by checking multiple paths and adding warnings.
- Use 'install' instead of 'reinstall' for package management commands.

### 💼 Other

- Change default configuration missing warning to an informational message.

### 🚜 Refactor

- *(uninstall)* Rewrite Suricata uninstall script for modularity and clarity
- Reorder Wazuh agent and pre-installation checks to execute earlier in the script.
- Relocate `suricata_macos_installation` function definition to improve script structure.
- Remove fallback configuration download from OISF and directly generate a minimal configuration.
- Remove informational message about system readiness from uninstall script.

### 🧪 Testing

- Verify Suricata service is not installed by default and make custom drop rule test conditional on IPS mode.
- Make detect-engine configuration test skippable if the config is not present.
- Enhance `suricata-update` accessibility check with fallback path verification.
- Add sudo to suricata-update executable checks in install test.
- Skip suricata-update accessibility test if binary is not found
- Improve robustness of Suricata installation tests by adding dependency checks and a process startup delay.
- Remove suricata-update accessibility and platform-specific tests

### ⚙️ Miscellaneous Tasks

- *(scripts)* Make install.sh executable
- *(scripts)* Make uninstall.sh executable
- Remove trailing blank lines from install script.
## [0.1.5] - 2025-09-28

### 🚀 Features

- Add automated PowerShell installation scripts for Npcap and Suricata

### 🐛 Bug Fixes

- Optimize Npcap installation timing and verification
- Remove check for npfs driver not used by mpcap
- String interpolation error
- String interpolation error
- Add check to install Suricata 7.x for EL9+ RHEL like systems
- Update uninstall.sh to consider all installed components in install.sh
- Remove dependency removal step, it is redundant

### ⚙️ Miscellaneous Tasks

- Update script url to reference main
## [0.1.4] - 2025-09-15

### 🚀 Features

- Replace Homebrew tap installation with GitHub release prebuilt binaries for macOS
- Add template suricata.yaml config file for use when installing
- Add architecture-specific config file installation to /opt/suricata/share
- Update install.sh to use rsync for macOS installation and add Homebrew cleanup
- Add libmagic dependency installation for macOS
- *(macos)* Restore Python wrapper for suricata-update with /usr/bin/python3
- Update uninstall.sh to consider suricata installed using prebuilt package
- Enhance rule downloading process with temporary directory and macOS quarantine handling
- Install suricata for centOS/RHEL

### 🐛 Bug Fixes

- Correct GitHub release download URL construction
- Adjust tar extraction to handle opt/suricata directory structure
- Extract only opt/suricata contents from tarball, excluding _meta directory
- Ensure quarantine attributes are removed from all files and directories
- Add PYTHONPATH configuration for suricata-update module resolution
- Handle unbound PYTHONPATH variable in install script
- Handle externally-managed-environment error for pyyaml installation on macOS
- Add brew install for all dependencies
- Remove local keyword
- Remove brew install pyyaml since deprecated
- Make python interpreter dynamic
- Prevent infinite loop in suricata-update wrapper script creation
- Fix python wrapper issue for amd macOS
- Standardize embedded /opt/suricata/bin/suricata-update shebang to #python3 for portability.
- Remove wrapper
- Revert to commit working for amd macOS
- Apply suricata-update shebang fix only on macOS ARM
- Implement architecture-specific suricata-update handling for macOS
- Resolve suricata-update wrapper recursion on macOS ARM
- *(install)* Replace suricata-update symlink with portable launcher
- Use direct path to suricata-update
- Make check conditional to macOS
- Reference exact path for suricata bin
- Add --no-check-certificate option to suricata-update command
- Remove --no-check-certificate option to suricata-update command
- Run Suricata installation script with sudo for proper permissions
- Use sudo to list rules directory for proper permissions
- Remove sudo to list rules directory for proper permissions
- Add sudo to tests for accessing rules and configuration files
- Remove outdated Suricata-update tests for macOS ARM64 and Intel
- Update macOS Suricata process check to use launchctl
- Run Suricata installation script with sudo in IPS mode and add macOS-specific tests for Suricata-update
- Add verification for Suricata process after loading macOS Launchd plist file
- Enhance rule initialization and combination in download_rules function
- Remove Suricata process verification after loading macOS Launchd plist file
- Clean up macOS installation script by removing unused variables and functions
- Set default Suricata version in installation script
- Install prebuilt suricata bin on ubuntu
- Update url's to prebuilt binaries
- Copy suricata bin folder to /opt and link to /usr/bin
- Create suricata service
- Install pyyaml system wide
- Remove pyyaml suricata update dependency
- Start suricata service when creating systemd service file
- Ensure Suricata service starts after configuration update
- Add check to see if usr/local/bin exists and added to PATH
- Add libhyperscan5 runtime library
- *(uninstall.sh)* Remove CELLAR_DIR only for macOS
- Remove suricata-update wiring log and hyperlevel dependency for centOS/RHEL
- Remove python and pip installation for suricata-update on macOS, disable stats in config file
- *(uninstall.sh)* Uninstall for centOS
- Remove python and pyyaml installs in install script
- Check /usr/local/bin dir exists for macOS
- Uninstall all required dependencies for macOS
- Add function to configure centOS/RHEL suricata service
- *(uninstall.sh)* Fix workflow to remove suricata dependencies if not required by other components
- *(install.sh)* Fix macOS fallback interface to en0
- Make sure linux and macOS systems get version-compatible rules
- Check for active/UP interfaces when using detect_wifi_interface function
- Check for active/UP interfaces when using detect_wifi_interface function

### 🧪 Testing

- Update bats tests for new /opt/suricata installation paths

### ⚙️ Miscellaneous Tasks

- *(install.sh)* Update suricata_github_tag to v8.0.0-adorsys.2-rc.2
## [0.1.3] - 2025-08-28

### 🐛 Bug Fixes

- *(macos)* Install Suricata via local Homebrew tap instead of direct download
- Update install.sh and uninstall.sh to for suricata@7.0.10 on macos
- Improve method to uninstall suricata on macos
- *(uninstall.sh)* Add unpin command before delete for proper suricata removal
## [0.1.2] - 2025-08-14

### 🐛 Bug Fixes

- Update method to retrieve logged-in user on macOS by using brew --prefix
- Enhance error handling for retrieving logged-in user on macOS
- Detect Homebrew owner via prefix path for launchd compatibility
- Restore deleted Homebrew helper functions
- Revert method of getting logged in user
- *(macos)* Resolve Suricata installation permissions with clean user environment
- Remove error handling
- Add -i flag to brew command to simulate initial login
- *(macos)* Change return to exit for critical installation failures

### 🚜 Refactor

- Clean up brew prefix detection logic

### 🧪 Testing

- Get logged in user using brew --prefix
## [0.1.1] - 2025-07-15

### 🐛 Bug Fixes

- *(install)* Update Suricata version check command for macOS installation
## [0.1.0] - 2025-06-05

### 🚀 Features

- *(uninstall)* Implement comprehensive uninstallation script for Suricata with service management and package removal
- *(install)* Enhance user experience with command-line options and improved logging
- *(install)* Add yq support for YAML configuration updates and improve command-line options
- *(uninstall)* Add warning message logging for uninstallation process
- Enhance install script with improved configuration and rule management; enchance uninstall script
- *(tests)* Update test-install.bats for improved Suricata checks and configuration validation
- *(rules)* Add custom drop rule for IPS mode and update tests to verify its presence
- *(chore)* Add script to install suricata on windows and add pester unit tests and update github actions workflow for windows testing
- *(uninstall)* Add uninstall script for Suricata and related components; remove obsolete install tests
- *(release)* Add release workflow with Bats tests and versioning steps
- *(install)* Enhance macOS installation process for Suricata using Homebrew
- *(install)* Add function to get logged-in user and run Homebrew commands as that user on macOS
- *(install)* Simplify user retrieval on macOS and run commands as logged-in user
- *(install)* Implement logged-in user retrieval for command execution in install and uninstall scripts
- *(install/uninstall)* Parameterize Suricata version and enhance uninstall process with mode detection
- *(install)* Add macOS installation support for Suricata from source
- *(install)* Add macOS installation support for Suricata from source
- *(uninstall)* Add unpin command for Homebrew during Suricata uninstallation
- *(uninstall)* Add unpin command for Homebrew before uninstalling Suricata
- *(uninstall)* Enhance uninstallation process for Suricata on Linux
- *(install)* Enhance Suricata installation process on macOS with version checks

### 🐛 Bug Fixes

- *(ci)* Fix suricata install in test workflow
- *(ci)* Fix suricata test workflow
- *(ci)* Remove unnecessary sudo for script execution in test workflow
- *(chore)* Improve Wi-Fi interface detection logic in install script
- *(install)* Unload previous plist file before loading new daemon
- *(install)* Update Suricata process check to use launchctl for macOS
- *(install)* Remove service status checks for Suricata in install script
- *(install)* Enhance OS and architecture detection logic in install script
- *(install)* Update Wi-Fi interface detection to prioritize networksetup command
- *(install)* Refactor installation script for improved command checks and directory handling
- *(uninstall)* Refactor command checks for service management and package removal
- *(uninstall)* Remove unnecessary sudo for Homebrew uninstallation command
- *(install)* Add default fallback for Wi-Fi interface and HOME_NET detection
- *(install)* Add default fallbacks for Wi-Fi interface and HOME_NET detection
- *(install)* Add check for non-empty netmask before setting HOME_NET
- *(install)* Fix yq usage on macos
- *(tests)* Improve tests
- *(uninstall)* Fix directory paths for Suricata configuration and logs on macOS
- *(install)* Update help message and change yq installation path to /usr/bin
- *(tests)* Improve test-install.bats for better OS detection and rule validation
- *(uninstall)* Update yq uninstallation path to /usr/bin
- *(workflow)* Rename test job to test-ids and update dependencies for test-ips
- *(tests)* Update custom drop rule test to check for rule presence in suricata.rules
- *(install)* Fix the check of existence of rules file using sudo permissions
- Fix scheduled-task quoting/bracing and run task as SYSTEM
- Clean PATH, use Npcap uninstaller, stop task before removal
- Use maybe_sudo for grep command in update_config function to ensure proper permissions
- Remove maybe_sudo from grep command in update_config function for consistency
- *(install)* Replace maybe_sudo with sudo for Homebrew installation on macOS
- *(uninstall)* Ensure Suricata default file removal only runs on Linux
- *(uninstall)* Ensure proper restoration of UFW configurations during uninstallation
- *(install)* Correct syntax for Suricata version assignment in install script
- *(install)* Remove redundant yq installation command for macOS
- *(install)* Improve brew command execution by ensuring correct user home directory
- Improve brew command execution
- Uninstall script for MacOS
- Improve uninstall script for MacOS

### 🚜 Refactor

- *(chore)* Pass Suricata binary path to plist file creation function
- *(install/uninstall)* Streamline logged-in user function to always execute commands as user
- *(install/uninstall)* Unify command execution as logged-in user for Homebrew operations
- *(install/uninstall)* Conditionally retrieve logged-in user on macOS
- *(install)* Move logged-in user retrieval to a dedicated section for clarity
- *(uninstall)* Streamline uninstallation process logging for Linux

### 🧪 Testing

- Test ci workflow

### ⚙️ Miscellaneous Tasks

- Initial commit
- *(uninstall)* Enhance error handling and logging in uninstall functions for Suricata and Npcap
