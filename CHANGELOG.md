# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

[41db349](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/41db349349cdf985cc357572abea938213ec0253)...[c605827](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c60582739f207bc67d5bdccb2a295a0d3e3fad94)

### Bug Fixes

- Update WAZUH_SURICATA_REPO_REF to v0.2.0-rc.4 in installation and uninstallation scripts ([`c605827`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c60582739f207bc67d5bdccb2a295a0d3e3fad94))

## 0.2.0-rc.4 - 2026-04-16

[554ad11](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/554ad11018b99ed73e93a1089f7e997dbe6bf6ff)...[41db349](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/41db349349cdf985cc357572abea938213ec0253)

### Documentation

- Update CHANGELOG.md and checksums [skip ci] ([`773821b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/773821b69e4fc20a800d7f455ccc94db0cff2a62))
- Update CHANGELOG.md and checksums [skip ci] ([`8a25a28`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8a25a28e18f9fa787f9e78ec7caa4245914acfc5))
- Update CHANGELOG.md and checksums [skip ci] ([`41db349`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/41db349349cdf985cc357572abea938213ec0253))

### Features

- Increase stream memcap to 512 MiB and improve Debian package detection logic ([`577c30f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/577c30fcda00154684de9b1a220aa4a03d924e84))

### Miscellaneous Tasks

- Remove GitHub action step generating full CHANGELOG.md ([`b9d666d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b9d666d818919c4764f4590ae93e7db102f91604))

## 0.2.0-rc3 - 2026-04-14

[dc6d8c0](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dc6d8c0ee8d311c845eb62d7ef9f04a1d7418a04)...[554ad11](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/554ad11018b99ed73e93a1089f7e997dbe6bf6ff)

### Features

- Add checksum to release assets ([`e16b893`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e16b89389477f7241647b25ae97b06016b1f32af))

## 0.2.0-rc2 - 2026-03-30

[affc78e](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/affc78e8deacb01a09af98edfe9b8b9dd9b3d391)...[dc6d8c0](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dc6d8c0ee8d311c845eb62d7ef9f04a1d7418a04)

### Bug Fixes

- Remove local uninstall script check in linux and macos install scripts ([`19b9ecb`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/19b9ecb4ffc542fb16f138aedab879d993438d58))
- Correct checksum generation and update job dependencies ([`61e4298`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/61e42984c993206debdfc41ad7a7b181d3d04222))

### Features

- Introduce modular installation and uninstallation scripts for Linux and macOS, enhancing Suricata setup with OS-specific handling and improved documentation in README.md. ([`db8fec3`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/db8fec32542223aaedb4aa53d0e618671dbe26f0))
- Add 'yq' dependency to installation scripts for Linux and macOS, and ensure Suricata configuration includes 'alert' in eve-log types ([`b8bba03`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b8bba038034a86559ff2530a710c3d3de14177bd))
- Implement automatic installation of 'yq' in Linux install script, ensuring availability for configuration management and enhancing dependency handling ([`3f923fc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/3f923fc7179cc8f2a1238bee7e2120b5963bee7d))
- Improve macOS installation script to capture and display Homebrew output during dependency installation, enhancing error handling and user feedback ([`2272e17`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2272e1740ae0fd6a070680cb92437433db923159))
- Enhance Suricata configuration setup in macOS install script by adding support for e_magic_file and improving yq command handling for eve-log types ([`b41b773`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b41b773b5008f1ee9b8007ccc3e361d116262bd9))
- Introduce robust placeholder replacement functions in macOS install script to enhance Suricata configuration reliability and error handling ([`1c61891`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1c6189146011bf16b436bb255fb7be17155c3d5a))
- Add checksum ([`9acbf75`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9acbf75cd2f241fb9c968b47021876270fc442ab))
- Make SURICATA_VERSION and RULES_VERSION configurable in installation scripts ([`faf9556`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/faf9556264dc3bd684c7003d1b16a10dd7f0ff5e))
- Automate checksum generation in release workflow ([`dc6d8c0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dc6d8c0ee8d311c845eb62d7ef9f04a1d7418a04))

### Miscellaneous Tasks

- Update script checksums and add portable string replacement utility ([`5cb2954`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5cb29548c93324b57727a08bc554db8457853803))
- Update installer scripts and fix parameter names ([`6613736`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/661373674759c8b01f490b68fd14b9bf7817a6e3))
- Enhance Suricata CI pipeline with changelog and checksum updates ([`8fdb97b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8fdb97b170fc99d30b5339d74a01b0f976da3066))
- Update CHANGELOG.md ([`ff008e8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ff008e87e29b8f7e73e2622c531c6b2d532c2bfe))

### Refactor

- Consolidate cleanup function in Linux install script and align config paths in uninstall scripts for Linux and macOS ([`30c6f15`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/30c6f1565b43b0e2c7623877a09e48e634172908))
- Enhance Suricata service integration removal in Linux install script to handle multiple unit file locations and SysV init scripts ([`73915f8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/73915f826661177e82c3c2988f41369f62e37346))
- Centralize shared logic into new utility scripts and implement checksum verification for all installations ([`9900d8e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9900d8e250d550f12dca8433211cd6c867ba7827))
- Standardize installation temporary directories, propagate repo references in CI, and fix Linux sed command ([`394356e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/394356ec4087a9a66700828091e2080eb2d43132))
- Improve installer logging, update registry checks, replace WMI with CIM, and add gitignore file ([`c79d677`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c79d6779b3476cdfa885c85a8fc8698a5fa115de))

## 0.2.0-rc1 - 2026-02-27

[218a2f4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/218a2f4d3656f5d0c7e51f03fa490af4c3d17e00)...[affc78e](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/affc78e8deacb01a09af98edfe9b8b9dd9b3d391)

### Bug Fixes

- Updated git repo in git cliff.toml ([`affc78e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/affc78e8deacb01a09af98edfe9b8b9dd9b3d391))

### Features

- Enhanced the installation script to include validation after installation. ([`9895e90`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9895e90cbd5ffda856c2613b6e8f1ee3ff6fc7f1))

### Miscellaneous Tasks

- Added automatic changelog and releasenotes generation ([`4e02b89`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4e02b8916d0f6949fc6a59e04a117657cbb28dfa))
- Added cliff configuration ([`ff89cd1`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ff89cd1795d8a5d782ff6b875788d483c34a80ac))
- Update CHANGELOG.md ([`04bbbbc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/04bbbbc264bdbdcb27be23f74deec410de481cb0))

## 0.2.0 - 2026-02-25

[69a0fea](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/69a0feac287b3f4c2d3c3f3eeee61f491a7c1cbe)...[218a2f4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/218a2f4d3656f5d0c7e51f03fa490af4c3d17e00)

### Features

- Delegate macOS Intel (amd64) installation to v0.1.5 installer when no package is available. ([`a4e0121`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a4e012123596708f802defecd06d33359b314ad3))
- Add architecture detection and delegate macOS Intel uninstallation to a legacy script while cleaning old installer directories. ([`254c277`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/254c277c8fcf51eb5b0b642b801171363512b352))
- Ensure rule downloads on existing Suricata installations and add the `-i` flag to macOS Homebrew dependency installations. ([`550f4f9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/550f4f9dc48431d7d1ccb0084fd8fd2e7c6b1185))

## 0.2.0-rc.3 - 2026-01-28

[e6bd864](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e6bd8644848b66f297d33379d74a9546248da51a)...[69a0fea](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/69a0feac287b3f4c2d3c3f3eeee61f491a7c1cbe)

### Features

- Remove macOS Intel delegation to remote installer and add cleanup for legacy `suricata-install` directory on macOS during install and uninstall ([`5b68505`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5b68505bbf5b27fb5e50d9f6eb8b99a68f0fe0cd))
- Add macOS-specific cleanup for legacy `suricata-install` directory during uninstallation. ([`69a0fea`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/69a0feac287b3f4c2d3c3f3eeee61f491a7c1cbe))

## 0.2.0-rc.2 - 2026-01-26

[9b971c6](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9b971c670b959412f3aee8c216d7e8a24d91d4e2)...[e6bd864](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e6bd8644848b66f297d33379d74a9546248da51a)

### Bug Fixes

- Update legacy uninstall script URL and add a manual cleanup fallback for download failures. ([`dfa25bc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dfa25bc33b2475c464dbcc192452d60adcd34627))
- Update LEGACY_UNINSTALL_URL to use the correct tag reference. ([`bde3cac`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/bde3caca1f56e8ffbcc6c624651ab5fe0131e05c))

### Miscellaneous Tasks

- Update legacy uninstaller URL to reference the v1.5.0 tag. ([`241758b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/241758b25cbdbfa89a102a1df53ba870a9e99d28))

### Refactor

- Remove restart_wazuh_agent function ([`a98ff3a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a98ff3aeb8029802c677da7d0a5607e37fbb54d5))

## 0.2.0-rc.1 - 2026-01-08

[b5b99d4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b5b99d404c1ed116b6ea7705146c7fe291084b6f)...[9b971c6](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9b971c670b959412f3aee8c216d7e8a24d91d4e2)

### Bug Fixes

- Update Suricata install script and improve macOS handling ([`fbe6a02`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fbe6a025e458b5013d0d6767dc1d28d22e7ac767))
- Remove misplaced message from install script ([`95edb9e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/95edb9ef19c7dce5b12bdfab9309432281ed4d9d))
- Correct script closing in install.sh ([`c2885b0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c2885b04b3d06daaf1f87d61ce079c3ffb8c8a47))
- Ensure symlinks for suricata binaries on PATH ([`2015aba`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2015aba5018a86a24e6ce088f5013f40d22bda87))
- Narrow scope of Suricata uninstallation steps ([`adf3620`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/adf36200014eb247fe56f6ed543ea208036209e3))
- Improve Suricata binary detection and symlink creation ([`05831d2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/05831d21d7382843e22a44e383c3281dc89b3da7))
- Improve Suricata binary search in install script ([`e105d94`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e105d94c7e66344f51b0b441312fd2727cc4acb1))
- Add PATH fallback setup for Suricata binary ([`6088a05`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6088a0524dc47a74b385ffaaddf330c680ceee81))
- Add ensure_path_profile call to suricata installation ([`ade1a79`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ade1a790644cccd968dce02d841dc51abbbf33a8))
- Add ensure_path_profile call to suricata installation ([`bdf0ebe`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/bdf0ebe057d7d34f53268920d8e005429e5a1382))
- Update Suricata paths and config setup for Wazuh integration ([`84b7355`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/84b735564f7608931449a2324017345477a6e4fc))
- Remove duplicate Suricata validation message ([`95482a9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/95482a9650780e0a5987bd523bc704f7d536626c))
- Correct conditional execution for suricata-update symlink creation. ([`534b96c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/534b96c76cd3cfc898aee35dd379736d9f6ebdaf))
- Enhance uninstall script to remove multiple Suricata symbolic links, library, and PATH configurations. ([`e031d7c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e031d7c3d123f3a94ab32a6d16bf1562c1017e6c))
- Update Suricata installation paths in tests to `/opt/wazuh/suricata` for both macOS and Linux. ([`26e2662`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/26e2662d1a63078e1e4daf27951d6afc914bd7bd))
- Add missing closing brace to `install_suricata_binary` function. ([`ad5715c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ad5715c5226a345cde2899b20b5f1d94b21dc160))
- Update Homebrew dependency warning message to include libpcap. ([`531a9b2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/531a9b2d6fb5f3f009b85fd0803cd695994630f4))
- Improve libpcap detection and linkage on Apple Silicon by checking multiple paths and adding warnings. ([`4088cf0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4088cf0ad038b05782b194fea8012c471b9f5d8c))
- Use 'install' instead of 'reinstall' for package management commands. ([`9b971c6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9b971c670b959412f3aee8c216d7e8a24d91d4e2))

### Features

- Enhance Suricata install script with pre-installation detection ([`b4085be`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b4085beb1cadec0584f6087c7524677eba70f048))
- Enhance Suricata binary detection logic and add debug information to installation validation. ([`5178fa3`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5178fa3ad806c5a17f14281d4e03c9fd86ef0f42))
- Add symlink creation verification to the Suricata installation script ([`43b87ff`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/43b87ff6ef05f6770bdae6143fa1f80db5726d36))
- Add checks for Suricata binary executability and test its basic execution. ([`9d549d0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9d549d087852f0dcb49df384898bf9cef3a1bab2))
- Add informational messages for suricata symlink creation success and existing symlinks, and refine error handling. ([`55dabe8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/55dabe85f80f433b62c6e3941ec8f4b97258d489))
- Always install Suricata PATH configuration and provide clearer guidance for shell updates. ([`be7ce72`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/be7ce7283eef8be598a1e081a6f444f517cf7063))
- Provide detailed post-installation instructions for Suricata usage, including PATH configuration and verification steps. ([`a1d391d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a1d391d2b59f1488723d7a04517d2e4337bed930))
- Manage system library paths and permissions during install, and clean up associated configurations and multiple symlinks during uninstall. ([`c378c87`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c378c871f3fb8a5cdddf67c43c9935c45ee0f5ab))
- Implement automatic removal of legacy Suricata installations and update uninstall script URLs. ([`f3bc4d9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/f3bc4d92add13c590928fefbd4027a28197ab64a))
- Enhance Suricata binary detection in the install script and improve `suricata-update` accessibility test with fallback path checks. ([`ab841f6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ab841f6673fa09ffc8b94c01543fee6551cb2147))
- Enhance Suricata binary detection and version retrieval with fallback `sudo` checks and update related tests. ([`95b3391`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/95b3391a81a8eaf3833bb7717828f7118f2144f1))
- Install suricata-update binary from DMG and update its accessibility test to skip if not found. ([`ef7533f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ef7533ff4f69f8eb10a2d740752f37c7b6a46309))
- Improve Suricata configuration file handling and enhance test reliability for suricata-update and process detection. ([`a880481`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a880481346a3c2270bc68df47c726ff524954f09))
- Remove `suricata-update` installation and testing, and add a fallback download for `suricata.yaml`. ([`dfce293`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dfce2933d5c13cf1be76e7f7b3e972c6300be9fd))
- Generate a minimal Suricata configuration file when fallback download fails ([`c78bf44`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c78bf44ee069219416e6a68bd7a0e2e1eca60779))
- Implement argument parsing for install script and add IPS mode configuration, while updating README to reflect unified installation paths and CI checks. ([`3f6f12f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/3f6f12fdef872ac2f1b12d959af89e2c62a8421e))
- Unify Suricata installation under `/opt/wazuh/suricata` by removing existing systemd services and configuring IPS mode. ([`c5a5a6d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c5a5a6d455c4527acdf0ff3a4e2e0136289a283c))
- Implement unified `/opt/wazuh/suricata` installation layout for all OS, add `libpcap` as a macOS dependency, and update documentation and CI tests accordingly. ([`b137588`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b13758887ce22549f5dbc8057d2473a7220486a0))
- Update fallback Suricata configuration URL and add libpcap linkage fix for Apple Silicon. ([`7c57146`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7c5714658be64928b5538018f9f8ef46ddf8aeca))
- Add default-log-dir configuration parameter ([`a15b035`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a15b035f99add9d9798c577b196c150f017b7063))
- Add macOS Launchd plist creation for Suricata persistence and expand Suricata configuration with new address and port groups. ([`59752ad`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/59752ad4c3744dfd6ba5ca50c5eca6fc6205ba6b))
- Standardize Suricata installation to `/opt/wazuh/suricata` and refactor pre-installation cleanup into `uninstall.sh`. ([`b0ac9d3`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b0ac9d364d9aaebcb3b2be36bf0167249af566d0))
- Replace local fallback Suricata config generation with remote download from URL ([`7e2a26c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7e2a26cdb5c0f05dff236c352485db9557a2b2b7))
- Enhance shell integration by adding zsh/fish PATH cleanup during uninstall and refining Suricata binary symlink management during install. ([`ef8260a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ef8260aef07e0e26e7cd9913b5e20634abec3c50))
- Add lz4, pcre2, jansson, and libyaml to macOS Homebrew dependency installation. ([`a91f6e8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a91f6e87c8d2d853581655333d41de65164dcc25))
- Add post-download processing for fallback Suricata configuration to resolve autoconf placeholders and disable optional features. ([`7969130`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7969130a7813c76857c2459be2aa1fb5de8dea69))
- Add libmagic to macOS Homebrew dependencies and update the related warning message. ([`ca81b93`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ca81b93a0794e828b541f6e2dedd6f4c5baff4b9))
- Add installation idempotency by verifying existing Suricata versions and skipping re-installation, and improve uninstall script handling. ([`ba476fb`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ba476fb340aed58b7104286f650e6b09bde85b36))
- Add explicit calls to remove Suricata packages, directories, and systemd services during uninstallation. ([`908f7ed`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/908f7ed8b62b772f3fe2a6c071c523f8878de0b3))

### Miscellaneous Tasks

- Make install.sh executable ([`ca3ffdb`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ca3ffdb7a63407c885d109279dbe82ef811c759d))
- Make uninstall.sh executable ([`b8008c2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b8008c2fb85c735bccecd843275d7a9fd221db93))
- Remove trailing blank lines from install script. ([`d2a6ca5`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d2a6ca5edc5fc0a0e48f01544ecd9c0d3f9d5020))

### Refactor

- Rewrite Suricata uninstall script for modularity and clarity ([`db53a76`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/db53a76e6e711498178d958f19c75f44b6213a23))
- Reorder Wazuh agent and pre-installation checks to execute earlier in the script. ([`83e695b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/83e695b87736cc792da7c9c9882bd77db9d42b0c))
- Relocate `suricata_macos_installation` function definition to improve script structure. ([`723552a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/723552a152cf44c3577fb927b454d08099786aa4))
- Remove fallback configuration download from OISF and directly generate a minimal configuration. ([`1664fb8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1664fb86926f127c861320df33638b510dc79b14))
- Remove informational message about system readiness from uninstall script. ([`e23b77f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e23b77f17bde9c16cb3310b54415344c76ce357d))

### Testing

- Verify Suricata service is not installed by default and make custom drop rule test conditional on IPS mode. ([`6a38521`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6a385210b614b370a0b7b622e971957e9118e6a4))
- Make detect-engine configuration test skippable if the config is not present. ([`809f839`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/809f839aed1cc291371ef07066b5b619c2ff621e))
- Enhance `suricata-update` accessibility check with fallback path verification. ([`cd114b0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/cd114b0c0fc6608c885ce809ab6b7892fc0e28f6))
- Add sudo to suricata-update executable checks in install test. ([`6ca65ac`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6ca65ac0d5b23707d3a63518b10f510c42bac9cc))
- Skip suricata-update accessibility test if binary is not found ([`03e5e48`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/03e5e48f336233e1c29c07b97ffed1249cf8aea5))
- Improve robustness of Suricata installation tests by adding dependency checks and a process startup delay. ([`e4d356b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e4d356b8d778ca1d7993dcc5ae84188f2e27d3a9))
- Remove suricata-update accessibility and platform-specific tests ([`2482047`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2482047493f392bd98dc5369cff6d5b7e61a3fe7))

### Build

- Change default configuration missing warning to an informational message. ([`99c4b9c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/99c4b9c0e93444051da58533442b3911c38e87d8))

## 0.1.5 - 2025-09-28

[255470e](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/255470e28749d7fd0f4ce7d18134ad53c31acb2d)...[b5b99d4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b5b99d404c1ed116b6ea7705146c7fe291084b6f)

### Bug Fixes

- Optimize Npcap installation timing and verification ([`7206716`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7206716516323f7d2d20c4a667328c22616122f7))
- Remove check for npfs driver not used by mpcap ([`d3b5ef5`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d3b5ef57d85945a21d3d61356abeb18a13469979))
- String interpolation error ([`1b58c23`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1b58c23752a5ccae1dc063d74d1c4312a07cdf93))
- String interpolation error ([`0b56604`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0b56604c858ad9a44fd5431795ea6ab7db17ef19))
- Add check to install Suricata 7.x for EL9+ RHEL like systems ([`749f562`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/749f562c2f76cd0204b5e5fdebf4ecfb8b6619ab))
- Update uninstall.sh to consider all installed components in install.sh ([`ade5caf`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ade5caf36cba7763c1f39facb840fae8057f4d62))
- Remove dependency removal step, it is redundant ([`2d021f0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2d021f0a0643cfbc4804fda0aced31199330b072))

### Features

- Add automated PowerShell installation scripts for Npcap and Suricata ([`11a38b6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/11a38b6d9f7b7224debcd2ab71616a49051bd0e9))

### Miscellaneous Tasks

- Update script url to reference main ([`b5b99d4`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b5b99d404c1ed116b6ea7705146c7fe291084b6f))

## 0.1.4 - 2025-09-15

[5c6f5a0](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5c6f5a0a7a46e6669915a21fea580b09e69e3a31)...[255470e](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/255470e28749d7fd0f4ce7d18134ad53c31acb2d)

### Bug Fixes

- Correct GitHub release download URL construction ([`60f6255`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/60f625579fd65815eb36b998c2b245fc54c5080e))
- Adjust tar extraction to handle opt/suricata directory structure ([`575ce19`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/575ce19f513d96d4c31bdb2df3fa5062543ee60c))
- Extract only opt/suricata contents from tarball, excluding _meta directory ([`bb8beae`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/bb8beaec19bd97dc668315aa9ffd4952285aba09))
- Ensure quarantine attributes are removed from all files and directories ([`7263351`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7263351edfbd985341dc09765e574b4d8b8c82d9))
- Add PYTHONPATH configuration for suricata-update module resolution ([`fc3571d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fc3571dae9b94ca0924513b22211b3a7dc252b5b))
- Handle unbound PYTHONPATH variable in install script ([`e5b7b31`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e5b7b31ad56b24bc0cd9ab3c592168e5f89619ef))
- Handle externally-managed-environment error for pyyaml installation on macOS ([`5d1aca8`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5d1aca804fee92085c1e1bffc0590bcc31344795))
- Add brew install for all dependencies ([`876d04f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/876d04fd174d6260588406282ebf0d2a81b7a8b7))
- Remove local keyword ([`4fe9432`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4fe9432f68680e35c958767c965d21e55b0e71c6))
- Remove brew install pyyaml since deprecated ([`b4a4684`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b4a4684c31c52036568ebbb773d048474927b1a9))
- Make python interpreter dynamic ([`c685d82`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c685d8214c3c2341e3ba2f4dbeec4c943fa42afb))
- Prevent infinite loop in suricata-update wrapper script creation ([`2273208`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/22732088866fd80bc2773a47121a6b849fb4c5c2))
- Fix python wrapper issue for amd macOS ([`d05799a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d05799aaf1b48ca6b2836009e9c0fe28fe3c7e5f))
- Standardize embedded /opt/suricata/bin/suricata-update shebang to #python3 for portability. ([`ed02f20`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ed02f206d5366d6063402e313ee4df5eda16b9c0))
- Remove wrapper ([`ba569f9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ba569f97ec5be3a8378ce9c3f9d25005693e1534))
- Revert to commit working for amd macOS ([`99a02fa`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/99a02faeaaf8a576c5c3213fdcdb934eb4d36f38))
- Apply suricata-update shebang fix only on macOS ARM ([`2a3e187`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2a3e1873ea6087cc743bda9a26dc2c4b2268d6dc))
- Implement architecture-specific suricata-update handling for macOS ([`9d28f9d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9d28f9df9def205136bd245b525f2f079e8778f8))
- Resolve suricata-update wrapper recursion on macOS ARM ([`45c47ad`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/45c47adddd43e6b92e19eef2f5b1d69d814b05db))
- Replace suricata-update symlink with portable launcher ([`d6f8ee5`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d6f8ee5753c55c25a1fc9f547c86f04039114eb0))
- Use direct path to suricata-update ([`b8a13bd`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b8a13bdb4d117db759350f8f9933372f586f7b59))
- Make check conditional to macOS ([`78ccedc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/78ccedc1def1e3e561629bd7de58ea85f1ccd912))
- Reference exact path for suricata bin ([`f46d63b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/f46d63b2ad6016fe2ea873510e9f44d6657bea20))
- Add --no-check-certificate option to suricata-update command ([`a072571`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a072571c97287cc336bf3ca6823ba326441059b6))
- Remove --no-check-certificate option to suricata-update command ([`4b4a8fe`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4b4a8fe835b6ecd4d1a37844f4566477d759a9a4))
- Run Suricata installation script with sudo for proper permissions ([`7bff108`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7bff108948bc86ca8808f417e9aee7893d4f7292))
- Use sudo to list rules directory for proper permissions ([`fba2131`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fba2131e267e2ebaab0e661fe8f720bf658d64e4))
- Remove sudo to list rules directory for proper permissions ([`9f26bb5`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/9f26bb55faf3b61a7851ee9623cb81a8fd01b6d9))
- Add sudo to tests for accessing rules and configuration files ([`aa3ac62`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/aa3ac621009fd55d92971201b8f87e7177e86887))
- Remove outdated Suricata-update tests for macOS ARM64 and Intel ([`d984508`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d9845085e0be418159b88294c5f8c336d5ca29cd))
- Update macOS Suricata process check to use launchctl ([`27a9562`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/27a9562052834f6e87c387e46b1474311b34a0f3))
- Run Suricata installation script with sudo in IPS mode and add macOS-specific tests for Suricata-update ([`b1d9ec2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b1d9ec27b861cf0149f8beee33933030bfda97c9))
- Add verification for Suricata process after loading macOS Launchd plist file ([`57cc427`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/57cc427201afb60e256152187a49e1bf43c3d843))
- Enhance rule initialization and combination in download_rules function ([`554a274`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/554a274821c0f0d73a11f10da2cf2bfcc00c81a7))
- Remove Suricata process verification after loading macOS Launchd plist file ([`8a46c42`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8a46c42ab30e7f487735115a8b4a3645ee6a9f89))
- Clean up macOS installation script by removing unused variables and functions ([`e873d73`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e873d73648ec01619fb399ca760604b848c59192))
- Set default Suricata version in installation script ([`e6c0b7f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e6c0b7fe2a5be42eb8cd56e664f507b40a95f0c6))
- Install prebuilt suricata bin on ubuntu ([`ba2eb31`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ba2eb31b4b643087a142a4a966d29d1fb55b364f))
- Update url's to prebuilt binaries ([`e1b1015`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e1b10157512fadb439623c416828b211d2ee71da))
- Copy suricata bin folder to /opt and link to /usr/bin ([`723ce98`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/723ce981eee23551079182f60d5f41538ce7d9da))
- Create suricata service ([`b11ce83`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b11ce83d6673e65ccbd94717a5e96210277adffe))
- Install pyyaml system wide ([`a8d5131`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a8d513132c32bc3f8e00bfe57cebad057b6c5fbd))
- Remove pyyaml suricata update dependency ([`629cbbc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/629cbbcee3bd3a44336587987ae0a91f8d4f065b))
- Start suricata service when creating systemd service file ([`5587336`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/55873365282e39334f1e14a7c02400e49eaa2d22))
- Ensure Suricata service starts after configuration update ([`fb8e9be`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fb8e9be2e9900ab0e74dbddce117af12ff37f872))
- Add check to see if usr/local/bin exists and added to PATH ([`e5c8b0d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e5c8b0d6958f9da78956f39233114d3e622070f5))
- Add libhyperscan5 runtime library ([`13f8071`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/13f80716d71b5934cf918611a5f8b64249dba73b))
- Remove CELLAR_DIR only for macOS ([`55f3cbb`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/55f3cbb275ba3c3640a8abda054bcc841881c37d))
- Remove suricata-update wiring log and hyperlevel dependency for centOS/RHEL ([`8977ed1`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8977ed148784bcb283ee4be2ea8201a7a66bed65))
- Remove python and pip installation for suricata-update on macOS, disable stats in config file ([`5d4caa0`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5d4caa0da472efa8a20f433908be0941922bd560))
- Uninstall for centOS ([`6d700f6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6d700f60db56a5eba13720add1b0e00d8a2c251d))
- Remove python and pyyaml installs in install script ([`a4d010e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a4d010ea5726ff8e5633c2b720570e68a17b4cb2))
- Check /usr/local/bin dir exists for macOS ([`1ce8bbc`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1ce8bbcf137aeab2316ed553085d49436f4cbc92))
- Uninstall all required dependencies for macOS ([`34fd428`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/34fd428e5e0a1fe4e94fc84a7f772eb5511353bb))
- Add function to configure centOS/RHEL suricata service ([`6082d64`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6082d64d0e7d2ae6967bb827de49271b21a55880))
- Fix workflow to remove suricata dependencies if not required by other components ([`0ab1229`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0ab1229fb3bda4e071c469c469213750809d1512))
- Fix macOS fallback interface to en0 ([`4937f3b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4937f3b6bc31fd5aa23244c6ba729ed289ab8aaf))
- Make sure linux and macOS systems get version-compatible rules ([`d5c9632`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d5c9632b7f2635fa49194166cfe037ecfc353f4d))
- Check for active/UP interfaces when using detect_wifi_interface function ([`895083f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/895083f04e632c359778d7736090248121aa8f8e))
- Check for active/UP interfaces when using detect_wifi_interface function ([`2f72380`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2f7238087df47d78577f633a943af297afb3e2b7))

### Features

- Replace Homebrew tap installation with GitHub release prebuilt binaries for macOS ([`01c4958`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/01c4958df170defcb61e7050a9c602f1ae98c65f))
- Add template suricata.yaml config file for use when installing ([`52e7f8e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/52e7f8e9e8d5e141f2837b680da0b1b411c250af))
- Add architecture-specific config file installation to /opt/suricata/share ([`4e8fab9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4e8fab964e049af9eb21fe59a584f32f1214417b))
- Update install.sh to use rsync for macOS installation and add Homebrew cleanup ([`ad1bea2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ad1bea265fecd366d3b8af35299e1695e37e7813))
- Add libmagic dependency installation for macOS ([`4911263`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4911263b1d228590f9a6391f9a64f8aa29034044))
- Restore Python wrapper for suricata-update with /usr/bin/python3 ([`507ea41`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/507ea41677c41cf54a774de15eee7a53210c7001))
- Update uninstall.sh to consider suricata installed using prebuilt package ([`369194e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/369194e72e5acac621b6be2c104dfddd5e1f5ecb))
- Enhance rule downloading process with temporary directory and macOS quarantine handling ([`d3c874e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d3c874ed80beec5a64aa796c68dba26f24f3d800))
- Install suricata for centOS/RHEL ([`7b47986`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7b4798675b8fa6e65a10a8790b2e0fc2a8ebf98e))

### Miscellaneous Tasks

- Update suricata_github_tag to v8.0.0-adorsys.2-rc.2 ([`1bbe10b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1bbe10b520a98781290164851906a90008581056))

### Testing

- Update bats tests for new /opt/suricata installation paths ([`17b9e41`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/17b9e418e9c11ef524f2920bcdcc982cefc3333a))

## 0.1.3 - 2025-08-28

[0ea9971](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0ea9971f3bf5582a26b0b4a129654b48faae94d1)...[5c6f5a0](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5c6f5a0a7a46e6669915a21fea580b09e69e3a31)

### Bug Fixes

- Install Suricata via local Homebrew tap instead of direct download ([`ca6a8fe`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ca6a8fe99a91ae2c5b8d56edd4277d092f87af8b))
- Update install.sh and uninstall.sh to for suricata@7.0.10 on macos ([`2149d0e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2149d0ef43d54dbf4ab79f386df6f1b856840e43))
- Improve method to uninstall suricata on macos ([`a2e1ac7`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a2e1ac76c8d729a34c8f6393348e72e528906dea))
- Add unpin command before delete for proper suricata removal ([`7f79ec9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7f79ec900a3099fa728cc4c898dd91bb975bbf5e))

## 0.1.2 - 2025-08-14

[c89fcb4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c89fcb48298e64241ca6f04ea174ca899b31dcfe)...[0ea9971](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0ea9971f3bf5582a26b0b4a129654b48faae94d1)

### Bug Fixes

- Update method to retrieve logged-in user on macOS by using brew --prefix ([`0d858d4`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0d858d40d37eaddea8ee0bc9a9569dc30c6d870a))
- Enhance error handling for retrieving logged-in user on macOS ([`e378aa1`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/e378aa1b9edff2f0784c56787e27b3baf28ebbba))
- Detect Homebrew owner via prefix path for launchd compatibility ([`49f6ea5`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/49f6ea503c572a02490acb9d6fb2c3ed5d422cc7))
- Restore deleted Homebrew helper functions ([`fa75e5b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fa75e5bd8eff6e51275d45a74355c7ba97d41502))
- Revert method of getting logged in user ([`497cd21`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/497cd21248092011d347615ce50f85a2adfe77d8))
- Resolve Suricata installation permissions with clean user environment ([`49848e9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/49848e99eee0d84171aab2a7348ed50f8a3ca3c1))
- Remove error handling ([`55b1e52`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/55b1e5274accbc71cc9ba9293f62240bac0c5c34))
- Add -i flag to brew command to simulate initial login ([`8662343`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/86623432b289b7e4ed2efe8e9f77d51e24f49f64))
- Change return to exit for critical installation failures ([`a85e566`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a85e5666e81cb7de7950611292570e9ca4b74b5f))

### Refactor

- Clean up brew prefix detection logic ([`5b3912a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5b3912ab2ce4d4646a93bb7c6e47c0fd84227ba4))

### Testing

- Get logged in user using brew --prefix ([`27d0237`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/27d023784806f9ec34ee1cecac49a8425a4c2535))

## 0.1.1 - 2025-07-15

[0213f41](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0213f411f719d2eb5d71f6b0a1637b05978d5514)...[c89fcb4](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c89fcb48298e64241ca6f04ea174ca899b31dcfe)

### Bug Fixes

- Update Suricata version check command for macOS installation ([`4b8f2ae`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4b8f2ae116e9521927a14939740b86365eb59e05))

## 0.1.0 - 2025-06-05

### Bug Fixes

- Fix suricata install in test workflow ([`5e62dc6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/5e62dc68b8a19d9e03dc440c4753aaa39663133a))
- Fix suricata test workflow ([`3ddcdc2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/3ddcdc23453043016c174a3824676ed83aa40c30))
- Remove unnecessary sudo for script execution in test workflow ([`448e102`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/448e1029be49722253f895e43f1703011dd1bf6b))
- Improve Wi-Fi interface detection logic in install script ([`6657013`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6657013546bf8ffab2694bee6405260ef34f1afb))
- Unload previous plist file before loading new daemon ([`db661c9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/db661c97742c3a916c40a0c8557e5a7e25295b57))
- Update Suricata process check to use launchctl for macOS ([`848f23c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/848f23c44ddc18f5765277659984dd3e60aa461a))
- Remove service status checks for Suricata in install script ([`c98cb98`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c98cb98d02bf2ef33b6f4f0c9458ad939fce3340))
- Enhance OS and architecture detection logic in install script ([`82df13e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/82df13e8a869b82d74a5093ed4fb376594dc07be))
- Update Wi-Fi interface detection to prioritize networksetup command ([`273dc7c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/273dc7c6580f7ac0f6203be4ba0fd0034c633168))
- Refactor installation script for improved command checks and directory handling ([`94a3369`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/94a3369e5c37646f69c39502bdff8ca2fffb2188))
- Refactor command checks for service management and package removal ([`0fe7804`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0fe7804a025009fc91b25cc8f0271925abf298c9))
- Remove unnecessary sudo for Homebrew uninstallation command ([`4afed95`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4afed95f07e5100c3de7833639130e8958b6b1a3))
- Add default fallback for Wi-Fi interface and HOME_NET detection ([`6152fd7`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6152fd747801db21d083718244f632576461b1b8))
- Add default fallbacks for Wi-Fi interface and HOME_NET detection ([`f491ced`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/f491cedfbbe82b953b5d442a4fe18b281273907e))
- Add check for non-empty netmask before setting HOME_NET ([`dd2adba`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dd2adba11addcfaed96a43dec4d0c5023834ce76))
- Fix yq usage on macos ([`b023317`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b0233177ef92122b648ecb29beb6cd371a32541f))
- Improve tests ([`46ca0f9`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/46ca0f9cd7d134a9645c58f549f44da0d63a2b46))
- Fix directory paths for Suricata configuration and logs on macOS ([`92f5724`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/92f572435b5846257375bf1a5f9c7ad03225a0c9))
- Update help message and change yq installation path to /usr/bin ([`541cd35`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/541cd3533abe937e197573d149fde0a1f70b2e65))
- Improve test-install.bats for better OS detection and rule validation ([`15f8d56`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/15f8d568e45025133e6dd4df766920e602e9b050))
- Update yq uninstallation path to /usr/bin ([`8258e5f`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8258e5f7dc9a448e90d24b33d72f9463cf5efc37))
- Fix(test): fix drop config test to occur only in ips mode ([`2bcc21c`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2bcc21c5bc3e1ad96d065de42370f8b78c9023fc))
- Rename test job to test-ids and update dependencies for test-ips ([`8ca17e2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/8ca17e2595815113b18cc07091a4d52f2e368918))
- Update custom drop rule test to check for rule presence in suricata.rules ([`1ced1b6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1ced1b6a48bb340bade5fab4024e06654a2ecc60))
- Fix the check of existence of rules file using sudo permissions ([`b9c6ede`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b9c6ede49c08965c9175a6133c3c31f110b8e095))
- Fix scheduled-task quoting/bracing and run task as SYSTEM ([`6759950`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/67599504da411109da1c14134043292528197afa))
- Clean PATH, use Npcap uninstaller, stop task before removal ([`cd44295`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/cd44295c3db4e563dc84c5e181b7d501b1c94c58))
- Use maybe_sudo for grep command in update_config function to ensure proper permissions ([`fa41ed6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fa41ed6f4f21197b0abc8f5955c79e6571d5984b))
- Remove maybe_sudo from grep command in update_config function for consistency ([`12c7034`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/12c7034ea2bd8d5053f3ee97f44b7364861e2c5d))
- Replace maybe_sudo with sudo for Homebrew installation on macOS ([`a5b57e4`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a5b57e4ba7ae5e90323a05c56b088d4fb872d0e0))
- Ensure Suricata default file removal only runs on Linux ([`cba1dbb`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/cba1dbb71ac838d7617002b6fbec54c8f4b8f020))
- Ensure proper restoration of UFW configurations during uninstallation ([`74584df`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/74584dfe215928e63ffd3b8074a868d7d82825e4))
- Correct syntax for Suricata version assignment in install script ([`aa8e07a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/aa8e07abdccdf2edd6beb305bbdadff40fb57973))
- Remove redundant yq installation command for macOS ([`159d128`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/159d128c5d57e19c9ef46ba5b6e097275e921e92))
- Improve brew command execution by ensuring correct user home directory ([`6612cda`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6612cda1fdf0050ef86442a6db0a11699180fac7))
- Improve brew command execution ([`fbefbc3`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fbefbc33edcab70561b59b2eab8cf6df502e44e6))
- Uninstall script for MacOS ([`b5bf362`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/b5bf3625501514bd4f16954066b0bd6cf7c423de))
- Improve uninstall script for MacOS ([`008a955`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/008a955e748f5b8df4a44685d060e6fb376ee5d3))

### Features

- Implement comprehensive uninstallation script for Suricata with service management and package removal ([`ff2bc5d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ff2bc5d4a3ac605ea259d17a9a2a6213265b77ed))
- Enhance user experience with command-line options and improved logging ([`4bfe6e2`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4bfe6e21ab6f7efe14686a97662539444752708a))
- Add yq support for YAML configuration updates and improve command-line options ([`0411799`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/04117999fd7253359a20a6cbceb2d9df87aeff5f))
- Add warning message logging for uninstallation process ([`0b3ad2b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/0b3ad2bbf5c6f067182b7168ec2a7ed59030b649))
- Enhance install script with improved configuration and rule management; enchance uninstall script ([`c88d572`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/c88d5722a934d60ed7c969c4b09ca72efc6a45a5))
- Update test-install.bats for improved Suricata checks and configuration validation ([`63f4cbf`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/63f4cbf1347924b78b49094184d470e574b6fcb0))
- Add custom drop rule for IPS mode and update tests to verify its presence ([`ed53149`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ed53149f10243fffab0765e657200e5b5a075564))
- Add script to install suricata on windows and add pester unit tests and update github actions workflow for windows testing ([`3919f75`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/3919f75de032cf3ef165e9320144f753aabb81f4))
- Add uninstall script for Suricata and related components; remove obsolete install tests ([`4f7e37b`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/4f7e37b6f624697cf1b0fc65f2251dfbacc7d45c))
- Add release workflow with Bats tests and versioning steps ([`dae9f54`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dae9f54eca975b9d1b293233f3102f465c47b245))
- Enhance macOS installation process for Suricata using Homebrew ([`f946586`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/f94658600b1757da343174447c81590b8b13e4df))
- Add function to get logged-in user and run Homebrew commands as that user on macOS ([`ac75da6`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ac75da6a8beca9e8f1352f751ff03817eb6d9df5))
- Simplify user retrieval on macOS and run commands as logged-in user ([`6a74897`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/6a7489769729a39f4a62f5d9f35a4e514e1a94eb))
- Implement logged-in user retrieval for command execution in install and uninstall scripts ([`41b3d48`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/41b3d485a58c53d21f01084d59146683df49cdab))
- Parameterize Suricata version and enhance uninstall process with mode detection ([`1ffc839`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/1ffc839008659ea9e770f854fbc125ae0716f3d3))
- Add macOS installation support for Suricata from source ([`7b5bd22`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/7b5bd2252b4f04fab82b52edde2c2355c30511dc))
- Add macOS installation support for Suricata from source ([`eee29fe`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/eee29fe45074b065c1782f22180e71b72e0f3130))
- Add unpin command for Homebrew during Suricata uninstallation ([`af09633`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/af096334d5a3f95578a6b7916e2ef52cdf706ed9))
- Add unpin command for Homebrew before uninstalling Suricata ([`fa2bf33`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/fa2bf33f8990e6f910ddd125dffe02892a7b313e))
- Enhance uninstallation process for Suricata on Linux ([`ead25ee`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/ead25eed0ad085318bec7e8ac70c1b0fae5b1f12))
- Enhance Suricata installation process on macOS with version checks ([`024c54e`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/024c54e5398e050aa5ed18f8d6c679f3de3bcc7b))

### Miscellaneous Tasks

- Initial commit ([`23fd164`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/23fd164ab3d57a7618a16ef751e85ae0e4aeaf3b))
- Enhance error handling and logging in uninstall functions for Suricata and Npcap ([`2f83e31`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/2f83e31f6edfb96b25e626c91a04118e5120884a))

### Refactor

- Pass Suricata binary path to plist file creation function ([`dfb1a7d`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/dfb1a7ddfe42a83ab6165ca9b732d497f868db9d))
- Streamline logged-in user function to always execute commands as user ([`30fac79`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/30fac791fc520b8a8f10801afde3e5592216267d))
- Unify command execution as logged-in user for Homebrew operations ([`53c345a`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/53c345a795e587554704a33c007a7c92aac504f9))
- Conditionally retrieve logged-in user on macOS ([`a3e04d1`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/a3e04d104c08031dc71131577d5f58a0d0863301))
- Move logged-in user retrieval to a dedicated section for clarity ([`32dedf3`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/32dedf39dfa3fb867cde2e31110939489d15f6e1))
- Streamline uninstallation process logging for Linux ([`d372ef4`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/d372ef411a44b4444a421966c578a3e068786e25))

### Testing

- Test ci workflow ([`eb94254`](https://github.com/ADORSYS-GIS/wazuh-suricata/commit/eb942549b95b55042611f91353fbb6dc42a3e4cf))

<!-- generated by git-cliff -->
