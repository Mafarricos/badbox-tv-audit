# Android TV & Google TV Forensic Suite (BadBox, XCPE, Vo1d & Malware Remediation)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-AI Rules](https://img.shields.io/badge/Detection-Deterministic%20Scoring-orange.svg)](#-zero-ai-deterministic-scoring-matrix)
[![App Remediation](https://img.shields.io/badge/TV%20App-On--Screen%20Remediation-success.svg)](#-native-android-tv-app)
[![Logging](https://img.shields.io/badge/Logging-Live%20Console%20%2B%20Transcripts-informational.svg)](#-live-telemetry--audit-logs)

An autonomous, dual-layer forensic, malware removal, and reversible remediation suite (CLI + native Android TV app with local loopback VPN sentinel) engineered to audit, detect, verify, neutralize, and restore Android TV, Google TV, and generic streaming devices compromised by supply-chain trojans, botnets, and malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS**, and **Residential Proxyware**).

> **Language:** English (Default) | [Para a versão em Português (PT-PT), consulte README.pt.md](README.pt.md) | [📱 Tested Devices Registry](DEVICES.md) | [🔬 Architecture Decisions (ADRs)](docs/DECISIONS.md) | [📜 Third-Party Notices](THIRD_PARTY_NOTICES.md)

---

## 🎯 Why this tool?

Thousands of budget Android TV boxes and Smart TVs arrive pre-infected straight from the factory or become compromised via malicious streaming apps and trojanized firmware. The malware typically:
1. Silently turns off **Google Play Protect** by forcing `package_verifier_user_consent = -1`.
2. Installs persistent trojans and backdoors (such as **Vo1d**, **BadBox**, or **XCPE**) into the `/system` or `/vendor` partition (surviving factory resets).
3. Secretly runs **residential proxyware SDKs** (turning your home TV into an illegal proxy exit node and reselling your home Internet bandwidth) and performs hidden background ad-fraud.

This suite provides two complete audit & cleanup paths:
- **For Everyday Users (No PC required, Remote D-Pad only):** Install the APK on your TV via USB flash drive or browser. The app runs the scan, displays the verdict, and exposes the red **"NEUTRALIZE THREATS"** button. For system implants that cannot be deleted without ADB, the app activates a persistent **VpnService Quarantine Sinkhole Mode** that blocks malicious network traffic directly on the TV.
- **For Technicians & AI Agents (Via PC / ADB):** 100% silent and automated pipeline (`audit_security.py`) featuring subnet discovery, token-saving pure JSON mode, mandatory backups, APK quarantining, and injection-safe parameterized rollback.

---

## 📱 1. Preparing Your TV (Enable Developer Options & ADB)

Before running tools or dispatching an AI Agent, enable **ADB Debugging** on your TV so it can be audited over Wi-Fi:

### A. Standard Android TV (Android 9, 10, 11 - e.g. Xiaomi, Strong, generic boxes):
1. Go to **Settings** (gear icon) -> **Device Preferences** -> **About**.
2. Scroll down to **Build**.
3. Press the **OK / Center button 7 times** until the screen confirms: *"You are now a developer!"*.
4. Go back to **Device Preferences** -> **Developer Options**.
5. Enable **USB Debugging** and (if available) **Network Debugging**.
6. When prompted on the TV screen *"Allow USB debugging from this computer?"*, select *"Always allow from this computer"* and confirm **OK**.

### B. Google TV (Android 12, 14 - e.g. Chromecast, realme, Thomson, TCL):
1. Navigate to your profile icon (top right) -> **Settings**.
2. Select **System** -> **About**.
3. Scroll to **Android TV OS build**.
4. Press the remote's **OK button 7 times** to unlock Developer Options.
5. Return to **System** -> **Developer Options**.
6. Enable **USB Debugging**.
7. Confirm the authorization pop-up on the TV screen.

> [!WARNING]
> 🔒 **Security Best Practice (Turn OFF Debugging when finished):**  
> Leaving ADB / USB Debugging permanently enabled on your home Wi-Fi network exposes a management port (5555) that other devices or malicious apps on the local network could theoretically probe.  
> **Always remember to turn OFF USB Debugging in Developer Options once the audit and remediation are complete!**

---

## 🤖 2. Dispatching an AI Agent (Antigravity, Claude Code, Grok, Cursor, Copilot)

This repository includes self-contained operational guidelines in [`AGENTS.md`](AGENTS.md) that modern AI coding agents automatically follow. **You don't need to manually configure Python, install drivers, or write commands.**

> [!IMPORTANT]
> 🛡️ **Safe Autonomous Workflow for AI Agents:**  
> Always instruct the AI Agent to run `--quick-scan` (100% read-only diagnosis) first. Review the technical findings and the remediation plan before executing `--remediate`.

Simply open your AI Agent and send this single prompt:

```text
Clone https://github.com/Mafarricos/badbox-tv-audit.git, read AGENTS.md, and audit my Android TV at IP <TV_IP>.
```
*(Tip: If you do not know your TV's IP address, ask the agent: `...read AGENTS.md, discover my Android TV devices on subnet 192.168.1.0/24, and audit them.`)*

The agent will autonomously:
1. Clone the repository and review [`AGENTS.md`](AGENTS.md) for forensic instructions.
2. Connect over pure-Python ADB (no external ADB installation required).
3. Execute the 6-layer static scan and live VPN network sentinel.
4. Generate a sanitized anonymous audit report (`community_audit_submission.json`) ready to help update the infected devices database.

---

## 📺 The Native Android TV App (`app/`)

The application is localized automatically (Portuguese if device is set to Portuguese; English for all other languages) and is 100% D-Pad navigable:

1. **Button 1: SCAN TV BOX (STATIC):** Audits `/oem/`, `/vendor/`, Play Protect integrity, trojan artifacts (Vo1d, XCPE), and inspects package signatures in seconds.
2. **Button 2: MONITOR NETWORK (VPN):** Local loopback sentinel alerting in real time:
   - **RED (`[CRITICAL]`):** If the TV initiates connections to known C2 servers or malicious domains.
   - **ORANGE (`[SUSPICIOUS]`):** If a connection is made to a known botnet/proxy port without matching a known C2 IP/domain.
   - **YELLOW (`[ANOMALY]`):** If unusual high-port network traffic is detected while the TV is idle.
   - > **Note on Network Connectivity during Monitoring:** During the VPN Sentinel window, DNS queries (UDP port 53) are actively inspected and forwarded so malware domain lookups succeed, while direct TCP/UDP data packets are inspected and dropped in the loopback interface. Consequently, general internet browsing/streaming is temporarily paused while the monitor is active and immediately resumes once the VPN is stopped.
3. **Button 3: NEUTRALIZE THREATS (Appears when anomalies are detected):**
   - **User Packages & Updates (/data/app):** Launches sequential uninstallation prompts.
   - **System Implants (/system, /vendor):** Isolates eligible packages via **VpnService Quarantine Sinkhole** mode. For factory packages sharing `android.uid.system` (UID 1000, such as `com.oemservice`), VPN quarantine is skipped so as not to block core Android system services, and the app displays the exact ADB command (`adb shell pm disable-user --user 0 <package>`) required to freeze them safely. Also notes that Android TV Settings disables the graphical "Disable" button (`canDisable=false`) for platform-signed system apps.
   - Shortcut to verify and re-enable Google Play Protect verification.

### 🛡️ Building & Signing the App
To protect repository integrity against binary supply-chain attacks, keystores and prebuilt APKs are not tracked in git (SEC-01).
- **Official Release APK**: The pipeline automatically downloads and verifies the official signed APK release (`xcpe-scanner-tv.apk`) into `tools/` with `apksigner` against `tools/apk_pin.json`. You can also manually download it from [GitHub Releases](https://github.com/Mafarricos/badbox-tv-audit/releases) and place it in `tools/xcpe-scanner-tv.apk`.
- **Compile Local Debug Build**: If you build the app locally with `./gradlew assembleDebug`, the pipeline detects local builds and allows the debug key with an explicit security warning.
- Compile debug build: `cd app && ./gradlew assembleDebug`
- Unit tests: `cd app && ./gradlew testDebugUnitTest`
- Release signing documentation: [`docs/RELEASE_SIGNING.md`](docs/RELEASE_SIGNING.md)

---

## 🚀 CLI & AI Agent Usage

The suite **automatically detects your system language** (defaults to **English** for international users, or **Portuguese** if your operating system is in Portuguese). You can also explicitly force a language with `--lang en` or `--lang pt`.

### Two Audit Modes Available:
- **Fast 6-Layer ADB Scan (`--quick-scan`)**: 100% read-only, takes 5-10 seconds, installs nothing on the device. Audits all known threat families (XCPE, BadBox, Vo1d, droppers, active C2 sockets, and Play Protect status).
- **Intensive Dynamic Sentinel (`--auto-pipeline`)**: Deploys the on-device TV app (`com.scanner.tv`), raises a local VPN loopback for 20-60 seconds to inspect live DNS/IP traffic looking for unknown or dormant botnets, pulls reports, evaluates rules, and automatically uninstalls the app cleanly.

```bash
# 1. Intensive Dynamic Audit (Installs APK, runs 20s VPN sentinel for unknown threats, and cleans up)
python tools/audit_security.py <TV_IP> --auto-pipeline

# 2. Fast 6-Layer ADB Read-Only Scan (Known threats triage - Standard or Token-Saving Pure JSON)
python tools/audit_security.py <TV_IP> --quick-scan
python tools/audit_security.py <TV_IP> --quick-scan --json

# 3. Discover and Audit all Android TVs across the Home Subnet
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 4. Multi-Layer Deep Remediation with Preview Plan (--dry-run)
python tools/audit_security.py <TV_IP> --remediate --dry-run
python tools/audit_security.py <TV_IP> --remediate

# 4.1 Non-Interactive Remediation for AI Agents (requires explicit --yes)
python tools/audit_security.py <TV_IP> --remediate --yes

# 4.2 Remediation with Post-Reboot Persistence Check & Cloudflare DoT
python tools/audit_security.py <TV_IP> --remediate --yes --verify-reboot --enable-dot

# 5. Restore Previous State (Rollback from snapshot)
python tools/audit_security.py <TV_IP> --restore --backup backups/<device_id>/backup_<timestamp>.json

# 6. Export C2 Domain Blocklists (for Pi-hole, AdGuard, dnsmasq, /etc/hosts)
python tools/export_blocklist.py --format all

# 7. Validate Canonical IoC Database Schema
python tools/validate_iocs.py
```

---

## 📤 Contributing: Submitting Audit Reports for the Device Registry

Help us track which Android TV and Google TV models ship with factory droppers or clean firmware!

Whenever an audit is performed (via `--quick-scan` or `--auto-pipeline`), the suite **automatically generates an anonymized report** at:
```text
community_audit_submission.json
```

### 🛡️ Privacy Guarantee (Allowlist Sanitization):
- **All private identifiers are automatically stripped** via strict allowlist: No local IP addresses, no public IPs, no MAC addresses, no serial numbers, no chip IDs, and no IMEIs (PRIV-01).
- Contains **only** technical firmware attributes: SoC model, build version, Play Protect status, detected dropper packages/hashes, and active C2 ports.

### How to Submit:
1. **GitHub Issues (Recommended):**
   - Open a new issue at: [https://github.com/Mafarricos/badbox-tv-audit/issues](https://github.com/Mafarricos/badbox-tv-audit/issues)
   - Title: `[Device Audit] <Brand> <Model>` (e.g. `[Device Audit] Strong 4K Google TV Stick`)
   - Paste the contents of `community_audit_submission.json`.
2. **Via E-mail:**
   - Send the `community_audit_submission.json` file directly to the email published on the YouTube channel: **`mafastudios@gmail.com`** (Subject: `TV Audit Report: <Brand> <Model>`).

Your report will be reviewed and merged into the official [Tested Devices Registry (DEVICES.md)](DEVICES.md)!

---

## 🔒 Safety & Reversibility Guarantee

Every remediation action creates an exact JSON snapshot under `backups/<device_id>/backup_<timestamp>.json` and an executable rollback script. Uninstalled APKs are quarantined with SHA-256 checksums under `backups/<device_id>/quarantine/`.

> [!IMPORTANT]
> **Persistence Notice (OTA Updates & Factory Reset):**  
> Because supply-chain droppers (such as `com.oemservice` / XCPE) are embedded by the manufacturer inside read-only system partitions (`/system` or `/vendor`), this tool mitigates and freezes them at the OS package-manager level (`pm disable-user --user 0`) without bricking your device.  
> As a result:
> 1. **Factory Reset:** If you perform a factory reset, the device resets to its initial factory image and the dormant backdoor will reactivate. You will need to run this audit/remediation tool again.
> 2. **System / OTA Updates:** A system update issued by the manufacturer could either definitively patch/remove the backdoor or, conversely, unfreeze system packages. If your TV receives a firmware update, re-run `--quick-scan` to verify whether the brand clean-patched the ROM or if remediation needs to be reapplied.

---

## ⚠️ Disclaimer

This software is provided for educational, forensic, and security research purposes only under the [MIT License](LICENSE). Third-party threat intelligence references remain the property of their respective authors ([Third-Party Notices](THIRD_PARTY_NOTICES.md)).

---

## 👨‍💻 About Me & Acknowledgments

Hi, I'm **Carlos Correia**! I'm a tech enthusiast, geek, and developer who has always been passionate about the Android TV box ecosystem. For years, I have actively advocated for and recommended certified Google TV and Android TV devices to friends, family, and the community.

Discovering the recent findings regarding **VideoStrong / SZBBOYS supply-chain compromises (BadBox & XCPE)** on certified and mainstream hardware motivated me to build this open, transparent, and autonomous repository — empowering anyone to easily audit, detect, and neutralize malware, trojans, and residential botnets with just their TV remote or a single command.

### Support My Work:
If you find this suite useful and want to support the project:
- 📺 **Subscribe and check out my YouTube channel:** [@Carlos___Correia](https://www.youtube.com/@Carlos___Correia)
- ⭐ Star this repository and share it with the Android TV community!
