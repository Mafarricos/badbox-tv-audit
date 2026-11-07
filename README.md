# Android TV & Google TV Forensic Suite (BadBox, XCPE, Vo1d & Malware Remediation)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-AI Rules](https://img.shields.io/badge/Detection-Deterministic%20Scoring-orange.svg)](#-zero-ai-deterministic-scoring-matrix)
[![App Remediation](https://img.shields.io/badge/TV%20App-On--Screen%20Remediation-success.svg)](#-native-android-tv-app)
[![Logging](https://img.shields.io/badge/Logging-Live%20Console%20%2B%20Transcripts-informational.svg)](#-live-telemetry--audit-logs)

An autonomous, dual-layer forensic, malware removal, and reversible remediation suite (CLI + native Android TV app with local loopback VPN sentinel) engineered to audit, detect, verify, neutralize, and restore Android TV, Google TV, and generic streaming devices compromised by supply-chain trojans, botnets, and malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS**, and **Residential Proxyware**).

> **Language:** English (Default) | [Para a versão em Português (PT-PT), consulte README.pt.md](README.pt.md) | [📱 Tested Devices Registry](DEVICES.md) | [🔬 Forensic Case Study](docs/FORENSIC_XCPE_OEMSERVICE.en.md)

---

## 🎯 Why this tool?

Thousands of budget Android TV boxes and Smart TVs arrive pre-infected straight from the factory or become compromised via malicious streaming apps and trojanized firmware. The malware typically:
1. Silently turns off **Google Play Protect** by forcing `package_verifier_user_consent = -1`.
2. Installs persistent trojans and backdoors (such as **Vo1d**, **BadBox**, or **XCPE**) into the `/system` or `/vendor` partition (surviving factory resets).
3. Secretly runs **residential proxyware SDKs** (turning your home TV into an illegal proxy exit node and reselling your home Internet bandwidth) and performs hidden background ad-fraud.

This suite provides two complete audit & cleanup paths:
- **For Everyday Users (No PC required, Remote D-Pad only):** Install the APK on your TV via USB flash drive or browser. The app runs the scan, displays the verdict, and exposes the red **"NEUTRALIZE THREATS"** button for on-screen app uninstallation and security hardening.
- **For Technicians & AI Agents (Via PC / ADB):** 100% silent and automated pipeline (`audit_security.py`) featuring subnet discovery, token-saving JSON mode, mandatory snapshots, and instant rollback scripts in `backups/`.

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

---

## 🤖 2. Dispatching an AI Agent (Antigravity, Claude Code, Grok, Cursor, Copilot)

This repository includes self-contained operational guidelines in [`AGENTS.md`](AGENTS.md) that modern AI coding agents automatically follow. **You don't need to manually configure Python, install drivers, or write commands.**

Simply open your AI Agent and send this single prompt:

```text
Clone https://github.com/Mafarricos/badbox-tv-audit.git, read AGENTS.md, and audit my Android TV at IP <TV_IP>.
```
*(Tip: If you do not know your TV's IP address, ask the agent: `...read AGENTS.md, discover my Android TV devices on subnet 192.168.1.0/24, and audit them.`)*

The agent will autonomously:
1. Clone the repository and review [`AGENTS.md`](AGENTS.md).
2. Connect over pure-Python ADB (no external ADB installation required).
3. Execute the 6-layer static scan and live VPN network sentinel.
4. Generate a sanitized anonymous audit report (`community_audit_submission.json`) ready to help update the infected devices database.

---

## 📺 The Native Android TV App (`app/`)

The application is localized automatically (Portuguese if device is set to Portuguese; English for all other languages) and is 100% D-Pad navigable:

1. **Button 1: SCAN TV BOX (STATIC):** Audits `/oem/`, `/vendor/`, Play Protect integrity, trojan artifacts (Vo1d, XCPE), and inspects package signatures in seconds.
2. **Button 2: MONITOR NETWORK (VPN):** Local loopback sentinel alerting in real time:
   - **RED (`[CRITICAL]`):** If the TV initiates connections to known C2 servers or proxy ports.
   - **YELLOW (`[ANOMALY]`):** If unusual high-port network traffic is detected while the TV is idle.
3. **Button 3: NEUTRALIZE THREATS (Appears when anomalies are detected):**
   - Launches guided on-screen uninstallation for detected botnet packages.
   - Shortcut to re-enable Google Play Protect verification.
   - Immediate re-scan to verify that the verdict transitions from **`DANGER [INFECTED]`** to **`DEVICE CLEAN`**.

---

## 🚀 CLI & AI Agent Usage

The suite **automatically detects your system language** (defaults to **English** for international users, or **Portuguese** if your operating system is in Portuguese). You can also explicitly force a language with `--lang en` or `--lang pt`.

### Two Audit Modes Available:
- **Fast 5-Layer ADB Scan (`--quick-scan`)**: 100% read-only, takes 5-10 seconds, installs nothing on the device. Audits all known threat families (XCPE, BadBox, Vo1d, droppers, active C2 sockets, and Play Protect status).
- **Intensive Dynamic Sentinel (`--auto-pipeline`)**: Deploys the on-device TV app (`com.scanner.tv`), raises a local VPN loopback for 20-60 seconds to inspect live DNS/IP traffic looking for unknown or dormant botnets, pulls reports, evaluates rules, and automatically uninstalls the app cleanly.

```bash
# 1. Intensive Dynamic Audit (Installs APK, runs 20s VPN sentinel for unknown threats, and cleans up)
python tools/audit_security.py <TV_IP> --auto-pipeline

# 2. Fast 5-Layer ADB Read-Only Scan (Known threats triage - Standard or Token-Saving JSON)
python tools/audit_security.py <TV_IP> --quick-scan
python tools/audit_security.py <TV_IP> --quick-scan --json

# 3. Infection Stage Classifier (Distinguish Stage 1 factory dropper vs Stage 2 active payload & /oem check)
python tools/detect_infection_stage.py <TV_IP>

# 4. Discover and Audit all Android TVs across the Home Subnet
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 5. Autonomous Remediation (Locks Play Protect, freezes droppers, activates Private DNS DoT)
python tools/audit_security.py <TV_IP> --remediate

# 6. Instant Reversible Restore / Rollback
python tools/audit_security.py <TV_IP> --restore

# 7. Deep Forensics / Package Inspector (Supports --lang en / --lang pt)
python tools/deep_forensics.py <TV_IP> --inspect-package <PACKAGE_NAME>
python tools/deep_forensics.py <TV_IP> --pull-and-analyze <REMOTE_APK_PATH>
```

---

## 📤 Contributing: Submitting Audit Reports for the Device Registry

Help us track which Android TV and Google TV models ship with factory droppers or clean firmware!

Whenever an audit is performed (via `--quick-scan` or `--auto-pipeline`), the suite **automatically generates an anonymized report** at:
```text
community_audit_submission.json
```

### 🛡️ Privacy Guarantee (Zero Personal Data):
- **All private identifiers are automatically stripped**: No local IP addresses, no MAC addresses, no serial numbers, and no Wi-Fi credentials.
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

Every remediation action creates an exact JSON snapshot under `backups/backup_<IP>_<timestamp>.json` and an executable rollback script `backups/restore_<IP>.ps1`. Nothing is modified without an immediate, one-click restoration path.

> [!IMPORTANT]
> **Persistence Notice (OTA Updates & Factory Reset):**  
> Because supply-chain droppers (such as `com.oemservice` / XCPE) are embedded by the manufacturer inside read-only system partitions (`/system` or `/vendor`), this tool mitigates and freezes them at the OS package-manager level (`pm disable-user`) without bricking your device.  
> As a result:
> 1. **Factory Reset:** If you perform a factory reset, the device resets to its initial factory image and the dormant backdoor will reactivate. You will need to run this audit/remediation tool again.
> 2. **System / OTA Updates:** A system update issued by the manufacturer could either definitively patch/remove the backdoor or, conversely, unfreeze system packages. If your TV receives a firmware update, re-run `--quick-scan` to verify whether the brand clean-patched the ROM or if remediation needs to be reapplied.

---

## ⚠️ Disclaimer

This software is provided for educational, forensic, and security research purposes only. 

I have personally tested these tools and remediation scripts on my own hardware devices: they accurately identified threats, remediated backdoors, and all devices continued to operate normally without any loss of core streaming functionality. However, given the vast diversity of Android TV hardware, proprietary OEM firmware builds, and customized Android partitions across the market, **I cannot guarantee 100% effectiveness or complete compatibility with devices I have not directly tested**.

Use this tool at your own discretion and risk. Neither the author nor contributors shall be held liable for any unexpected behavior, unintended system state, or issues resulting from the use of these scripts or application. Always keep the automatic backups generated in `backups/` handy.

---

## 👨‍💻 About Me & Acknowledgments

Hi, I'm **Carlos Correia**! I'm a tech enthusiast, geek, and developer who has always been passionate about the Android TV box ecosystem. For years, I have actively advocated for and recommended certified Google TV and Android TV devices to friends, family, and the community.

Discovering the recent findings regarding **VideoStrong / SZBBOYS supply-chain compromises (BadBox & XCPE)** on certified and mainstream hardware came as quite a shock. That revelation motivated me to team up with modern AI agents to build this open, transparent, and autonomous repository — empowering anyone to easily audit, detect, and neutralize malware, trojans, and residential botnets with just their TV remote or a single command.

The architectural concept and pure-Python ADB connectivity of this tool draw strong inspiration from the great work of [CleanYourTV](https://cleanyour.tv), the technical forensic investigation by [Synthient](https://synthient.com/blog/the-internals-of-a-badbox-operation), [Eclypsium](https://eclypsium.com/blog/android-tv-devices-pre-0wned-supply-chain-security-threats/), and [Dr.Web](https://vms.drweb.com/bulletin/).

### Support My Work:
If you find this suite useful and want to support the project:
- 📺 **Subscribe and check out my YouTube channel:** [@Carlos___Correia](https://www.youtube.com/@Carlos___Correia)
- ⭐ Star this repository and share it with the Android TV community!
