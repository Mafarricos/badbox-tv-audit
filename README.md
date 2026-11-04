# Android TV & Google TV Forensic Suite (BadBox, Vo1d & Malware Remediation)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-AI Rules](https://img.shields.io/badge/Detection-Deterministic%20Scoring-orange.svg)](#-zero-ai-deterministic-scoring-matrix)
[![App Remediation](https://img.shields.io/badge/TV%20App-On--Screen%20Remediation-success.svg)](#-native-android-tv-app)
[![Logging](https://img.shields.io/badge/Logging-Live%20Console%20%2B%20Transcripts-informational.svg)](#-live-telemetry--audit-logs)

An autonomous, dual-layer forensic, malware removal, and reversible remediation suite (CLI + native Android TV app with local loopback VPN sentinel) engineered to audit, detect, verify, neutralize, and restore Android TV, Google TV, and generic streaming devices compromised by supply-chain trojans, botnets, and malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS**, and **Residential Proxyware**).

> **Language:** English (Default) | [Para a versão em Português (PT-PT), consulte README.pt.md](README.pt.md) | [📱 Tested Devices Registry](DEVICES.md)

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

## 🤖 Using with AI Agents (Antigravity, Claude Code, Grok, Cursor, Copilot)

This repository includes full instructions in [`AGENTS.md`](AGENTS.md) that modern AI coding agents automatically follow. You don't need to manually run Python scripts or terminal commands:

Simply open your AI Agent (Antigravity, Claude Code, Cursor, Copilot, Grok CLI, etc.) and give it this single instruction:

```text
Clone https://github.com/Mafarricos/badbox-tv-audit.git and audit my Android TV box at IP <TV_IP>.
```
*(Tip: If you don't know your TV's IP address, replace `<TV_IP>` with: `...discover my Android TV devices on subnet 192.168.1.0/24 and audit them.`)*

The agent will clone the repository, read [`AGENTS.md`](AGENTS.md), install requirements, run the token-saving 5-layer audit (`--quick-scan --json`), and present the findings or apply reversible remediation with automatic backup.

---

## 📱 Preparing Your TV (Enable Developer Options & ADB)

To allow PC tools or AI agents to communicate with your TV over Wi-Fi, enable **ADB Debugging**:

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

The suite **automatically detects your system language** (defaults to **English** for international users, or **Portuguese** if your operating system is in Portuguese). You can also explicitly force a language with `--lang en` or `--lang pt`:

```bash
# 1. 100% Automated Pipeline (Install APK, 5-layer scan, 20s VPN sentinel, score, and cleanup)
python tools/audit_security.py <TV_IP> --auto-pipeline

# 2. Fast 5-Layer ADB Read-Only Scan (Standard or Token-Saving JSON)
python tools/audit_security.py <TV_IP> --quick-scan
python tools/audit_security.py <TV_IP> --quick-scan --json

# 3. Discover and Audit all Android TVs across the Home Subnet
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 4. Autonomous Remediation (Locks Play Protect, freezes droppers, activates Private DNS DoT)
python tools/audit_security.py <TV_IP> --remediate

# 5. Instant Reversible Restore / Rollback
python tools/audit_security.py <TV_IP> --restore

# 6. Deep Forensics / Package Inspector (Supports --lang en / --lang pt)
python tools/deep_forensics.py <TV_IP> --inspect-package <PACKAGE_NAME>
python tools/deep_forensics.py <TV_IP> --pull-and-analyze <REMOTE_APK_PATH>
```

---

## 🔒 Safety & Reversibility Guarantee

Every remediation action creates an exact JSON snapshot under `backups/backup_<IP>_<timestamp>.json` and an executable rollback script `backups/restore_<IP>.ps1`. Nothing is modified without an immediate, one-click restoration path.

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
