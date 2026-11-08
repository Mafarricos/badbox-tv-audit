# AGENTS.md

Instructions for AI coding agents (Claude Code, Gemini CLI, Cursor, Copilot, Antigravity, and others) working in this repository. Humans should start with [README.md](README.md).

---

## 1. Project Mission

This repository contains an autonomous, dual-layer forensic and remediation suite specifically designed to audit, detect, and sanitize Android TV, Google TV, and Android TV Box streaming devices compromised by supply-chain malware, trojans, and botnet backdoors, including **BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS**, and **Residential Proxyware SDKs**.

It delivers:
1. **Remote ADB Layer**: Read-only fast triage across 6 forensic layers with live console reporting.
2. **On-Device TV App (`com.scanner.tv`)**: Native Leanback UI + local loopback VPN packet sentinel to detect hidden proxy botnet traffic and silent C2 callbacks.
3. **Deterministic Scoring Engine (`audit_security.py`)**: Zero-AI rule evaluation yielding mathematically backed verdicts (`INFETADO - CRÍTICO`, `SUSPEITO`, `LIMPO / SEGURO`).
4. **Complete Execution Logs (`logs/session_<timestamp>.log`)**: Automatic mirroring of all console output and operational telemetry for post-run agent reasoning and user reporting.
5. **Host-Independent Reversible Remediation (`--remediate` & `--restore`)**: Autonomous cleanup of infected TV boxes applying OS-level countermeasures with mandatory prior backup and 100% reversible scripts in `backups/`.

---

## 2. Agent Guiding Protocol: Preparing the Device (Developer Options & ADB)

Before running any remote ADB command, agents **MUST verify connection**. If the connection fails, times out, or the user asks how to prepare the TV, the agent must clearly instruct the user on how to enable Developer Options and ADB debugging:

### Standard Android TV (Android 9, 10, 11, e.g. Xiaomi, Strong, generic boxes):
1. Navigate to **Settings (Definições)** -> **Device Preferences (Preferências do Dispositivo)** -> **About (Acerca de)**.
2. Scroll down to **Build (Número de Compilação)** and press the remote's **OK / Center button 7 times** until the message *"You are now a developer!" ("É agora um programador!")* appears.
3. Press Back, enter **Developer Options (Opções do Programador)**.
4. Turn ON **USB Debugging (Depuração USB)** and **Network Debugging (Depuração de Rede)** (if available).
5. When the prompt *"Allow USB debugging from this computer?"* pops up on the TV screen, check *"Always allow from this computer"* and select **OK**.

### Google TV (Android 12, 14, e.g. Chromecast, realme, Thomson, TCL):
1. Navigate to the top profile icon -> **Settings (Definições)** -> **System (Sistema)** -> **About (Acerca de)**.
2. Scroll to **Android TV OS build (Versão do SO Android TV)** and click **7 times**.
3. Press Back, go to **System (Sistema)** -> **Developer Options (Opções do Programador)**.
4. Enable **USB Debugging (Depuração USB)**.
5. Confirm the computer's authorization dialog on the TV screen.

> **CRITICAL AGENT POST-RUN ADVISORY:**  
> Upon completing audits or remediation, agents **MUST remind the user** to navigate back to Developer Options and **turn OFF USB Debugging** to ensure no network management ports (5555) remain exposed to other local devices.

---

## 3. Workspace Synchronization & Environment Setup (Agent Protocol)

Before running any audit or tool, agents **MUST ensure the repository is updated with the latest signatures and engine fixes**:
1. **Pull Latest Changes**: If the repository was already cloned in a previous session, execute `git pull origin main` to fetch updated IoCs, malware rules, and device profiles.
2. **Environment Readiness**:
- Python 3.9+ runtime.
- Pip requirements: `pip install -r requirements.txt` (provides `adb-shell`, `rsa`, `pyasn1`).
- **No external ADB binary needed**: `tools/tv.py` implements pure Python ADB over TCP sockets.
- If running in a fresh workspace or container:
  - Windows: execute `setup.bat` or `pip install -r requirements.txt`
  - Linux / macOS: execute `bash setup.sh` or `pip3 install -r requirements.txt`

---

## 4. Real-Time Telemetry & Log Inspection Protocol

Every execution of `audit_security.py` records full transcripts to `logs/session_<timestamp>.log`.
Agents can:
1. Stream stdout during execution for live user visibility.
2. Read `logs/` or `last_scan_report.json` and `vpn_events.log` upon completion to extract exact forensic proofs and formulate detailed findings to the user.

---

## 5. APK Compatibility & Autonomous On-Demand Recompilation Protocol

The repository ships with an optimized precompiled universal APK in `tools/xcpe-scanner-tv.apk` (supports SDK 21 to SDK 34).

However, **if the target device is legacy, exotic, or reports an install error**:
1. **Self-Healing Fallback**: If `pm install` rejects the prebuilt APK (e.g. `INSTALL_FAILED_OLDER_SDK`, `INSTALL_FAILED_NO_MATCHING_ABIS`), `audit_security.py` automatically detects the device specs (`getprop ro.build.version.sdk`), triggers `ensure_build_environment()`, and recompiles a custom build targeting the device's exact API level.
2. **Explicit On-Demand Recompilation**: If an agent wants to guarantee an APK compiled specifically for the device's exact architecture and Android version, use:
   ```bash
   python tools/audit_security.py <IP> --recompile-for-device
   ```
   Or in automated pipeline mode:
   ```bash
   python tools/audit_security.py <IP> --auto-pipeline --recompile-for-device
   ```
3. **Toolchain Installation by Agents**:
   - **Windows**: `winget install -e --id EclipseAdoptium.Temurin.17.JDK`
   - **Linux**: `apt-get install -y openjdk-17-jdk`
   - **Android SDK**: `audit_security.py` automatically sets `local.properties` with the path to `ANDROID_HOME` or standard SDK directories (`C:\AndroidSDK`, `$HOME/Android/Sdk`, `%LOCALAPPDATA%\Android\Sdk`).

---

## 6. Remediation & Reversibility Protocol (Backup First)

**Rule: Never remediate without backup.**
When a device is verified as `INFETADO - CRÍTICO` or `SUSPEITO`, running `--remediate` **automatically performs a snapshot backup first**:
```bash
# 1. Remediate with automatic backup & restore script generation:
python tools/audit_security.py <IP> --remediate

# 2. Revert back to original state if needed:
python tools/audit_security.py <IP> --restore
# Or execute the generated PowerShell restore script directly:
powershell -ExecutionPolicy Bypass -File backups/restore_<IP_CLEAN>.ps1
```

The remediation cycle operates completely inside Android:
1. **Snapshots State**: Records original `package_verifier_*` and `private_dns_*` settings and disabled package lists in `backups/backup_<IP>_<timestamp>.json`.
2. **Generates Restore Script**: Automatically crafts `backups/restore_<IP>.ps1`.
3. **Play Protect Restoration**: Forces `settings put global package_verifier_user_consent 1` and `package_verifier_enable 1`.
4. **Botnet App Purge**: Uninstalls user-space residential proxy apps (`com.abc.nexus`, `traffmonetizer`, `android-grass`, etc.) via `pm uninstall`.
5. **OEM Backdoor Freezing**: Disables immutable system backdoors (`x.cpe`, `com.oemservice`) via `pm disable-user --user 0`.
6. **Local Private DNS Hardening**: Configures `settings put global private_dns_specifier security.cloudflare-dns.com` on the device.

---

## 7. Non-Negotiable Operational Rules for Agents

- **Audit Strategy: Ask User (Fast vs Intensive Sentinel)**: When asked by a user to audit or inspect a TV box for malware without specifying the mode, the agent **MUST present the choice** to the user (unless the user has a standing rule or preference configured):
  1. **Fast 6-Layer ADB Scan (`--quick-scan`)**: Instant (5-10s), zero installation on TV, checks all known malware families (XCPE, BadBox, Vo1d, droppers, C2 sockets, Play Protect tampering).
  2. **Intensive Dynamic Sentinel (`--auto-pipeline`)**: Deploys the native TV APK (`com.scanner.tv`), runs a local VPN sentinel to intercept live network/DNS traffic looking for unknown or novel threats, pulls reports, and automatically uninstalls the APK.
- **Zero-Damage & Reversibility**: Never disable critical core system packages (`com.android.systemui`, `com.android.settings`, Bluetooth/Wi-Fi stack).
- **Mandatory Backup Before Change**: Every modifying operation must save original state to `backups/`.
- **Strict Read-Only Diagnostics by Default**: Diagnostics must never modify system properties unless `--remediate` or `--restore` is explicitly invoked.
- **Persistence Boundary Awareness**: Agents must understand and communicate that OEM backdoor freezing (`pm disable-user`) survives standard reboots, but will be reset if the user performs a **Factory Reset** or if a manufacturer **OTA system update** replaces `/system`. Remediation remains valid until the OEM issues a clean firmware update or until a factory reset occurs.
- **Silent VPN Grant**: In automated mode, grant VPN permissions via `adb shell appops set com.scanner.tv ACTIVATE_VPN allow` to avoid blocking on user UI dialogs.
- **TV Safe Operation**: When auditing is done, instruct or remind the operator to disable USB/Network Debugging in TV Developer Options to prevent exposed ADB ports on the local network.

---

## 8. CLI Agent Usage Matrix

When executing autonomous forensic audits, invoke `tools/audit_security.py` directly using flags. The CLI automatically detects the host OS locale (defaulting to English for international environments) and can be forced with `--lang en` or `--lang pt`:

| Goal | Command | Description |
|---|---|---|
| **Full Automated Pipeline** | `python tools/audit_security.py <IP> --auto-pipeline` | Installs APK, grants VPN silent, runs 6-layer scan, monitors network for 20s, pulls logs, evaluates scoring rules, uninstalls APK. |
| **Fast 6-Layer ADB Scan** | `python tools/audit_security.py <IP> --quick-scan` | 100% read-only scan via ADB (checks Play Protect, C2 sockets, IoC packages, props). |
| **Token-Optimized AI Scan (JSON)** | `python tools/audit_security.py <IP> --quick-scan --json` | **Recommended for AI Agents**: Outputs a compact, machine-readable JSON structure with exact findings, saving context tokens. |
| **Subnet TV Discovery & Batch Audit** | `python tools/audit_security.py --scan-subnet 192.168.1.0/24` | Scans local subnet for active Android TV ADB ports (5555) and audits all found devices in parallel. |
| **Remediate in Depth** | `python tools/audit_security.py <IP> --remediate` | Multi-layer defense: force-stop, pm clear, AppOps ignore, freeze + user-0 uninstall. Generates .ps1 and .sh restore scripts. Preserves local network DNS. |
| **Remediate + Verify Reboot** | `python tools/audit_security.py <IP> --remediate --verify-reboot` | Remediates and reboots TV, awaiting boot_completed to verify watchdogs do not resurrect. |
| **Remediate + Force DoT** | `python tools/audit_security.py <IP> --remediate --enable-dot` | Remediates and explicitly forces Cloudflare DoT (security.cloudflare-dns.com). |
| **Scan Init.rc Watchdogs** | `python tools/audit_security.py <IP> --scan-init-watchdogs` | Inspects init.rc scripts and non-standard binaries for boot persistences. |
| **Restore Previous State** | `python tools/audit_security.py <IP> --restore` | Restores settings, re-installs user-0 packages, re-enables apps, and resets AppOps from latest backup snapshot. |
| **Automated with Custom Recompilation** | `python tools/audit_security.py <IP> --auto-pipeline --recompile-for-device` | Gathers device SoC/SDK specs, recompiles tailored APK, runs full pipeline and cleans up. |
| **Install Tailored App** | `python tools/audit_security.py <IP> --recompile-for-device` | Compiles from `app/` and installs on the box. |
| **Launch TV Interface** | `python tools/audit_security.py <IP> --launch-app` | Opens the D-Pad optimized scanner on the TV display. |
| **Pull & Score Reports** | `python tools/audit_security.py <IP> --pull-report` | Extracts `last_scan.json` and `vpn_events.log`, executes the rule engine, prints verdict. |
| **Clean Up / Uninstall** | `python tools/audit_security.py <IP> --remove-app` | Removes `com.scanner.tv` from the device. |
| **Deep Reverse Engineering / Inspection** | `python tools/deep_forensics.py <IP> --inspect-package <PKG>` | Extracts package details, UID 1000 system permissions, and declared receivers. |
| **Infection Stage Classification (Stage 1 vs 2)** | `python tools/detect_infection_stage.py <IP>` | Differentiates Stage 1 factory dropper vs Stage 2 `/data/app` or `/oem` active botnet payload, verifies memory processes and alarms. |
| **Pull & Analyze Remote APK Dex Strings** | `python tools/deep_forensics.py <IP> --pull-and-analyze <REMOTE_PATH>` | Pulls APK to `scratch/pulled/` and reverse-engineers classes, URLs, and dropper strings. |
| **Scan System Partitions for Droppers** | `python tools/deep_forensics.py <IP> --scan-oem-droppers` | Fast deep hunt for XCPE, Titan, Grass, Yoka files in `/system`, `/vendor`, `/oem`. |
| **Dump TV Network Sockets** | `python tools/deep_forensics.py <IP> --dump-network-state` | Dumps active TCP/UDP sockets and listening ports directly from the TV. |

---

## 9. Repository Map

```
badbox-tv-audit/
├── backups/              # Reversible device snapshots, restore_<IP>.ps1 (Windows) and restore_<IP>.sh (Linux/macOS)
├── logs/                 # Comprehensive real-time execution transcripts (session_<timestamp>.log)
├── setup.bat             # One-click Windows prerequisite installer (Python + JDK/SDK option)
├── setup.sh              # One-click Linux/macOS prerequisite installer
├── app/                  # Full Android Studio project for com.scanner.tv (SDK 34, Java 17)
│   ├── app/src/main/     # CoreScanner.java, PacketMonitorVpnService.java, MainActivity.java
│   └── gradlew / build   # Gradle build system
├── tools/
│   ├── audit_security.py # Main forensic orchestrator, remediation & restore engine
│   ├── detect_infection_stage.py # Stage 1 dropper vs Stage 2 active payload classifier & OEM hunter
│   ├── deep_forensics.py # Specialized reverse-engineering, package inspector & string analyzer
│   ├── setup_env.py      # Python environment and SDK toolchain configurator
│   ├── tv.py             # Pure Python ADB protocol client (no system adb required)
│   └── xcpe-scanner-tv.apk # Prebuilt universal ready-to-install Android TV package
├── AGENTS.md             # This agent instruction manual
├── README.md             # Human-facing installation and usage guide
└── requirements.txt      # Python dependencies (adb-shell, rsa, pyasn1)
```

---

## 10. Community Submission & Anonymized Device Reports (Agent Protocol)

Whenever an audit completes (`--quick-scan` or `--auto-pipeline`), `audit_security.py` outputs an anonymized technical report at:
```text
community_audit_submission.json
```

### Agent Actions for Report Submission:
1. **Verify Sanitization**: The file is stripped of all personal/local network data (no LAN IPs, MACs, serial numbers, or Wi-Fi info).
2. **Offer Submission Guidance**: At the end of an audit, agents should inform the user:
   - *"If you would like to help the community track this device model, you can submit the generated `community_audit_submission.json` to the project's GitHub Issues (https://github.com/Mafarricos/badbox-tv-audit/issues) or via email to `mafastudios@gmail.com`."*

---

## 11. Decision Logic, Thresholds & Semantic Exit Codes

The deterministic rule engine evaluates risks without cloud AI calls:

- **Score >= 8 OR Critical Signature found** -> `INFETADO - CRÍTICO` (>99% certainty). Process exit code: `1`.
  - Triggers: `package_verifier_user_consent = -1`, direct C2 IP connections (`219.134.163.210`, `:3885-3887`), or known botnet packages (`x.cpe`, `traffmonetizer`).
- **Score >= 3 OR >=2 Anomalies** -> `SUSPEITO` (~80% certainty). Process exit code: `2`.
  - Triggers: Unprotected package verification (`enable = 0`), abnormal UDP/TCP outbound packets in quiet state.
- **Score < 3** -> `LIMPO / SEGURO` (>98% certainty). Process exit code: `0`.
  - Normal clean devices (e.g. system APK permission warnings without signatures).
- **Target Unreachable / ADB Refused** -> Process exit code: `3`.

Agents and automated CI/CD runners can inspect the shell exit code (`$LASTEXITCODE` or `$?`) immediately without parsing prose.
