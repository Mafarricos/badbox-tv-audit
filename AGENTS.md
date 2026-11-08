# AGENTS.md

Instructions for AI coding agents (Claude Code, Gemini CLI, Cursor, Copilot, Antigravity, and others) working in this repository. Humans should start with [README.md](README.md).

---

## 1. Project Mission

This repository contains an autonomous, dual-layer forensic and remediation suite specifically designed to audit, detect, and sanitize Android TV, Google TV, and Android TV Box streaming devices compromised by supply-chain malware, trojans, and botnet backdoors, including **BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS**, and **Residential Proxyware SDKs**.

It delivers:
1. **Remote ADB Layer**: Read-only fast triage across 6 forensic layers with pure JSON output or live console reporting.
2. **On-Device TV App (`com.scanner.tv`)**: Native Leanback UI + local loopback VPN packet sentinel to detect hidden proxy botnet traffic, silent C2 callbacks, and persistent sinkhole quarantine mode.
3. **Deterministic Rule Engine (`tools/engine.py` & `data/rules.json`)**: Formally weighted rule evaluation yielding mathematically backed verdicts (`INFETADO - CRÍTICO`, `SUSPEITO`, `LIMPO / SEGURO`).
4. **Complete Execution Logs (`logs/session_<timestamp>.log`)**: Automatic mirroring of all console output and operational telemetry for post-run agent reasoning and user reporting.
5. **Host-Independent Reversible Remediation (`--remediate` & `--restore`)**: Autonomous cleanup of infected TV boxes applying OS-level countermeasures with mandatory prior backup, APK quarantine, and injection-safe parameterized restore.

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

## 3. Environment Readiness & Deterministic Execution (Agent Protocol)

Before running any audit or forensic tool, agents **MUST verify environment prerequisites**:
1. **Deterministic Workspace**: Operate on the local codebase state without automated remote pulls during execution to guarantee repeatability and offline audit capability.
2. **Environment Readiness**:
   - Python 3.9+ runtime (verified with `vermin -t=3.9- --violations tools`).
   - Pip requirements: `pip install -r requirements.txt` (provides `adb-shell`, `rsa`, `pyasn1`).
   - **No external ADB binary needed**: `tools/tv.py` implements pure Python ADB over TCP sockets.
   - If running in a fresh workspace or container:
     - Windows: execute `setup.bat` or `pip install -r requirements.txt`
     - Linux / macOS: execute `bash setup.sh` or `pip3 install -r requirements.txt`

---

## 4. Real-Time Telemetry & Log Inspection Protocol

Every execution of `audit_security.py` records full transcripts to `logs/session_<timestamp>.log`.
When running with `--json`, stdout contains **strictly valid JSON** (no banners or decorative headers), allowing agents to parse results directly:
```bash
python tools/audit_security.py 192.168.1.61 --quick-scan --json
```

---

## 5. APK Compilation & Security Protocol

To maintain complete supply-chain integrity, binary `.keystore` files and precompiled APKs are never tracked in git (SEC-01).
1. **On-Demand Compilation**: Agents can trigger local compilation targeting the device's architecture:
   ```bash
   python tools/audit_security.py <IP> --recompile-for-device
   ```
2. **Release Signing**: Documented in `docs/RELEASE_SIGNING.md`. Release signing uses environment variables (`KEYSTORE_PATH`, `KEYSTORE_PASSWORD`, etc.) or `keystore.properties` (gitignored).

---

## 6. Remediation & Reversibility Protocol (Backup First)

**Rule: Never remediate without backup.**
When a device is verified as `INFETADO - CRÍTICO` or `SUSPEITO`, running `--remediate` **automatically performs a snapshot backup first**:
```bash
# 1. Preview actions without making any changes (strictly read-only):
python tools/audit_security.py <IP> --remediate --dry-run

# 2. Remediate with explicit confirmation (or --yes for autonomous agents):
python tools/audit_security.py <IP> --remediate --yes

# 3. Remediate and verify watchdog survival across reboot:
python tools/audit_security.py <IP> --remediate --yes --verify-reboot

# 4. Revert back to original state if needed:
python tools/audit_security.py <IP> --restore --backup backups/<device_id>/backup_<timestamp>.json
```

The remediation cycle operates in depth:
1. **Package Classification**: Separates packages into `system`, `updated_system`, and `user`.
2. **Double Action on Droppers**: For updated system apps, executes both user uninstallation (`pm uninstall`) and user-0 disabling (`pm disable-user --user 0`).
3. **Execution Restriction**: Enforces `cmd appops set <pkg> RUN_IN_BACKGROUND ignore`.
4. **Clean Baseline**: Only modifies devices with active findings or disabled Play Protect.
5. **APK Quarantine**: Any uninstalled APK is pulled to `backups/<device_id>/quarantine/*.apk.quarantined` with `.sha256`. Restoring APKs requires `--restore-quarantined-apks`.

---

## 7. Non-Negotiable Operational Rules for Agents

- **Audit Strategy: Ask User (Fast vs Intensive Sentinel)**: When asked by a user to audit or inspect a TV box for malware without specifying the mode, the agent **MUST present the choice** to the user:
  1. **Fast 6-Layer ADB Scan (`--quick-scan`)**: Instant (5-10s), zero installation on TV, checks all known malware families (XCPE, BadBox, Vo1d, droppers, C2 sockets, Play Protect tampering).
  2. **Intensive Dynamic Sentinel (`--auto-pipeline`)**: Deploys the native TV APK (`com.scanner.tv`), runs a local VPN sentinel to intercept live network/DNS traffic looking for unknown or novel threats, pulls reports, and automatically uninstalls the APK.
- **Zero-Damage & Reversibility**: Never disable critical core system packages (`com.android.systemui`, `com.android.settings`, Bluetooth/Wi-Fi stack).
- **Mandatory Backup Before Change**: Every modifying operation must save original state to `backups/`.
- **Strict Read-Only Diagnostics by Default**: Diagnostics must never modify system properties unless `--remediate` or `--restore` is explicitly invoked.
- **TV Safe Operation**: When auditing is done, instruct or remind the operator to disable USB/Network Debugging in TV Developer Options to prevent exposed ADB ports on the local network.

---

## 8. CLI Agent Usage Matrix

| Goal | Command | Description |
|---|---|---|
| **Full Automated Pipeline** | `python tools/audit_security.py <IP> --auto-pipeline` | Installs APK, grants VPN silent, runs 6-layer scan, monitors network for 20s, pulls logs, evaluates scoring rules, uninstalls APK. |
| **Fast 6-Layer ADB Scan** | `python tools/audit_security.py <IP> --quick-scan` | 100% read-only scan via ADB (checks Play Protect, C2 sockets, IoC packages, props). |
| **Token-Optimized AI Scan (JSON)** | `python tools/audit_security.py <IP> --quick-scan --json` | **Recommended for AI Agents**: Outputs strictly pure JSON on stdout. |
| **Subnet TV Discovery & Batch Audit** | `python tools/audit_security.py --scan-subnet 192.168.1.0/24` | Scans local subnet for active Android TV ADB ports (5555) and audits found devices. |
| **Remediate in Depth** | `python tools/audit_security.py <IP> --remediate --yes` | Deep remediation with automatic backup, force-stop, AppOps, and freeze. |
| **Remediate Dry Run** | `python tools/audit_security.py <IP> --remediate --dry-run` | Prints execution plan without modifying the device. |
| **Remediate + Verify Reboot** | `python tools/audit_security.py <IP> --remediate --yes --verify-reboot` | Remediates and reboots TV, awaiting boot_completed to verify watchdogs do not resurrect. |
| **Scan Init.rc Watchdogs** | `python tools/audit_security.py <IP> --scan-init-watchdogs` | Inspects init.rc scripts and non-standard binaries for boot persistences. |
| **Restore Previous State** | `python tools/audit_security.py <IP> --restore --backup <dir>` | Restores settings and re-enables apps from backup snapshot. |
| **Export C2 Blocklists** | `python tools/export_blocklist.py --format all` | Exports C2 domains to hosts, dnsmasq, and AdGuard formats. |
| **Validate IoC Database** | `python tools/validate_iocs.py` | Validates schema and integrity of `data/iocs_database.json`. |

---

## 9. Decision Logic, Thresholds & Semantic Exit Codes

The deterministic rule engine evaluates risks without cloud AI calls:

- **Exit Code 0 (`LIMPO / SEGURO`)**: Clean device, no critical or high threats.
- **Exit Code 1 (`INFETADO - CRÍTICO`)**: Confirmed infection (active malware packages, C2 network connections, dropper in `/system`).
- **Exit Code 2 (`SUSPEITO / INCONCLUSIVO`)**: Anomalies found or missing static report.
- **Exit Code 3 (`ERRO DE CONEXÃO`)**: Target unreachable or ADB authorization refused.
- **Exit Code 6 (`REJEITADO`)**: Remediation confirmation refused (non-interactive run without `--yes`).
- **Exit Code 64 (`ARGUMENTO INVÁLIDO`)**: Unrecognized or invalid CLI argument.

---

## 10. Community Submission & Anonymized Device Reports (PRIV-01)

Whenever an audit completes (`--quick-scan` or `--auto-pipeline`), `audit_security.py` outputs an anonymized technical report at `community_audit_submission.json`.
The report strictly follows an allowlist and strips all LAN/public IP addresses, MAC addresses, serial numbers, chip IDs, and IMEIs.
Users can submit this report to GitHub Issues or via email to `mafastudios@gmail.com`.
