# Architecture Decision Records (ADRs)

This document records the architectural and security decisions established during the comprehensive audit and hardening of the `badbox-tv-audit` suite (v2.0.0).

---

## ADR-01: Exclusion of Keystores and Compiled Binaries from Git (SEC-01)
- **Context:** Previous versions tracked `release.keystore` and pre-built `.apk` files inside the git repository.
- **Decision:** Removed all keystore files, private keys, and precompiled APK binaries from the repository. Git tracking of `.keystore`, `.jks`, `.apk`, and `keystore.properties` is forbidden via `.gitignore` and enforced by CI.
- **Consequence:** Users or build servers compile their own signed binaries following `docs/RELEASE_SIGNING.md`, eliminating supply-chain tampering risks.

---

## ADR-02: Separation of Pure Logic in Android App for Unit Testing (JT-01..07)
- **Context:** The Android application code combined Android framework dependencies (`Context`, `VpnService`, `PackageManager`) with protocol parsing and classification algorithms, preventing automated unit testing outside an emulator or physical device.
- **Decision:** Extracted all protocol, IP, domain, packet parsing, and serialization logic into standalone, framework-independent pure Java classes:
  - `IpClassifier`: IP range and infrastructure classification.
  - `DnsPacketParser`: DNS query QNAME parsing.
  - `FlowTracker`: 5-tuple deduplication and state tracking.
  - `ScanReportSerializer`: Strict JSON serialization with escaping.
  - `PackageMatcher`: Exact package matching against IoC collections.
  - `IpPacketParser`: IPv4/IPv6 packet header unpacking.
  - `DnsDispatcher`: Defensive payload copy and UDP DNS response generation.
- **Consequence:** Fast, deterministic unit tests run in JVM via `./gradlew testDebugUnitTest` in under 1 second.

---

## ADR-03: Rule Engine & Centralized IoC Database (VER-01, IOC-01)
- **Context:** Forensic evaluation logic was duplicated between Python scripts and the Android app, leading to inconsistent scoring and false positives.
- **Decision:**
  - Unified all detection rules and weights into `data/rules.json`.
  - Unified all indicators of compromise into `data/iocs_database.json`.
  - Built `tools/engine.py` as a deterministic decision engine implementing explicit finding codes and layer evaluations.
- **Consequence:** Identical verdict logic across CLI, automated pipelines, and batch subnet audits.

---

## ADR-04: Prevention of False Positives in Package & Network Matching (IOC-02, FP-01)
- **Context:** Substring matching on package names (`"spirit"`, `"moyu"`) caused false alarms on legitimate applications. Text search on `netstat` lines matched Android local ephemeral ports.
- **Decision:**
  - Package matching is strictly exact (`PackageMatcher.matches()` and `pkg in EXACT_IOC_PACKAGES`).
  - Network connection parsing inspects the remote address and port column numerically (`int(remote_port)`).
  - Benign ports (`2222` for SSH, `7000` for AirPlay) and standard build tags (`test-keys`) are classified as informational (0 risk score).
- **Consequence:** Clean devices never produce false critical verdicts.

---

## ADR-05: Multi-Stage Deep Remediation & Secure Restore (REM-01..04, RST-01..02)
- **Context:** Simple `pm disable-user` on updated system packages left malicious versions active in `/data/app`. Generated restore shell scripts were vulnerable to command injection.
- **Decision:**
  - Remediation classifies packages into `system`, `updated_system`, and `user`. Updated system apps receive both `pm uninstall` (reverting to stock) and `pm disable-user --user 0`.
  - Background execution is suppressed via `cmd appops set <pkg> RUN_IN_BACKGROUND ignore`.
  - Deep remediation requires interactive confirmation (`SIM`/`YES`) or `--yes` non-interactively; unknown flags exit with code 64.
  - Restoring is performed through parameterized CLI calls (`--restore --backup <dir>`), and quarantined APKs are restored only with explicit `--restore-quarantined-apks`.
- **Consequence:** Safe, fully reversible remediation with zero vulnerability to shell script injection.

---

## ADR-06: Persistent Quarantine Sinkhole Mode for Remote D-Pad TV Users (VPN-05)
- **Context:** Untrusted user-space applications on Android TV cannot remove or disable factory `/system` packages without ADB or root access.
- **Decision:** Implemented a persistent VPN Sinkhole quarantine mode in `PacketMonitorVpnService`. When factory droppers are detected, the user can activate quarantine, routing the malicious package's UID traffic into a local sinkhole (`10.99.99.2`). The setting persists across reboots via `SharedPreferences`.
- **Consequence:** Everyday TV users without a PC can neutralize C2 communications immediately using only their remote D-Pad.
