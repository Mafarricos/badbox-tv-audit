# Changelog

All notable changes to the `badbox-tv-audit` project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-11-08

### Added
- **Pure Logic Java Module (JT-01..07):** Added `IpClassifier`, `DnsPacketParser`, `FlowTracker`, `ScanReportSerializer`, `PackageMatcher`, `IpPacketParser`, and `DnsDispatcher` to `app/`.
- **Comprehensive Unit Testing Suite:**
  - 7 JUnit tests in `PureLogicTest.java` running on JVM.
  - 29 Pytest tests across `test_reproduce_bugs`, `test_phase1_secrets`, `test_phase3_remediation`, `test_phase4_rules_iocs`, `test_phase7_features`, and `test_phase8_privacy`.
- **Deterministic Rule Engine (`tools/engine.py`):** Standalone rule evaluator consuming `data/rules.json` and generating typed findings with precedence rules.
- **Unified Canonical IoC Database (`data/iocs_database.json`):** Over 1,200 curated indicators validated with `tools/validate_iocs.py`.
- **Blocklist Exporter (`tools/export_blocklist.py`):** Generates C2 domain blocklists in `/etc/hosts`, `dnsmasq`, and `AdGuard/Pi-hole` formats.
- **Quarantine Sinkhole Mode in Android App:** Isolates factory `/system` malware network traffic via `VpnService` with persistence across reboots.
- **Deep Remediation Pipeline:** Sequential package uninstallation, AppOps background restrictions, `--dry-run`, `--verify-reboot`, and parameterized backup restore.
- **Allowlist Privacy Sanitization (PRIV-01):** Community submissions strip all IP addresses, MACs, serial numbers, chip IDs, and IMEIs.
- **Architecture Documentation:** Added `docs/DECISIONS.md`, `docs/RELEASE_SIGNING.md`, `SECURITY.md`, and `THIRD_PARTY_NOTICES.md`.

### Changed
- **Removed Hardcoded Credentials & Binaries (SEC-01):** Removed `release.keystore`, prebuilt APKs, and hardcoded passwords.
- **Eliminated False Positives (FP-01):** Replaced substring package matching with exact matching; fixed numeric parsing for remote network ports; exempted standard development ports (`2222`, `7000`) and AOSP `test-keys`.
- **Hardened Subnet Scanner:** Fixed variable scope bug in `scan_subnet` and made `--json` stdout strictly pure JSON.
- **Standardized Process Exit Codes:** 0 (clean), 1 (critical threats), 2 (inconclusive / suspicious), 3 (connection / tool error), 6 (non-interactive confirmation refused), 64 (invalid CLI argument).

### Fixed
- Fixed command injection vulnerability in generated restore scripts (RST-01).
- Fixed dropper survival on updated system apps by enforcing both user uninstallation and user-0 package disabling (REM-01).
- Fixed duplicate log reading in `step_pull_report()` (AUD-01).
- Fixed Python 3.15 deprecation warning by replacing `locale.getdefaultlocale()` with `locale.getlocale()`.
