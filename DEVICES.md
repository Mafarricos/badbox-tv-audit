# Tested Devices Registry / Registo de Aparelhos Testados

This document maintains a living, transparent list of Android TV and Google TV devices audited by the community and the author (**Carlos Correia**), documenting both certified/clean devices and devices confirmed to be infected or carrying factory backdoors.

Este documento mantém uma lista pública e transparente dos aparelhos auditados pela comunidade e pelo autor (**Carlos Correia**), registando quer os modelos limpos, quer os aparelhos onde foram confirmadas anomalias ou backdoors de fábrica.

---

## 🟢 Clean / Safe Devices (Dispositivos Limpos e Seguros)

Devices audited with 0 anomalies, valid Google certifications, untampered Play Protect, and no suspicious network or background traffic.

| Brand / Model | SoC / Hardware | Android / API | Audit Status | Remediation Required? | Notes |
|---|---|---|---|---|---|
| **THOMSON Thomson 140G** | SEI Robotics / `YZF` (`amlogic`) | Android 12 (API 31) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Genuine Google TV certified device built by SEI Robotics (Tier-1 ODM). No factory droppers (`com.oemservice` not present), untampered Play Protect, zero botnet indicators. |
| **Nokia Streaming Box 8000** | SEI Robotics / `HND` (`amlogic`) | Android 12 (API 31) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Genuine Google TV / Android TV certified device built by SEI Robotics (Tier-1 ODM). No factory droppers, untampered Play Protect, zero botnet indicators (`risk_score: 0`). |

---

## 🟡 Neutralized Devices (Aparelhos com Backdoor Identificada e Neutralizada)

Devices that shipped with dormant or active dropper components from the OEM supply chain, successfully neutralized and verified with this suite.

| Brand / Model | SoC / Hardware | Android / API | Initial Finding | Final State | Verified Persistence |
|---|---|---|---|---|---|
| **MECOOL 4K Google TV Stick** | SkyworthDigital / `HP46BY4` (`amlogic`) | Android 11 (API 30) | **ACTIVE XCPE BOTNET IN MEMORY**: `com.oemservice` (v6.5.0.20230804.alpha in `/data/app` overriding v1.2.1 in system) actively running 3 persistent processes (`:AccessService` PID 1122, `:NetworkService` PID 1755, and `:WorkService` PID 2758). | **NEUTRALIZED / FROZEN** | All 3 botnet processes terminated, dropper package frozen via `pm disable-user --user 0`, DoT Private DNS enforced (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). |
| **Mecool UHD Google TV Stick** | SkyworthDigital / `HPR3B1325_4K` (`rtd1325`) | Android 14 (API 34) | **ACTIVE XCPE BOTNET IN MEMORY**: `com.oemservice` (v6.8.4 in `/data/app` overriding v1.2.1 in system) actively running 3 persistent processes (`:NetworkService` PID 2131, `:WorkService` PID 2477, and main PID 2937). | **NEUTRALIZED / FROZEN** | All 3 botnet processes terminated, dropper package frozen via `pm disable-user --user 0`, DoT Private DNS enforced (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). |
| **Strong 4K Google TV Stick** (`HP4613-STRONG`) | SkyworthDigital / `HP46BY4` (`amlogic`) | Android 14 (API 34) | `com.oemservice` (`/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk`) | **NEUTRALIZED / FROZEN** | Backdoor package frozen via `pm disable-user --user 0`, DoT Private DNS enforced (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). |

---

## 🔴 Known Compromised / Risky Devices (Aparelhos Problemáticos de Fábrica)

Models historically documented by security research (Synthient, Malwarebytes, DesktopECHO, BitSight) to ship with active backdoors, root access, test-keys, or ad-fraud malware.

| Device Family | Typical Chipset | Known Threats / Signatures | Severity | Recommendation |
|---|---|---|---|---|
| **T95 / T95 Max / T95Z** | Allwinner H616, H618 | `Corejava`, `ycxrl.com`, `libandroid_runtime.so` injection, Adups FOTA | **CRITICAL (Active Botnet)** | Run automated remediation or replace device. |
| **R4 TV Box / KJ-SMART4KVIP (Vo1d)** | Allwinner / Rockchip generic | `Android.Vo1d` (`/system/xbin/vo1d`, `/system/xbin/wd`, `/data/google/daemon`) | **CRITICAL (Vo1d Botnet)** | Run `--remediate` to remove binaries or isolate device. |
| **Allwinner H616 generic clones** | Allwinner H616 | BadBox click-fraud, CopyCat adware, test-keys signed ROMs | **CRITICAL** | Isolate from local LAN immediately. |
| **Q96 / Q96 Max** | Rockchip RK3228A, RK3328 | Preinstalled proxy nodes (Grass, TitanNet, Traffmonetizer) | **CRITICAL** | Audit with `--auto-pipeline` and isolate. |
| **MECOOL / Videostrong KM series** (Certain older batches) | Amlogic S905X | Preloaded XCPE droppers (`x.cpe`, `com.oemservice`, `uota.club`) | **HIGH** | Run `--remediate` to freeze the OEM dropper. |

---

### How to contribute your device / Como submeter o seu aparelho:
Run the audit on your TV box and submit the resulting sanitized log from `logs/session_<timestamp>.log`:
```bash
python tools/audit_security.py <TV_IP> --quick-scan --lang en
```
Open a pull request or issue on GitHub: [https://github.com/Mafarricos/badbox-tv-audit](https://github.com/Mafarricos/badbox-tv-audit)
