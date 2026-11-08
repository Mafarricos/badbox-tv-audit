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
| **Homatics Dongle G 4K** | SEI Robotics / `YQX` (`amlogic`) | Android 11 (API 30) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Genuine Google TV certified device built by SEI Robotics (Tier-1 ODM). Verified clean of OEM droppers, untampered Play Protect, zero botnet indicators (`risk_score: 0`). |
| **realme 4K Google TV Stick** (`HP4607_realme`) | SkyworthDigital / `HP46BY4` / `YYT` | Android 14 (API 34) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Google TV certified build for realme by SkyworthDigital. Unlike other Skyworth-based sticks, verified free from `com.oemservice` / preset XCPE droppers, clean system image. |
| **MECOOL UHD Google TV STB** (`HP4CQ`) | SkyworthDigital / `HP4CQ` (`amlogic`) | Android 14 (API 34, Patch 2025-12-01) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Full standalone set-top-box build by SkyworthDigital. Certified Google TV with Play Protect active (`user_consent=1`). No `com.oemservice` dropper found, 0 botnet processes, and 0 suspicious C2 connections during live VPN monitor. OEM system packages (`com.sdt.*`) verified free of backdoors. |
| **TOX TOX5** (`tmx5miks`) | TOX / Ugoos base (`amlogic`) | Android 14 (API 34, Patch 2025-06-05) | **CLEAN / SAFE (No Malware)** (`risk_score: 0`) | **NO** | Audited with full 5-layer scan and dynamic VPN sentinel monitor. 0 botnet packages, 0 C2 connections, Play Protect active. Firmware is a factory `userdebug` build signed with generic `test-keys` carrying Ugoos/TOX OEM utilities (`com.trustonx`, `com.tox.updater`), but verified completely free of active malware or proxyware. |
| **BuzzTV G Series** (`SEID04BBZG`) | SEI Robotics / `SEID04BBZG` (`amlogic`) | Android 14 (API 34, Patch 2025-12-01) | **CLEAN / SAFE** (`risk_score: 0`) | **NO** | Genuine Android TV device manufactured by SEI Robotics (Tier-1 ODM). Verified clean of OEM droppers (`com.oemservice` not present), untampered Play Protect (`user_consent=1`), 0 botnet indicators, and zero suspicious external traffic during dynamic VPN monitoring. |

---

## 🟡 Neutralized Devices (Aparelhos com Backdoor Identificada e Neutralizada)

Devices that shipped with dormant or active dropper components from the OEM supply chain, successfully neutralized and verified with this suite.

| Brand / Model | SoC / Hardware | Android / API | Initial Finding | Final State | Verified Persistence |
|---|---|---|---|---|---|
| **MECOOL 4K Google TV Stick** (`HP4610-Mecool` / `KD3` / `YYT`) | SkyworthDigital / `HP46BY4` (`amlogic`) | Android 11 (API 30) | **FACTORY ODM DROPPER & PERSISTENCE**:<br>• **Build Display ID:** `RTT0.210829.002.C2.2.8_20240604 release-keys`<br>• **Versão Incremental:** `C2.2.8_20240604` (compilação: 4 de junho de 2024)<br>• **Versão do Android:** Android 11 (API 30)<br>• **Patch de Segurança:** `2024-05-05`<br>• **Fabricante Real / ODM:** `SkyworthDigital` (Amlogic, placa `YYT` / `HP4610-Mecool`)<br>• **Impressão Digital (Fingerprint):** `MECOOL/HP4610-Mecool/YYT:11/RTT0.210829.002/C2.2.8_20240604:user/release-keys`<br>• **Payload de Fábrica:** `/oem/app_xcpe_ext_sign` (8.2 MB APK gravado na partição read-only com `dm-verity` a 2024-06-05 05:10:20) + `com.oemservice` ativo. | **ACTIVE BOTNET / REQUIRES REMEDIATION** | O pacote `com.oemservice` encontra-se ativo em memória. O aparelho requer execução de remediação (`--remediate`) para congelar o dropper via `pm disable-user --user 0`. Note: `/oem/app_xcpe_ext_sign` provado 100% de fábrica da Skyworth ODM. |
| **Mecool UHD Google TV Stick** (`HPR323-Mecool` / `KHH`) | SkyworthDigital / `HPR3B1325_4K` (`rtd1325`) | Android 14 (API 34) | **FACTORY ODM DROPPER & PERSISTENCE**:<br>• **Build Display ID:** `UTT1.250214.001.C1.0.4_20251128`<br>• **Versão Incremental:** `C1.0.4_20251128` (compilação: 28 de novembro de 2025)<br>• **Versão do Android:** Android 14 (API 34)<br>• **Patch de Segurança:** `2025-09-05`<br>• **Fabricante Real / ODM:** `SkyworthDigital` (Realtek `rtd1325`, placa `KHH` / `HPR323-Mecool`)<br>• **Impressão Digital (Fingerprint):** `Mecool/HPR323-Mecool/KHH:14/UTT1.250214.001/C1.0.4_20251128:user/release-keys`<br>• **Payload de Fábrica:** `/oem/app_xcpe_ext_sign` (8.3 MB APK gravado na partição read-only com `dm-verity` a 2025-12-05 05:59:20 UTC) + `com.oemservice` pré-instalado. | **NEUTRALIZED / FROZEN** | Backdoor package frozen via `pm disable-user --user 0`, DoT Private DNS enforced (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). Note: `/oem/app_xcpe_ext_sign` is verified as 100% factory-embedded by Skyworth ODM during manufacturing (read-only dm-verity partition). |
| **Strong 4K Google TV Stick** (`HP4613-STRONG` / `YYT`) | SkyworthDigital / `HP46BY4` (`amlogic`) | Android 14 (API 34) | **FACTORY ODM DROPPER IN PRIV-APP**:<br>• **Build Display ID:** `UKG3.250826.001.C3.3.0_20260520`<br>• **Versão Incremental:** `C3.3.0_20260520` (compilação: 20 de maio de 2026)<br>• **Versão do Android:** Android 14 (API 34)<br>• **Patch de Segurança:** `2026-05-05`<br>• **Fabricante Real / ODM:** `SkyworthDigital` (Amlogic, placa `YYT` / `HP4613-STRONG`)<br>• **Impressão Digital (Fingerprint):** `Strong/HP4613-STRONG/YYT:14/UKG3.250826.001/C3.3.0_20260520:user/release-keys`<br>• **Payload de Fábrica:** `com.oemservice` pré-instalado em `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk`. Partição `/oem` verificada sem ficheiro `app_xcpe_ext_sign`. | **NEUTRALIZED / FROZEN** | Backdoor package frozen via `pm disable-user --user 0`, DoT Private DNS enforced (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). |
| **ugoos UHD Google TV STB** (`HPR3A1325_4K`) | SkyworthDigital / `HPR3A1325_4K` (`rtd1325`) | Android 12 (API 31, Patch 2025-02-05) | **STAGE 1 DORMANT DROPPER (Adormecido de Fábrica)**: `com.oemservice` (v1.2.1 in `/system/priv-app/app_xcpe_preset/app_xcpe_preset.apk` with `android.uid.system`). Stage 2 payload not yet triggered in `/data/app` (0 active processes in RAM). | **NEUTRALIZED / FROZEN** | Dropper frozen via `pm disable-user --user 0 com.oemservice`, Play Protect enforced (`user_consent=1`), Private DNS DoT enabled (`security.cloudflare-dns.com`), verified clean across reboots (`risk_score: 0`). Stock launcher kept enabled for firmware stability. |

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
