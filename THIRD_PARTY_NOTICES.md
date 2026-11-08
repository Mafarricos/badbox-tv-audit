# Third-Party Notices & Attribution

The `badbox-tv-audit` project aggregates, synthesizes, and builds upon cybersecurity research, threat intelligence, and open-source contributions from multiple organizations and independent researchers investigating the Android TV supply-chain botnets (XCPE, BadBox 2.0, Vo1d, PeachPit, and associated residential proxywares).

We gratefully acknowledge the foundational investigations, indicators of compromise (IoCs), and technical analyses provided by:

---

## 1. Threat Intelligence & Research Attributions

### Human Security (Satori Threat Intelligence)
- **Investigation:** The Badbox Botnet and PEACHPIT Ad-Fraud Operation.
- **Contributions:** Identification of compromised firmware supply chains, C2 domains, dropper mechanisms, and app spoofing behaviours across over 200 Android TV and mobile device models.
- **Reference:** https://www.humansecurity.com/learn/research/satori-threat-intelligence

### Eclypsium Research
- **Investigation:** Uncovering BadBox 2.0 and Supply Chain Backdoors in Android TV Boxes.
- **Contributions:** Identification of `com.oemservice`, `/oem/` partition droppers, and encrypted payload delivery mechanisms in low-cost off-brand streaming devices.
- **Reference:** https://eclypsium.com/blog/

### Synthient (Daniel Gallagher & Team)
- **Investigation:** Tracking the Badbox Threat Actor and Infrastructure Evolution.
- **Contributions:** Exhaustive mapping of C2 IP addresses, ports (3885-3887, 8082-8083, 16000), MQTT command protocols, and reverse SSH infrastructure.
- **Reference:** https://synthient.com/

### Plume Design, Inc.
- **Investigation:** Whitepaper on Residential Proxyware and IoT Exploitation.
- **Contributions:** Forensic categorization of residential proxy SDKs embedded into consumer devices, including TitanNet, GetGrass, TraffMonetizer, Linkfog, and AppSalt.
- **Reference:** https://www.plume.com/

### DesktopECHO
- **Investigation:** T95 Allwinner H616 Malware Analysis and Mitigation Scripts.
- **Contributions:** Initial community discovery of the `ycxrl.com` / `corejava` background downloader in T95 Android TV boxes and Pi-hole blocklist rules.
- **Reference:** https://github.com/DesktopECHO/T95-H616-Malware

---

## 2. Platform & Open Source Software Components

### Android Open Source Project (AOSP)
- **License:** Apache License 2.0
- **Usage:** Android TV Leanback components, VpnService API architecture, and platform permission models.

### Google Play Protect
- **Usage:** Reference settings key `package_verifier_user_consent` and verifier integration.

---

## 3. License Notice

All original software and tooling created for this repository are released under the [MIT License](LICENSE).
Third-party IoCs, domain lists, and threat intelligence references remain the intellectual property and research work of their respective authors and publishers.
