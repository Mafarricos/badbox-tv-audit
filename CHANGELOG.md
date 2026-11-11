# Changelog

All notable changes to the `badbox-tv-audit` project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.2] - 2026-11-11

### Correções e Endurecimento Criptográfico (Auditoria Externa Review #4)
- **Verificação Robusta com `apksigner` Oficial**:
  - A verificação de certificados no instalador (`tools/audit_security.py`) agora invoca estritamente o `apksigner verify --print-certs` oficial da Google, validando esquemas v1, v2 e v3 como o Android 7+ faz nativamente.
  - O fallback ingénuo para parser de blocos PKCS#7 em `META-INF` foi totalmente removido para prevenir evasões com assinaturas v2 truncadas ou adulteradas. Se o `apksigner` não estiver disponível, a instalação aborta com segurança.
- **Resolução do `--auto-pipeline` em Clones Novos**:
  - Quando a pasta `tools/` não contém o APK universal compilado e assinado, o pipeline agora descarrega-o automaticamente da Release oficial do GitHub e verifica-o criptograficamente com o `apksigner` contra `tools/apk_pin.json`.
  - Para utilizadores que compilam o APK localmente via `./gradlew assembleDebug`, o instalador deteta a compilação local e autoriza a chave debug emitindo um aviso explícito de segurança em terminal.
- **Filtro Geral de UIDs de Sistema e Partilhados na Quarentena**:
  - O filtro de quarentena da VPN na `MainActivity` e no `PacketMonitorVpnService` foi generalizado para além do UID 1000: qualquer pacote com `uid < 10000` (ex.: `android.uid.phone`, 1001) ou com UIDs partilhados por múltiplos pacotes (`getPackagesForUid(uid).length > 1`) é salvaguardado da quarentena Sinkhole e direcionado para neutralização segura via ADB, prevenindo o corte de rede em serviços essenciais da ROM.
- **Precisão Semântica sobre Tráfego na TV**:
  - Atualizadas as mensagens no ecrã da TV (`MainActivity.java`) e nos recursos (`strings.xml` PT/EN) para indicar com precisão técnica que o tráfego não-DNS é **"descartado"** (dropped) em vez de "retido".

---

## [2.0.2-rc1] - 2026-11-10

### Correções Críticas e Auditoria Externa (Review #3)
- **Prevenção de Blackout na Quarentena Sinkhole (0 Pacotes Associados)**:
  - Quando todos os implantes detetados têm `uid == 1000` (ex.: `com.oemservice` de fábrica) ou falham no `getApplicationInfo`, o `PacketMonitorVpnService` contabiliza `addedCount` e **aborta antes de chamar `builder.establish()`**, limpa o estado persistente em `SharedPreferences` (`KEY_ACTIVE = false`), desativa o `START_STICKY` e encerra o serviço (`stopSelf()`), impedindo que o Android aplique a VPN Sinkhole a toda a box e corte a internet globalmente.
  - A `MainActivity` pré-filtra pacotes `uid == 1000` antes de iniciar a quarentena e apresenta apenas a instrução direta de desativação via ADB (`adb shell pm disable-user --user 0 <pacote>`).
- **Portas Isoladas na VPN (`PacketMonitorVpnService.java` e `audit_security.py`)**:
  - Todas as portas remotas suspeitas (`2082, 2095, 8082, 8083, 3885-3887, 1080, 9050, 4145, 7777, 6667, 22345, 16000, 12000, 9992, 9994, 2375`) passaram para `SUSPICIOUS_MALWARE_PORTS`.
  - Uma porta isolada num IP desconhecido gera apenas `"AVISO [SUSPICIOUS]"` (mapeado para `SUSPICIOUS_PORT_ONLY` / severidade `LOW` no motor forense), reservando `"PERIGO [CRÍTICO]"` exclusivamente para correspondências exatas com IPs ou domínios de C2.
- **Aviso Explícito sobre Retenção de Tráfego durante a Monitorização VPN**:
  - Adicionado aviso claro na interface da TV (`MainActivity.java` e `strings.xml` PT/EN), no terminal (`step_automated_pipeline` em `tools/audit_security.py`) e na documentação (`README.md` e `README.pt.md`) explicando que durante a janela de captura da Sentinela VPN apenas o DNS (UDP 53) é reencaminhado e o restante tráfego TCP/UDP é inspecionado e descartado.
- **Mensagem do Botão "Desativar" em Apps de Sistema (`MainActivity.java`)**:
  - Corrigida a instrução prévia à abertura das Definições do Android TV para não indicar o clique em `'Desativar'` em apps de sistema onde o botão está bloqueado.
- **Assinatura Oficial no CI (`build-release.yml`) e Pinning Estrito (`apk_pin.json`)**:
  - Configurados os segredos oficiais de assinatura no GitHub Actions (`ANDROID_KEYSTORE_BASE64`, etc.), removida a geração de chaves descartáveis (`keytool -genkeypair`) e adicionada validação em CI que exige correspondência exata do certificado SHA-256 com `tools/apk_pin.json`.
  - Em `tools/audit_security.py` (`step_install_custom_app` / `verify_apk_pin`), o certificado de assinatura do APK é agora verificado sempre (independentemente do nome do ficheiro) contra `tools/apk_pin.json`, abortando imediatamente a instalação (`return False`) caso não coincida.
- **Estabilidade de Testes em CI (`test_at09`)**:
  - Isolado o relógio de geração de snapshots de backup face ao fixture `fast_sleep`, garantindo nomes únicos em execuções rápidas consecutivas em Python 3.9–3.12.

## [2.0.1] - 2026-11-10

### Segurança e Heurísticas
- **Portas Isoladas**: Conexões a portas remotas suspeitas ou endpoints de CDN (como 2095 e 2082) isoladas sem correspondência de IP C2 passam a ser classificadas rigorosamente como `LOW` / `SUSPICIOUS_PORT_ONLY`, eliminando falsos positivos de `CRITICAL`.
- **Restauro de AppOps**: O comando `--restore` agora repõe integralmente o estado das permissões de AppOps (`RUN_IN_BACKGROUND allow`, etc.) gravadas durante a remediação.
- **Confirmação no Menu Interativo**: A opção 8 do menu de terminal passa a exigir confirmação explícita (`yes=False`).
- **Verificação de Integridade de APK**: Adicionada validação do hash SHA-256 do APK contra o manifesto oficial `tools/apk_pin.json` antes da instalação.

### Aplicação Android TV
- **Prevenção de Race Condition em DNS**: Criada cópia independente do buffer (`Arrays.copyOfRange`) na thread de resolução DNS do `PacketMonitorVpnService`.
- **Proteção do UID 1000**: A Quarentena Sinkhole ignora pacotes com `uid == 1000` (partilhado com o `system_server`), prevenindo o bloqueio inadvertido do sistema e informando que a desativação de apps de sistema requer o comando ADB.
- **Transparência de Desativação**: Mensagem honesta na interface alertando que o Android TV bloqueia nativamente o botão "Desativar" para apps de sistema (`canDisable = false`), direcionando para a remediação via ADB.
- **Clarificação do Sentinela VPN**: Aviso explícito de que a inspeção passiva atua durante a janela de teste (DNS resolvido, tráfego IP sob inspeção).

### CI / CD e Compatibilidade
- **Assinatura Automática no CI**: O workflow `build-release.yml` agora assina formalmente os APKs de release no GitHub com chaves RSA de 2048 bits com manifesto `META-INF`, permitindo instalação direta.
- **Compatibilidade Python 3.9 - 3.12**: Runners de CI ajustados para garantir compatibilidade e execução em Python 3.9, 3.10, 3.11 e 3.12.

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
