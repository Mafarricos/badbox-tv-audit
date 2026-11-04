# BadBox & XCPE Forensic Suite for Android TV / Google TV

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-AI Rules](https://img.shields.io/badge/Detection-Deterministic%20Scoring-orange.svg)](#-matriz-de-decis%C3%A3o-determin%C3%ADstica-zero-ai)
[![App Remediation](https://img.shields.io/badge/TV%20App-On--Screen%20Remediation-success.svg)](#-a-app-nativa-android-tv-app)
[![Logging](https://img.shields.io/badge/Logging-Live%20Console%20%2B%20Transcripts-informational.svg)](#-telemetria-visual-e-auditoria-de-logs)

Suite forense e de remediação reversível completa e autónoma (CLI + App nativa Android TV com Sentinela VPN) projetada para auditoria, deteção, verificação, neutralização e restauro de malware de supply-chain e botnets residenciais (**BadBox**, **XCPE**, **Fuyao**, **Videostrong/SZBBOYS**) em dispositivos Android TV, Google TV e TV Boxes genéricas.

---

## 🎯 Porquê esta ferramenta?

Milhares de Smart TVs e TV Boxes Android económicas chegam ao utilizador pré-infetadas de fábrica. O malware:
1. Desativa silenciosamente o **Google Play Protect** definindo `package_verifier_user_consent = -1`.
2. Instala backdoors persistentes na partição `/system` ou `/vendor` (imunes a reposições de fábrica).
3. Transforma o dispositivo num **nó de proxy residencial ilegal** (vendendo a largura de banda da sua casa para cibercriminosos) e participa em fraudes de cliques e visualizações ocultas.

Esta ferramenta fornece dois métodos completos para auditar e limpar a sua TV:
- **Para quem quer usar apenas o comando da TV (Sem PC/Scripts):** Instale o APK na TV via Pen USB ou browser. A própria App faz o varrimento, mostra o veredito no ecrã e disponibiliza o botão vermelho **"NEUTRALIZAR AMEAÇAS"**, permitindo desinstalar as apps da botnet e reativar proteções com o comando físico.
- **Para Técnicos e Agentes de IA (Via PC/ADB):** Pipeline 100% silencioso e automatizado (`audit_security.py`) com criação de backup prévio e reversibilidade instantânea em `backups/`.

---

## 📱 Como Preparar a TV (Ativar Modo de Programador & ADB)

Para que a ferramenta via PC ou um Agente de IA consiga comunicar com a sua Android TV / Google TV através da rede Wi-Fi, necessita de ativar a **Depuração ADB**:

### A. Em Android TV Padrão (Android 9, 10, 11 - ex: Xiaomi, Strong, boxes genéricas):
1. No comando da TV, vá a **Definições (Settings)** (ícone da roda dentada) -> **Preferências do Dispositivo (Device Preferences)** -> **Acerca de (About)**.
2. Desça até à opção **Número de Compilação (Build)**.
3. Carregue **7 vezes seguidas no botão OK / Central do comando**, até aparecer a mensagem no ecrã: *"É agora um programador!"*.
4. Volte atrás com o comando e entre no novo menu **Opções do Programador (Developer Options)**.
5. Ative a opção **Depuração USB (USB Debugging)** e, se existir, **Depuração de Rede (Network Debugging)**.
6. Na primeira ligação, irá surgir um pop-up na TV a perguntar *"Permitir depuração USB a partir deste computador?"*. Marque *"Permitir sempre"* e selecione **OK**.

---

### B. Em Google TV (Android 12, 14 - ex: Chromecast, realme, Thomson, TCL):
1. No canto superior direito da TV, clique na sua foto/perfil -> **Definições (Settings)**.
2. Selecione **Sistema (System)** -> **Acerca de (About)**.
3. Desça até **Versão do SO Android TV (Android TV OS build)**.
4. Carregue **7 vezes seguidas no botão OK do comando** até desbloquear o modo de programador.
5. Volte atrás para **Sistema (System)** -> **Opções do Programador (Developer Options)**.
6. Ative a **Depuração USB (USB Debugging)**.
7. Confirme o pop-up de autorização na TV quando o computador se conectar.

> [!TIP]
> **Como ver o IP da sua TV:**
> Vá a **Definições** -> **Rede e Internet** -> Clique na sua rede Wi-Fi ligada -> Veja o endereço no campo **Endereço IP** (ex: `192.168.1.127`).

---

## 📺 A App Nativa Android TV (`app/`)

A aplicação para Android TV foi desenhada especificamente para controlo por comando (D-Pad):

1. **Botão 1: ANALISAR BOX (ESTÁTICO):** Varre partições `/oem/`, `/vendor/`, integridade do Play Protect e enumera pacotes instalados em segundos.
2. **Botão 2: MONITORIZAR REDE (VPN):** Sentinela local loopback que alerta em tempo real:
   - **A Vermelho (`[CRÍTICO]`):** Se a box tentar falar com servidores C2 ou portas MQTT conhecidas.
   - **A Amarelo (`[ANOMALIA]`):** Se houver tráfego anómalo em portas altas enquanto a TV devia estar em repouso.
3. **Botão 3: NEUTRALIZAR AMEAÇAS (Aparece se forem detetadas anomalias):**
   - Inicia a desinstalação guiada das apps da botnet com diálogo direto no ecrã.
   - Abre o atalho para confirmação da reativação do Google Play Protect.
   - Permite voltar a carregar em **"ANALISAR BOX"** imediatamente a seguir para comprovar que o veredito mudou de **`PERIGO [INFETADO]`** para **`DISPOSITIVO LIMPO`**.

---

## 📊 Telemetria Visual e Auditoria de Logs

Toda a interação com a box é apresentada em tempo real com **feedback visual detalhado** na consola e gravada simultaneamente em ficheiro:

- **Na Consola:** O utilizador humano ou o agente de IA visualiza cada passo da execução (comunicação ADB, contagens regressivas do Sentinela VPN, respostas dos comandos `pm` e `settings`, tabelas de pontuação de risco).
- **Na Pasta `logs/`:** Cada sessão gera automaticamente um ficheiro `logs/session_<timestamp>.log`.
  - Permite aos utilizadores rever o histórico de auditorias e intervenções passadas.
  - Permite a agentes de IA consultar as evidências exatas para responder a perguntas técnicas ou formular relatórios forenses.

---

## 🧹 Remediação Avançada via Script (100% Reversível)

**Regra de Ouro: Nada é alterado sem backup prévio.**

Se utilizar o script via PC, as contramedidas são aplicadas silenciosamente com salvaguarda automática:
1. **Backup de Estado Prévio:** Grava o estado original do Play Protect, DNS e pacotes em `backups/backup_<IP>_<timestamp>.json` e gera um script autónomo `backups/restore_<IP>.ps1`.
2. **Repõe e Tranca o Google Play Protect:** Força `package_verifier_user_consent = 1` e `package_verifier_enable = 1`.
3. **Remove Módulos de Utilizador:** Desinstala apps de proxy e ad-fraud via `pm uninstall`.
4. **Congela Backdoors de Sistema:** Desativa backdoors OEM de fábrica (`x.cpe`, `com.oemservice`) via `pm disable-user --user 0`.
5. **Ativa Private DNS Seguro com Filtro Anti-Malware:** Configura o Android para usar DNS sobre TLS (`security.cloudflare-dns.com`), cortando a resolução dos domínios de comando e controlo diretamente na TV.

### Comandos de Script:
```bash
# Remediar com backup automático:
python tools/audit_security.py <IP_DA_BOX> --remediate

# Reverter e repor o estado anterior:
python tools/audit_security.py <IP_DA_BOX> --restore
```

---

## ⚙️ Instalação dos Pré-Requisitos (Para quem usa o PC)

### Método A: Instalação Automática com Scripts (1 Clique)
- **Windows:** Dê duplo clique em `setup.bat`.
- **Linux / macOS:** Corra `chmod +x setup.sh && ./setup.sh`.
- **Menu Integrado:** Corra `python tools/setup_env.py`.

### Método B: Instalação Manual Passo a Passo
```bash
python -m venv venv
# Windows: venv\Scripts\activate | Linux: source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Como Executar

### 1. Menu Interativo Guiado (Para Humanos)
```bash
python tools/audit_security.py
```
Menu com opções de diagnóstico rápido, pipeline 100% automático, remediação, restauro e configuração.

### 2. Linha de Comandos (Para Agentes de IA e Automação)
```bash
# Diagnóstico rápido de 5 camadas sem instalar nada (100% leitura):
python tools/audit_security.py <IP_DA_BOX> --quick-scan

# Pipeline 100% automático com APK pré-compilado:
python tools/audit_security.py <IP_DA_BOX> --auto-pipeline

# Remediar e limpar a box infetada (com backup prévio):
python tools/audit_security.py <IP_DA_BOX> --remediate

# Reverter remediação e repor estado original:
python tools/audit_security.py <IP_DA_BOX> --restore
```

---

## ⚖️ Matriz de Decisão Determinística (Zero-AI)

| Evidência Detetada | Gravidade | Pontos |
| :--- | :--- | :--- |
| `package_verifier_user_consent = -1` (Play Protect forçado a desligar) | **CRÍTICO** | +10 |
| Conexão a IPs/portas conhecidas de C2 (`219.134.163.210`, `:3885-3887`, etc.) | **CRÍTICO** | +10 |
| Assinaturas BadBox em APKs/Props (`szbboys`, `anyevonline`, `videostrong`, etc.) | **CRÍTICO** | +8 |
| Pacotes maliciosos instalados (`x.cpe`, `traffmonetizer`, `nexus`, etc.) | **CRÍTICO** | +8 |
| `package_verifier_enable = 0` | **SUSPEITO** | +3 |
| Tráfego não padrão em portas altas em repouso | **ANOMALIA** | +3 |
| Modelo em linha visada Videostrong/MECOOL (Aviso Informativo) | **CONTEXTO** | 0 (Requer Evidências) |

### Limiares de Veredito:
- **`INFETADO - CRÍTICO`** (Pontuação >= 8 ou qualquer indicador crítico): Confiança **> 99%**.
- **`SUSPEITO`** (Pontuação >= 3 ou 2+ anomalias): Confiança **~80%**.
- **`LIMPO / SEGURO`** (Pontuação < 3): Confiança **> 98%**.

---

## 📄 Licença

Distribuído sob a licença MIT. Consulte `LICENSE` para mais detalhes.
