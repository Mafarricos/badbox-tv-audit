# BadBox & XCPE Forensic Suite for Android TV / Google TV

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-AI Rules](https://img.shields.io/badge/Detection-Deterministic%20Scoring-orange.svg)](#-matriz-de-decis%C3%A3o-determin%C3%ADstica-zero-ai)
[![Logging](https://img.shields.io/badge/Logging-Live%20Console%20%2B%20Transcripts-informational.svg)](#-telemetria-visual-e-auditoria-de-logs)
[![Remediation](https://img.shields.io/badge/Remediation-100%25%20Reversible-success.svg)](#-remedia%C3%A7%C3%A3o-e-neutraliza%C3%A7%C3%A3o-revers%C3%ADvel)

Suite forense e de remediação reversível completa e autónoma (CLI + App nativa Android TV com Sentinela VPN) projetada para auditoria, deteção, verificação, neutralização e restauro de malware de supply-chain e botnets residenciais (**BadBox**, **XCPE**, **Fuyao**, **Videostrong/SZBBOYS**) em dispositivos Android TV, Google TV e TV Boxes genéricas.

---

## 🎯 Porquê esta ferramenta?

Milhares de Smart TVs e TV Boxes Android económicas chegam ao utilizador pré-infetadas de fábrica. O malware:
1. Desativa silenciosamente o **Google Play Protect** definindo `package_verifier_user_consent = -1`.
2. Instala backdoors persistentes na partição `/system` ou `/vendor` (imunes a reposições de fábrica).
3. Transforma o dispositivo num **nó de proxy residencial ilegal** (vendendo a largura de banda da sua casa para cibercriminosos) e participa em fraudes de cliques e visualizações ocultas.

Esta ferramenta fornece uma inspeção de **camada dupla**, **remediação 100% reversível** e **registo integral de operações**:
- **Diagnóstico ADB Remoto:** Análise forense rápida de 5 camadas sem instalar nada no aparelho.
- **Sentinela VPN Local (App TV):** Captura em tempo real via `VpnService` de tráfego de rede invisível e ligações secretas aos servidores de Comando e Controlo (C2).
- **Módulo de Remediação & Restauro (`--remediate` / `--restore`):** Neutraliza a botnet com backup prévio obrigatório em `backups/`, permitindo anular qualquer alteração a qualquer altura.
- **Logs Completos em Tempo Real (`logs/`):** Gravação integral de todas as mensagens de consola para inspeção humana ou extração por modelos de IA.

---

## 📊 Telemetria Visual e Auditoria de Logs

Toda a interação com a box é apresentada em tempo real com **feedback visual detalhado** na consola e gravada simultaneamente em ficheiro:

- **Na Consola:** O utilizador humano ou o agente de IA visualiza cada passo da execução (comunicação ADB, contagens regressivas do Sentinela VPN, respostas dos comandos `pm` e `settings`, tabelas de pontuação de risco).
- **Na Pasta `logs/`:** Cada sessão gera automaticamente um ficheiro `logs/session_<timestamp>.log`.
  - Permite aos utilizadores rever o histórico de auditorias e intervenções passadas.
  - Permite a agentes de IA consultar as evidências exatas para responder a perguntas técnicas ou formular relatórios forenses.

---

## 🧹 Remediação e Neutralização Reversível

**Regra de Ouro: Nada é alterado sem backup prévio.**

Se uma box for diagnosticada como `INFETADO - CRÍTICO` ou `SUSPEITO`, a ferramenta aplica contramedidas no Android **com salvaguarda automática**:

1. **Backup de Estado Prévio:** Grava o estado original do Play Protect, DNS e pacotes em `backups/backup_<IP>_<timestamp>.json` e gera um script autónomo `backups/restore_<IP>.ps1`.
2. **Repõe e Tranca o Google Play Protect:** Força `package_verifier_user_consent = 1` e `package_verifier_enable = 1`.
3. **Remove Módulos de Utilizador:** Desinstala apps de proxy e ad-fraud (`com.abc.nexus`, `traffmonetizer`, `android-grass`, etc.) via `pm uninstall`.
4. **Congela Backdoors de Sistema:** Desativa backdoors OEM de fábrica (`x.cpe`, `com.oemservice`) ao nível do utilizador via `pm disable-user --user 0`.
5. **Ativa Private DNS Seguro com Filtro Anti-Malware:** Configura o Android para usar DNS sobre TLS (`security.cloudflare-dns.com`), cortando a resolução dos domínios de comando e controlo diretamente na TV.

### Como Remediá-la:
```bash
python tools/audit_security.py <IP_DA_BOX> --remediate
```
*(Ou selecione a **Opção 8** no menu interativo).*

### Como Reverter a Remediação (Restauro):
Se por qualquer motivo quiser repor o estado anterior:
```bash
python tools/audit_security.py <IP_DA_BOX> --restore
```
*(Ou selecione a **Opção 9** no menu interativo, ou execute diretamente `backups/restore_<IP>.ps1`).*

---

## ⚙️ Instalação dos Pré-Requisitos

Existem dois caminhos de instalação: **Modo Automático (Recomendado)** e **Modo Manual Passo a Passo**.

### Método A: Instalação Automática com Scripts (1 Clique)

Os scripts detetam o sistema operativo, instalam as dependências Python e oferecem a opção de instalar o compilador Java 17 e SDK Android caso pretenda recompilar o APK de raiz:

- **No Windows:**
  Dê duplo clique em `setup.bat` ou abra uma consola e corra:
  ```cmd
  setup.bat
  ```
- **No Linux / macOS:**
  Abra o terminal e execute:
  ```bash
  chmod +x setup.sh
  ./setup.sh
  ```
- **Dentro da Suite (Menu Integrado):**
  Pode também gerir e instalar qualquer dependência a qualquer altura correndo:
  ```bash
  python tools/setup_env.py
  ```

---

### Método B: Instalação Manual Passo a Passo (Sem Scripts)

Se prefere configurar tudo manualmente na sua linha de comandos:

#### 1. Instalar Dependências Mínimas de Auditoria (Modo Rápido com APK Universal)
Necessita apenas de Python 3.9+:
```bash
# Criar e ativar ambiente virtual (opcional mas recomendado)
python -m venv venv

# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

# Instalar bibliotecas de comunicação ADB pura
pip install -r requirements.txt
```
> [!NOTE]
> **Não precisa de instalar o executável oficial `adb.exe` nem o Android SDK** para auditar a sua TV! O ficheiro `tools/tv.py` comunica diretamente através do protocolo de rede ADB nativo em Python, utilizando o APK universal pré-compilado em `tools/xcpe-scanner-tv.apk`.

#### 2. Instalar Toolchain de Compilação (Apenas se quiser Recompilar de Raiz)
Se desejar modificar o código-fonte Java em `app/` ou compilar à medida para um aparelho específico:
1. **Instalar Java JDK 17:**
   - Windows: `winget install -e --id EclipseAdoptium.Temurin.17.JDK` ou descarregue de [adoptium.net](https://adoptium.net/).
   - Linux: `sudo apt install -y openjdk-17-jdk`
   - macOS: `brew install openjdk@17`
2. **Configurar o Android SDK:**
   - Defina a variável de ambiente `ANDROID_HOME` a apontar para o seu Android SDK.
   - Crie o ficheiro `app/local.properties` com o caminho do seu SDK:
     ```properties
     # Exemplo Windows:
     sdk.dir=C:\\AndroidSDK
     # Exemplo Linux:
     sdk.dir=/home/utilizador/Android/Sdk
     ```

---

## 🚀 Como Executar

Antes de executar, ative a **Depuração USB / Rede** no seu dispositivo:
*(Definições da TV -> Preferências do Dispositivo -> Acerca de -> Carregue 7 vezes em 'Número de Compilação' -> Opções do Programador -> Depuração de Rede / Depuração USB).*

### 1. Menu Interativo Guiado (Para Humanos)

Execute o comando principal:
```bash
python tools/audit_security.py
```

Irá ver o menu intuitivo:
```text
================================================================================
       XCPE / BADBOX FORENSIC SUITE - Android TV (192.168.1.127)                
================================================================================
  --- EXECUÇÃO AUTOMATIZADA ---
  1. Pipeline 100% Automatizado (Usa APK Universal - Rápido)
  2. Pipeline 100% Automatizado (Força RECOMPILAÇÃO no momento para a box)

  --- DIAGNÓSTICO E INSTALAÇÃO MANUAL ---
  3. Diagnóstico Rápido ADB (5 Camadas - Apenas Leitura, Sem Instalar)
  4. Instalar App na Box (Opção de Escolher: APK Existente ou Recompilar)
  5. Abrir App no Ecrã da TV
  6. Descarregar Relatório (JSON + Log VPN) e Avaliar Regras
  7. Desinstalar App da Box (Limpeza Forense)

  --- REMEDIAÇÃO E RESTAURO (REVERSÍVEL) ---
  8. Neutralizar / Limpar Box (Repõe Play Protect, Desativa Bots e Ativa DNS Seguro)
  9. Reverter Remediação / Restaurar Estado Anterior (Usar Backup)

  --- CONFIGURAÇÃO E PRÉ-REQUISITOS ---
 10. Gerir / Instalar Pré-Requisitos e Toolchains (Python / JDK / SDK)
 11. Mudar IP da Box
  0. Sair
================================================================================
```

---

### 2. Linha de Comandos e Automação (Para Agentes de IA e Scripts)

Pode invocar a ferramenta diretamente com flags:

```bash
# Pipeline 100% automático com APK pré-compilado:
python tools/audit_security.py <IP_DA_BOX> --auto-pipeline

# Remediar e limpar a box infetada (com backup prévio):
python tools/audit_security.py <IP_DA_BOX> --remediate

# Reverter remediação e repor estado original:
python tools/audit_security.py <IP_DA_BOX> --restore

# Pipeline 100% automático com recompilação à medida do hardware:
python tools/audit_security.py <IP_DA_BOX> --auto-pipeline --recompile-for-device

# Diagnóstico rápido de 5 camadas sem instalar nada (100% leitura):
python tools/audit_security.py <IP_DA_BOX> --quick-scan

# Configurar pré-requisitos via linha de comandos:
python tools/audit_security.py --setup-env
```

---

## 📺 A App Nativa Android TV (`app/`)

- **Navegação D-Pad:** 100% controlável com o comando físico da TV.
- **Sentinela VPN Loopback:** Analisa pacotes IP localmente com zero consumo de dados e alerta visualmente a vermelho (`[CRÍTICO]`) ou amarelo (`[ANOMALIA]`) perante tentativas de ligação estranhas.
- **Extração Forense Segura:** Regista os achados em `files/last_scan.json` e `files/audit_events.log`, extraídos automaticamente via ADB.

---

## ⚖️ Matriz de Decisão Determinística (Zero-AI)

O veredito final é calculado com base em pontuação e regras fixas de segurança:

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

## 🤖 Guia para Agentes de IA

Consulte o ficheiro [AGENTS.md](AGENTS.md) para a especificação das diretrizes de integridade, auto-recompilação com fallback, ciclo de remediação reversível, telemetria de logs e matriz de comandos não interativos.

---

## 📄 Licença

Distribuído sob a licença MIT. Consulte `LICENSE` para mais detalhes.
