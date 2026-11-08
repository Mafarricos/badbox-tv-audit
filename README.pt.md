# Suite Forense e Antimalware para Android TV / Google TV (BadBox, XCPE, Vo1d & Remediação)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Suite forense, de remoção de malware e de remediação reversível completa e autónoma (CLI + App nativa Android TV com Sentinela VPN) projetada para auditoria, deteção, verificação, neutralização e restauro de trojans de supply-chain, botnets residenciais e malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS** e **Proxyware Residencial**) em dispositivos Android TV, Google TV e TV Boxes genéricas.

> **Idioma:** Português (PT-PT) | [For English version, see README.md](README.md) | [📱 Registo de Aparelhos Testados](DEVICES.md) | [🔬 Decisões de Arquitetura (ADRs)](docs/DECISIONS.md) | [📜 Avisos de Terceiros](THIRD_PARTY_NOTICES.md)

---

## 🎯 Porquê esta ferramenta?

Milhares de Smart TVs e TV Boxes Android económicas chegam ao utilizador pré-infetadas de fábrica ou são comprometidas através de firmwares adulterados e aplicações não oficiais. O malware habitualmente:
1. Desativa silenciosamente o **Google Play Protect** definindo `package_verifier_user_consent = -1`.
2. Instala trojans e backdoors persistentes na partição `/system` ou `/vendor` (como o **Vo1d**, **BadBox** ou **XCPE**, imunes a reposições de fábrica).
3. Transforma o dispositivo num **nó de proxy residencial ilegal** (vendendo a largura de banda da sua casa para cibercriminosos através de SDKs ocultos de proxyware) e participa em fraudes de cliques e visualizações em segundo plano.

Esta ferramenta fornece dois métodos completos para auditar e limpar a sua TV:
- **Para quem quer usar apenas o comando da TV (Sem PC/Scripts):** Instale o APK na TV via Pen USB ou browser. A própria App faz o varrimento, mostra o veredito no ecrã e disponibiliza o botão vermelho **"NEUTRALIZAR AMEAÇAS"**. Para implantes de sistema que não podem ser desinstalados sem ADB, a App ativa o modo de **Quarentena Sinkhole via VpnService**, bloqueando todo o tráfego malicioso de rede no próprio aparelho.
- **Para Técnicos e Agentes de IA (Via PC/ADB):** Pipeline 100% silencioso e automatizado (`audit_security.py`) com descoberta de sub-rede, modo JSON puro otimizado para agentes de IA, criação de backup prévio, quarentena de APKs e reversibilidade garantida em `backups/`.

---

## 📱 1. Como Preparar a TV (Ativar Modo de Programador & ADB)

Antes de iniciar ferramentas ou pedir a um Agente de IA para analisar o aparelho, necessita de ativar a **Depuração ADB** na TV para permitir a ligação via Wi-Fi:

### A. Em Android TV Padrão (Android 9, 10, 11 - ex: Xiaomi, Strong, boxes genéricas):
1. No comando da TV, vá a **Definições (Settings)** (ícone da roda dentada) -> **Preferências do Dispositivo (Device Preferences)** -> **Acerca de (About)**.
2. Desça até à opção **Número de Compilação (Build)**.
3. Carregue **7 vezes seguidas no botão OK / Central do comando**, até aparecer a mensagem no ecrã: *"É agora um programador!"*.
4. Volte atrás com o comando e entre no novo menu **Opções do Programador (Developer Options)**.
5. Ative a opção **Depuração USB (USB Debugging)** e, se existir, **Depuração de Rede (Network Debugging)**.
6. Na primeira ligação, irá surgir um pop-up na TV a perguntar *"Permitir depuração USB a partir deste computador?"*. Marque *"Permitir sempre"* e selecione **OK**.

### B. Em Google TV (Android 12, 14 - ex: Chromecast, realme, Thomson, TCL):
1. No canto superior direito da TV, clique na sua foto/perfil -> **Definições (Settings)**.
2. Selecione **Sistema (System)** -> **Acerca de (About)**.
3. Desça até **Versão do SO Android TV (Android TV OS build)**.
4. Carregue **7 vezes seguidas no botão OK do comando** até desbloquear o modo de programador.
5. Volte atrás para **Sistema (System)** -> **Opções do Programador (Developer Options)**.
6. Ative a **Depuração USB (USB Debugging)**.
7. Confirme o pop-up de autorização na TV quando o computador se conectar.

> [!WARNING]
> 🔒 **Recomendação Essencial de Segurança (Desativar a Depuração no Fim):**  
> Manter a Depuração USB / ADB permanentemente ativada na sua rede Wi-Fi doméstica deixa aberta a porta de gestão remota (5555), que pode ser sondada por outros aparelhos ou apps maliciosas na rede.  
> **Não se esqueça de voltar a DESLIGAR a Depuração USB nas Opções do Programador assim que terminar o diagnóstico e a limpeza da TV!**

---

## 🤖 2. Como Usar com Agentes de IA (Antigravity, Claude Code, Grok, Cursor, Copilot)

Este repositório inclui instruções autónomas completas no ficheiro [`AGENTS.md`](AGENTS.md) que os agentes de IA leem e seguem de forma transparente. **Não precisa de configurar Python manualmente, instalar drivers ou escrever comandos.**

> [!IMPORTANT]
> 🛡️ **Fluxo Operacional Seguro para Agentes de IA:**  
> O agente deve sempre executar primeiro o `--quick-scan` (diagnóstico 100% de leitura). O plano de remediação e as evidências técnicas encontradas devem ser validados pelo utilizador antes de disparar o `--remediate`.

Basta abrir o seu Agente de IA favorito e enviar-lhe esta simples instrução:

```text
Faz o clone de https://github.com/Mafarricos/badbox-tv-audit.git, lê o ficheiro AGENTS.md e audita a minha Android TV no IP <IP_DA_TV>.
```
*(Dica: Se não souber o IP da sua TV, diga ao agente: `...lê o AGENTS.md, descobre as Android TVs na minha sub-rede 192.168.1.0/24 e audita-as.`)*

O agente tratará autonomamente de:
1. Clonar o repositório e consultar as diretrizes operacionais de [`AGENTS.md`](AGENTS.md).
2. Ligar-se por ADB em Python puro (sem exigir instalação de binários externos).
3. Executar o varrimento estático de 6 camadas e o sentinela VPN em tempo real.
4. Gerar o ficheiro sanitizado anónimo (`community_audit_submission.json`) pronto para submissão.

---

## 📺 A App Nativa Android TV (`app/`)

A aplicação deteta o idioma da box automaticamente (em Português se a TV estiver em Português; em Inglês para todos os outros idiomas) e é 100% controlável pelo comando (D-Pad):

1. **Botão 1: ANALISAR BOX (ESTÁTICO):** Varre partições `/oem/`, `/vendor/`, integridade do Play Protect, artefactos de trojans (Vo1d, XCPE) e enumera pacotes instalados em segundos.
2. **Botão 2: MONITORIZAR REDE (VPN):** Sentinela local loopback que alerta em tempo real:
   - **A Vermelho (`[CRÍTICO]`):** Se a box tentar falar com servidores C2 ou portas MQTT/proxy conhecidas.
   - **A Amarelo (`[ANOMALIA]`):** Se houver tráfego anómalo em portas altas enquanto a TV devia estar em repouso.
3. **Botão 3: NEUTRALIZAR AMEAÇAS (Aparece se forem detetadas anomalias):**
   - **Aplicações de Utilizador e Atualizações (/data/app):** Abre o diálogo nativo de desinstalação sequencial.
   - **Implantes de Sistema (/system, /vendor):** Bloqueia o tráfego ativando o modo de **Quarentena Sinkhole via VpnService** e guia o operador nas Definições do sistema para forçar paragem/desativar, indicando também o comando ADB (`pm disable-user --user 0`).
   - Atalho direto para reativar a verificação de aplicações do Google Play Protect.

### 🛡️ Compilação e Assinatura da App
Para garantir a integridade da cadeia de fornecimento, não são versionadas chaves criptográficas nem APKs pré-compilados no git (SEC-01).
- Compilação de debug: `cd app && ./gradlew assembleDebug`
- Testes unitários puros: `cd app && ./gradlew testDebugUnitTest`
- Procedimento de assinatura de release: [`docs/RELEASE_SIGNING.md`](docs/RELEASE_SIGNING.md)

---

## 🚀 Utilização da Linha de Comandos (CLI) & Agentes

A suite **deteta automaticamente o idioma do seu sistema** (assume **Inglês** para utilizadores internacionais ou **Português** se o sistema operativo estiver em Português). Pode forçar o idioma com `--lang en` ou `--lang pt`.

### Dois Modos de Auditoria Disponíveis:
- **Diagnóstico Rápido ADB 6 Camadas (`--quick-scan`)**: 100% leitura, demora 5 a 10 segundos, não instala nada no aparelho. Cobre todas as famílias de trojans conhecidas (XCPE, BadBox, Vo1d, droppers, sockets C2 ativos e Play Protect).
- **Sentinela Dinâmico Intensivo (`--auto-pipeline`)**: Instala a app na TV (`com.scanner.tv`), ativa a VPN de loopback durante 20 a 60 segundos para inspecionar tráfego DNS/IP à procura de tráfego C2 dormente, recolhe relatórios, avalia regras e desinstala a app no fim de forma limpa.

```bash
# 1. Auditoria Dinâmica Completa (Instala APK, corre 20s sentinela VPN, recolhe logs e desinstala)
python tools/audit_security.py <IP_DA_TV> --auto-pipeline

# 2. Diagnóstico Rápido de Leitura via ADB (Modo Padrão ou JSON Puro para Agentes)
python tools/audit_security.py <IP_DA_TV> --quick-scan
python tools/audit_security.py <IP_DA_TV> --quick-scan --json

# 3. Descobrir e Auditar Todas as TVs na Sub-rede Doméstica
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 4. Remediação Profunda com Pré-visualização do Plano (--dry-run)
python tools/audit_security.py <IP_DA_TV> --remediate --dry-run
python tools/audit_security.py <IP_DA_TV> --remediate

# 4.1 Remediação Não-Interativa para Agentes de IA (requer --yes explícito)
python tools/audit_security.py <IP_DA_TV> --remediate --yes

# 4.2 Remediação com Validação de Ressurreição Pós-Reboot e Cloudflare DoT
python tools/audit_security.py <IP_DA_TV> --remediate --yes --verify-reboot --enable-dot

# 5. Reversão e Restauro do Estado Anterior a partir de Backup
python tools/audit_security.py <IP_DA_TV> --restore --backup backups/<device_id>/backup_<timestamp>.json

# 6. Exportação de Listas de Bloqueio de C2 (Pi-hole, AdGuard, dnsmasq, /etc/hosts)
python tools/export_blocklist.py --format all

# 7. Validação da Base de Dados Canónica de IoCs
python tools/validate_iocs.py
```

---

## 📤 Contribuição: Envio de Relatórios para o Registo de Aparelhos

Ajude a comunidade a mapear quais os modelos de Android TV e Google TV que trazem implantes de fábrica ou firmwares limpos!

Sempre que realiza uma auditoria (via `--quick-scan` ou `--auto-pipeline`), a suite **gera automaticamente um relatório sanitizado** em:
```text
community_audit_submission.json
```

### 🛡️ Garantia de Privacidade e Sanitização (Allowlist):
- **Todos os identificadores pessoais são estritamente removidos** através de uma allowlist estrita: sem endereços IP locais ou públicos, sem endereços MAC, sem números de série, sem chip IDs e sem IMEIs (PRIV-01).
- Contém **apenas** características técnicas de firmware: modelo de SoC, versão de build, estado do Play Protect, hashes de pacotes suspeitos e portas ativas de C2.

### Como Submeter:
1. **No GitHub Issues (Recomendado):**
   - Abra um novo Issue em: [https://github.com/Mafarricos/badbox-tv-audit/issues](https://github.com/Mafarricos/badbox-tv-audit/issues)
   - Título: `[Device Audit] <Marca> <Modelo>` (ex: `[Device Audit] Strong 4K Google TV Stick`)
   - Cole o conteúdo do ficheiro `community_audit_submission.json`.
2. **Por Correio Eletrónico:**
   - Envie o ficheiro `community_audit_submission.json` diretamente para o e-mail: **`mafastudios@gmail.com`** (Assunto: `Auditoria TV: <Marca> <Modelo>`).

O seu relatório será validado e incorporado no registo oficial de [Aparelhos Testados (DEVICES.md)](DEVICES.md)!

---

## 🔒 Garantia de Segurança e Reversibilidade

Cada operação de remediação cria um snapshot integral sob `backups/<device_id>/backup_<timestamp>.json`. Os APKs desinstalados são colocados em quarentena com verificação criptográfica SHA-256 sob `backups/<device_id>/quarantine/`.

> [!IMPORTANT]
> **Nota sobre Persistência (Atualizações OTA e Reposição de Fábrica):**  
> Como os droppers de supply-chain (como o `com.oemservice` / XCPE) vêm gravados de fábrica nas partições só de leitura (`/system` ou `/vendor`), esta ferramenta mitiga-os e congela-os no gestor de pacotes do Android (`pm disable-user --user 0`) sem risco de inutilizar o dispositivo.  
> Consequentemente:
> 1. **Reposição de Fábrica (Factory Reset):** Se repuser o aparelho para as definições originais de fábrica, a partição volta ao estado inicial e o backdoor será reativado. Terá de correr a ferramenta de remediação novamente.
> 2. **Atualizações de Sistema (OTA):** Uma atualização do fabricante pode corrigir definitivamente a vulnerabilidade ou repor os pacotes de sistema. Se a TV receber um update, execute `--quick-scan` para verificar se a ROM foi limpa.

---

## ⚠️ Isenção de Responsabilidade

Este software é disponibilizado estritamente para fins educativos, forenses e de investigação de segurança ao abrigo da [Licença MIT](LICENSE). Referências a relatórios e IoCs de terceiros pertencem aos respetivos autores ([Avisos de Terceiros](THIRD_PARTY_NOTICES.md)).

---

## 👨‍💻 Sobre o Autor & Agradecimentos

Olá, sou o **Carlos Correia**! Sou entusiasta de tecnologia e programador, apaixonado pelo ecossistema Android TV e Google TV. A revelação recente de comprometimentos de supply-chain (**VideoStrong / SZBBOYS / BadBox / XCPE**) motivou-me a desenvolver esta suite aberta, transparente e autónoma.

### Apoie o Projeto:
- 📺 **Subscreva o meu canal no YouTube:** [@Carlos___Correia](https://www.youtube.com/@Carlos___Correia)
- ⭐ Deixe uma estrela neste repositório e partilhe-o com a comunidade de Android TV!
