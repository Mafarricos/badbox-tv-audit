# Suite Forense e Antimalware para Android TV / Google TV (BadBox, Vo1d & Remediação)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Suite forense, de remoção de malware e de remediação reversível completa e autónoma (CLI + App nativa Android TV com Sentinela VPN) projetada para auditoria, deteção, verificação, neutralização e restauro de trojans de supply-chain, botnets residenciais e malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS** e **Proxyware Residencial**) em dispositivos Android TV, Google TV e TV Boxes genéricas.

> **Idioma:** Português (PT-PT) | [For English version, see README.md](README.md) | [📱 Registo de Aparelhos Testados](DEVICES.md)

---

## 🎯 Porquê esta ferramenta?

Milhares de Smart TVs e TV Boxes Android económicas chegam ao utilizador pré-infetadas de fábrica ou são comprometidas através de firmwares adulterados e aplicações não oficiais. O malware habitualmente:
1. Desativa silenciosamente o **Google Play Protect** definindo `package_verifier_user_consent = -1`.
2. Instala trojans e backdoors persistentes na partição `/system` ou `/vendor` (como o **Vo1d**, **BadBox** ou **XCPE**, imunes a reposições de fábrica).
3. Transforma o dispositivo num **nó de proxy residencial ilegal** (vendendo a largura de banda da sua casa para cibercriminosos através de SDKs ocultos de proxyware) e participa em fraudes de cliques e visualizações em segundo plano.

Esta ferramenta fornece dois métodos completos para auditar e limpar a sua TV:
- **Para quem quer usar apenas o comando da TV (Sem PC/Scripts):** Instale o APK na TV via Pen USB ou browser. A própria App faz o varrimento, mostra o veredito no ecrã e disponibiliza o botão vermelho **"NEUTRALIZAR AMEAÇAS"**, permitindo desinstalar as apps maliciosas e reativar proteções com o comando físico.
- **Para Técnicos e Agentes de IA (Via PC/ADB):** Pipeline 100% silencioso e automatizado (`audit_security.py`) com descoberta de sub-rede, modo JSON otimizado para economia de tokens, criação de backup prévio e reversibilidade instantânea em `backups/`.

---

## 🤖 Como Usar com Agentes de IA (Antigravity, Claude Code, Grok, Cursor, Copilot)

Este repositório inclui instruções completas em [`AGENTS.md`](AGENTS.md) que os agentes de IA leem e seguem de forma autónoma. Não precisa de correr scripts Python nem executar comandos no terminal manualmente:

Basta abrir o seu Agente de IA favorito (Antigravity, Claude Code, Cursor, Copilot, Grok CLI, etc.) e dar-lhe esta simples instrução:

```text
Faz o clone de https://github.com/Mafarricos/badbox-tv-audit.git e audita a minha Android TV box no IP <IP_DA_TV>.
```
*(Dica: Se não souber o IP da sua TV, substitua `<IP_DA_TV>` por: `...descobre as Android TVs na minha sub-rede 192.168.1.0/24 e audita-as.`)*

O agente tratará de clonar o repositório, ler o ficheiro [`AGENTS.md`](AGENTS.md), preparar o ambiente, executar o diagnóstico rápido e económico (`--quick-scan --json`) e aplicar a remediação segura com backup automático se forem detetadas anomalias.

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

### B. Em Google TV (Android 12, 14 - ex: Chromecast, realme, Thomson, TCL):
1. No canto superior direito da TV, clique na sua foto/perfil -> **Definições (Settings)**.
2. Selecione **Sistema (System)** -> **Acerca de (About)**.
3. Desça até **Versão do SO Android TV (Android TV OS build)**.
4. Carregue **7 vezes seguidas no botão OK do comando** até desbloquear o modo de programador.
5. Volte atrás para **Sistema (System)** -> **Opções do Programador (Developer Options)**.
6. Ative a **Depuração USB (USB Debugging)**.
7. Confirme o pop-up de autorização na TV quando o computador se conectar.

---

## 📺 A App Nativa Android TV (`app/`)

A aplicação deteta o idioma da box automaticamente (em Português se a TV estiver em Português; em Inglês para todos os outros idiomas) e é 100% controlável pelo comando (D-Pad):

1. **Botão 1: ANALISAR BOX (ESTÁTICO):** Varre partições `/oem/`, `/vendor/`, integridade do Play Protect, artefactos de trojans (Vo1d, XCPE) e enumera pacotes instalados em segundos.
2. **Botão 2: MONITORIZAR REDE (VPN):** Sentinela local loopback que alerta em tempo real:
   - **A Vermelho (`[CRÍTICO]`):** Se a box tentar falar com servidores C2 ou portas MQTT/proxy conhecidas.
   - **A Amarelo (`[ANOMALIA]`):** Se houver tráfego anómalo em portas altas enquanto a TV devia estar em repouso.
3. **Botão 3: NEUTRALIZAR AMEAÇAS (Aparece se forem detetadas anomalias):**
   - Inicia a desinstalação guiada das apps da botnet com diálogo direto no ecrã.
   - Abre o atalho para confirmação da reativação do Google Play Protect.
   - Permite voltar a carregar em **"ANALISAR BOX"** imediatamente a seguir para comprovar que o veredito mudou de **`PERIGO [INFETADO]`** para **`DISPOSITIVO LIMPO`**.

---

## 🚀 Utilização da Linha de Comandos (CLI) & Agentes

Pode especificar o idioma pretendido através de `--lang pt` ou `--lang en`:

```bash
# 1. Pipeline 100% Automatizado (Instala APK, scan 5 camadas, sentinela VPN 20s, scoring e limpeza)
python tools/audit_security.py <TV_IP> --auto-pipeline --lang pt

# 2. Diagnóstico Rápido ADB (Apenas Leitura - Normal ou Modo JSON para Agentes)
python tools/audit_security.py <TV_IP> --quick-scan --lang pt
python tools/audit_security.py <TV_IP> --quick-scan --json

# 3. Descobrir e Auditar todas as Android TVs na Rede Local (Sub-rede)
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 4. Remediação Autónoma (Tranca Play Protect, desativa droppers, ativa DNS DoT seguro)
python tools/audit_security.py <TV_IP> --remediate --lang pt

# 5. Restauro Reversível Imediato
python tools/audit_security.py <TV_IP> --restore --lang pt
```

---

## ⚠️ Isenção de Responsabilidade

Este software e ferramentas são disponibilizados estritamente para fins educativos, forenses e de investigação de cibersegurança.

Realizei os testes e validações em **aparelhos pessoais meus**: as ferramentas detetaram com precisão os problemas, neutralizaram as ameaças/backdoors e os aparelhos continuaram a funcionar perfeitamente e sem qualquer anomalia. No entanto, perante a enorme diversidade de fabricantes, firmwares proprietários de operadores e versões modificadas de Android existentes no mercado, **não posso garantir a 100% a eficácia ou compatibilidade total em aparelhos que não tenham sido testados diretamente por mim**.

A utilização desta ferramenta é da exclusiva responsabilidade de quem a executa. Nem o autor nem eventuais colaboradores poderão ser responsabilizados por qualquer comportamento inesperado ou instabilidade decorrente do seu uso. Recomenda-se sempre a salvaguarda dos backups gerados automaticamente na pasta `backups/`.

---

## 👨‍💻 Sobre Mim & Agradecimentos

Olá, sou o **Carlos Correia**! Sou um entusiasta geek e programador que sempre acompanhou e adorou o mundo das TV boxes Android. Ao longo dos anos sempre recomendei ativamente aparelhos certificados Google TV e Android TV pela sua segurança e qualidade.

Foi por isso uma enorme surpresa descobrir a investigação forense recente sobre a **VideoStrong / SZBBOYS (BadBox & XCPE)** e como estas ameaças de cadeia de distribuição conseguiram infiltrar-se em hardware certificado e de grande circulação. Essa descoberta motivou-me a criar este repositório, desenvolvido em estreita colaboração com Agentes de IA, para oferecer a qualquer utilizador ou técnico uma ferramenta transparente, gratuita e acessível para limpar facilmente malwares, trojans e botnets — quer seja diretamente pelo comando da TV, quer seja por linha de comandos com segurança e reversibilidade total.

O conceito estrutural deste script teve por base o excelente projeto [CleanYourTV](https://cleanyour.tv) e assentou na investigação detalhada publicada pela [Synthient](https://synthient.com/blog/the-internals-of-a-badbox-operation), [Eclypsium](https://eclypsium.com/blog/android-tv-devices-pre-0wned-supply-chain-security-threats/) e [Dr.Web](https://vms.drweb.com/bulletin/).

### Apoie o Projeto:
Se esta ferramenta lhe foi útil e deseja apoiar o meu trabalho:
- 📺 **Siga-me e veja os meus vídeos no YouTube:** [@Carlos___Correia](https://www.youtube.com/@Carlos___Correia)
- ⭐ Deixe uma estrela no repositório e partilhe com a comunidade!
