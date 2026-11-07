# Suite Forense e Antimalware para Android TV / Google TV (BadBox, XCPE, Vo1d & Remediação)

[![Platform](https://img.shields.io/badge/Platform-Android%20TV%20%7C%20Google%20TV-3DDC84.svg?logo=android)](https://www.android.com/tv/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Suite forense, de remoção de malware e de remediação reversível completa e autónoma (CLI + App nativa Android TV com Sentinela VPN) projetada para auditoria, deteção, verificação, neutralização e restauro de trojans de supply-chain, botnets residenciais e malware (**BadBox**, **XCPE**, **Vo1d**, **Fuyao**, **Videostrong/SZBBOYS** e **Proxyware Residencial**) em dispositivos Android TV, Google TV e TV Boxes genéricas.

> **Idioma:** Português (PT-PT) | [For English version, see README.md](README.md) | [📱 Registo de Aparelhos Testados](DEVICES.md) | [🔬 Estudo Forense (XCPE/com.oemservice)](docs/FORENSIC_XCPE_OEMSERVICE.md)

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

> [!TIP]
> ⚡ **Recomendação para Utilizadores do Google Antigravity:**  
> Se estiver a utilizar o **Antigravity**, configure o modelo para **Gemini 3.8 Flash** com nível de raciocínio em **Low** e ative o modo **Turbo**. Desta forma, o agente executa a auditoria de forma ultrarrápida, consome uma fração mínima de tokens e procede autonomamente sem interromper continuamente o utilizador com pedidos de confirmação desnecessários.

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
   - Inicia a desinstalação guiada das apps da botnet com diálogo direto no ecrã.
   - Abre o atalho para confirmação da reativação do Google Play Protect.
   - Permite voltar a carregar em **"ANALISAR BOX"** imediatamente a seguir para comprovar que o veredito mudou de **`PERIGO [INFETADO]`** para **`DISPOSITIVO LIMPO`**.

---

## 🚀 Utilização da Linha de Comandos (CLI) & Agentes

A suite **deteta automaticamente o idioma do seu sistema operativo** (assume **Português** em sistemas em português, e **Inglês** por omissão internacional). Pode também forçar o idioma desejado com `--lang pt` ou `--lang en`.

### Dois Modos de Auditoria Disponíveis:
- **Diagnóstico Rápido ADB (`--quick-scan`)**: 100% apenas de leitura, demora 5-10 segundos, não instala nada no aparelho. Verifica todas as famílias de ameaças conhecidas (XCPE, BadBox, Vo1d, droppers, sockets C2 e integridade do Play Protect).
- **Diagnóstico Intensivo Sentinela (`--auto-pipeline`)**: Instala a app nativa (`com.scanner.tv`), levanta uma VPN loopback local durante 20-60 segundos para inspecionar tráfego dinâmico de rede/DNS à procura de ameaças desconhecidas ou adormecidas, recolhe relatórios, avalia regras e desinstala automaticamente a app no fim.

```bash
# 1. Diagnóstico Intensivo com App (Instala APK, sentinela VPN 20s para tráfego desconhecido e limpa a box)
python tools/audit_security.py <TV_IP> --auto-pipeline

# 2. Diagnóstico Rápido ADB (Ameaças conhecidas - Normal ou Modo JSON para Agentes)
python tools/audit_security.py <TV_IP> --quick-scan
python tools/audit_security.py <TV_IP> --quick-scan --json

# 3. Classificador de Estágio de Infeção (Diferencia Estágio 1 dropper vs Estágio 2 ativo e payload /oem)
python tools/detect_infection_stage.py <TV_IP>

# 4. Descobrir e Auditar todas as Android TVs na Rede Local (Sub-rede)
python tools/audit_security.py --scan-subnet 192.168.1.0/24

# 5. Remediação Autónoma (Tranca Play Protect, desativa droppers, ativa DNS DoT seguro)
python tools/audit_security.py <TV_IP> --remediate

# 6. Restauro Reversível Imediato
python tools/audit_security.py <TV_IP> --restore

# 7. Forense Avançada / Inspeção de Pacotes (Suporta --lang pt / --lang en)
python tools/deep_forensics.py <TV_IP> --inspect-package <NOME_DO_PACOTE>
```

---

## 📤 Como Contribuir: Submeter Relatórios para o Registo de Aparelhos

Ajude a comunidade a mapear quais os modelos de Android TV e Google TV que trazem droppers de fábrica ou firmwares limpos!

Sempre que realiza uma auditoria (seja via `--quick-scan` ou `--auto-pipeline`), o código **gera automaticamente um relatório sanitizado e anónimo** no ficheiro:
```text
community_audit_submission.json
```

### 🛡️ Garantia Total de Privacidade (Zero Dados Pessoais):
- **Todos os identificadores pessoais são removidos na origem**: Nenhum endereço IP local, nenhum endereço MAC, número de série ou credencial Wi-Fi é incluído.
- Contém **estritamente** dados técnicos de hardware e segurança: Modelo do SoC, versão de firmware, estado do Play Protect, pacotes/hashes maliciosos detetados e portas C2 ativas.

### Como Submeter o Resultado:
1. **Pelo GitHub Issues (Recomendado):**
   - Abra um novo Issue em: [https://github.com/Mafarricos/badbox-tv-audit/issues](https://github.com/Mafarricos/badbox-tv-audit/issues)
   - Título: `[Device Audit] <Marca> <Modelo>` (ex: `[Device Audit] Strong 4K Google TV Stick`)
   - Cole o conteúdo do ficheiro `community_audit_submission.json`.
2. **Por E-mail:**
   - Envie o ficheiro `community_audit_submission.json` diretamente para o e-mail indicado no canal de YouTube: **`mafastudios@gmail.com`** (Assunto: `Auditoria TV: <Marca> <Modelo>`).

O seu relatório será analisado e adicionado à lista pública oficial no [Registo de Aparelhos Testados (DEVICES.md)](DEVICES.md)!

---

## 🔒 Garantia de Segurança e Reversibilidade

Cada ação de remediação cria um snapshot exato em formato JSON em `backups/backup_<IP>_<timestamp>.json` e um script de reversão imediata executável em `backups/restore_<IP>.ps1`. Nada é alterado sem existir um caminho de restauro imediato a um clique.

> [!IMPORTANT]
> **Nota de Persistência (Reposição de Fábrica & Atualizações de Sistema / OTA):**  
> Como os droppers de cadeia de distribuição (como o `com.oemservice` / XCPE) vêm gravados de fábrica pelo fabricante em partições de sistema protegidas (`/system` ou `/vendor`), esta ferramenta mitiga e congela-os ao nível do gestor de pacotes do SO (`pm disable-user`) com total segurança e sem risco de inutilizar o aparelho (*brick*).  
> Por este motivo:
> 1. **Reposição de Fábrica (*Factory Reset*):** Se efetuar uma reposição de valores de fábrica na TV, a partição de dados é limpa e o backdoor do sistema voltará a ficar ativo como veio de fábrica. Terá de executar novamente este script ou a aplicação para voltar a neutralizá-lo.
> 2. **Atualizações de Sistema (OTA do Fabricante):** A mitigação permanece válida até que a própria marca lance uma atualização de firmware que remova em definitivo a ameaça da ROM. Caso a sua box receba uma atualização de sistema, execute o `--quick-scan` para verificar se a marca corrigiu o problema ou se é necessário reaplicar a remediação.

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
