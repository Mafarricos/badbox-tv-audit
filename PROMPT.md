# AI Agent Prompt / Prompt para o Agente de IA

> Copy the prompt below into your AI Agent (Antigravity, Claude Code, Cursor, Copilot, Windsurf, Grok, etc.) to start the autonomous audit and cleanup.
>
> *(Copie a prompt abaixo para o seu Agente de IA para iniciar a auditoria e limpeza autónoma.)*

---

### English:

```text
Please read AGENTS.md and audit my Android TV / Google TV box.

Device Information:
- IP Address: <TV_IP> (or scan my local subnet 192.168.1.0/24 if unknown)
- TV Model / Brand: <OPTIONAL_TV_MODEL_OR_BRAND>

Tasks:
1. Verify connectivity and guide me if Developer Options / ADB debugging is not enabled.
2. Run a fast, token-efficient 5-layer audit (--quick-scan --json) checking for BadBox, XCPE, Vo1d trojans, supply-chain backdoors, and residential proxyware.
3. If threats or anomalies are detected, present the findings clearly and perform an autonomous, safe remediation (--remediate) with mandatory snapshot backups and restore scripts.
```

---

### Português (PT):

```text
Por favor lê o ficheiro AGENTS.md e efetua uma auditoria à minha Android TV / Google TV.

Informações do Aparelho:
- Endereço IP: <IP_DA_TV> (ou faz scan à minha sub-rede local 192.168.1.0/24 se não souber o IP)
- Modelo / Marca da TV: <MODELO_OU_MARCA_OPCIONAL>

Objetivos:
1. Valida a ligação ADB e guia-me se o Modo de Programador / Depuração USB ainda não estiver ativo.
2. Executa uma auditoria rápida de 5 camadas otimizada para poupança de tokens (--quick-scan --json) à procura de BadBox, XCPE, trojans Vo1d, backdoors de fábrica e proxyware residencial.
3. Se forem detetadas ameaças ou anomalias, apresenta o diagnóstico de forma clara e aplica a remediação autónoma segura (--remediate), gerando previamente o snapshot de backup e o script de reversão.
```
