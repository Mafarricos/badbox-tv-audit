# -*- coding: utf-8 -*-
"""
Internationalization (i18n) module for badbox-tv-audit suite.
Provides English (default/fallback) and Portuguese (pt-PT).
Detects OS/environment locale automatically if no flag is passed.
"""

import os
import sys
import locale


def detect_system_language():
    """Detects system or environment language, defaulting to 'en'."""
    env_lang = os.environ.get("TV_LANG") or os.environ.get("LANG", "")
    if env_lang.lower().startswith("pt"):
        return "pt"
    try:
        loc = locale.getdefaultlocale()[0]
        if loc and loc.lower().startswith("pt"):
            return "pt"
    except Exception:
        pass
    return "en"


_CURRENT_LANG = detect_system_language()

MESSAGES = {
    "en": {
        # General & Banner
        "banner_auto_pipeline": "100% AUTOMATED AUDIT PIPELINE (STATIC + SENTINEL VPN)",
        "banner_target": "Target: {target} | Sentinel Window: {duration} seconds",
        "banner_quick_audit": "QUICK ADB DIAGNOSTIC (5 FORENSIC LAYERS)",
        "banner_remediation": "FORENSIC REMEDIATION & DEFENSIVE HARDENING - ANDROID TV ({target})",
        "banner_restore": "FORENSIC RESTORE / ROLLBACK - ANDROID TV ({target})",
        "banner_scoring": "DETERMINISTIC FORENSIC EVALUATION ENGINE",
        "context_warning": "[CONTEXT WARNING] This device model ('{model}') matches records in the Synthient/Eclypsium supply-chain reports.\n                   Performing rigorous technical validation.",
        
        # Specs
        "loading_specs": "[*] Loading hardware specifications for {target}...",
        "specs_model": "    - Model: {brand} {model} (Android {ver}, API {sdk})",
        "specs_soc": "    - Vendor/SoC: {vendor} | {board} / {hw}",
        "specs_patch": "    - Security Patch: {patch}",
        
        # Layer 1: Play Protect
        "layer_1_title": "[Layer 1/6] Checking Google Play Protect integrity...",
        "layer_1_crit": "    [!] CRITICAL ALERT: Play Protect was forced OFF (-1)!",
        "layer_1_ok": "    [✓] Play Protect is not disabled.",
        
        # Layer 2: IoCs & Packages
        "layer_2_title": "[Layer 2/6] Scanning installed packages against IoC database...",
        "layer_2_active_threat": "    [!] ACTIVE malicious packages detected: {pkgs}",
        "layer_2_frozen": "    [✓] Suspicious packages detected but NEUTRALIZED / FROZEN: {pkgs}",
        "layer_2_clean": "    [✓] No known botnet packages detected ({count} packages scanned).",
        
        # Layer 3: Build props & Kill Switches
        "layer_3_title": "[Layer 3/6] Verifying system properties and botnet kill-switches...",
        "layer_3_suspicious": "    [!] Suspicious properties / kill-switches found: {props}",
        "layer_3_ok": "    [✓] No system properties tampered by BadBox/XCPE.",

        # Layer 4: Content Providers & IPC
        "layer_4_title": "[Layer 4/6] Probing hidden Content Providers & IPC interfaces...",
        "layer_4_provider_found": "    [!] UNRESTRICTED Content Provider detected: {uri}",
        "layer_4_ok": "    [✓] No exposed malicious Content Providers detected.",
        
        # Layer 5: Sockets & Network
        "layer_5_title": "[Layer 5/6] Inspecting active network sockets, MQTT and C2 connections...",
        "layer_5_c2_found": "    [!] Real-time C2 connection detected: {conn}",
        "layer_5_ok": "    [✓] No active connections to botnet C2 IPs/ports.",
        
        # Layer 6: Native ELF & Partition Integrity
        "layer_6_title": "[Layer 6/6] Auditing native ELF binaries (.so), OEM payloads & Vo1d persistence...",
        "layer_6_bin_found": "    [!] CRITICAL ALERT: Persistence / backdoor binaries detected: {bins}",
        "layer_6_total": "    - Total system packages analyzed: {count}",
        "layer_6_ok": "    [✓] System partitions & native libraries verified clean.",
        
        # Remediation
        "remediation_backup": "[*] Creating reversible backup snapshot in backups/...",
        "remediation_backup_done": "    [✓] State snapshot saved: {filename}",
        "remediation_p1": "\n[Step 1/4] Restoring and locking Google Play Protect...",
        "remediation_p1_done": "    [✓] Play Protect restored successfully! Package verification active.",
        "remediation_p2": "\n[Step 2/4] Hunting and neutralizing botnet packages and proxies...",
        "remediation_p2_uninstalled": "        -> Uninstalled successfully: {pkg}",
        "remediation_p2_frozen": "        -> System package frozen/disabled: {pkg} ({res})",
        "remediation_p2_none": "    [✓] No botnet packages found to remove.",
        "remediation_p2_total": "    [✓] Total malicious packages neutralized: {count}",
        "remediation_p3": "\n[Step 3/4] Terminating botnet runtime processes and background services...",
        "remediation_p3_done": "    [✓] Residual background processes terminated.",
        "remediation_p4": "\n[Step 4/4] Hardening Private DNS on device (Malware Blocking DoT)...",
        "remediation_p4_done": "    [✓] DNS protection active: C2 server domains blocked at source.",
        "remediation_script_done": "    [✓] Rollback script generated successfully: {filename}",
        "remediation_success": "REMEDIATION COMPLETE: Device cleaned and botnet traffic blocked!",
        
        # Restore
        "restore_loading": "[*] Loading latest backup: {filename}...",
        "restore_p1": "\n[1/2] Restoring original global settings...",
        "restore_p1_done": "    [✓] Settings restored.",
        "restore_p2": "\n[2/2] Re-enabling packages disabled during remediation...",
        "restore_p2_pkg": "    [*] Re-enabling: {pkg}",
        "restore_p2_done": "    [✓] Packages re-enabled.",
        "restore_success": "RESTORE COMPLETE! Device returned to previous state.",
        
        # Subnet scan
        "subnet_searching": "[*] Scanning for Android TV devices on subnet {cidr} (port 5555)...",
        "subnet_found": "[✓] Found {count} device(s) with ADB: {devices}",
        "subnet_none": "[!] No devices found with port 5555 open on {cidr}.",
        
        # Verdicts
        "score_total": "Total Risk Score: {score} points\n",
        "verdict_crit": "FINAL VERDICT: INFECTED - CRITICAL (Confidence: >99%)",
        "verdict_crit_desc": "Irrefutable evidence of supply-chain malware/botnet (XCPE/BadBox/Vo1d) found.",
        "verdict_susp": "FINAL VERDICT: SUSPICIOUS (Confidence: 80%)",
        "verdict_susp_desc": "Device exhibits structural anomalies or abnormal idle background traffic.",
        "verdict_clean": "FINAL VERDICT: CLEAN / SAFE (Confidence: >98%)",
        "verdict_clean_desc": "No malicious evidence, botnet sockets, or dropper components detected.",
        
        # Automated pipeline
        "pipe_pushing": "\n[*] Transferring and installing on TV...",
        "pipe_install_ok": "    [✓] App installed successfully.",
        "pipe_vpn_perm": "\n[*] Granting VPN permissions and background alerts...",
        "pipe_launching": "\n[*] Launching App on TV screen...",
        "pipe_running_scan": "\n[*] Triggering deep Static Scan (5 Layers)...",
        "pipe_sentinel_start": "\n[*] Activating real-time Sentinel VPN (listening for {sec}s)...",
        "pipe_sentinel_tick": "    -> Sentinel active monitoring ports & traffic... {remaining}s remaining",
        "pipe_sentinel_done": "\n    [✓] Network traffic monitoring window complete.",
        "pipe_sentinel_stop": "\n[*] Disabling Sentinel VPN...",
        "pipe_pull_report": "\n[*] Pulling device reports to computer...",
        "pipe_cleaning": "\n[*] Cleaning up device...",
        "pipe_uninstall": "\n[*] Uninstalling App {pkg} from TV...",
        "pipe_complete": "PIPELINE COMPLETED SUCCESSFULLY: Verdict = {verdict}",
        "pipe_log_saved": "Full audit log saved to: {log_path}",
        
        # Interactive Menu
        "menu_header": "       XCPE / BADBOX / VO1D FORENSIC SUITE - Android TV ({target})       ",
        "menu_section_auto": "  --- AUTOMATED EXECUTION ---",
        "menu_opt_1": "  1. 100% Automated Pipeline (Fast Universal APK)",
        "menu_opt_2": "  2. 100% Automated Pipeline (Force ON-DEMAND RECOMPILATION for device)",
        "menu_section_diag": "  --- DIAGNOSTICS & MANUAL APP INSTALLATION ---",
        "menu_opt_3": "  3. Fast 6-Layer ADB Scan (Read-Only, No App Installed)",
        "menu_opt_4": "  4. Install App on TV (Choice: Prebuilt Universal or Custom Recompile)",
        "menu_opt_5": "  5. Launch App on TV Screen",
        "menu_opt_6": "  6. Pull Report (JSON + VPN Log) and Run Rules Engine",
        "menu_opt_7": "  7. Uninstall App from TV (Forensic Clean)",
        "menu_section_rem": "  --- REMEDIATION & ROLLBACK (REVERSIBLE) ---",
        "menu_opt_8": "  8. Neutralize / Remediate TV (Lock Play Protect, Freeze Bots, Enable Secure DNS)",
        "menu_opt_9": "  9. Revert Remediation / Restore Previous State (From Backup)",
        "menu_section_cfg": "  --- CONFIGURATION & PREREQUISITES ---",
        "menu_opt_10": " 10. Manage / Install Prerequisites & Toolchains (Python / JDK / SDK)",
        "menu_opt_11": " 11. Change Target TV IP",
        "menu_opt_0": "  0. Exit",
        "menu_choice_prompt": "Select an option [0-11]: ",
        "menu_press_enter": "\nPress ENTER to continue...",
        "menu_new_ip_prompt": "New TV IP address: ",
        "menu_exit_msg": "\nEnding session. Device security guaranteed!",
        "menu_invalid_opt": "[!] Invalid option. Please try again.",
        
        # Deep Forensics
        "forensics_inspecting": "\n[*] Inspecting package: {pkg} on {target}...",
        "forensics_pm_path": "    - Package path (pm path): {path}",
        "forensics_not_found": "Not found",
        "forensics_dumpsys_hdr": "\n--- PACKAGE DETAILS (Dumpsys) ---",
        "forensics_components_hdr": "\n--- DECLARED COMPONENTS (Receivers / Services) ---",
        "forensics_state_hdr": "\n--- ACTIVATION STATE (pm list packages -d / -e) ---",
        "forensics_disabled": "    - Disabled (disabled-user / disabled): {state}",
        "forensics_enabled": "    - Enabled: {state}",
        "forensics_user_state_hdr": "\n--- USER STATE BLOCK (Dumpsys Package) ---"
    },
    "pt": {
        # Geral & Banner
        "banner_auto_pipeline": "PIPELINE 100% AUTOMATIZADO (ESTÁTICO + SENTINELA VPN)",
        "banner_target": "Alvo: {target} | Janela Sentinela: {duration} segundos",
        "banner_quick_audit": "DIAGNÓSTICO RÁPIDO VIA ADB (6 CAMADAS FORENSES)",
        "banner_remediation": "PLANO DE REMEDIAÇÃO & NEUTRALIZAÇÃO FORENSE - ANDROID TV ({target})",
        "banner_restore": "RESTAURO REVERSÍVEL FORENSE - ANDROID TV ({target})",
        "banner_scoring": "MOTOR DETERMINÍSTICO DE AVALIAÇÃO FORENSE",
        "context_warning": "[AVISO DE CONTEXTO] Este modelo ('{model}') coincide com linhas documentadas no relatório Synthient/Eclypsium.\n                   Será feita uma verificação rigorosa de evidências técnicas.",
        
        # Especificações
        "loading_specs": "[*] A carregar especificações do dispositivo {target}...",
        "specs_model": "    - Modelo: {brand} {model} (Android {ver}, API {sdk})",
        "specs_soc": "    - Fabricante/SoC: {vendor} | {board} / {hw}",
        "specs_patch": "    - Patch de Segurança: {patch}",
        
        # Camada 1: Play Protect
        "layer_1_title": "[Camada 1/6] A verificar integridade do Google Play Protect...",
        "layer_1_crit": "    [!] ALERTA CRÍTICO: O Play Protect foi forçado a desligar (-1)!",
        "layer_1_ok": "    [✓] Play Protect não está desativado.",
        
        # Camada 2: IoCs e Pacotes
        "layer_2_title": "[Camada 2/6] A verificar pacotes instalados contra a base de IoCs...",
        "layer_2_active_threat": "    [!] Pacotes maliciosos ATIVOS detetados: {pkgs}",
        "layer_2_frozen": "    [✓] Pacotes suspeitos detetados mas CONGELADOS / INATIVOS: {pkgs}",
        "layer_2_clean": "    [✓] Nenhum pacote conhecido de botnet detetado ({count} analisados).",
        
        # Camada 3: Build props & Kill Switches
        "layer_3_title": "[Camada 3/6] A verificar propriedades de sistema e kill-switches...",
        "layer_3_suspicious": "    [!] Propriedades suspeitas / kill-switches detetados: {props}",
        "layer_3_ok": "    [✓] Nenhuma propriedade adulterada por BadBox/XCPE.",

        # Camada 4: Content Providers & IPC
        "layer_4_title": "[Camada 4/6] A sondar Content Providers ocultos e canais IPC...",
        "layer_4_provider_found": "    [!] Content Provider ABERTO detetado: {uri}",
        "layer_4_ok": "    [✓] Nenhum Content Provider malicioso exposto detetado.",
        
        # Camada 5: Sockets & Rede
        "layer_5_title": "[Camada 5/6] A verificar sockets de rede ativos, MQTT e conexões C2...",
        "layer_5_c2_found": "    [!] Conexão em tempo real ao C2 detetada: {conn}",
        "layer_5_ok": "    [✓] Nenhuma conexão ativa aos IPs/portas da botnet.",
        
        # Camada 6: Binários Nativos ELF & Partições
        "layer_6_title": "[Camada 6/6] Auditoria a binários nativos ELF (.so), payloads OEM e persistência Vo1d...",
        "layer_6_bin_found": "    [!] ALERTA CRÍTICO: Ficheiros de persistência / backdoors detetados: {bins}",
        "layer_6_total": "    - Total de pacotes de sistema encontrados: {count}",
        "layer_6_ok": "    [✓] Partições de sistema e bibliotecas nativas verificadas limpas.",
        
        # Remediação
        "remediation_backup": "[*] A criar BACKUP de segurança reversível em backups/...",
        "remediation_backup_done": "    [✓] Ficheiro de estado guardado: {filename}",
        "remediation_p1": "\n[Passo 1/4] A restaurar e trancar o Google Play Protect...",
        "remediation_p1_done": "    [✓] Play Protect restaurado com sucesso! Verificação ativa de pacotes.",
        "remediation_p2": "\n[Passo 2/4] A procurar e neutralizar pacotes de botnet, trojans e proxies...",
        "remediation_p2_uninstalled": "        -> Desinstalada com sucesso: {pkg}",
        "remediation_p2_frozen": "        -> App de sistema desativada/congelada: {pkg} ({res})",
        "remediation_p2_none": "    [✓] Nenhuma app de botnet para remover.",
        "remediation_p2_total": "    [✓] Total de pacotes maliciosos neutralizados: {count}",
        "remediation_p3": "\n[Passo 3/4] A terminar processos e serviços em execução da botnet...",
        "remediation_p3_done": "    [✓] Processos residuais terminados.",
        "remediation_p4": "\n[Passo 4/4] A configurar Private DNS seguro na Box (Proteção anti-malware)...",
        "remediation_p4_done": "    [✓] Proteção de DNS ativa: pedidos para servidores C2 serão bloqueados na fonte.",
        "remediation_script_done": "    [✓] Script de reversão gerado com sucesso: {filename}",
        "remediation_success": "REMEDIAÇÃO CONCLUÍDA: A TV foi limpa e o tráfego de botnet bloqueado!",
        
        # Restauro
        "restore_loading": "[*] A carregar último backup: {filename}...",
        "restore_p1": "\n[1/2] A restaurar definições globais originais...",
        "restore_p1_done": "    [✓] Definições repostas.",
        "restore_p2": "\n[2/2] A reativar pacotes congelados na remediação...",
        "restore_p2_pkg": "    [*] A reativar: {pkg}",
        "restore_p2_done": "    [✓] Pacotes reativados.",
        "restore_success": "RESTAURO CONCLUÍDO COM SUCESSO! Dispositivo reposto no estado anterior.",
        
        # Varrimento de Sub-rede
        "subnet_searching": "[*] A pesquisar dispositivos Android TV na sub-rede {cidr} (porta 5555)...",
        "subnet_found": "[✓] Foram encontrados {count} dispositivo(s) com ADB: {devices}",
        "subnet_none": "[!] Nenhum dispositivo encontrado com porta 5555 aberta em {cidr}.",
        
        # Vereditos
        "score_total": "Pontuação de Risco Total: {score} pontos\n",
        "verdict_crit": "VEREDITO FINAL: INFETADO - CRÍTICO (Grau de Certeza: >99%)",
        "verdict_crit_desc": "Foram identificadas evidências irrefutáveis de malware/botnet (XCPE/BadBox/Vo1d).",
        "verdict_susp": "VEREDITO FINAL: SUSPEITO (Grau de Certeza: 80%)",
        "verdict_susp_desc": "A box apresenta anomalias estruturais ou tráfego de rede não habitual em repouso.",
        "verdict_clean": "VEREDITO FINAL: LIMPO / SEGURO (Grau de Certeza: >98%)",
        "verdict_clean_desc": "Nenhuma evidência maliciosa ou conexão à botnet detetada.",
        
        # Pipeline automatizado
        "pipe_pushing": "\n[*] A transferir e instalar na box...",
        "pipe_install_ok": "    [✓] App instalada com sucesso.",
        "pipe_vpn_perm": "\n[*] A autorizar permissões de VPN e alertas em segundo plano...",
        "pipe_launching": "\n[*] A abrir a App no ecrã da TV...",
        "pipe_running_scan": "\n[*] A disparar Análise Estática profunda (6 Camadas)...",
        "pipe_sentinel_start": "\n[*] A ativar Sentinela VPN em tempo real (à escuta durante {sec}s)...",
        "pipe_sentinel_tick": "    -> Sentinela ativo a monitorizar portas e tráfego... {remaining}s restantes",
        "pipe_sentinel_done": "\n    [✓] Janela de monitorização de tráfego concluída.",
        "pipe_sentinel_stop": "\n[*] A desligar Sentinela VPN...",
        "pipe_pull_report": "\n[*] A transferir os relatórios da box para o computador...",
        "pipe_cleaning": "\n[*] A limpar o dispositivo...",
        "pipe_uninstall": "\n[*] A desinstalar a App {pkg} da box...",
        "pipe_complete": "PIPELINE CONCLUÍDO COM SUCESSO: Veredito = {verdict}",
        "pipe_log_saved": "Registo integral da auditoria guardado em: {log_path}",
        
        # Menu Interativo
        "menu_header": "       XCPE / BADBOX / VO1D FORENSIC SUITE - Android TV ({target})       ",
        "menu_section_auto": "  --- EXECUÇÃO AUTOMATIZADA ---",
        "menu_opt_1": "  1. Pipeline 100% Automatizado (Usa APK Universal - Rápido)",
        "menu_opt_2": "  2. Pipeline 100% Automatizado (Força RECOMPILAÇÃO no momento para a box)",
        "menu_section_diag": "  --- DIAGNÓSTICO E INSTALAÇÃO MANUAL ---",
        "menu_opt_3": "  3. Diagnóstico Rápido ADB (6 Camadas - Apenas Leitura, Sem Instalar)",
        "menu_opt_4": "  4. Instalar App na Box (Opção de Escolher: APK Existente ou Recompilar)",
        "menu_opt_5": "  5. Abrir App no Ecrã da TV",
        "menu_opt_6": "  6. Descarregar Relatório (JSON + Log VPN) e Avaliar Regras",
        "menu_opt_7": "  7. Desinstalar App da Box (Limpeza Forense)",
        "menu_section_rem": "  --- REMEDIAÇÃO E RESTAURO (REVERSÍVEL) ---",
        "menu_opt_8": "  8. Neutralizar / Limpar Box (Repõe Play Protect, Desativa Bots e Ativa DNS Seguro)",
        "menu_opt_9": "  9. Reverter Remediação / Restaurar Estado Anterior (Usar Backup)",
        "menu_section_cfg": "  --- CONFIGURAÇÃO E PRÉ-REQUISITOS ---",
        "menu_opt_10": " 10. Gerir / Instalar Pré-Requisitos e Toolchains (Python / JDK / SDK)",
        "menu_opt_11": " 11. Mudar IP da Box",
        "menu_opt_0": "  0. Sair",
        "menu_choice_prompt": "Escolha uma opção [0-11]: ",
        "menu_press_enter": "\nPrima ENTER para continuar...",
        "menu_new_ip_prompt": "Novo IP: ",
        "menu_exit_msg": "\nA terminar sessão. Segurança garantida!",
        "menu_invalid_opt": "[!] Opção inválida. Tente novamente.",
        
        # Deep Forensics
        "forensics_inspecting": "\n[*] A inspecionar pacote: {pkg} em {target}...",
        "forensics_pm_path": "    - Caminho (pm path): {path}",
        "forensics_not_found": "Não encontrado",
        "forensics_dumpsys_hdr": "\n--- DADOS PRINCIPAIS DO PACOTE (Dumpsys) ---",
        "forensics_components_hdr": "\n--- COMPONENTES DECLARADOS (Receivers / Services) ---",
        "forensics_state_hdr": "\n--- ESTADO DE ATIVAÇÃO (pm list packages -d / -e) ---",
        "forensics_disabled": "    - Desativado (disabled-user / disabled): {state}",
        "forensics_enabled": "    - Ativo (enabled): {state}",
        "forensics_user_state_hdr": "\n--- BLOCO USER STATE (Dumpsys Package) ---"
    }
}


def set_language(lang_code):
    """Sets the active language code ('en' or 'pt')."""
    global _CURRENT_LANG
    if not lang_code:
        _CURRENT_LANG = detect_system_language()
    elif lang_code.lower().startswith("pt"):
        _CURRENT_LANG = "pt"
    else:
        _CURRENT_LANG = "en"


def get_language():
    """Returns the current active language code ('en' or 'pt')."""
    return _CURRENT_LANG


def t(key, **kwargs):
    """Translates a message key according to the active language."""
    bundle = MESSAGES.get(_CURRENT_LANG, MESSAGES["en"])
    template = bundle.get(key, MESSAGES["en"].get(key, key))
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template
