# -*- coding: utf-8 -*-
"""
Internationalization (i18n) module for badbox-tv-audit suite.
Provides English (default) and Portuguese (pt-PT).
"""

import os
import sys

_CURRENT_LANG = "en"

MESSAGES = {
    "en": {
        # General & Banner
        "banner_auto_pipeline": "100% AUTOMATED AUDIT PIPELINE (STATIC + SENTINEL VPN)",
        "banner_target": "Target: {target} | Sentinel Window: {duration} seconds",
        "banner_quick_audit": "QUICK ADB DIAGNOSTIC (5 FORENSIC LAYERS)",
        "banner_remediation": "FORENSIC REMEDIATION & DEFENSIVE HARDENING - ANDROID TV ({target})",
        "banner_restore": "FORENSIC RESTORE / ROLLBACK - ANDROID TV ({target})",
        "banner_scoring": "DETERMINISTIC FORENSIC EVALUATION ENGINE",
        
        # Specs
        "loading_specs": "[*] Loading hardware specifications for {target}...",
        "specs_model": "    - Model: {brand} {model} (Android {ver}, API {sdk})",
        "specs_soc": "    - Vendor/SoC: {vendor} | {board} / {hw}",
        "specs_patch": "    - Security Patch: {patch}",
        
        # Layer 1: Play Protect
        "layer_1_title": "[Layer 1/5] Checking Google Play Protect integrity...",
        "layer_1_crit": "    [!] CRITICAL ALERT: Play Protect was forced OFF (-1)!",
        "layer_1_ok": "    [✓] Play Protect is not disabled.",
        
        # Layer 2: IoCs & Packages
        "layer_2_title": "[Layer 2/5] Scanning installed packages against IoC database...",
        "layer_2_active_threat": "    [!] ACTIVE malicious packages detected: {pkgs}",
        "layer_2_frozen": "    [✓] Suspicious packages detected but NEUTRALIZED / FROZEN: {pkgs}",
        "layer_2_clean": "    [✓] No known botnet packages detected ({count} packages scanned).",
        
        # Layer 3: Build props
        "layer_3_title": "[Layer 3/5] Verifying system properties (Build Props)...",
        "layer_3_suspicious": "    [!] Suspicious properties found: {props}",
        "layer_3_ok": "    [✓] No system properties tampered by BadBox/XCPE.",
        
        # Layer 4: Sockets
        "layer_4_title": "[Layer 4/5] Inspecting active network sockets and C2 connections...",
        "layer_4_c2_found": "    [!] Real-time C2 connection detected: {conn}",
        "layer_4_ok": "    [✓] No active connections to botnet C2 IPs/ports.",
        
        # Layer 5: OEM
        "layer_5_title": "[Layer 5/5] Auditing OEM system APK signatures...",
        "layer_5_total": "    - Total system packages analyzed: {count}",
        "layer_5_ok": "    [✓] System partition sampling complete.",
        
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
        
        # Verdicts
        "score_total": "Total Risk Score: {score} points\n",
        "verdict_crit": "FINAL VERDICT: INFECTED - CRITICAL (Confidence: >99%)",
        "verdict_crit_desc": "Irrefutable evidence of XCPE/BadBox malware found.",
        "verdict_susp": "FINAL VERDICT: SUSPICIOUS (Confidence: 80%)",
        "verdict_susp_desc": "Device shows structural anomalies or unusual network activity.",
        "verdict_clean": "FINAL VERDICT: CLEAN / SAFE (Confidence: >98%)",
        "verdict_clean_desc": "No malicious evidence or botnet activity detected.",
        
        # Automated pipeline
        "pipe_pushing": "\n[*] Transferring and installing TV audit app...",
        "pipe_install_ok": "    [✓] App installed successfully.",
        "pipe_vpn_perm": "\n[*] Granting silent VPN and alert permissions...",
        "pipe_launching": "\n[*] Launching audit app on TV screen...",
        "pipe_running_scan": "\n[*] Triggering deep 5-Layer static analysis...",
        "pipe_sentinel_start": "\n[*] Activating real-time Sentinel VPN (monitoring for {sec}s)...",
        "pipe_sentinel_tick": "    -> Sentinel monitoring network traffic... {remaining}s remaining",
        "pipe_sentinel_done": "\n    [✓] Network traffic monitoring window complete.",
        "pipe_sentinel_stop": "\n[*] Disabling Sentinel VPN...",
        "pipe_pull_report": "\n[*] Transferring reports from TV to computer...",
        "pipe_cleaning": "\n[*] Cleaning up target device...",
        "pipe_uninstall": "\n[*] Uninstalling audit app {pkg} from device...",
        "pipe_complete": "PIPELINE COMPLETED: Verdict = {verdict}",
        "pipe_log_saved": "Full audit log saved to: {log_path}"
    },
    
    "pt": {
        # General & Banner
        "banner_auto_pipeline": "PIPELINE DE AUDITORIA 100% AUTOMATIZADO (ESTÁTICO + SENTINELA VPN)",
        "banner_target": "Alvo: {target} | Janela Sentinela: {duration} segundos",
        "banner_quick_audit": "DIAGNÓSTICO RÁPIDO VIA ADB (5 CAMADAS FORENSES)",
        "banner_remediation": "PLANO DE REMEDIAÇÃO & NEUTRALIZAÇÃO FORENSE - ANDROID TV ({target})",
        "banner_restore": "REVERSÃO / RESTAURO DE SEGURANÇA - ANDROID TV ({target})",
        "banner_scoring": "MOTOR DE AVALIAÇÃO FORENSE DETERMINÍSTICO",
        
        # Specs
        "loading_specs": "[*] A carregar especificações do dispositivo {target}...",
        "specs_model": "    - Modelo: {brand} {model} (Android {ver}, API {sdk})",
        "specs_soc": "    - Fabricante/SoC: {vendor} | {board} / {hw}",
        "specs_patch": "    - Patch de Segurança: {patch}",
        
        # Layer 1: Play Protect
        "layer_1_title": "[Camada 1/5] A verificar integridade do Play Protect...",
        "layer_1_crit": "    [!] ALERTA CRÍTICO: Play Protect foi forçado a desligar (-1)!",
        "layer_1_ok": "    [✓] Play Protect não está forçado a desligar.",
        
        # Layer 2: IoCs & Packages
        "layer_2_title": "[Camada 2/5] A analisar pacotes instalados contra lista de IoCs...",
        "layer_2_active_threat": "    [!] Pacotes maliciosos ATIVOS detetados: {pkgs}",
        "layer_2_frozen": "    [✓] Pacotes suspeitos identificados mas NEUTRALIZADOS / CONGELADOS: {pkgs}",
        "layer_2_clean": "    [✓] Nenhum pacote conhecido de botnet detetado ({count} pacotes analisados).",
        
        # Layer 3: Build props
        "layer_3_title": "[Camada 3/5] A verificar propriedades do sistema (Build Props)...",
        "layer_3_suspicious": "    [!] Propriedades suspeitas: {props}",
        "layer_3_ok": "    [✓] Nenhuma propriedade adulterada por BadBox.",
        
        # Layer 4: Sockets
        "layer_4_title": "[Camada 4/5] A verificar sockets de rede ativos e conexões C2...",
        "layer_4_c2_found": "    [!] Conexão C2 detetada em tempo real: {conn}",
        "layer_4_ok": "    [✓] Nenhuma conexão ativa aos IPs/portas da botnet.",
        
        # Layer 5: OEM
        "layer_5_title": "[Camada 5/5] Amostragem de APKs OEM do sistema...",
        "layer_5_total": "    - Total de pacotes de sistema encontrados: {count}",
        "layer_5_ok": "    [✓] Amostragem concluída.",
        
        # Remediation
        "remediation_backup": "[*] A criar BACKUP de segurança reversível em backups/...",
        "remediation_backup_done": "    [✓] Ficheiro de estado guardado: {filename}",
        "remediation_p1": "\n[Passo 1/4] A restaurar e trancar o Google Play Protect...",
        "remediation_p1_done": "    [✓] Play Protect restaurado com sucesso! Verificação ativa de pacotes.",
        "remediation_p2": "\n[Passo 2/4] A procurar e neutralizar pacotes de botnet, trojans e proxies...",
        "remediation_p2_uninstalled": "        -> Desinstalado com sucesso: {pkg}",
        "remediation_p2_frozen": "        -> App de sistema desativada/congelada: {pkg} ({res})",
        "remediation_p2_none": "    [✓] Nenhum pacote malicioso da botnet encontrado para desinstalar.",
        "remediation_p2_total": "    [✓] Total de pacotes maliciosos neutralizados: {count}",
        "remediation_p3": "\n[Passo 3/4] A terminar processos e serviços em execução da botnet...",
        "remediation_p3_done": "    [✓] Processos residuais terminados.",
        "remediation_p4": "\n[Passo 4/4] A configurar Private DNS seguro na Box (Proteção anti-malware)...",
        "remediation_p4_done": "    [✓] Proteção de DNS ativa: pedidos para servidores C2 serão bloqueados na fonte.",
        "remediation_script_done": "    [✓] Script de reversão gerado com sucesso: {filename}",
        "remediation_success": "REMEDIAÇÃO CONCLUÍDA: A TV foi limpa e o tráfego de botnet bloqueado!",
        
        # Restore
        "restore_loading": "[*] A carregar backup mais recente: {filename}...",
        "restore_p1": "\n[1/2] A repor definições globais originais...",
        "restore_p1_done": "    [✓] Definições restauradas.",
        "restore_p2": "\n[2/2] A reativar pacotes desativados durante a remediação...",
        "restore_p2_pkg": "    [*] A reativar: {pkg}",
        "restore_p2_done": "    [✓] Pacotes reativados.",
        "restore_success": "RESTAURO CONCLUÍDO COM SUCESSO! Dispositivo reposto no estado anterior.",
        
        # Verdicts
        "score_total": "Pontuação de Risco Total: {score} pontos\n",
        "verdict_crit": "VEREDITO FINAL: INFETADO - CRÍTICO (Grau de Certeza: >99%)",
        "verdict_crit_desc": "Foram identificadas evidências irrefutáveis de malware/botnet (XCPE/BadBox).",
        "verdict_susp": "VEREDITO FINAL: SUSPEITO (Grau de Certeza: 80%)",
        "verdict_susp_desc": "A box apresenta anomalias estruturais ou tráfego de rede não habitual em repouso.",
        "verdict_clean": "VEREDITO FINAL: LIMPO / SEGURO (Grau de Certeza: >98%)",
        "verdict_clean_desc": "Nenhuma evidência maliciosa ou conexão à botnet detetada.",
        
        # Automated pipeline
        "pipe_pushing": "\n[*] A transferir e instalar na box...",
        "pipe_install_ok": "    [✓] App instalada com sucesso.",
        "pipe_vpn_perm": "\n[*] A autorizar permissões de VPN e alertas em segundo plano...",
        "pipe_launching": "\n[*] A abrir a App no ecrã da TV...",
        "pipe_running_scan": "\n[*] A disparar Análise Estática profunda (5 Camadas)...",
        "pipe_sentinel_start": "\n[*] A ativar Sentinela VPN em tempo real (à escuta durante {sec}s)...",
        "pipe_sentinel_tick": "    -> Sentinela ativo a monitorizar portas e tráfego... {remaining}s restantes",
        "pipe_sentinel_done": "\n    [✓] Janela de monitorização de tráfego concluída.",
        "pipe_sentinel_stop": "\n[*] A desligar Sentinela VPN...",
        "pipe_pull_report": "\n[*] A transferir os relatórios da box para o computador...",
        "pipe_cleaning": "\n[*] A limpar o dispositivo...",
        "pipe_uninstall": "\n[*] A desinstalar a App {pkg} da box...",
        "pipe_complete": "PIPELINE CONCLUÍDO COM SUCESSO: Veredito = {verdict}",
        "pipe_log_saved": "Registo integral da auditoria guardado em: {log_path}"
    }
}


def set_language(lang_code):
    global _CURRENT_LANG
    if not lang_code:
        _CURRENT_LANG = "en"
    elif lang_code.lower().startswith("pt"):
        _CURRENT_LANG = "pt"
    else:
        _CURRENT_LANG = "en"


def get_language():
    return _CURRENT_LANG


def t(key, **kwargs):
    bundle = MESSAGES.get(_CURRENT_LANG, MESSAGES["en"])
    template = bundle.get(key, MESSAGES["en"].get(key, key))
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template
