#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ferramenta Forense: Detetor de Estágio de Infeção XCPE / BadBox (Fase 1 vs Fase 2)
Inspeciona em detalhe se o dropper de fábrica foi sobreposto por uma carga ativa em /data/app,
quais os processos em execução e se existem alarmes agendados.
"""

import sys
import os
import argparse

# Garante acesso aos módulos internos de audit_security
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from audit_security import AdbDevice

TARGET_PACKAGES = [
    "com.oemservice",
    "x.cpe",
    "com.abc.nexus",
    "io.popanet",
    "gaganode",
    "appsalt",
    "traffmonetizer"
]

def analyze_device_infection_stage(host):
    print("=" * 80)
    print(f"  ANÁLISE DE ESTÁGIO DE INFEÇÃO FORENSE (XCPE / BADBOX) - {host}")
    print("=" * 80)
    
    adb = AdbDevice(host)
    adb.load_specs()
    
    print(f"\n[*] Dispositivo: {adb.specs.get('brand')} {adb.specs.get('model')} (Android {adb.specs.get('android_version')})")
    print(f"[*] Fabricante / Board: {adb.specs.get('manufacturer')} | {adb.specs.get('board')}")
    print("-" * 80)

    found_any = False

    for pkg in TARGET_PACKAGES:
        path_out = adb.run(f"pm path {pkg}").strip()
        if not path_out:
            continue
            
        found_any = True
        apk_paths = [p.replace("package:", "").strip() for p in path_out.splitlines()]
        
        # 1. Dumpsys Package Details
        dumpsys_pkg = adb.run(f"dumpsys package {pkg}")
        version_name = "Desconhecido"
        version_code = "Desconhecido"
        enabled_state = "Ativo"
        hidden_system = False
        
        for line in dumpsys_pkg.splitlines():
            sline = line.strip()
            if sline.startswith("versionName="):
                version_name = sline.split("=", 1)[1]
            elif sline.startswith("versionCode="):
                version_code = sline.split("=", 1)[1].split()[0]
            elif "enabled=" in sline:
                if "enabled=3" in sline or "disabled-user" in sline:
                    enabled_state = "CONGELADO (disabled-user)"
                elif "enabled=2" in sline:
                    enabled_state = "DESATIVADO (disabled)"
            if "Hidden system package:" in sline:
                hidden_system = True

        # 2. Processos Ativos em Memória
        ps_out = adb.run(f"ps -ef 2>/dev/null || ps 2>/dev/null")
        active_procs = [l.strip() for l in ps_out.splitlines() if pkg in l and "grep" not in l]

        # 3. Alarmes / Jobs Agendados
        alarm_out = adb.run(f"dumpsys alarm 2>/dev/null | grep -i {pkg}")
        has_alarms = bool(alarm_out.strip())
        
        # Inspeciona se existem tarefas agendadas específicas (JOB #... pacote)
        job_out = adb.run(f"dumpsys jobscheduler 2>/dev/null | grep -E 'JOB #.*{pkg}'")
        has_jobs = bool(job_out.strip())

        # 4. Verificação de Payload pré-carregado na partição /oem
        oem_payload_out = adb.run("ls -la /oem/app_xcpe_ext_sign 2>/dev/null")
        has_oem_payload = "app_xcpe_ext_sign" in oem_payload_out

        # Classificação de Estágio
        is_in_data = any("/data/app" in p for p in apk_paths)
        is_in_system = any("/system" in p or "/priv-app" in p for p in apk_paths)

        print(f"\n[!] PACOTE DETETADO: {pkg}")
        print(f"    - Estado Operacional: {enabled_state}")
        print(f"    - Versão Ativa:       v{version_name} (Code: {version_code})")
        print(f"    - Ficheiros no Disco: {', '.join(apk_paths)}")
        if has_oem_payload:
            print("    [📦] PAYLOAD OEM EM DISCO: /oem/app_xcpe_ext_sign detetado (Stage 2 pré-carregado de fábrica!)")
        
        if is_in_data:
            print("    [🚨] ESTÁGIO 2 (BOTNET ATIVA): Carga descarregada em /data/app!")
            if hidden_system:
                print("         -> Sobrepõe a versão original de fábrica da partição /system.")
        elif is_in_system:
            if has_oem_payload:
                print("    [⚠️] ESTÁGIO 1+ (BOMBA-RELÓGIO): Dropper presente em /system e payload pronto em /oem!")
            else:
                print("    [⚠️] ESTÁGIO 1 (DROPPER DORMENTE DE FÁBRICA): Presente em /system/priv-app.")
                print("         -> Ainda não descarregou a sobreposição da Fase 2 para /data/app.")

        if active_procs:
            print(f"    [🔥] PROCESSOS EM MEMÓRIA ATIVOS ({len(active_procs)}):")
            for pr in active_procs:
                print(f"         * {pr}")
        else:
            print("    [✓] Nenhum processo deste pacote em execução de momento.")

        if has_alarms or has_jobs:
            print(f"    [⏰] AGENDAMENTO DE PERSISTÊNCIA: Alarmes ({has_alarms}) | Jobs ({has_jobs})")
        else:
            print("    [✓] Nenhum alarme ou JobScheduler agendado.")

    if not found_any:
        print("\n[✓] Nenhum pacote conhecido de botnet/dropper instalado no dispositivo.")

    print("\n" + "=" * 80 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detetor de Estágio de Infeção XCPE / BadBox (Fase 1 vs Fase 2)")
    parser.add_argument("host", help="Endereço IP do dispositivo Android TV (ex: 192.168.1.118)")
    args = parser.parse_args()
    
    analyze_device_infection_stage(args.host)
