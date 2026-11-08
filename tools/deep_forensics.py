# -*- coding: utf-8 -*-
"""
Deep Forensics & Reverse Engineering Utility for Android TV.
Dedicated tool for inspecting suspicious packages, system partitions, APK dex strings, and dropper mechanisms.

Usage:
  python tools/deep_forensics.py <IP> --inspect-package <PACKAGE_NAME>
  python tools/deep_forensics.py <IP> --pull-and-analyze <REMOTE_APK_PATH>
  python tools/deep_forensics.py <IP> --scan-oem-droppers
  python tools/deep_forensics.py <IP> --dump-network-state
"""

import sys
import os
import re
import json
import zipfile
import argparse
import hashlib

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from audit_security import AdbDevice
from i18n import t, set_language


def inspect_package(adb, package_name):
    print(t("forensics_inspecting", pkg=package_name, target=adb.host))
    path = adb.run(f"pm path {package_name}").strip()
    print(t("forensics_pm_path", path=(path or t("forensics_not_found"))))
    
    dumpsys = adb.run(f"dumpsys package {package_name}")
    print(t("forensics_dumpsys_hdr"))
    for line in dumpsys.splitlines():
        if any(k in line for k in ["userId", "sharedUser", "versionName", "versionCode", "codePath", "flags=", "timeStamp=", "firstInstallTime", "installerPackage"]):
            print(f"    {line.strip()}")
            
    print(t("forensics_components_hdr"))
    for line in dumpsys.splitlines():
        if any(k in line for k in ["Receiver", "Service", "BOOT_COMPLETED", "UpgradeService", "BootReceiver"]):
            print(f"    {line.strip()}")

    print(t("forensics_state_hdr"))
    d_list = adb.run("pm list packages -d")
    e_list = adb.run("pm list packages -e")
    is_disabled = any(l.strip() == f"package:{package_name}" for l in d_list.splitlines())
    is_enabled = any(l.strip() == f"package:{package_name}" for l in e_list.splitlines())
    print(t("forensics_disabled", state=is_disabled))
    print(t("forensics_enabled", state=is_enabled))

    print("\n--- BLOCO USER STATE (Dumpsys Package) ---")
    in_user_block = False
    for line in dumpsys.splitlines():
        if "User 0:" in line or "User " in line:
            in_user_block = True
        if in_user_block:
            print(f"    {line.strip()}")
            if "hidden=" in line or "stopped=" in line or "enabled=" in line:
                break


def pull_and_analyze_apk(adb, remote_apk_path, local_dest=None):
    if not local_dest:
        dev_id = getattr(adb, "device_id", adb.host).replace(":", "_")
        dest_dir = os.path.join(PROJECT_ROOT, "backups", dev_id, "quarantine")
        os.makedirs(dest_dir, exist_ok=True)
        base = os.path.basename(remote_apk_path)
        local_dest = os.path.join(dest_dir, f"{base}.quarantined")

    print(f"\n[*] A descarregar APK da TV: {remote_apk_path} -> {local_dest}...")
    success = adb.pull(remote_apk_path, local_dest)
    if not success or not os.path.exists(local_dest):
        print(f"[!] Falha ao descarregar {remote_apk_path}")
        return

    with open(local_dest, "rb") as f:
        sha256_hash = hashlib.sha256(f.read()).hexdigest()
    with open(f"{local_dest}.sha256", "w", encoding="utf-8") as f:
        f.write(f"{sha256_hash}  {os.path.basename(local_dest)}\n")

    size = os.path.getsize(local_dest)
    print(f"    [✓] Descarregado e em quarentena ({size} bytes, SHA256: {sha256_hash[:16]}...).")
    
    print("\n--- ANALISE DE ESTRUTURA DO APK ---")
    try:
        with zipfile.ZipFile(local_dest, "r") as z:
            names = z.namelist()
            print(f"    Ficheiros no APK: {names}")
            
            dex_files = [n for n in names if n.endswith(".dex")]
            for dex in dex_files:
                raw = z.read(dex)
                strings = re.findall(b'[\x20-\x7e]{4,}', raw)
                clean_strings = [s.decode("latin1") for s in strings]
                
                print(f"\n    [+] Strings suspeitas em {dex} (Classes, URLs, Comandos):")
                keywords = [
                    "http://", "https://", "x.cpe", "xcpe", "BootReceiver", "UpgradeService", 
                    "PackageInstaller", "execInstall", "persist.sys", "titannet", "getgrass", 
                    "traffmonetizer", "oem", "startForegroundService", "ycxrl", "corejava",
                    "vo1d", "adups", "netnut", "popanet", "neunative", "alphasdk", "lumiapps",
                    "install-recovery", "daemon", "watchdog"
                ]
                found = set()
                for s in clean_strings:
                    if any(k.lower() in s.lower() for k in keywords):
                        found.add(s)
                for f_str in sorted(list(found)):
                    print(f"        -> {f_str}")
    except Exception as e:
        print(f"[!] Erro ao analisar APK: {e}")


def scan_oem_droppers(adb):
    print(f"\n[*] A pesquisar vestigios de droppers / backdoors em particoes do sistema ({adb.host})...")
    find_cmd = "find /system /vendor /product /system_ext /oem /data/google /data/system -iname '*xcpe*' -o -iname '*titan*' -o -iname '*grass*' -o -iname '*yoka*' -o -iname '*vo1d*' -o -iname '*corejava*' 2>/dev/null"
    out = adb.run(find_cmd)
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    if lines:
        print("    [!] Foram detetados ficheiros suspeitos:")
        for l in lines:
            print(f"        -> {l}")
    else:
        print("    [✓] Nenhum ficheiro com assinaturas conhecidas encontrado nas particoes do sistema.")

    print("\n[*] Conteudo da particao /oem:")
    oem_ls = adb.run("ls -la /oem 2>/dev/null")
    for l in oem_ls.splitlines():
        print(f"    {l}")


def dump_network_state(adb):
    print(f"\n[*] A inspecionar conexões e sockets de rede ativos em {adb.host}...")
    netstat = adb.run("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null")
    print(netstat)

    print("\n[*] A inspecionar sockets com associação de processo (PID / Programa)...")
    netstat_proc = adb.run("ss -tanp 2>/dev/null || netstat -tanp 2>/dev/null")
    if netstat_proc.strip():
        print(netstat_proc)

    print("\n[*] Processos nativos fora do runtime Zygote (root / system / adb):")
    ps_out = adb.run("ps -ef 2>/dev/null || ps 2>/dev/null")
    non_zygote_count = 0
    for line in ps_out.splitlines():
        if any(b in line for b in ["/system/bin/", "/vendor/bin/", "/data/local/tmp/", "wd", "vo1d", "corejava", "titannet", "linkfog", "oemservice"]):
            if not any(ign in line for ign in ["zygote", "adbd", "logd", "servicemanager", "hwservicemanager", "vndservicemanager"]):
                print(f"    -> {line.strip()}")
                non_zygote_count += 1
    if non_zygote_count == 0:
        print("    [✓] Nenhum processo nativo anómalo detetado.")


def scan_init_watchdogs(adb):
    from audit_security import scan_init_watchdogs as _scan_watchdogs
    return _scan_watchdogs(adb)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep Forensics Utility for Android TV")
    parser.add_argument("target", help="IP do dispositivo Android TV / Target TV IP")
    parser.add_argument("--lang", choices=["en", "pt"], default=None, help="Idioma das mensagens / Language (en or pt)")
    parser.add_argument("--inspect-package", metavar="PKG", help="Inspeciona pacote em detalhe (path, UID, permissoes, componentes)")
    parser.add_argument("--pull-and-analyze", metavar="PATH", help="Descarrega e faz engenharia reversa das strings do APK")
    parser.add_argument("--scan-oem-droppers", action="store_true", help="Pesquisa ficheiros suspeitos em /system, /vendor, /oem")
    parser.add_argument("--scan-init-watchdogs", action="store_true", help="Inspeciona scripts init.rc e binários não-standard à procura de persistências de watchdogs")
    parser.add_argument("--dump-network-state", action="store_true", help="Lista portas em escuta, ligacoes ativas e correlaciona com processos")

    args = parser.parse_args()
    if args.lang:
        set_language(args.lang)
    adb = AdbDevice(args.target)

    if args.inspect_package:
        inspect_package(adb, args.inspect_package)
    elif args.pull_and_analyze:
        pull_and_analyze_apk(adb, args.pull_and_analyze)
    elif args.scan_oem_droppers:
        scan_oem_droppers(adb)
    elif args.scan_init_watchdogs:
        scan_init_watchdogs(adb)
    elif args.dump_network_state:
        dump_network_state(adb)
    else:
        # Se nenhum argumento especifico for passado, executa analise forense profunda completa
        scan_oem_droppers(adb)
        scan_init_watchdogs(adb)
        dump_network_state(adb)
