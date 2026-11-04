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

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from audit_security import AdbDevice


def inspect_package(adb, package_name):
    print(f"\n[*] A inspecionar pacote: {package_name} em {adb.host}...")
    path = adb.run(f"pm path {package_name}").strip()
    print(f"    - Caminho (pm path): {path or 'Nao encontrado'}")
    
    dumpsys = adb.run(f"dumpsys package {package_name}")
    print("\n--- DADOS PRINCIPAIS DO PACOTE (Dumpsys) ---")
    for line in dumpsys.splitlines():
        if any(k in line for k in ["userId", "sharedUser", "versionName", "versionCode", "codePath", "flags=", "timeStamp=", "firstInstallTime", "installerPackage"]):
            print(f"    {line.strip()}")
            
    print("\n--- COMPONENTES DECLARADOS (Receivers / Services) ---")
    for line in dumpsys.splitlines():
        if any(k in line for k in ["Receiver", "Service", "BOOT_COMPLETED", "UpgradeService", "BootReceiver"]):
            print(f"    {line.strip()}")


def pull_and_analyze_apk(adb, remote_apk_path, local_dest=None):
    if not local_dest:
        dest_dir = os.path.join(PROJECT_ROOT, "scratch", "pulled")
        os.makedirs(dest_dir, exist_ok=True)
        local_dest = os.path.join(dest_dir, os.path.basename(remote_apk_path))

    print(f"\n[*] A descarregar APK da TV: {remote_apk_path} -> {local_dest}...")
    success = adb.pull(remote_apk_path, local_dest)
    if not success or not os.path.exists(local_dest):
        print(f"[!] Falha ao descarregar {remote_apk_path}")
        return

    size = os.path.getsize(local_dest)
    print(f"    [✓] Descarregado com sucesso ({size} bytes).")
    
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
                keywords = ["http://", "https://", "x.cpe", "xcpe", "BootReceiver", "UpgradeService", 
                            "PackageInstaller", "execInstall", "persist.sys", "titannet", "getgrass", 
                            "traffmonetizer", "oem", "startForegroundService"]
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
    find_cmd = "find /system /vendor /product /system_ext /oem -iname '*xcpe*' -o -iname '*titan*' -o -iname '*grass*' -o -iname '*yoka*' 2>/dev/null"
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
    print(f"\n[*] A inspecionar conexoes e sockets de rede ativos em {adb.host}...")
    netstat = adb.run("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null")
    print(netstat)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep Forensics Utility for Android TV")
    parser.add_argument("target", help="IP do dispositivo Android TV")
    parser.add_argument("--inspect-package", metavar="PKG", help="Inspeciona pacote em detalhe (path, UID, permissoes, componentes)")
    parser.add_argument("--pull-and-analyze", metavar="PATH", help="Descarrega e faz engenharia reversa das strings do APK")
    parser.add_argument("--scan-oem-droppers", action="store_true", help="Pesquisa ficheiros suspeitos em /system, /vendor, /oem")
    parser.add_argument("--dump-network-state", action="store_true", help="Lista portas em escuta e ligacoes ativas")

    args = parser.parse_args()
    adb = AdbDevice(args.target)

    if args.inspect_package:
        inspect_package(adb, args.inspect_package)
    elif args.pull_and_analyze:
        pull_and_analyze_apk(adb, args.pull_and_analyze)
    elif args.scan_oem_droppers:
        scan_oem_droppers(adb)
    elif args.dump_network_state:
        dump_network_state(adb)
    else:
        # Se nenhum argumento especifico for passado, executa analise forense profunda completa
        scan_oem_droppers(adb)
        dump_network_state(adb)
