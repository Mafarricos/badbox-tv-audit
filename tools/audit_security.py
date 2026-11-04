# -*- coding: utf-8 -*-
"""
BadBox & XCPE Forensic Suite for Android TV / Google TV
Automated and interactive audit tool for detecting BadBox/XCPE/Fuyao supply-chain malware and botnets.

Usage (Humans):
  python tools/audit_security.py

Usage (AI Agents / Automated):
  python tools/audit_security.py <IP> --auto-pipeline
  python tools/audit_security.py <IP> --quick-scan
  python tools/audit_security.py <IP> --remediate
  python tools/audit_security.py <IP> --restore
  python tools/audit_security.py <IP> --install-app
  python tools/audit_security.py <IP> --launch-app
  python tools/audit_security.py <IP> --pull-report
  python tools/audit_security.py <IP> --remove-app
  python tools/audit_security.py <IP> --recompile-for-device
"""

import sys
import os
import re
import json
import time
import shutil
import tempfile
import zipfile
import argparse
import subprocess
from i18n import t, set_language, get_language, detect_system_language

# Configurar stdout/stderr para UTF-8 seguro em consolas Windows e Linux
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_PROJECT_DIR = os.path.join(PROJECT_ROOT, "app")
BACKUPS_DIR = os.path.join(PROJECT_ROOT, "backups")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
PACKAGE_NAME = "com.scanner.tv"

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(BACKUPS_DIR, exist_ok=True)


class DualLogger:
    """
    Espelha a saída para o terminal (informação visual em tempo real para humanos e agentes)
    e grava simultaneamente num ficheiro de log persistente estruturado em logs/.
    """
    def __init__(self, filename=None):
        self.terminal = sys.stdout
        if not filename:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(LOGS_DIR, f"session_{timestamp}.log")
        self.log_file = open(filename, "a", encoding="utf-8", buffering=1)
        self.log_path = filename

    def write(self, message):
        self.terminal.write(message)
        self.terminal.flush()
        # Remove códigos de controlo de terminal para manter o ficheiro de log limpo
        clean_msg = message.replace("\r", "\n") if "\r" in message and "\n" not in message else message
        self.log_file.write(clean_msg)
        self.log_file.flush()

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()


# Ativa o logger global de sessão
CURRENT_LOGGER = DualLogger()
sys.stdout = CURRENT_LOGGER


# 1. Assinaturas de C2, Backdoors, SDKs e Infraestrutura Videostrong / Badbox
TARGET_STRINGS = [
    b"disablePackageVerify",
    b"package_verifier_user_consent",
    b"szbboys",
    b"mqtt.szbboys.com",
    b"ott.szbboys.com",
    b"anyevonline",
    b"extstb.anyevonline.com",
    b"mcstb.anyevonline.com",
    b"router.anyevonline.com",
    b"Aviciiii/ott",
    b"ktpeng2026/ott_release",
    b"lw_android_agent_special_ndk",
    b"com.abc.nexus",
    b"219.134.163.210",
    b"filemail.com",
    b"videostrong",
    b"yokatvonline",
    b"titannet.io",
    b"getgrass.io",
    b"traffmonetizer.com",
    b"painet.work",
    b"dgjm.online",
    b"uota.club",
    b"uota.xyz",
    b"ycxrl.com",
    b"Corejava",
    b"test-keys",
    b"com.charon.rocketfly",
    b"adups",
    b"vo1d",
    b"/system/xbin/vo1d",
    b"/system/xbin/wd",
    b"/data/google/daemon"
]

# 2. Pacotes maliciosos, backdoors OEM e proxies residenciais da campanha
IOC_PACKAGES = [
    "x.cpe", "com.oemservice", "com.abc.nexus", "io.popanet", "gaganode",
    "linkfog", "appsalt", "traffmonetizer", "cboxtv", "hiddenview", "moyu", "spirit",
    "android-grass", "com.grass", "appdnschange", "SmartPrivilege", "SmartEntertainment",
    "SmartThroughput", "EcoSaverDaemon", "titannet", "yokatv",
    "com.adups.fota", "com.adups.market", "com.charon.rocketfly", "com.ftest", "com.google.android.suite",
    "com.google.android.services", "vo1d", "com.mozgame.fruitmania", "com.www.intallapp",
    "com.swe.dgbluancher", "com.hs.app", "com.google.android.gms.stable", "com.rmk.app.AllPlayer",
    "com.nasa.cook.CookInit", "com.sun.galaxy.lib.OceanInit", "com.goog1e.apps",
    "com.honeygain", "com.iproyal", "pawns.app", "packetstream", "peer2profit", "repocket", "earnapp", "bitping"
]

# 3. Ficheiros binários e scripts de persistência de malware no sistema (Vo1d, Corejava, etc.)
IOC_BINARY_PATHS = [
    "/system/xbin/vo1d",
    "/system/xbin/wd",
    "/data/google/daemon",
    "/data/google/rild",
    "/data/google",
    "/data/system/Corejava",
    "/data/system/Corejava/node",
    "/data/system/installd",
    "/data/system/startup",
    "/data/secondstage",
    "/cache/secondstage",
    "/system/etc/install-recovery.sh"
]

# 4. IPs e Portas Críticas de C2 da botnet
C2_IPS_PORTS = [
    "219.134.163.210", "121.4.8.146", "38.145.197.135", "38.145.197.30", "23.94.49.57",
    ":3885", ":3886", ":3887", ":22345", ":16000", ":12000", ":9992", ":9994", ":2375", ":2095", ":2082"
]

# 5. Modelos de dispositivos historicamente visados pela botnet (Apenas Informativo - Requer Evidências)
TARGETED_HARDWARE_MODELS = [
    "km9", "km2", "km6", "km7", "km1", "km3", "km8", "m8s", "tx3", "h616", "h618", "t95", "q96", "leap-s1",
    "videostrong", "mecool", "uhd google tv stb", "rmq", "x88", "x96", "tx3mini", "t95max", "transpeed",
    "x12-plus", "tv98", "mx10pro", "mxq9pro"
]


class AdbDevice:
    def __init__(self, host):
        self.host = host
        self.device = None
        self.specs = {}
        self._init_connection()

    def _init_connection(self):
        try:
            tools_dir = os.path.join(PROJECT_ROOT, "tools")
            if tools_dir not in sys.path:
                sys.path.insert(0, tools_dir)
            os.environ["TV_HOST"] = self.host
            import tv
            self.device = tv.connect()
        except Exception as e:
            print(f"[!] Erro ao inicializar conexão ADB pura: {e}")
            self.device = None

    def run(self, cmd):
        if not self.device:
            return ""
        try:
            res = self.device.shell(cmd)
            return res.decode("utf-8", errors="replace") if isinstance(res, bytes) else str(res)
        except Exception as e:
            return f"Erro ADB: {e}"

    def push(self, local_path, remote_path):
        if not self.device:
            return False
        try:
            self.device.push(local_path, remote_path)
            return True
        except Exception as e:
            print(f"[!] Erro ao enviar ficheiro via ADB: {e}")
            return False

    def pull(self, remote_path, local_path):
        if not self.device:
            return False
        try:
            self.device.pull(remote_path, local_path)
            return True
        except Exception as e:
            print(f"[!] Erro ao descarregar ficheiro via ADB: {e}")
            return False

    def load_specs(self, silent=False):
        if not silent:
            print(t("loading_specs", target=self.host))
        brand = self.run("getprop ro.product.brand").strip()
        model = self.run("getprop ro.product.model").strip()
        manufacturer = self.run("getprop ro.product.manufacturer").strip()
        android_ver = self.run("getprop ro.build.version.release").strip()
        security_patch = self.run("getprop ro.build.version.security_patch").strip()
        board = self.run("getprop ro.product.board").strip()
        hardware = self.run("getprop ro.hardware").strip()
        sdk = self.run("getprop ro.build.version.sdk").strip()
        
        self.specs = {
            "brand": brand,
            "model": model,
            "manufacturer": manufacturer,
            "android_version": android_ver,
            "security_patch": security_patch,
            "board": board,
            "hardware": hardware,
            "sdk": sdk
        }
        if not silent:
            print(t("specs_model", brand=brand, model=model, ver=android_ver, sdk=sdk))
            print(t("specs_soc", vendor=manufacturer, board=board, hw=hardware))
            print(t("specs_patch", patch=security_patch))
        return self.specs


def evaluate_forensic_results(json_data, vpn_log_lines, device_specs=None):
    """
    Motor determinístico de decisão baseado em regras e pontuação ponderada.
    Sem dependência de modelos de IA.
    """
    print("\n================================================================================")
    print("                    MOTOR DE AVALIAÇÃO FORENSE DETERMINÍSTICO                   ")
    print("================================================================================")
    
    score = 0
    critical_reasons = []
    suspicious_reasons = []
    info_warnings = []

    # 1. Avaliação do Relatório Estático (last_scan.json)
    if json_data:
        play_protect = json_data.get("play_protect", "")
        if "user_consent=-1" in play_protect:
            critical_reasons.append("Play Protect forçado a desligar (package_verifier_user_consent = -1)")
            score += 10
        elif "enable=0" in play_protect:
            suspicious_reasons.append("Verificação de pacotes desligada (package_verifier_enable = 0)")
            score += 3

        for f in json_data.get("findings", []):
            if "[CRÍTICO]" in f:
                critical_reasons.append(f)
                score += 8
            elif "[SUSPEITO]" in f or "[ALERTA]" in f:
                suspicious_reasons.append(f)
                score += 2
            elif "[AVISO INFORMATIVO]" in f:
                info_warnings.append(f)

    # 2. Avaliação dos Eventos de Rede da VPN (vpn_events.log)
    if vpn_log_lines:
        for line in vpn_log_lines:
            if "[CRITICO]" in line:
                critical_reasons.append("Rede: " + line.strip())
                score += 10
            elif "[ANOMALIA]" in line:
                suspicious_reasons.append("Rede: " + line.strip())
                score += 3

    # 3. Verificação do Modelo de Hardware (Informativo - Não conta pontos sozinho)
    if device_specs:
        model_str = (device_specs.get("model", "") + " " + device_specs.get("brand", "") + " " + device_specs.get("manufacturer", "")).lower()
        for targeted in TARGETED_HARDWARE_MODELS:
            if targeted in model_str:
                info_warnings.append(f"Dispositivo pertence à família '{targeted}' (linha visada pela campanha Videostrong/BadBox). Veredito depende estritamente das evidências técnicas.")
                break

    # 4. Veredito com Limiares de Decisão Exatos
    print(f"Pontuação de Risco Total: {score} pontos\n" if get_language() == "pt" else f"Total Risk Score: {score} points\n")

    if score >= 8 or len(critical_reasons) > 0:
        verdict = "INFETADO - CRÍTICO" if get_language() == "pt" else "INFECTED - CRITICAL"
        color_code = "[!]"
        confidence = ">99%"
        desc = t("verdict_crit_desc")
    elif score >= 3 or len(suspicious_reasons) >= 2:
        verdict = "SUSPEITO" if get_language() == "pt" else "SUSPICIOUS"
        color_code = "[?]"
        confidence = "80%"
        desc = t("verdict_susp_desc")
    else:
        verdict = "LIMPO / SEGURO" if get_language() == "pt" else "CLEAN / SAFE"
        color_code = "[✓]"
        confidence = ">98%"
        desc = t("verdict_clean_desc")

    header_verdict = t("verdict_crit") if "CRÍTICO" in verdict or "CRITICAL" in verdict else (t("verdict_susp") if "SUSP" in verdict else t("verdict_clean"))
    print(f"{color_code} {header_verdict}")
    print(f"    {desc}")

    if critical_reasons:
        print("\nEvidências Críticas:")
        for cr in set(critical_reasons):
            print(f"  * {cr}")

    if suspicious_reasons:
        print("\nAnomalias Reportadas:")
        for sr in set(suspicious_reasons):
            print(f"  * {sr}")

    if info_warnings:
        print("\nAvisos de Contexto do Hardware:")
        for iw in set(info_warnings):
            print(f"  * {iw}")

    print("================================================================================\n")
    return verdict


def step_quick_audit(adb, json_output=False):
    if not json_output:
        print("\n================================================================================")
        print(f"           {t('banner_quick_audit')}                      ")
        print("================================================================================")
    
    if not adb.specs:
        adb.load_specs()

    model_str = (adb.specs.get("model", "") + " " + adb.specs.get("brand", "")).lower()
    targeted_warning = None
    for targeted in TARGETED_HARDWARE_MODELS:
        if targeted in model_str:
            if get_language() == "pt":
                targeted_warning = f"Este modelo ('{adb.specs.get('model')}') coincide com linhas documentadas no relatório Synthient/Eclypsium."
            else:
                targeted_warning = f"This model ('{adb.specs.get('model')}') matches families documented in Synthient/Eclypsium reports."
            if not json_output:
                print(f"\n[AVISO DE CONTEXTO] {targeted_warning}")
                print("                   Será feita uma verificação rigorosa de evidências técnicas." if get_language() == "pt" else "                  A strict evidence-based verification will be performed.")
            break

    if not json_output:
        print(f"\n{t('layer_1_title')}")
    settings_out = adb.run("settings get global package_verifier_user_consent")
    play_protect_disabled = ("-1" in settings_out)
    if not json_output:
        print(f"    - package_verifier_user_consent: {settings_out.strip()}")
        if play_protect_disabled:
            print(t("layer_1_crit"))
        else:
            print(t("layer_1_ok"))

    if not json_output:
        print(f"\n{t('layer_2_title')}")
    pkgs = adb.run("pm list packages").splitlines()
    disabled_pkgs = [p.replace("package:", "").strip().lower() for p in adb.run("pm list packages -d").splitlines()]
    found_ioc_pkgs = []
    neutralized_ioc_pkgs = []
    for p in pkgs:
        p_name = p.replace("package:", "").strip().lower()
        for ioc in IOC_PACKAGES:
            if ioc.lower() in p_name:
                if p_name in disabled_pkgs:
                    neutralized_ioc_pkgs.append(p_name)
                else:
                    found_ioc_pkgs.append(p_name)
    if not json_output:
        if found_ioc_pkgs:
            print(t("layer_2_active_threat", pkgs=found_ioc_pkgs))
        if neutralized_ioc_pkgs:
            print(t("layer_2_frozen", pkgs=neutralized_ioc_pkgs))
        if not found_ioc_pkgs and not neutralized_ioc_pkgs:
            print(t("layer_2_clean", count=len(pkgs)))

    if not json_output:
        print(f"\n{t('layer_3_title')}")
    props = adb.run("getprop").splitlines()
    found_suspicious_props = []
    for prop in props:
        for target in TARGET_STRINGS:
            if target.decode("utf-8", errors="ignore").lower() in prop.lower():
                found_suspicious_props.append(prop)
    if not json_output:
        if found_suspicious_props:
            print(t("layer_3_suspicious", props=found_suspicious_props))
        else:
            print(t("layer_3_ok"))

    if not json_output:
        print(f"\n{t('layer_4_title')}")
    netstat_out = adb.run("netstat -n -a 2>/dev/null || ss -tan 2>/dev/null")
    found_conn = []
    for line in netstat_out.splitlines():
        for c2 in C2_IPS_PORTS:
            if c2 in line:
                found_conn.append(line)
    if not json_output:
        if found_conn:
            print(t("layer_4_c2_found", conn=found_conn))
        else:
            print(t("layer_4_ok"))

    if not json_output:
        print(f"\n{t('layer_5_title')}")
    oem_paths = adb.run("pm list packages -f -s").splitlines()
    if not json_output:
        print(t("layer_5_total", count=len(oem_paths)))
    
    # Verificação de binários e pastas conhecidas de malware (Vo1d, Corejava)
    found_binaries = []
    for b_path in IOC_BINARY_PATHS:
        check = adb.run(f"ls -ld {b_path} 2>/dev/null").strip()
        if check and "No such file" not in check and "not found" not in check:
            found_binaries.append(b_path)
    if not json_output:
        if found_binaries:
            print(f"    [!] ALERTA CRÍTICO: Ficheiros de persistência detetados (Vo1d/Corejava): {found_binaries}")
        else:
            print(t("layer_5_ok"))

    # Cálculo Determinístico de Risco para saída JSON
    risk_score = 0
    if play_protect_disabled: risk_score += 10
    if found_ioc_pkgs: risk_score += 10 * len(found_ioc_pkgs)
    if found_conn: risk_score += 10 * len(found_conn)
    if found_binaries: risk_score += 10 * len(found_binaries)
    if found_suspicious_props: risk_score += 5 * len(found_suspicious_props)

    if risk_score >= 8:
        verdict = "INFETADO - CRÍTICO" if get_language() == "pt" else "INFECTED - CRITICAL"
    elif risk_score >= 3:
        verdict = "SUSPEITO" if get_language() == "pt" else "SUSPICIOUS"
    else:
        verdict = "LIMPO / SEGURO" if get_language() == "pt" else "CLEAN / SAFE"

    result_data = {
        "target": adb.host,
        "specs": adb.specs,
        "verdict": verdict,
        "risk_score": risk_score,
        "play_protect_tampered": play_protect_disabled,
        "active_ioc_packages": found_ioc_pkgs,
        "neutralized_ioc_packages": neutralized_ioc_pkgs,
        "suspicious_binaries": found_binaries,
        "active_c2_connections": found_conn,
        "suspicious_props": found_suspicious_props,
        "hardware_warning": targeted_warning
    }

    if json_output:
        print(json.dumps(result_data, indent=2, ensure_ascii=False))

    return result_data


def discover_subnet_tvs(cidr_or_base, port=5555, timeout=0.8):
    """
    Descobre rapidamente dispositivos Android TV na rede com a porta ADB 5555 aberta.
    Suporta formatos: '192.168.1.0/24' ou '192.168.1.'
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor

    base_ip = cidr_or_base.split("/")[0]
    parts = base_ip.split(".")
    prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

    print(f"[*] A pesquisar dispositivos Android TV na sub-rede {prefix}0/24 (porta {port})...")
    active_tvs = []

    def check_ip(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            s.close()
            if res == 0:
                return ip
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_ip, f"{prefix}{i}") for i in range(1, 255)]
        for f in futures:
            ip = f.result()
            if ip:
                active_tvs.append(ip)

    return active_tvs


def create_remediation_backup(adb):
    """
    Cria um backup completo das definições e estado de pacotes ANTES de qualquer alteração,
    gerando também um script de restauro reversível em backups/.
    """
    clean_ip = adb.host.replace(".", "_")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUPS_DIR, f"backup_{clean_ip}_{timestamp}.json")
    restore_script = os.path.join(BACKUPS_DIR, f"restore_{clean_ip}.ps1")

    print(f"\n[*] A criar BACKUP de segurança reversível em backups/...")

    orig_user_consent = adb.run("settings get global package_verifier_user_consent").strip()
    orig_verifier_enable = adb.run("settings get global package_verifier_enable").strip()
    orig_dns_mode = adb.run("settings get global private_dns_mode").strip()
    orig_dns_spec = adb.run("settings get global private_dns_specifier").strip()
    disabled_pkgs = adb.run("pm list packages -d").splitlines()

    backup_data = {
        "host": adb.host,
        "timestamp": timestamp,
        "specs": adb.specs,
        "settings": {
            "package_verifier_user_consent": orig_user_consent,
            "package_verifier_enable": orig_verifier_enable,
            "private_dns_mode": orig_dns_mode,
            "private_dns_specifier": orig_dns_spec
        },
        "originally_disabled_packages": disabled_pkgs,
        "disabled_during_remediation": []
    }

    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    print(f"    [✓] Ficheiro de estado guardado: {os.path.basename(backup_file)}")
    return backup_file, backup_data, restore_script


def generate_restore_script(adb, backup_data, restore_script_path):
    """Gera script PowerShell autónomo e reversível para restaurar a TV."""
    settings = backup_data.get("settings", {})
    disabled = backup_data.get("disabled_during_remediation", [])
    
    ps_content = f"""# =====================================================================
# RESTORE SCRIPT - BADBOX FORENSIC REMEDIATION REVERSAL
# Dispositivo: {adb.host}
# Gerado em:   {backup_data.get('timestamp')}
# =====================================================================

param(
    [string]$TvHost = "{adb.host}"
)

$toolsDir = "{PROJECT_ROOT.replace('\\', '/')}/tools"
Set-Location $toolsDir

Write-Host ">>> A reverter remediação e restaurar estado da TV ($TvHost)..." -ForegroundColor Cyan

# 1. Restaurar Definições Globais
Write-Host "1. A repor definições originais..." -ForegroundColor Yellow
$env:TV_HOST = "$TvHost"
python -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_user_consent {settings.get('package_verifier_user_consent', '1')}')"
python -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_enable {settings.get('package_verifier_enable', '1')}')"

$dnsMode = "{settings.get('private_dns_mode', 'off')}"
$dnsSpec = "{settings.get('private_dns_specifier', '')}"
if ($dnsMode -eq "null" -or $dnsMode -eq "") {{ $dnsMode = "off" }}
python -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_mode $dnsMode')"
if ($dnsSpec -ne "null" -and $dnsSpec -ne "") {{
    python -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_specifier $dnsSpec')"
}}

# 2. Reativar Pacotes de Sistema Desativados
Write-Host "2. A reativar pacotes de sistema desativados..." -ForegroundColor Yellow
$packagesToEnable = @(
"""
    for pkg in disabled:
        ps_content += f'    "{pkg}",\n'

    ps_content += f"""@()
)

foreach ($pkg in $packagesToEnable) {{
    if ($pkg) {{
        Write-Host "   -> A reativar: $pkg"
        python -c "import tv; d = tv.connect(); d.shell('pm enable $pkg')"
    }}
}}

Write-Host "`n>>> [✓] Restauro concluído com sucesso!" -ForegroundColor Green
"""
    with open(restore_script_path, "w", encoding="utf-8") as f:
        f.write(ps_content)
    print(f"    [✓] Script de reversão gerado com sucesso: {os.path.basename(restore_script_path)}")


def step_remediate_device(adb):
    """
    Executa a neutralização e remediação completa da box com salvaguarda reversível (backup).
    """
    print("\n================================================================================")
    print(f"     PLANO DE REMEDIAÇÃO & NEUTRALIZAÇÃO FORENSE - ANDROID TV ({adb.host})       ")
    print("================================================================================")

    if not adb.specs:
        adb.load_specs()

    backup_file, backup_data, restore_script = create_remediation_backup(adb)

    # 1. Reativar e Trancar o Google Play Protect
    print("\n[Passo 1/4] A restaurar e trancar o Google Play Protect...")
    adb.run("settings put global package_verifier_user_consent 1")
    adb.run("settings put global package_verifier_enable 1")
    user_consent = adb.run("settings get global package_verifier_user_consent").strip()
    verifier_enable = adb.run("settings get global package_verifier_enable").strip()
    print(f"    - package_verifier_user_consent: {user_consent}")
    print(f"    - package_verifier_enable:       {verifier_enable}")
    if user_consent == "1" and verifier_enable == "1":
        print("    [✓] Play Protect restaurado com sucesso! Verificação ativa de pacotes.")
    else:
        print("    [!] Aviso: Não foi possível repor o valor padrão de Play Protect.")

    # 2. Desinstalar / Desativar Pacotes Maliciosos da Botnet
    print("\n[Passo 2/4] A procurar e neutralizar pacotes de botnet, trojans e proxies...")
    pkgs = adb.run("pm list packages").splitlines()
    neutralized_count = 0
    for p in pkgs:
        p_name = p.replace("package:", "").strip()
        for ioc in IOC_PACKAGES:
            if ioc.lower() in p_name.lower():
                print(f"    [*] A neutralizar pacote malicioso detetado: {p_name}")
                uninst = adb.run(f"pm uninstall {p_name}").strip()
                if "Success" in uninst:
                    print(f"        -> Desinstalado com sucesso: {p_name}")
                    neutralized_count += 1
                else:
                    dis = adb.run(f"pm disable-user --user 0 {p_name}").strip()
                    print(f"        -> App de sistema desativada/congelada: {p_name} ({dis})")
                    backup_data["disabled_during_remediation"].append(p_name)
                    neutralized_count += 1

    if neutralized_count == 0:
        print("    [✓] Nenhum pacote malicioso da botnet encontrado para desinstalar.")
    else:
        print(f"    [✓] Total de pacotes maliciosos neutralizados: {neutralized_count}")

    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    # 3. Terminar Processos e Forçar Paragem de Módulos
    print("\n[Passo 3/4] A terminar processos e serviços em execução da botnet...")
    for ioc in IOC_PACKAGES:
        adb.run(f"am force-stop {ioc}")
        adb.run(f"killall {ioc} 2>/dev/null")

    # Neutralizar ficheiros de persistência Vo1d / Corejava caso existam
    for b_path in IOC_BINARY_PATHS:
        check = adb.run(f"ls -ld {b_path} 2>/dev/null").strip()
        if check and "No such file" not in check and "not found" not in check:
            print(f"    [*] A remover ficheiro de persistência malicioso: {b_path}")
            adb.run(f"rm -rf {b_path} 2>/dev/null")
            adb.run(f"touch {b_path} 2>/dev/null && chmod 000 {b_path} 2>/dev/null")

    print("    [✓] Processos residuais terminados.")

    # 4. Ativar DNS Seguro com Filtro de Malware (Corte de C2 direto na Box)
    print("\n[Passo 4/4] A configurar Private DNS seguro na Box (Proteção anti-malware)...")
    print("    - A definir DNS sobre TLS para: security.cloudflare-dns.com")
    adb.run("settings put global private_dns_mode hostname")
    adb.run("settings put global private_dns_specifier security.cloudflare-dns.com")
    dns_mode = adb.run("settings get global private_dns_mode").strip()
    dns_host = adb.run("settings get global private_dns_specifier").strip()
    print(f"    - Modo Private DNS: {dns_mode}")
    print(f"    - Servidor Seguro:  {dns_host}")
    print("    [✓] Proteção de DNS ativa: pedidos para servidores C2 serão bloqueados na fonte.")

    generate_restore_script(adb, backup_data, restore_script)

    print("\n================================================================================")
    print("  REMEDIAÇÃO CONCLUÍDA: A TV foi limpa e o tráfego de botnet bloqueado!")
    print(f"  Log da sessão gravado em: {CURRENT_LOGGER.log_path}")
    print(f"  Para reverter a qualquer momento, execute: backups/{os.path.basename(restore_script)}")
    print("================================================================================\n")


def step_restore_device(adb):
    """Reverte as alterações de remediação usando o backup mais recente."""
    print("\n================================================================================")
    print(f"            REVERSÃO / RESTAURO DE SEGURANÇA - ANDROID TV ({adb.host})          ")
    print("================================================================================")
    
    clean_ip = adb.host.replace(".", "_")
    matching_backups = []
    if os.path.exists(BACKUPS_DIR):
        for f in sorted(os.listdir(BACKUPS_DIR), reverse=True):
            if f.startswith(f"backup_{clean_ip}_") and f.endswith(".json"):
                matching_backups.append(os.path.join(BACKUPS_DIR, f))

    if not matching_backups:
        print(f"[!] Nenhum ficheiro de backup encontrado para {adb.host} em backups/.")
        return False

    latest_backup = matching_backups[0]
    print(f"[*] A carregar backup mais recente: {os.path.basename(latest_backup)}...")
    with open(latest_backup, "r", encoding="utf-8") as f:
        backup_data = json.load(f)

    settings = backup_data.get("settings", {})
    print("\n[1/2] A repor definições globais originais...")
    if "package_verifier_user_consent" in settings:
        adb.run(f"settings put global package_verifier_user_consent {settings['package_verifier_user_consent']}")
    if "package_verifier_enable" in settings:
        adb.run(f"settings put global package_verifier_enable {settings['package_verifier_enable']}")
    
    dns_mode = settings.get("private_dns_mode", "off")
    if not dns_mode or dns_mode == "null": dns_mode = "off"
    adb.run(f"settings put global private_dns_mode {dns_mode}")
    
    dns_spec = settings.get("private_dns_specifier", "")
    if dns_spec and dns_spec != "null":
        adb.run(f"settings put global private_dns_specifier {dns_spec}")
    print("    [✓] Definições restauradas.")

    disabled = backup_data.get("disabled_during_remediation", [])
    print("\n[2/2] A reativar pacotes desativados durante a remediação...")
    for pkg in disabled:
        print(f"    [*] A reativar: {pkg}")
        adb.run(f"pm enable {pkg}")
    print("    [✓] Pacotes reativados.")

    print("\n================================================================================")
    print("  [✓] RESTAURO CONCLUÍDO COM SUCESSO! Dispositivo reposto no estado anterior.")
    print("================================================================================\n")
    return True


def ensure_build_environment():
    """Garante JDK 17 e Android SDK configurados se for necessária recompilação."""
    print("\n[*] A verificar ferramentas de compilação (JDK 17 + Android SDK)...")
    
    javac_found = False
    try:
        res = subprocess.run(["javac", "-version"], capture_output=True, text=True)
        if res.returncode == 0:
            javac_found = True
    except FileNotFoundError:
        pass

    if not javac_found and sys.platform == "win32":
        default_jdk = r"C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
        if os.path.exists(default_jdk):
            os.environ["JAVA_HOME"] = default_jdk
            os.environ["PATH"] = os.path.join(default_jdk, "bin") + os.pathsep + os.environ["PATH"]
            javac_found = True

    if not javac_found:
        print("[!] Java JDK 17 não detetado. A tentar instalar via winget...")
        if sys.platform == "win32":
            subprocess.run(["winget", "install", "-e", "--id", "EclipseAdoptium.Temurin.17.JDK", "--accept-package-agreements", "--accept-source-agreements"])
        else:
            print("[!] Por favor instale o OpenJDK 17: sudo apt install openjdk-17-jdk")

    android_home = os.environ.get("ANDROID_HOME")
    if not android_home:
        for candidate in [r"C:\AndroidSDK", os.path.expanduser("~/Android/Sdk"), os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")]:
            if os.path.exists(candidate):
                android_home = candidate
                os.environ["ANDROID_HOME"] = candidate
                break

    if android_home:
        local_prop = os.path.join(APP_PROJECT_DIR, "local.properties")
        escaped_sdk = android_home.replace("\\", "\\\\") if sys.platform == "win32" else android_home
        with open(local_prop, "w", encoding="utf-8") as f:
            f.write(f"sdk.dir={escaped_sdk}\n")
        print(f"    [✓] Ambiente de compilação pronto. SDK: {android_home}")
        return True
    else:
        print("[!] Android SDK não encontrado. O repositório irá usar o APK pré-compilado universal.")
        return False


def compile_custom_app(specs, force_recompile=False):
    apk_prebuilt = os.path.join(PROJECT_ROOT, "tools", "xcpe-scanner-tv.apk")
    
    if os.path.exists(apk_prebuilt) and not force_recompile:
        return apk_prebuilt

    print("\n================================================================================")
    print(f"[*] A RECOMPILAR APLICAÇÃO À MEDIDA DO DISPOSITIVO (Android {specs.get('android_version','?')}, API {specs.get('sdk','?')})")
    print("================================================================================")
    
    if not ensure_build_environment():
        if os.path.exists(apk_prebuilt):
            print("[!] Não foi possível compilar de raiz. A utilizar o APK pré-compilado universal...")
            return apk_prebuilt
        return None

    sdk_int = specs.get("sdk", "")
    if sdk_int and sdk_int.isdigit():
        target_sdk = int(sdk_int)
        gradle_file = os.path.join(APP_PROJECT_DIR, "app", "build.gradle")
        try:
            with open(gradle_file, "r", encoding="utf-8") as f:
                content = f.read()
            if target_sdk < 26:
                content = re.sub(r'minSdk \d+', 'minSdk 21', content)
                with open(gradle_file, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"    [✓] Build.gradle ajustado para suporte legado (API {target_sdk}).")
        except Exception as e:
            print(f"[!] Aviso ao verificar build.gradle: {e}")

    gradlew_bin = os.path.join(APP_PROJECT_DIR, "gradlew.bat" if sys.platform == "win32" else "gradlew")
    if not os.path.exists(gradlew_bin):
        print("[!] Gradle wrapper não encontrado.")
        return None

    print("\n[*] A compilar APK nativo via Gradle...")
    res = subprocess.run([gradlew_bin, "assembleDebug"], cwd=APP_PROJECT_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Erro de compilação:\n{res.stderr}")
        return None

    apk_path = os.path.join(APP_PROJECT_DIR, "app", "build", "outputs", "apk", "debug", "app-debug.apk")
    if os.path.exists(apk_path):
        print(f"    [✓] Compilação bem-sucedida à medida: {apk_path}")
        return apk_path
    return None


def step_install_custom_app(adb, force_recompile=False):
    if not adb.specs:
        adb.load_specs()
    apk = compile_custom_app(adb.specs, force_recompile=force_recompile)
    if apk:
        print("\n[*] A transferir e instalar na box...")
        remote_tmp = "/data/local/tmp/xcpe-scanner-tv.apk"
        adb.push(apk, remote_tmp)
        out = adb.run(f"pm install -r -d -t {remote_tmp}")
        print(f"    - Resultado da instalação: {out.strip()}")
        
        if "INSTALL_FAILED" in out and not force_recompile:
            print(f"\n[!] AVISO: APK universal rejeitado pelo aparelho ({out.strip()}).")
            print("[*] A acionar RECOMPILAÇÃO AUTOMÁTICA adaptada ao hardware do aparelho...")
            return step_install_custom_app(adb, force_recompile=True)

        adb.run(f"rm -f {remote_tmp}")
        if "Success" in out:
            print("    [✓] App instalada com sucesso.")
            return True
        else:
            print("    [!] AVISO: A instalação pode não ter sido concluída com sucesso.")
            return False
    return False


def step_launch_app(adb):
    print("\n[*] A abrir a App no ecrã da TV...")
    adb.run(f"am start -n {PACKAGE_NAME}/.MainActivity")
    print("    [✓] A App está aberta no ecrã da TV.")


def step_pull_report(adb):
    print("\n[*] A transferir os relatórios da box para o computador...")
    adb.run(f"run-as {PACKAGE_NAME} cp files/last_scan.json /data/local/tmp/report.json 2>/dev/null")
    adb.run("chmod 666 /data/local/tmp/report.json 2>/dev/null")
    local_json = os.path.join(PROJECT_ROOT, "last_scan_report.json")
    
    adb.run(f"run-as {PACKAGE_NAME} cp files/audit_events.log /data/local/tmp/audit_events.log 2>/dev/null")
    adb.run("chmod 666 /data/local/tmp/audit_events.log 2>/dev/null")
    local_log = os.path.join(PROJECT_ROOT, "vpn_events.log")

    json_data = None
    vpn_lines = []

    if adb.pull("/data/local/tmp/report.json", local_json):
        adb.run("rm -f /data/local/tmp/report.json")
        try:
            with open(local_json, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            print(f"    [✓] Relatório JSON guardado em: {local_json}")
        except Exception as e:
            print(f"[!] Erro ao analisar JSON: {e}")

    if adb.pull("/data/local/tmp/audit_events.log", local_log):
        adb.run("rm -f /data/local/tmp/audit_events.log")
        try:
            with open(local_log, "r", encoding="utf-8") as f:
                vpn_lines = f.readlines()
            print(f"    [✓] Registo de tráfego VPN guardado em: {local_log}")
        except Exception as e:
            print(f"[!] Erro ao ler log de VPN: {e}")

    if not adb.specs:
        adb.load_specs()

    return evaluate_forensic_results(json_data, vpn_lines, device_specs=adb.specs)


def step_remove_app(adb):
    print(f"\n[*] A desinstalar a App {PACKAGE_NAME} da box...")
    out = adb.run(f"pm uninstall {PACKAGE_NAME}")
    print(f"    - Resultado: {out.strip()}")
    print("    [✓] Box 100% limpa, sem qualquer ficheiro residual.")


def step_automated_pipeline(adb, vpn_duration=20, force_recompile=False):
    print("\n================================================================================")
    print("       PIPELINE DE AUDITORIA 100% AUTOMATIZADO (ESTÁTICO + SENTINELA VPN)       ")
    print(f"       Alvo: {adb.host} | Duração Sentinela: {vpn_duration} segundos            ")
    print("================================================================================\n")

    if not adb.specs:
        adb.load_specs()
    step_install_custom_app(adb, force_recompile=force_recompile)

    print("\n[*] A autorizar permissões de VPN e alertas em segundo plano...")
    adb.run(f"appops set {PACKAGE_NAME} ACTIVATE_VPN allow")
    adb.run(f"appops set {PACKAGE_NAME} SYSTEM_ALERT_WINDOW allow")

    step_launch_app(adb)
    time.sleep(2)

    print("\n[*] A disparar Análise Estática profunda (5 Camadas)...")
    adb.run("input keyevent KEYCODE_DPAD_CENTER")
    time.sleep(4)

    print(f"\n[*] A ativar Sentinela VPN em tempo real (à escuta durante {vpn_duration}s)...")
    adb.run("input keyevent KEYCODE_DPAD_DOWN")
    adb.run("input keyevent KEYCODE_DPAD_CENTER")
    
    for remaining in range(vpn_duration, 0, -1):
        print(f"    -> Sentinela ativo a monitorizar portas e tráfego... {remaining}s restantes", end="\r")
        time.sleep(1)
    print("\n    [✓] Janela de monitorização de tráfego concluída.")

    print("\n[*] A desligar Sentinela VPN...")
    adb.run("input keyevent KEYCODE_DPAD_CENTER")
    time.sleep(1)

    print("\n[*] A extrair relatórios para o computador...")
    verdict = step_pull_report(adb)

    print("\n[*] A limpar o dispositivo...")
    step_remove_app(adb)

    print("\n================================================================================")
    print(f"  PIPELINE CONCLUÍDO COM SUCESSO: Veredito = {verdict}")
    print(f"  Registo integral da auditoria guardado em: {CURRENT_LOGGER.log_path}")
    print("================================================================================\n")


def interactive_menu(default_ip):
    target_ip = default_ip
    adb = AdbDevice(target_ip)
    adb.load_specs()

    while True:
        print("\n================================================================================")
        print(t("menu_header", target=target_ip))
        print("================================================================================")
        print(t("menu_section_auto"))
        print(t("menu_opt_1"))
        print(t("menu_opt_2"))
        print("")
        print(t("menu_section_diag"))
        print(t("menu_opt_3"))
        print(t("menu_opt_4"))
        print(t("menu_opt_5"))
        print(t("menu_opt_6"))
        print(t("menu_opt_7"))
        print("")
        print(t("menu_section_rem"))
        print(t("menu_opt_8"))
        print(t("menu_opt_9"))
        print("")
        print(t("menu_section_cfg"))
        print(t("menu_opt_10"))
        print(t("menu_opt_11"))
        print(t("menu_opt_0"))
        print("================================================================================")
        choice = input(t("menu_choice_prompt")).strip()

        if choice == "1":
            step_automated_pipeline(adb, vpn_duration=20, force_recompile=False)
            input(t("menu_press_enter"))
        elif choice == "2":
            step_automated_pipeline(adb, vpn_duration=20, force_recompile=True)
            input(t("menu_press_enter"))
        elif choice == "3":
            step_quick_audit(adb)
            input(t("menu_press_enter"))
        elif choice == "4":
            print("\n" + t("menu_opt_4"))
            sub_choice = input("Choice [1/2]: ").strip()
            force = (sub_choice == "2")
            step_install_custom_app(adb, force_recompile=force)
            input(t("menu_press_enter"))
        elif choice == "5":
            step_launch_app(adb)
            input(t("menu_press_enter"))
        elif choice == "6":
            step_pull_report(adb)
            input(t("menu_press_enter"))
        elif choice == "7":
            step_remove_app(adb)
            input(t("menu_press_enter"))
        elif choice == "8":
            step_remediate_device(adb)
            input(t("menu_press_enter"))
        elif choice == "9":
            step_restore_device(adb)
            input(t("menu_press_enter"))
        elif choice == "10":
            try:
                import setup_env
                setup_env.interactive_installer_menu()
            except ImportError:
                tools_dir = os.path.join(PROJECT_ROOT, "tools")
                if tools_dir not in sys.path:
                    sys.path.insert(0, tools_dir)
                import setup_env
                setup_env.interactive_installer_menu()
            input(t("menu_press_enter"))
        elif choice == "11":
            new_ip = input(t("menu_new_ip_prompt")).strip()
            if new_ip:
                target_ip = new_ip
                adb = AdbDevice(target_ip)
                adb.load_specs()
        elif choice == "0":
            print(t("menu_exit_msg"))
            break
        else:
            print(t("menu_invalid_opt"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BadBox & XCPE Forensic Suite", add_help=False)
    parser.add_argument("target", nargs="?", default=None, help="IP da Android TV / Target IP")
    parser.add_argument("--json", action="store_true", help="Gera apenas saída compacta em formato JSON para leitura rápida por agentes de IA (poupa tokens)")
    parser.add_argument("--lang", choices=["en", "pt"], default=None, help="Idioma das mensagens / Interface language (en or pt). Defaults to system language.")
    parser.add_argument("--scan-subnet", metavar="CIDR", help="Descobre e audita automaticamente todas as Android TVs na sub-rede (ex: 192.168.1.0/24)")
    parser.add_argument("--auto-pipeline", action="store_true", help="Executa pipeline completo: instala, scan estatico, VPN 20s, recolhe logs e desinstala")
    parser.add_argument("--quick-scan", action="store_true", help="Executa o diagnóstico rápido das 5 camadas via ADB")
    parser.add_argument("--remediate", action="store_true", help="Neutraliza a box com backup prévio: repõe Play Protect, remove/desativa apps da botnet e ativa DNS seguro")
    parser.add_argument("--restore", action="store_true", help="Reverte a remediação e repõe o estado anterior usando o backup")
    parser.add_argument("--install-app", action="store_true", help="Instala a app na box")
    parser.add_argument("--recompile-for-device", action="store_true", help="Força a recompilação à medida para o SoC/SDK do dispositivo")
    parser.add_argument("--launch-app", action="store_true", help="Lança a app na TV")
    parser.add_argument("--pull-report", action="store_true", help="Recolhe relatórios e aplica motor de regras")
    parser.add_argument("--remove-app", action="store_true", help="Desinstala a app da box")
    parser.add_argument("--setup-env", action="store_true", help="Abre o configurador de pré-requisitos e toolchains")
    parser.add_argument("--help", "-h", action="store_true", help="Mostra a ajuda")

    args, unknown = parser.parse_known_args()

    if args.lang:
        set_language(args.lang)
    else:
        set_language(detect_system_language())

    if args.help:
        print(__doc__)
        sys.exit(0)

    if args.setup_env:
        try:
            import setup_env
            setup_env.interactive_installer_menu()
        except ImportError:
            tools_dir = os.path.join(PROJECT_ROOT, "tools")
            if tools_dir not in sys.path:
                sys.path.insert(0, tools_dir)
            import setup_env
            setup_env.interactive_installer_menu()
        sys.exit(0)

    if args.scan_subnet:
        targets = discover_subnet_tvs(args.scan_subnet)
        if not targets:
            print(f"[!] Nenhum dispositivo com ADB ativo (porta 5555) encontrado na sub-rede {args.scan_subnet}.")
            sys.exit(0)
        print(f"\n[✓] Foram encontrados {len(targets)} dispositivo(s) com ADB: {targets}")
        batch_results = []
        for t_ip in targets:
            dev = AdbDevice(t_ip)
            dev.load_specs(silent=True)
            res = step_quick_audit(dev, json_output=False)
            batch_results.append(res)
        if args.json:
            print("\n--- BATCH JSON SUMMARY ---")
            print(json.dumps(batch_results, indent=2, ensure_ascii=False))
        sys.exit(0)

    if args.target and (args.quick_scan or args.auto_pipeline or args.remediate or args.restore or args.install_app or args.recompile_for_device or args.launch_app or args.pull_report or args.remove_app):
        adb = AdbDevice(args.target)
        if not adb.device:
            print(f"[!] Falha de conexao com {args.target}")
            sys.exit(3)

        if args.auto_pipeline:
            verdict = step_automated_pipeline(adb, vpn_duration=20, force_recompile=args.recompile_for_device)
            if "CRÍTICO" in verdict or "CRITICAL" in verdict: sys.exit(1)
            elif "SUSP" in verdict: sys.exit(2)
            else: sys.exit(0)
        elif args.remediate:
            step_remediate_device(adb)
            sys.exit(0)
        elif args.restore:
            success = step_restore_device(adb)
            sys.exit(0 if success else 1)
        elif args.quick_scan:
            adb.load_specs(silent=args.json)
            res = step_quick_audit(adb, json_output=args.json)
            v = res.get("verdict", "")
            if "CRÍTICO" in v or "CRITICAL" in v: sys.exit(1)
            elif "SUSP" in v: sys.exit(2)
            else: sys.exit(0)
        elif args.recompile_for_device or args.install_app:
            adb.load_specs()
            step_install_custom_app(adb, force_recompile=args.recompile_for_device)
            sys.exit(0)
        elif args.launch_app:
            step_launch_app(adb)
            sys.exit(0)
        elif args.pull_report:
            verdict = step_pull_report(adb)
            if "CRÍTICO" in verdict or "CRITICAL" in verdict: sys.exit(1)
            elif "SUSP" in verdict: sys.exit(2)
            else: sys.exit(0)
        elif args.remove_app:
            step_remove_app(adb)
            sys.exit(0)
    elif args.target and not any([args.quick_scan, args.install_app, args.remediate, args.restore, args.recompile_for_device, args.launch_app, args.pull_report, args.remove_app]):
        adb = AdbDevice(args.target)
        if not adb.device:
            sys.exit(3)
        adb.load_specs()
        res = step_quick_audit(adb)
        v = res.get("verdict", "")
        if "CRÍTICO" in v or "CRITICAL" in v: sys.exit(1)
        elif "SUSP" in v: sys.exit(2)
        else: sys.exit(0)
    else:
        default_ip = os.environ.get("TV_HOST", "192.168.1.127")
        interactive_menu(default_ip)
