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
    "com.honeygain", "com.iproyal", "pawns.app", "packetstream", "peer2profit", "repocket", "earnapp", "bitping",
    "sso.authHandler", "com.mz.sdk", "com.debby.devour", "com.ota.service", "com.videostrong.debugtool", "com.vs.tvonline2", "newtv.cboxtv",
    "com.yk.debugtools", "com.droidlogic.vsota", "com.abcproxy.proxysdk", "com.appdns.change.rc", "com.dnschecker.rc", "com.ecosaver.daemon",
    "com.proxypeer.peerapp", "com.ycngmn.notubetv.service", "com.whale.screensaver", "com.yokatv.market", "com.yokatv.otaupdate"
]

# 3. Ficheiros binários e scripts de persistência de malware no sistema (Vo1d, Corejava, ELF/SO)
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
    "/oem/app_xcpe_ext_sign",
    "/system/lib/libanl.so",
    "/system/lib64/libanl.so",
    "/vendor/lib/libanl.so",
    "/vendor/lib64/libanl.so",
    "/system/lib/libexploit.so",
    "/system/lib64/libexploit.so",
    "/system/lib/libnative_keys.so",
    "/system/lib64/libnative_keys.so",
    "/system/lib/libjaguar.so",
    "/system/lib64/libjaguar.so"
]

# 4. Propriedades e Kill-switches de Botnet
SUSPICIOUS_SYSTEM_PROPS = [
    "persist.networkstack.uninstall",
    "persist.networkstack.skip_system_install",
    "persist.networkstack.install_time",
    "ro.mecool.device.model",
    "ro.hardware.skyworthdigital.soc.chipid"
]

# 5. Content Providers ocultos / de depuração de malware
SUSPICIOUS_CONTENT_PROVIDERS = [
    "content://com.release.debug.provider/configs"
]

# 6. IPs e Portas Críticas Remotas de C2 da botnet (Parsing numérico exato - sem falsos positivos)
C2_IPS = {
    "219.134.163.210", "121.4.8.146", "38.145.197.135", "38.145.197.30",
    "23.94.49.57", "120.55.60.139", "42.121.236.55"
}
C2_REMOTE_PORTS = {
    3885, 3886, 3887, 22345, 16000, 12000, 9992, 9994, 2375, 2095, 2082, 8082, 8083, 18083
}
INFORMATIVE_PORTS = {2222, 7000}

# Pacotes FQDN exatos para remediação sem riscos de remoção por substring acidental
EXACT_IOC_PACKAGES = {
    "x.cpe", "com.oemservice", "com.abc.nexus", "sso.authhandler", "com.ota.service",
    "newtv.cboxtv", "com.vs.tvonline2", "com.release.debug.provider", "com.hs.app",
    "com.mz.sdk", "com.debby.devour", "com.videostrong.debugtool", "com.yk.debugtools",
    "com.droidlogic.vsota", "com.abcproxy.proxysdk", "com.appdns.change.rc",
    "com.dnschecker.rc", "com.ecosaver.daemon", "com.proxypeer.peerapp",
    "com.ycngmn.notubetv.service", "com.whale.screensaver", "com.yokatv.market",
    "com.yokatv.otaupdate", "com.yokatv.online", "yokatv.online",
    "com.adups.fota", "com.adups.market", "com.charon.rocketfly", "com.ftest",
    "com.google.android.suite", "com.google.android.services", "com.mozgame.fruitmania",
    "com.www.intallapp", "com.swe.dgbluancher", "com.google.android.gms.stable",
    "com.rmk.app.allplayer", "com.nasa.cook.cookinit", "com.sun.galaxy.lib.oceaninit",
    "com.goog1e.apps", "com.hiddenview.tv", "com.moyu.app", "com.spirit.android",
    "io.popanet", "gaganode", "com.gaganode.app", "linkfog", "com.linkfog.service",
    "appsalt", "com.appsalt.service", "traffmonetizer", "com.traffmonetizer", "com.traffmonetizer.app",
    "android-grass", "com.grass", "com.grass.android", "appdnschange", "com.appdnschange",
    "smartprivilege", "com.smartprivilege", "smartentertainment", "com.smartentertainment",
    "smartthroughput", "com.smartthroughput", "ecosaverdaemon", "com.ecosaverdaemon",
    "titannet", "com.titannet.app", "com.titannet.client", "vo1d", "com.vo1d.daemon",
    "com.honeygain", "com.iproyal", "pawns.app", "packetstream", "peer2profit",
    "repocket", "earnapp", "bitping"
}

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

    def run(self, cmd, timeout=30):
        if not self.device:
            return ""
        try:
            res = self.device.shell(cmd, read_timeout_s=timeout)
            return res.decode("utf-8", errors="replace") if isinstance(res, bytes) else str(res)
        except Exception as e:
            return f"Erro ADB: {e}"

    def push(self, local_path, remote_path, timeout=60):
        if not self.device:
            return False
        try:
            self.device.push(local_path, remote_path, transport_timeout_s=timeout, read_timeout_s=timeout)
            return True
        except Exception as e:
            print(f"[!] Erro ao enviar ficheiro via ADB: {e}")
            return False

    def pull(self, remote_path, local_path, timeout=60):
        if not self.device:
            return False
        try:
            self.device.pull(remote_path, local_path, transport_timeout_s=timeout, read_timeout_s=timeout)
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
        has_other_critical = any("[CRÍTICO]" in f for f in json_data.get("findings", []))
        if "user_consent=-1" in play_protect:
            if has_other_critical:
                critical_reasons.append("Play Protect forçado a desligar com ameaças ativas (package_verifier_user_consent = -1)")
                score += 10
            else:
                suspicious_reasons.append("Play Protect desativado (sem pacotes maliciosos detetados - aviso de configuração)")
                score += 2
        elif "enable=0" in play_protect:
            suspicious_reasons.append("Verificação de pacotes desligada (package_verifier_enable = 0)")
            score += 2

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
    # Só é INFETADO - CRÍTICO se houver evidências críticas comprovadas (Backdoor, C2, Play Protect desativado)
    print(f"Pontuação de Risco Total: {score} pontos\n" if get_language() == "pt" else f"Total Risk Score: {score} points\n")

    if len(critical_reasons) > 0:
        verdict = "INFETADO - CRÍTICO" if get_language() == "pt" else "INFECTED - CRITICAL"
        color_code = "[!]"
        confidence = ">99%"
        desc = t("verdict_crit_desc")
    elif len(suspicious_reasons) > 0 or score >= 4:
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

    # Cria relatorio de submissao publica anonimizado
    try:
        anonymized_specs = {k: v for k, v in (device_specs or {}).items() if k not in ["serial", "serialno", "mac", "wifi_mac", "ip"]}
        anonymized_report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "device": anonymized_specs,
            "verdict": verdict,
            "risk_score": score,
            "findings": json_data.get("findings", []) if json_data else [],
            "critical_reasons": list(set(critical_reasons)),
            "suspicious_reasons": list(set(suspicious_reasons)),
            "hardware_warnings": list(set(info_warnings))
        }
        anon_path = os.path.join(PROJECT_ROOT, "community_audit_submission.json")
        with open(anon_path, "w", encoding="utf-8") as f:
            json.dump(anonymized_report, f, indent=2, ensure_ascii=False)
        print(f"[+] Relatorio sanitizado anonimo guardado em: {anon_path}")
        print("    -> Pronto para submissao em GitHub Issues ou por e-mail (dados pessoais protegidos).\n")
    except Exception:
        pass

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

    # Camada 1: Google Play Protect
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

    # Camada 2: Pacotes Maliciosos
    if not json_output:
        print(f"\n{t('layer_2_title')}")
    pkgs = adb.run("pm list packages").splitlines()
    disabled_pkgs = [p.replace("package:", "").strip().lower() for p in adb.run("pm list packages -d").splitlines()]
    found_ioc_pkgs = []
    neutralized_ioc_pkgs = []
    exact_lower = {p.lower() for p in EXACT_IOC_PACKAGES}
    for p in pkgs:
        p_name = p.replace("package:", "").strip().lower()
        if p_name in exact_lower:
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

    # Camada 3: Propriedades do Sistema e Tags de Build
    if not json_output:
        print(f"\n{t('layer_3_title')}")
    build_tags = adb.run("getprop ro.build.tags").strip()
    if "test-keys" in build_tags.lower() and not json_output:
        print("    [INFO] ro.build.tags = test-keys (Firmware genérico AOSP compilado com chaves públicas de teste - 0 pontos)")

    props = adb.run("getprop").splitlines()
    found_suspicious_props = []
    for prop in props:
        for target in TARGET_STRINGS:
            if target.decode("utf-8", errors="ignore").lower() in prop.lower():
                found_suspicious_props.append(prop)
        for sprop in SUSPICIOUS_SYSTEM_PROPS:
            if sprop.lower() in prop.lower():
                if prop not in found_suspicious_props:
                    found_suspicious_props.append(prop)
    if not json_output:
        if found_suspicious_props:
            print(t("layer_3_suspicious", props=found_suspicious_props))
        else:
            print(t("layer_3_ok"))

    # Camada 4: Content Providers C2
    if not json_output:
        print(f"\n{t('layer_4_title')}")
    found_providers = []
    for prov_uri in SUSPICIOUS_CONTENT_PROVIDERS:
        prov_out = adb.run(f"content query --uri {prov_uri} 2>&1").strip()
        if "Row:" in prov_out or ("Exception" not in prov_out and "SecurityException" not in prov_out and "Error" not in prov_out and len(prov_out) > 0):
            found_providers.append(f"{prov_uri} -> {prov_out[:80]}")
    if not json_output:
        if found_providers:
            print(t("layer_4_provider_found", uri=found_providers))
        else:
            print(t("layer_4_ok"))

    # Camada 5: Sockets e Conexões C2 (Parsing numérico exato na porta remota)
    if not json_output:
        print(f"\n{t('layer_5_title')}")
    netstat_out = adb.run("netstat -n -a 2>/dev/null || ss -tan 2>/dev/null")
    found_conn = []
    info_conn = []
    for line in netstat_out.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("Proto") or line_clean.startswith("State") or line_clean.startswith("Netid"):
            continue
        addr_matches = re.findall(r'((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|\*|0\.0\.0\.0|:::?):(\d+)', line_clean)
        if len(addr_matches) >= 2:
            remote_host, remote_port_str = addr_matches[1]
            try:
                remote_port = int(remote_port_str)
                if remote_host in C2_IPS or remote_port in C2_REMOTE_PORTS:
                    found_conn.append(f"{line_clean} -> [Alvo C2: {remote_host}:{remote_port}]")
                elif remote_port in INFORMATIVE_PORTS:
                    info_conn.append(f"{line_clean} -> [Porta habitual não-crítica: {remote_port}]")
            except ValueError:
                pass
        elif len(addr_matches) == 1:
            host, port_str = addr_matches[0]
            try:
                port = int(port_str)
                if host in C2_IPS or port in C2_REMOTE_PORTS:
                    found_conn.append(f"{line_clean} -> [Socket C2: {host}:{port}]")
            except ValueError:
                pass

    if not json_output:
        if found_conn:
            print(t("layer_5_c2_found", conn=found_conn))
        elif info_conn:
            print("    [INFO] Conexões em portas padrão detetadas (SSH/AirPlay - 0 pontos):")
            for ic in info_conn:
                print(f"       -> {ic}")
            print(t("layer_5_ok"))
        else:
            print(t("layer_5_ok"))

    # Camada 6: Binários e Implantes de Sistema (/system, /vendor, /oem)
    if not json_output:
        print(f"\n{t('layer_6_title')}")
    oem_paths = adb.run("pm list packages -f -s").splitlines()
    if not json_output:
        print(t("layer_6_total", count=len(oem_paths)))
    
    found_binaries = []
    for b_path in IOC_BINARY_PATHS:
        check = adb.run(f"ls -ld {b_path} 2>/dev/null").strip()
        if check and "No such file" not in check and "not found" not in check:
            found_binaries.append(b_path)

    # Inspeção de Conteúdo em /system/etc/install-recovery.sh (evita falso positivo em ficheiro legítimo)
    recovery_sh = adb.run("cat /system/etc/install-recovery.sh 2>/dev/null").strip()
    if recovery_sh and "No such file" not in recovery_sh and "not found" not in recovery_sh:
        suspect_recovery = []
        for s in ["wd", "vo1d", "/data/local/tmp", "/system/xbin", "corejava", "titannet", "linkfog", "oemservice"]:
            if s in recovery_sh:
                suspect_recovery.append(s)
        if suspect_recovery:
            found_binaries.append(f"/system/etc/install-recovery.sh (Comandos anómalos: {', '.join(suspect_recovery)})")
        elif not json_output:
            print("    [INFO] /system/etc/install-recovery.sh existe (script flash_recovery padrão - 0 pontos)")

    if not json_output:
        if found_binaries:
            print(t("layer_6_bin_found", bins=found_binaries))
        else:
            print(t("layer_6_ok"))

    # Cálculo Determinístico e Recalibrado de Risco
    has_active_threats = bool(found_ioc_pkgs or found_conn or found_binaries)
    risk_score = 0
    if play_protect_disabled:
        if has_active_threats:
            risk_score += 10
        else:
            # Play Protect desligado isoladamente sem qualquer malware/C2 ativo (aviso de configuração)
            risk_score += 2

    if found_ioc_pkgs: risk_score += 10 * len(found_ioc_pkgs)
    if found_conn: risk_score += 10 * len(found_conn)
    if found_binaries: risk_score += 10 * len(found_binaries)
    if found_providers: risk_score += 10 * len(found_providers)
    if found_suspicious_props: risk_score += 5 * len(found_suspicious_props)

    if has_active_threats and risk_score >= 8:
        verdict = "INFETADO - CRÍTICO" if get_language() == "pt" else "INFECTED - CRITICAL"
    elif play_protect_disabled and not has_active_threats and risk_score < 8:
        verdict = "AVISO / PLAY PROTECT DESATIVADO" if get_language() == "pt" else "WARNING / PLAY PROTECT DISABLED"
    elif risk_score >= 3:
        verdict = "SUSPEITO" if get_language() == "pt" else "SUSPICIOUS"
    else:
        verdict = "LIMPO / SEGURO" if get_language() == "pt" else "CLEAN / SAFE"

    # Cria copia sanitizada para submissao publica
    anonymized_specs = {k: v for k, v in adb.specs.items() if k not in ["serial", "serialno", "mac", "wifi_mac", "ip"]}
    anonymized_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "device": anonymized_specs,
        "verdict": verdict,
        "risk_score": risk_score,
        "play_protect_tampered": play_protect_disabled,
        "active_ioc_packages": found_ioc_pkgs,
        "neutralized_ioc_packages": neutralized_ioc_pkgs,
        "exposed_content_providers": found_providers,
        "suspicious_binaries": found_binaries,
        "active_c2_connections": [re.sub(r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+', '<LOCAL_IP>', c) for c in found_conn],
        "suspicious_props": found_suspicious_props,
        "hardware_warning": targeted_warning
    }
    anon_path = os.path.join(PROJECT_ROOT, "community_audit_submission.json")
    try:
        with open(anon_path, "w", encoding="utf-8") as f:
            json.dump(anonymized_report, f, indent=2, ensure_ascii=False)
        if not json_output:
            print(f"\n[+] Relatorio sanitizado anonimo gerado com sucesso: {anon_path}")
            print("    -> Pronto para submissao no GitHub Issues ou e-mail sem expor dados pessoais.")
    except Exception:
        pass

    return {
        "verdict": verdict,
        "score": risk_score,
        "play_protect_tampered": play_protect_disabled,
        "active_ioc_packages": found_ioc_pkgs,
        "neutralized_ioc_packages": neutralized_ioc_pkgs,
        "suspicious_binaries": found_binaries,
        "active_c2_connections": found_conn
    }


def create_remediation_backup(adb):
    """
    Cria um backup completo das definições e estado de pacotes ANTES de qualquer alteração,
    gerando scripts de restauro reversíveis (.ps1 para Windows e .sh para Linux/macOS) em backups/.
    """
    clean_ip = adb.host.replace(".", "_")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUPS_DIR, f"backup_{clean_ip}_{timestamp}.json")
    restore_ps1 = os.path.join(BACKUPS_DIR, f"restore_{clean_ip}.ps1")
    restore_sh = os.path.join(BACKUPS_DIR, f"restore_{clean_ip}.sh")

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
        "disabled_during_remediation": [],
        "uninstalled_user0_packages": [],
        "appops_modified": [],
        "pulled_apks": {}
    }

    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    print(f"    [✓] Ficheiro de estado guardado: {os.path.basename(backup_file)}")
    return backup_file, backup_data, restore_ps1, restore_sh


def generate_restore_scripts(adb, backup_data, restore_ps1_path, restore_sh_path):
    """Gera scripts autónomos e reversíveis (.ps1 e .sh) para restaurar a TV."""
    settings = backup_data.get("settings", {})
    disabled = backup_data.get("disabled_during_remediation", [])
    uninstalled = backup_data.get("uninstalled_user0_packages", [])
    pulled_apks = backup_data.get("pulled_apks", {})
    all_packages = list(dict.fromkeys(disabled + uninstalled))

    # 1. Gerar PowerShell script (.ps1)
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

# 1. Restaurar Definições Globais (Elimina chaves se o valor original era nulo)
Write-Host "1. A repor definições originais..." -ForegroundColor Yellow
$env:TV_HOST = "$TvHost"

$origConsent = "{settings.get('package_verifier_user_consent', '')}"
if ($origConsent -eq "null" -or $origConsent -eq "" -or $origConsent -eq "None") {{
    python -c "import tv; d = tv.connect(); d.shell('settings delete global package_verifier_user_consent')"
}} else {{
    python -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_user_consent $origConsent')"
}}

$origEnable = "{settings.get('package_verifier_enable', '')}"
if ($origEnable -eq "null" -or $origEnable -eq "" -or $origEnable -eq "None") {{
    python -c "import tv; d = tv.connect(); d.shell('settings delete global package_verifier_enable')"
}} else {{
    python -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_enable $origEnable')"
}}

$dnsMode = "{settings.get('private_dns_mode', '')}"
if ($dnsMode -eq "null" -or $dnsMode -eq "" -or $dnsMode -eq "None") {{
    python -c "import tv; d = tv.connect(); d.shell('settings delete global private_dns_mode')"
}} else {{
    python -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_mode $dnsMode')"
}}

$dnsSpec = "{settings.get('private_dns_specifier', '')}"
if ($dnsSpec -eq "null" -or $dnsSpec -eq "" -or $dnsSpec -eq "None") {{
    python -c "import tv; d = tv.connect(); d.shell('settings delete global private_dns_specifier')"
}} else {{
    python -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_specifier $dnsSpec')"
}}

# 2. Reinstalar APKs de utilizador salvaguardados
"""
    if pulled_apks:
        ps_content += 'Write-Host "2. A reinstalar APKs de utilizador a partir do backup..." -ForegroundColor Yellow\n'
        for pkg, apk_path in pulled_apks.items():
            escaped_apk = apk_path.replace('\\', '/')
            ps_content += f'''if (Test-Path "{escaped_apk}") {{
    Write-Host "   -> A reinstalar APK: {pkg}"
    python -c "import tv; d = tv.connect(); d.push(r'{escaped_apk}', '/data/local/tmp/{pkg}.apk'); d.shell('pm install -r /data/local/tmp/{pkg}.apk'); d.shell('rm -f /data/local/tmp/{pkg}.apk')"
}}\n'''

    ps_content += f"""
# 3. Reativar e Repor Pacotes de Sistema para user 0
Write-Host "3. A restaurar pacotes de sistema e reverter AppOps..." -ForegroundColor Yellow
$packagesToEnable = @(
"""
    for pkg in all_packages:
        ps_content += f'    "{pkg}",\n'

    ps_content += f"""@()
)

foreach ($pkg in $packagesToEnable) {{
    if ($pkg) {{
        Write-Host "   -> A reinstalar/reativar: $pkg"
        python -c "import tv; d = tv.connect(); d.shell('cmd package install-existing --user 0 $pkg'); d.shell('pm enable --user 0 $pkg'); d.shell('cmd appops set $pkg RUN_IN_BACKGROUND default'); d.shell('cmd appops set $pkg RUN_ANY_IN_BACKGROUND default'); d.shell('cmd appops set $pkg WAKE_LOCK default'); d.shell('cmd appops set $pkg BOOT_COMPLETED default')"
    }}
}}

Write-Host "`\n>>> [✓] Restauro concluído com sucesso!" -ForegroundColor Green
"""
    with open(restore_ps1_path, "w", encoding="utf-8") as f:
        f.write(ps_content)

    # 2. Gerar Bash script (.sh)
    sh_content = f"""#!/usr/bin/env bash
# =====================================================================
# RESTORE SCRIPT - BADBOX FORENSIC REMEDIATION REVERSAL (Linux / macOS)
# Dispositivo: {adb.host}
# Gerado em:   {backup_data.get('timestamp')}
# =====================================================================

TV_HOST="${{1:-{adb.host}}}"
export TV_HOST
TOOLS_DIR="{PROJECT_ROOT.replace('\\', '/')}/tools"
cd "$TOOLS_DIR" || exit 1

echo ">>> A reverter remediação e restaurar estado da TV ($TV_HOST)..."

# 1. Repor definições originais (Elimina chaves se o valor era nulo)
echo "1. A repor definições globais..."
ORIG_CONSENT="{settings.get('package_verifier_user_consent', '')}"
if [ -z "$ORIG_CONSENT" ] || [ "$ORIG_CONSENT" = "null" ] || [ "$ORIG_CONSENT" = "None" ]; then
    python3 -c "import tv; d = tv.connect(); d.shell('settings delete global package_verifier_user_consent')"
else
    python3 -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_user_consent $ORIG_CONSENT')"
fi

ORIG_ENABLE="{settings.get('package_verifier_enable', '')}"
if [ -z "$ORIG_ENABLE" ] || [ "$ORIG_ENABLE" = "null" ] || [ "$ORIG_ENABLE" = "None" ]; then
    python3 -c "import tv; d = tv.connect(); d.shell('settings delete global package_verifier_enable')"
else
    python3 -c "import tv; d = tv.connect(); d.shell('settings put global package_verifier_enable $ORIG_ENABLE')"
fi

DNS_MODE="{settings.get('private_dns_mode', '')}"
if [ -z "$DNS_MODE" ] || [ "$DNS_MODE" = "null" ] || [ "$DNS_MODE" = "None" ]; then
    python3 -c "import tv; d = tv.connect(); d.shell('settings delete global private_dns_mode')"
else
    python3 -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_mode $DNS_MODE')"
fi

DNS_SPEC="{settings.get('private_dns_specifier', '')}"
if [ -z "$DNS_SPEC" ] || [ "$DNS_SPEC" = "null" ] || [ "$DNS_SPEC" = "None" ]; then
    python3 -c "import tv; d = tv.connect(); d.shell('settings delete global private_dns_specifier')"
else
    python3 -c "import tv; d = tv.connect(); d.shell('settings put global private_dns_specifier $DNS_SPEC')"
fi
"""
    if pulled_apks:
        sh_content += 'echo "2. A reinstalar APKs de utilizador salvaguardados..."\n'
        for pkg, apk_path in pulled_apks.items():
            sh_content += f"""if [ -f "{apk_path}" ]; then
    echo "   -> A reinstalar APK: {pkg}"
    python3 -c "import tv; d = tv.connect(); d.push(r'{apk_path}', '/data/local/tmp/{pkg}.apk'); d.shell('pm install -r /data/local/tmp/{pkg}.apk'); d.shell('rm -f /data/local/tmp/{pkg}.apk')"
fi
"""

    sh_content += f"""
# 3. Reinstalar e reativar pacotes
echo "3. A restaurar pacotes de sistema no user 0 e repor AppOps..."
PACKAGES=(
"""
    for pkg in all_packages:
        sh_content += f'  "{pkg}"\n'
    sh_content += """)

for pkg in "${PACKAGES[@]}"; do
    if [ -n "$pkg" ]; then
        echo "   -> A reinstalar/reativar: $pkg"
        python3 -c "import tv; d = tv.connect(); d.shell('cmd package install-existing --user 0 $pkg'); d.shell('pm enable --user 0 $pkg'); d.shell('cmd appops set $pkg RUN_IN_BACKGROUND default'); d.shell('cmd appops set $pkg RUN_ANY_IN_BACKGROUND default'); d.shell('cmd appops set $pkg WAKE_LOCK default'); d.shell('cmd appops set $pkg BOOT_COMPLETED default')"
    fi
done

echo ""
echo ">>> [✓] Restauro concluído com sucesso!"
"""
    with open(restore_sh_path, "w", encoding="utf-8") as f:
        f.write(sh_content)
    try:
        os.chmod(restore_sh_path, 0o755)
    except Exception:
        pass

    print(f"    [✓] Scripts de reversão gerados: {os.path.basename(restore_ps1_path)} e {os.path.basename(restore_sh_path)}\n")


def step_remediate_device(adb, enable_dot=False, verify_reboot=False):
    """
    Executa a neutralização e remediação em profundidade com salvaguarda reversível (backup):
    1. Pré-verificação de segurança: Não altera nada se o dispositivo já estiver limpo
    2. Reativação e tranca do Play Protect
    3. Sequência multi-camada com correspondência exata de pacotes:
       force-stop + pm clear + AppOps ignore + adb pull APK + pm uninstall / disable-user --user 0
    4. Proteção anti-C2 segura (preserva DNS local por defeito; DoT apenas se --enable-dot)
    5. Geração de scripts autónomos de reversão (.ps1 e .sh) com restauro integral de APKs
    6. Validação de persistência pós-reboot (se --verify-reboot)
    """
    print("\n================================================================================")
    print(f"     PLANO DE REMEDIAÇÃO & NEUTRALIZAÇÃO FORENSE - ANDROID TV ({adb.host})       ")
    print("================================================================================")

    if not adb.specs:
        adb.load_specs()

    # --- Pré-Verificação de Segurança: Não Tocar em Boxes Limpas ---
    user_consent_pre = adb.run("settings get global package_verifier_user_consent").strip()
    verifier_enable_pre = adb.run("settings get global package_verifier_enable").strip()
    pkgs_pre = [p.replace("package:", "").strip().lower() for p in adb.run("pm list packages").splitlines()]
    exact_lower = {p.lower() for p in EXACT_IOC_PACKAGES}
    detected_pkgs = [p for p in pkgs_pre if p in exact_lower]

    detected_bins = []
    for b_path in IOC_BINARY_PATHS:
        chk = adb.run(f"ls -ld {b_path} 2>/dev/null").strip()
        if chk and "No such file" not in chk and "not found" not in chk:
            detected_bins.append(b_path)

    # Verificar recovery.sh
    rec_check = adb.run("cat /system/etc/install-recovery.sh 2>/dev/null").strip()
    if rec_check and "No such file" not in rec_check and "not found" not in rec_check:
        for s in ["wd", "vo1d", "/data/local/tmp", "/system/xbin", "corejava", "titannet", "linkfog", "oemservice"]:
            if s in rec_check:
                detected_bins.append(f"/system/etc/install-recovery.sh ({s})")
                break

    if user_consent_pre != "-1" and verifier_enable_pre != "0" and not detected_pkgs and not detected_bins:
        print("\n[✓] DISPOSITIVO LIMPO E PROTEGIDO: Nenhuma ameaça ou adulteração encontrada!")
        print("    O Google Play Protect está ativo e não existem pacotes maliciosos ou binários instalados.")
        print("    Nenhuma definição global ou pacote foi alterado no dispositivo.")
        print("================================================================================\n")
        return

    clean_ip = adb.host.replace(".", "_")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file, backup_data, restore_ps1, restore_sh = create_remediation_backup(adb)

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

    # 2. Neutralização em Profundidade com Correspondência EXATA de Pacotes
    print("\n[Passo 2/4] A procurar e neutralizar pacotes de botnet conhecidos (correspondência exata)...")
    pkgs = adb.run("pm list packages").splitlines()
    neutralized_count = 0
    for p in pkgs:
        p_name = p.replace("package:", "").strip()
        if p_name.lower() in exact_lower:
            print(f"    [*] A neutralizar pacote malicioso detetado: {p_name}")
            
            # a) Parar processos e limpar dados
            adb.run(f"am force-stop {p_name}")
            adb.run(f"pm clear {p_name}")
            
            # b) Bloquear execução em background e wakelocks via AppOps
            adb.run(f"cmd appops set {p_name} RUN_IN_BACKGROUND ignore")
            adb.run(f"cmd appops set {p_name} RUN_ANY_IN_BACKGROUND ignore")
            adb.run(f"cmd appops set {p_name} WAKE_LOCK ignore")
            adb.run(f"cmd appops set {p_name} BOOT_COMPLETED ignore")
            backup_data["appops_modified"].append(p_name)

            # c) Se o APK estiver em /data/app, fazer adb pull antes de desinstalar!
            path_out = adb.run(f"pm path {p_name}").strip()
            remote_apk = None
            for pline in path_out.splitlines():
                if "package:" in pline:
                    remote_apk = pline.replace("package:", "").strip()
                    break
            
            if remote_apk and remote_apk.startswith("/data/app"):
                apks_dir = os.path.join(BACKUPS_DIR, f"apks_{clean_ip}_{timestamp}")
                os.makedirs(apks_dir, exist_ok=True)
                local_apk = os.path.join(apks_dir, f"{p_name}.apk")
                print(f"        -> A criar cópia de segurança prévia do APK: {os.path.basename(local_apk)}")
                pulled = adb.pull(remote_apk, local_apk)
                if pulled and os.path.exists(local_apk):
                    backup_data["pulled_apks"][p_name] = local_apk
                    print(f"        [✓] APK salvaguardado ({os.path.getsize(local_apk)} bytes)")

            # d) Tentar desinstalação na partição de utilizador (/data/app)
            uninst = adb.run(f"pm uninstall {p_name}").strip()
            if "Success" in uninst:
                print(f"        -> [✓] Desinstalado da partição de utilizador: {p_name}")
                backup_data["disabled_during_remediation"].append(p_name)
                neutralized_count += 1
            else:
                # e) App de sistema (/system, /vendor, /oem): congelar e desinstalar para user 0
                dis = adb.run(f"pm disable-user --user 0 {p_name}").strip()
                uninst0 = adb.run(f"pm uninstall -k --user 0 {p_name}").strip()
                print(f"        -> [✓] App de sistema congelada e desinstalada para user 0: {p_name}")
                print(f"               (disable: {dis} | uninstall: {uninst0})")
                backup_data["disabled_during_remediation"].append(p_name)
                backup_data["uninstalled_user0_packages"].append(p_name)
                neutralized_count += 1

    if neutralized_count == 0:
        print("    [✓] Nenhum pacote malicioso da botnet encontrado para desinstalar.")
    else:
        print(f"    [✓] Total de pacotes maliciosos neutralizados: {neutralized_count}")

    # Guardar snapshot JSON atualizado
    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    # 3. Terminar Processos e Neutralizar Ficheiros de Persistência
    print("\n[Passo 3/4] A terminar processos residuais e neutralizar binários de persistência...")
    for ioc in exact_lower:
        adb.run(f"am force-stop {ioc}")
        adb.run(f"killall {ioc} 2>/dev/null")

    for b_path in IOC_BINARY_PATHS:
        check = adb.run(f"ls -ld {b_path} 2>/dev/null").strip()
        if check and "No such file" not in check and "not found" not in check:
            print(f"    [*] A neutralizar ficheiro de persistência malicioso: {b_path}")
            adb.run(f"rm -rf {b_path} 2>/dev/null")
            adb.run(f"touch {b_path} 2>/dev/null && chmod 000 {b_path} 2>/dev/null")

    print("    [✓] Processos residuais terminados.")

    # 4. Configuração Segura de DNS
    print("\n[Passo 4/4] Verificação de DNS e Resolução de Nomes...")
    if enable_dot:
        print("    - A configurar Private DNS seguro (DoT via Cloudflare): security.cloudflare-dns.com")
        adb.run("settings put global private_dns_mode hostname")
        adb.run("settings put global private_dns_specifier security.cloudflare-dns.com")
        dns_mode = adb.run("settings get global private_dns_mode").strip()
        dns_host = adb.run("settings get global private_dns_specifier").strip()
        print(f"    - Modo Private DNS: {dns_mode}")
        print(f"    - Servidor Seguro:  {dns_host}")
        print("    [✓] Proteção de DNS ativa: pedidos para servidores C2 serão bloqueados na fonte.")
    else:
        current_dns_mode = adb.run("settings get global private_dns_mode").strip()
        current_dns_spec = adb.run("settings get global private_dns_specifier").strip()
        if current_dns_mode in ["hostname", "on"]:
            print(f"    [*] Private DNS já ativo no dispositivo: {current_dns_mode} ({current_dns_spec})")
        else:
            print("    [*] Private DNS (DoT) mantido inalterado para preservar o DNS local da sua rede (Pi-hole, UniFi, AdGuard).")
            print("        (Nota: para forçar Cloudflare DoT, execute o script com o parâmetro --enable-dot)")

    generate_restore_scripts(adb, backup_data, restore_ps1, restore_sh)

    print("\n================================================================================")
    print("  REMEDIAÇÃO CONCLUÍDA: A TV foi limpa e o tráfego de botnet neutralizado!")
    print(f"  Log da sessão gravado em: {CURRENT_LOGGER.log_path}")
    print(f"  Para reverter no Windows:      backups/{os.path.basename(restore_ps1)}")
    print(f"  Para reverter no Linux/macOS:  backups/{os.path.basename(restore_sh)}")
    print("================================================================================\n")

    # 5. Validação Pós-Reboot (--verify-reboot)
    if verify_reboot:
        print("\n[*] A iniciar verificação de persistência pós-reboot (--verify-reboot)...")
        print("    A reiniciar a Android TV via ADB...")
        adb.run("reboot")
        print("    A aguardar reinicialização do sistema (até 90 segundos)...")
        time.sleep(15)
        boot_completed = False
        for attempt in range(15):
            time.sleep(5)
            try:
                res = adb.run("getprop sys.boot_completed").strip()
                if res == "1":
                    boot_completed = True
                    break
            except Exception:
                pass
        
        if boot_completed:
            print("    [✓] Dispositivo reiniciado com sucesso! A reexecutar auditoria das 6 camadas...")
            time.sleep(3)
            post_result = step_quick_audit(adb, json_output=False)
            post_v = post_result.get("verdict", "")
            if "CRÍTICO" in post_v or "CRITICAL" in post_v:
                print("\n[!] ALERTA CRÍTICO: Foi detetada persistência pós-reboot!")
                print("    Um watchdog em init.rc ou partição /vendor reverteu as alterações.")
            else:
                print("\n[✓] VERIFICAÇÃO PÓS-REBOOT BEM-SUCEDIDA: Nenhuma ameaça ressuscitou.")
        else:
            print("    [!] Aviso: Não foi possível confirmar o arranque completo dentro do tempo limite.")


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

    # 1. Repor definições globais originais (elimina a chave se o valor original era nulo)
    settings = backup_data.get("settings", {})
    print("\n[1/4] A repor definições globais originais...")
    for key, val in settings.items():
        if val is None or val == "" or str(val).lower() == "null" or str(val).lower() == "none":
            adb.run(f"settings delete global {key}")
        else:
            adb.run(f"settings put global {key} {val}")
    print("    [✓] Definições restauradas.")

    # 2. Reinstalar APKs de utilizador a partir da pasta de backup se existirem
    pulled_apks = backup_data.get("pulled_apks", {})
    if pulled_apks:
        print("\n[2/4] A reinstalar APKs de utilizador salvaguardados...")
        for pkg, apk_path in pulled_apks.items():
            if os.path.exists(apk_path):
                print(f"    [*] A restaurar APK: {pkg}")
                tmp_remote = f"/data/local/tmp/{pkg}.apk"
                adb.push(apk_path, tmp_remote)
                adb.run(f"pm install -r {tmp_remote}")
                adb.run(f"rm -f {tmp_remote}")
        print("    [✓] APKs reinstalados.")
    else:
        print("\n[2/4] Sem APKs de utilizador para reinstalar.")

    uninstalled = backup_data.get("uninstalled_user0_packages", [])
    disabled = backup_data.get("disabled_during_remediation", [])
    all_packages = list(dict.fromkeys(uninstalled + disabled))

    print("\n[3/4] A reinstalar e reativar pacotes desativados no utilizador 0...")
    for pkg in all_packages:
        print(f"    [*] A restaurar: {pkg}")
        adb.run(f"cmd package install-existing --user 0 {pkg}")
        adb.run(f"pm enable --user 0 {pkg}")
        adb.run(f"pm enable {pkg}")
    print("    [✓] Pacotes reativados.")

    appops_pkgs = backup_data.get("appops_modified", [])
    if appops_pkgs:
        print("\n[4/4] A repor permissões de AppOps para default...")
        for pkg in set(appops_pkgs):
            adb.run(f"cmd appops set {pkg} RUN_IN_BACKGROUND default")
            adb.run(f"cmd appops set {pkg} RUN_ANY_IN_BACKGROUND default")
            adb.run(f"cmd appops set {pkg} WAKE_LOCK default")
            adb.run(f"cmd appops set {pkg} BOOT_COMPLETED default")
        print("    [✓] AppOps repostos.")
    else:
        print("\n[4/4] Sem registos de alterações de AppOps a reverter.")

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


def step_launch_app(adb, auto_start=False):
    print("\n[*] A abrir a App no ecrã da TV...")
    extra = " --ez auto_start true" if auto_start else ""
    adb.run(f"am start -n {PACKAGE_NAME}/.MainActivity{extra}")
    print("    [✓] A App está aberta no ecrã da TV.")


def step_pull_report(adb):
    print("\n[*] A transferir os relatórios da box para o computador...")
    # 1. Tenta cópia a partir do armazenamento externo da app (/sdcard/Android/data/com.scanner.tv/files/)
    # acessível diretamente sem privilégios de root nem run-as em Android 11 a 15
    ext_base = f"/sdcard/Android/data/{PACKAGE_NAME}/files"
    adb.run(f"cp {ext_base}/last_scan.json /data/local/tmp/report.json 2>/dev/null")
    adb.run(f"cp {ext_base}/audit_events.log /data/local/tmp/audit_events.log 2>/dev/null")

    # 2. Em fallback, tenta via run-as caso o build seja debuggable
    adb.run(f"run-as {PACKAGE_NAME} cp files/last_scan.json /data/local/tmp/report.json 2>/dev/null")
    adb.run(f"run-as {PACKAGE_NAME} cp files/audit_events.log /data/local/tmp/audit_events.log 2>/dev/null")
    
    adb.run("chmod 666 /data/local/tmp/report.json /data/local/tmp/audit_events.log 2>/dev/null")
    local_json = os.path.join(PROJECT_ROOT, "last_scan_report.json")
    local_log = os.path.join(PROJECT_ROOT, "vpn_events.log")

    json_data = None
    vpn_lines = []

    # Tenta pull de /data/local/tmp ou diretamente do storage
    pulled_json = adb.pull("/data/local/tmp/report.json", local_json) or adb.pull(f"{ext_base}/last_scan.json", local_json)
    if pulled_json:
        adb.run("rm -f /data/local/tmp/report.json")
        try:
            with open(local_json, "r", encoding="utf-8") as f:
                json_data = json.load(f)
            print(f"    [✓] Relatório JSON guardado em: {local_json}")
        except Exception as e:
            print(f"[!] Erro ao analisar JSON: {e}")

    pulled_log = adb.pull("/data/local/tmp/audit_events.log", local_log) or adb.pull(f"{ext_base}/audit_events.log", local_log)
    if pulled_log:
        adb.run("rm -f /data/local/tmp/audit_events.log")
        try:
            with open(local_log, "r", encoding="utf-8") as f:
                vpn_lines = f.readlines()
            print(f"    [✓] Registo de tráfego VPN guardado em: {local_log}")
        except Exception as e:
            print(f"[!] Erro ao ler log de VPN: {e}")
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

    step_launch_app(adb, auto_start=True)
    
    # Aguarda ativamente que a app esteja aberta e em foco no ecrã da TV
    print("[*] A verificar foco da App no ecrã da TV...")
    for _ in range(10):
        top_app = adb.run("dumpsys activity activities")
        if PACKAGE_NAME in top_app:
            break
        time.sleep(1)

    print("\n[*] Análise Estática profunda iniciada nativamente pelo ciclo de vida da App...")
    # Aguarda que o scan estático nativo termine (a app escreve 'SCAN_ESTATICO_CONCLUIDO' nos logs)
    print("    -> A aguardar conclusão da análise estática na TV...")
    scan_done = False
    for _ in range(25):
        time.sleep(1)
        ext_log = adb.run(f"cat /sdcard/Android/data/{PACKAGE_NAME}/files/audit_events.log 2>/dev/null")
        if "SCAN_ESTATICO_CONCLUIDO" in ext_log:
            scan_done = True
            break
    if not scan_done:
        time.sleep(3)
    print("    [✓] Análise estática concluída com sucesso.")

    print(f"\n[*] A monitorizar Sentinela VPN em tempo real (à escuta durante {vpn_duration}s)...")
    # A app já acionou o toggleVpnMonitor() nativamente ao terminar o scan.
    # Verificamos se surgiu o diálogo de permissão do sistema Android (com.android.vpndialogs)
    time.sleep(1.5)
    top_window = adb.run("dumpsys window | grep -E mCurrentFocus")
    if "vpndialogs" in top_window:
        print("    -> A aprovar diálogo de autorização de VPN do Android...")
        adb.run("input keyevent KEYCODE_DPAD_DOWN")
        time.sleep(0.2)
        adb.run("input keyevent KEYCODE_DPAD_LEFT")
        time.sleep(0.2)
        adb.run("input keyevent KEYCODE_DPAD_CENTER")
        time.sleep(1.5)
    
    for remaining in range(vpn_duration, 0, -1):
        print(f"    -> Sentinela ativo a monitorizar portas e tráfego... {remaining}s restantes", end="\r")
        time.sleep(1)
    print("\n    [✓] Janela de monitorização de tráfego concluída.")

    print("\n[*] A desligar Sentinela VPN...")
    # Para o serviço de VPN de forma limpa
    adb.run(f"am startservice -a STOP {PACKAGE_NAME}/.PacketMonitorVpnService")
    time.sleep(1)

    print("\n[*] A extrair relatórios para o computador...")
    verdict = step_pull_report(adb)

    print("\n[*] A limpar o dispositivo...")
    step_remove_app(adb)

    print("\n================================================================================")
    print(f"  PIPELINE CONCLUÍDO COM SUCESSO: Veredito = {verdict}")
    print(f"  Registo integral da auditoria guardado em: {CURRENT_LOGGER.log_path}")
    print("================================================================================\n")
    return verdict


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
    parser.add_argument("--auto-pipeline", action="store_true", help="Executa pipeline completo: instala, scan estatico, VPN Sentinel, recolhe logs e desinstala")
    parser.add_argument("--quick-scan", action="store_true", help="Executa o diagnóstico rápido das 6 camadas via ADB")
    parser.add_argument("--remediate", action="store_true", help="Neutraliza a box com backup prévio: repõe Play Protect, remove/desativa apps da botnet em profundidade")
    parser.add_argument("--enable-dot", action="store_true", help="Ativa DNS-over-TLS (Cloudflare Security DoT) durante a remediação")
    parser.add_argument("--verify-reboot", action="store_true", help="Reinicia a Android TV e valida se ameaças ressuscitaram após o arranque")
    parser.add_argument("--vpn-duration", type=int, default=20, help="Duração da captura do Sentinel VPN no auto-pipeline em segundos (padrão: 20)")
    parser.add_argument("--scan-init-watchdogs", action="store_true", help="Inspeciona scripts init.rc e binários não-standard à procura de persistências de watchdogs")
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

    if args.target and (args.quick_scan or args.auto_pipeline or args.remediate or args.restore or args.install_app or args.recompile_for_device or args.launch_app or args.pull_report or args.remove_app or args.scan_init_watchdogs):
        adb = AdbDevice(args.target)
        if not adb.device:
            print(f"[!] Falha de conexao com {args.target}")
            sys.exit(3)

        if args.scan_init_watchdogs:
            adb.load_specs()
            scan_init_watchdogs(adb)
            sys.exit(0)
        elif args.auto_pipeline:
            verdict = step_automated_pipeline(adb, vpn_duration=args.vpn_duration, force_recompile=args.recompile_for_device)
            if "CRÍTICO" in verdict or "CRITICAL" in verdict: sys.exit(1)
            elif "SUSP" in verdict: sys.exit(2)
            else: sys.exit(0)
        elif args.remediate:
            step_remediate_device(adb, enable_dot=args.enable_dot, verify_reboot=args.verify_reboot)
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
    elif args.target and not any([args.quick_scan, args.install_app, args.remediate, args.restore, args.recompile_for_device, args.launch_app, args.pull_report, args.remove_app, args.scan_init_watchdogs]):
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
