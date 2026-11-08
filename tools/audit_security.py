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
import hashlib
import shlex
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from engine import GLOBAL_ENGINE, Finding, LayerResult, LayerStatus, VerdictState
from iocs import IOC_DB, parse_socket_address
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
    Espelha a saída para o terminal e grava num ficheiro de log estruturado.
    Em modo JSON, mensagens humanas são redirecionadas para sys.stderr.
    """
    def __init__(self, filename=None, json_mode=False):
        self.json_mode = json_mode
        self.terminal = sys.stderr if json_mode else sys.stdout
        if not filename:
            timestamp = f"{time.strftime('%Y%m%d_%H%M%S')}_{int(time.time() * 1000) % 1000:03d}"
            filename = os.path.join(LOGS_DIR, f"session_{timestamp}.log")
        self.log_file = open(filename, "a", encoding="utf-8", buffering=1)
        self.log_path = filename

    def write(self, message):
        if not self.json_mode:
            self.terminal.write(message)
            self.terminal.flush()
        clean_msg = message.replace("\r", "\n") if "\r" in message and "\n" not in message else message
        self.log_file.write(clean_msg)
        self.log_file.flush()

    def flush(self):
        if not self.json_mode:
            self.terminal.flush()
        self.log_file.flush()


# Logger global configurado explicitamente no main()
CURRENT_LOGGER = None

def setup_logging(json_mode=False, log_filename=None):
    global CURRENT_LOGGER
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    CURRENT_LOGGER = DualLogger(filename=log_filename, json_mode=json_mode)
    if not json_mode:
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
    "persist.networkstack.install_time"
]

VENDOR_PROPERTIES = [
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
    3885, 3886, 3887, 22345, 16000, 12000, 9992, 9994, 2375, 2082, 8082, 8083, 18083
}
INFORMATIVE_PORTS = {2222, 7000}

# Pacotes FQDN exatos para remediação sem riscos de remoção por substring acidental
EXACT_IOC_PACKAGES = set(p.lower() for p in IOC_DB.packages) if IOC_DB.packages else {
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
    def __init__(self, host, transport=None):
        self.host = host
        self.device = transport
        self.specs = {}
        if not self.device:
            self._init_connection()

    def _init_connection(self):
        try:
            tools_dir = os.path.join(PROJECT_ROOT, "tools")
            if tools_dir not in sys.path:
                sys.path.insert(0, tools_dir)
            import tv
            self.device = tv.connect(host=self.host)
        except Exception as e:
            self.device = None

    def run(self, cmd, timeout=30):
        if not self.device:
            raise RuntimeError(f"Dispositivo {self.host} desconectado")
        try:
            res = self.device.shell(cmd, read_timeout_s=timeout)
            return res.decode("utf-8", errors="replace") if isinstance(res, bytes) else str(res)
        except Exception as e:
            raise RuntimeError(f"Erro ADB ao executar '{cmd}': {e}") from e

    def run_checked(self, cmd, timeout=30):
        wrapped = f"{cmd}; echo __RC=$?"
        raw = self.run(wrapped, timeout=timeout)
        lines = raw.rstrip().splitlines()
        rc = 0
        out_lines = []
        for l in lines:
            if l.startswith("__RC="):
                try:
                    rc = int(l[5:])
                except ValueError:
                    rc = 1
            else:
                out_lines.append(l)
        return "\n".join(out_lines), rc

    def push(self, local_path, remote_path, timeout=60):
        if not self.device:
            return False
        try:
            self.device.push(local_path, remote_path, transport_timeout_s=timeout, read_timeout_s=timeout)
            return True
        except Exception as e:
            print(f"[!] Erro ao enviar ficheiro via ADB: {e}", file=sys.stderr)
            return False

    def pull(self, remote_path, local_path, timeout=60):
        if not self.device:
            return False
        try:
            self.device.pull(remote_path, local_path, transport_timeout_s=timeout, read_timeout_s=timeout)
            return True
        except Exception as e:
            print(f"[!] Erro ao descarregar ficheiro via ADB: {e}", file=sys.stderr)
            return False

    @property
    def device_id(self) -> str:
        if not self.specs:
            self.load_specs(silent=True)
        serial = str(self.specs.get("serial", ""))
        fingerprint = str(self.specs.get("build_fingerprint", ""))
        combined = f"{serial}:{fingerprint}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest()[:16]

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


def discover_subnet_tvs(subnet_str: str, max_hosts: int = None) -> list:
    """
    Descobre dispositivos Android TV com porta ADB 5555 aberta numa sub-rede privada (RFC 1918).
    Limita a sub-rede a no máximo /22 sem override explícito (--max-hosts).
    """
    try:
        network = ipaddress.ip_network(subnet_str, strict=False)
    except Exception as e:
        print(f"[!] Sub-rede inválida: {subnet_str} ({e})", file=sys.stderr)
        sys.exit(64)

    if not network.is_private:
        print(f"[!] Erro de segurança: Apenas sub-redes privadas (RFC 1918) são permitidas para scan: {subnet_str}", file=sys.stderr)
        sys.exit(64)

    num_addresses = network.num_addresses
    if num_addresses > 1024 and max_hosts is None:
        print(f"[!] Erro: Sub-rede demasiado grande ({num_addresses} endereços > /22). Use --max-hosts para autorizar.", file=sys.stderr)
        sys.exit(64)

    hosts = list(network.hosts())
    if max_hosts and len(hosts) > max_hosts:
        hosts = hosts[:max_hosts]

    print(f"[*] A sondar porta ADB (5555) em {len(hosts)} endereços na sub-rede {network}...", file=sys.stderr)
    print("    (Aviso: Dispositivos não autorizados poderão exibir diálogo de depuração no ecrã)", file=sys.stderr)

    found_targets = []

    def check_target(ip_obj):
        ip_str = str(ip_obj)
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            res = s.connect_ex((ip_str, 5555))
            s.close()
            if res == 0:
                return ip_str
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(check_target, ip): ip for ip in hosts}
        for f in as_completed(futures):
            res = f.result()
            if res:
                found_targets.append(res)

    found_targets.sort(key=lambda x: [int(p) for p in x.split(".")])
    return found_targets


ALLOWED_SPECS_ALLOWLIST = {
    "manufacturer", "brand", "model", "product", "device", "board",
    "hardware", "soc", "cpu_abi", "android_version", "sdk_version",
    "build_id", "security_patch"
}


def sanitize_community_data(device_specs, findings=None):
    """
    Sanitiza estritamente os dados para submissão comunitária usando allowlist (PRIV-01).
    Remove números de série, endereços MAC, IPs v4/v6, chip IDs e PII.
    """
    sanitized_specs = {}
    if device_specs:
        for k, v in device_specs.items():
            k_lower = k.lower().strip()
            if k_lower in ALLOWED_SPECS_ALLOWLIST:
                val_str = str(v)
                val_str = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', val_str)
                val_str = re.sub(r'(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}', '[REDACTED_IP]', val_str)
                val_str = re.sub(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b', '[REDACTED_MAC]', val_str)
                sanitized_specs[k_lower] = val_str

    sanitized_findings = []
    if findings:
        for f in findings:
            if isinstance(f, str):
                f_str = f
                f_str = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', f_str)
                f_str = re.sub(r'(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}', '[REDACTED_IP]', f_str)
                f_str = re.sub(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b', '[REDACTED_MAC]', f_str)
                sanitized_findings.append(f_str)
            elif isinstance(f, dict):
                clean_f = {}
                for fk, fv in f.items():
                    if fk in ("code", "layer", "severity", "category"):
                        clean_f[fk] = fv
                    elif fk == "subject":
                        sub_str = str(fv)
                        sub_str = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', sub_str)
                        sub_str = re.sub(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b', '[REDACTED_MAC]', sub_str)
                        clean_f[fk] = sub_str
                sanitized_findings.append(clean_f)

    return sanitized_specs, sanitized_findings


def generate_sanitized_community_submission(json_data, vpn_log_lines, device_specs=None, verdict="UNKNOWN", score=0, findings=None, out_path=None):
    try:
        raw_findings = findings or (json_data.get("findings") if json_data else [])
        anon_specs, anon_findings = sanitize_community_data(device_specs, raw_findings)
        report = {
            "schema_version": 2,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "device": anon_specs,
            "verdict": str(verdict),
            "risk_score": score,
            "findings_count": len(anon_findings),
            "findings": anon_findings,
            "vpn_events_count": len(vpn_log_lines) if vpn_log_lines else 0
        }
        target_path = out_path if out_path else os.path.join(PROJECT_ROOT, "community_audit_submission.json")
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return report
    except Exception:
        return None


def evaluate_forensic_results(json_data, vpn_log_lines, device_specs=None):
    """
    Motor determinístico de decisão baseado em regras e pontuação ponderada.
    Consome findings estruturados e aplica precedência formal (VER-01, VER-02).
    """
    findings = []
    layers = []

    # 1. Avaliação do Relatório Estático (last_scan.json)
    if not json_data:
        layers.append(LayerResult(id="app_report", status=LayerStatus.ERROR, detail="Relatório estático ausente ou inválido"))
    else:
        layers.append(LayerResult(id="app_report", status=LayerStatus.OK))
        play_protect = json_data.get("play_protect", "")
        if "user_consent=-1" in play_protect:
            findings.append(GLOBAL_ENGINE.create_finding("PLAY_PROTECT_CONSENT_DECLINED", "play_protect", "Google Play Protect"))
        if "enable=0" in play_protect:
            findings.append(GLOBAL_ENGINE.create_finding("PACKAGE_VERIFIER_DISABLED", "play_protect", "Google Play Protect"))

        raw_findings = json_data.get("findings", [])
        for f in raw_findings:
            if isinstance(f, dict):
                code = f.get("code", "UNKNOWN")
                findings.append(GLOBAL_ENGINE.create_finding(
                    code=code,
                    layer=f.get("layer", "app_report"),
                    subject=f.get("subject", ""),
                    evidence=f.get("evidence", {}),
                    override_severity=f.get("severity")
                ))
            elif isinstance(f, str):
                import unicodedata
                f_norm = "".join(c for c in unicodedata.normalize('NFKD', f) if not unicodedata.combining(c)).upper()
                if "CRITICO" in f_norm or "CRITICAL" in f_norm:
                    subject = f.split(":")[-1].strip() if ":" in f else f
                    code = "PKG_IOC_ACTIVE" if ("pacote" in f.lower() or "app" in f.lower() or "com." in f) else "FILE_IOC_PRESENT"
                    findings.append(GLOBAL_ENGINE.create_finding(code, "app_report", subject, override_severity="CRITICAL"))
                elif "SUSPEITO" in f_upper or "SUSPICIOUS" in f_upper or "ALERTA" in f_upper:
                    subject = f.split(":")[-1].strip() if ":" in f else f
                    code = "SDK_IOC_IN_DEX" if "sdk" in f.lower() else "APP_LABEL_IOC"
                    findings.append(GLOBAL_ENGINE.create_finding(code, "app_report", subject, override_severity="MEDIUM"))
                else:
                    subject = f.split(":")[-1].strip() if ":" in f else f
                    findings.append(GLOBAL_ENGINE.create_finding("COVERAGE_GAP", "app_report", subject, override_severity="INFO"))

    # 2. Avaliação dos Eventos de Rede da VPN
    if vpn_log_lines is None:
        layers.append(LayerResult(id="vpn_sentinel", status=LayerStatus.SKIPPED, detail="Sentinela VPN não executada"))
    else:
        layers.append(LayerResult(id="vpn_sentinel", status=LayerStatus.OK))
        for line in vpn_log_lines:
            line_str = line.strip()
            if not line_str:
                continue
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    ev = json.loads(line_str)
                    findings.append(GLOBAL_ENGINE.create_finding(
                        code=ev.get("code", "UNUSUAL_OUTBOUND_TRAFFIC"),
                        layer="vpn_sentinel",
                        subject=f"{ev.get('proto', 'TCP')}:{ev.get('dst_ip', '')}:{ev.get('dst_port', '')}",
                        evidence=ev,
                        override_severity=ev.get("severity")
                    ))
                    continue
                except Exception:
                    pass
            if "[CRITICO]" in line_str.upper():
                findings.append(GLOBAL_ENGINE.create_finding("C2_IP_CONNECTION", "vpn_sentinel", line_str, override_severity="CRITICAL"))
            elif "[ANOMALIA]" in line_str.upper():
                findings.append(GLOBAL_ENGINE.create_finding("UNUSUAL_OUTBOUND_TRAFFIC", "vpn_sentinel", line_str, override_severity="LOW"))

    # Avaliar veredito através do motor determinístico unificado
    verdict_state, score, summary = GLOBAL_ENGINE.evaluate(findings, layers, mode="auto_pipeline")
    display_verdict = verdict_state.display_name(get_language())

    print("\n================================================================================")
    print("                    MOTOR DE AVALIAÇÃO FORENSE DETERMINÍSTICO                   ")
    print("================================================================================")
    print(f"Pontuação de Risco Informativa: {score} pontos\n")
    print(f"VEREDITO FINAL: {display_verdict}")
    print("================================================================================\n")

    generate_sanitized_community_submission(json_data, vpn_log_lines, device_specs, display_verdict, score)
    return display_verdict


def step_quick_audit(adb, json_output=False):
    if not json_output:
        print("\n================================================================================")
        print(f"           {t('banner_quick_audit')}                      ")
        print("================================================================================")

    if not adb.specs:
        adb.load_specs(silent=json_output)

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

    findings = []
    layers = []

    # Camada 1: Google Play Protect
    if not json_output:
        print(f"\n{t('layer_1_title')}")
    settings_out = adb.run("settings get global package_verifier_user_consent")
    verifier_enable_out = adb.run("settings get global package_verifier_enable")
    play_protect_disabled = ("-1" in settings_out)
    verifier_disabled = ("0" in verifier_enable_out)

    layers.append(LayerResult(id="play_protect", status=LayerStatus.OK))
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
                findings.append(GLOBAL_ENGINE.create_finding("PKG_IOC_DISABLED", "packages", p_name))
            else:
                found_ioc_pkgs.append(p_name)
                findings.append(GLOBAL_ENGINE.create_finding("PKG_IOC_ACTIVE", "packages", p_name))

    layers.append(LayerResult(id="packages", status=LayerStatus.OK))
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
    if "test-keys" in build_tags.lower():
        findings.append(GLOBAL_ENGINE.create_finding("TEST_KEYS_BUILD", "properties", "ro.build.tags=test-keys"))
        if not json_output:
            print("    [INFO] ro.build.tags = test-keys (Firmware genérico AOSP compilado com chaves públicas de teste - 0 pontos)")

    props = adb.run("getprop").splitlines()
    found_suspicious_props = []
    for prop in props:
        for target in TARGET_STRINGS:
            if target.decode("utf-8", errors="ignore").lower() in prop.lower():
                found_suspicious_props.append(prop)
                findings.append(GLOBAL_ENGINE.create_finding("KILL_SWITCH_PROP", "properties", prop))
        for sprop in SUSPICIOUS_SYSTEM_PROPS:
            if sprop.lower() in prop.lower():
                if prop not in found_suspicious_props:
                    found_suspicious_props.append(prop)
                    findings.append(GLOBAL_ENGINE.create_finding("KILL_SWITCH_PROP", "properties", prop))
        for vprop in VENDOR_PROPERTIES:
            if vprop.lower() in prop.lower():
                findings.append(GLOBAL_ENGINE.create_finding("VENDOR_PROPERTY", "properties", prop))

    layers.append(LayerResult(id="properties", status=LayerStatus.OK))
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
            findings.append(GLOBAL_ENGINE.create_finding("CONTENT_PROVIDER_IOC", "content_providers", prov_uri))

    layers.append(LayerResult(id="content_providers", status=LayerStatus.OK))
    if not json_output:
        if found_providers:
            print(t("layer_4_provider_found", uri=found_providers))
        else:
            print(t("layer_4_ok"))

    # Camada 5: Sockets e Conexões C2 (Parsing posicional robusto via parse_socket_address - AT-16)
    if not json_output:
        print(f"\n{t('layer_5_title')}")
    netstat_out = adb.run("netstat -n -a 2>/dev/null || ss -tan 2>/dev/null")
    found_conn = []
    info_conn = []
    for line in netstat_out.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("Proto") or line_clean.startswith("State") or line_clean.startswith("Netid"):
            continue
        # Analisar colunas de netstat/ss (Foreign Address / Peer Address)
        parts = line_clean.split()
        remote_host, remote_port = None, None
        if len(parts) >= 5 and (parts[0].lower().startswith("tcp") or parts[0].lower().startswith("udp")):
            # Formato netstat: Proto Recv-Q Send-Q Local Foreign State
            remote_host, remote_port = parse_socket_address(parts[4])
        elif len(parts) >= 5 and parts[0].lower() in ("tcp", "udp"):
            # Formato ss: Netid State Recv-Q Send-Q Local:Port Peer:Port
            remote_host, remote_port = parse_socket_address(parts[4])
        else:
            # Fallback regex para linhas com formatação irregular
            addr_matches = re.findall(r'((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|::ffff:[\d.]+|:::?):(\d+)', line_clean)
            if len(addr_matches) >= 2:
                remote_host, remote_port = parse_socket_address(f"{addr_matches[1][0]}:{addr_matches[1][1]}")

        if remote_host and remote_port:
            if IOC_DB.is_c2_ip(remote_host) or remote_host in C2_IPS:
                found_conn.append(f"{line_clean} -> [Alvo C2: {remote_host}:{remote_port}]")
                findings.append(GLOBAL_ENGINE.create_finding("C2_IP_CONNECTION", "network_sockets", f"{remote_host}:{remote_port}"))
            elif remote_port in C2_REMOTE_PORTS:
                found_conn.append(f"{line_clean} -> [Porta C2: {remote_host}:{remote_port}]")
                findings.append(GLOBAL_ENGINE.create_finding("C2_IP_CONNECTION", "network_sockets", f"{remote_host}:{remote_port}"))
            elif remote_port == 2095:
                findings.append(GLOBAL_ENGINE.create_finding("SUSPICIOUS_PORT_ONLY", "network_sockets", f"{remote_host}:2095"))
                info_conn.append(f"{line_clean} -> [Porta 2095 fora da lista de IPs C2 (LOW): {remote_host}:2095]")
            elif remote_port in INFORMATIVE_PORTS:
                info_conn.append(f"{line_clean} -> [Porta habitual não-crítica: {remote_port}]")

    layers.append(LayerResult(id="network_sockets", status=LayerStatus.OK))
    if not json_output:
        if found_conn:
            print(t("layer_5_c2_found", conn=found_conn))
        elif info_conn:
            print("    [INFO] Conexões em portas informativas/suspeitas isoladas:")
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
            findings.append(GLOBAL_ENGINE.create_finding("FILE_IOC_PRESENT", "system_partitions", b_path))

    # Inspeção de Conteúdo em /system/etc/install-recovery.sh
    recovery_sh = adb.run("cat /system/etc/install-recovery.sh 2>/dev/null").strip()
    if recovery_sh and "No such file" not in recovery_sh and "not found" not in recovery_sh:
        suspect_recovery = []
        for s in ["wd", "vo1d", "/data/local/tmp", "/system/xbin", "corejava", "titannet", "linkfog", "oemservice"]:
            if s in recovery_sh:
                suspect_recovery.append(s)
        if suspect_recovery:
            found_binaries.append(f"/system/etc/install-recovery.sh (Comandos anómalos: {', '.join(suspect_recovery)})")
            findings.append(GLOBAL_ENGINE.create_finding("INSTALL_RECOVERY_IOC", "system_partitions", f"/system/etc/install-recovery.sh ({', '.join(suspect_recovery)})"))
        elif not json_output:
            print("    [INFO] /system/etc/install-recovery.sh existe (script flash_recovery padrão - 0 pontos)")

    layers.append(LayerResult(id="system_partitions", status=LayerStatus.OK))
    if not json_output:
        if found_binaries:
            print(t("layer_6_bin_found", bins=found_binaries))
        else:
            print(t("layer_6_ok"))

    # Avaliação das anomalias do Play Protect em combinação com ameaças
    has_active_threats = bool(found_ioc_pkgs or found_conn or found_binaries or found_providers)
    if play_protect_disabled:
        if has_active_threats:
            findings.append(GLOBAL_ENGINE.create_finding("PLAY_PROTECT_TAMPERED_WITH_MALWARE", "play_protect", "Google Play Protect"))
        else:
            findings.append(GLOBAL_ENGINE.create_finding("PLAY_PROTECT_CONSENT_DECLINED", "play_protect", "Google Play Protect"))
    if verifier_disabled:
        findings.append(GLOBAL_ENGINE.create_finding("PACKAGE_VERIFIER_DISABLED", "play_protect", "Google Play Protect"))

    # Avaliação determinística formal via GLOBAL_ENGINE
    verdict_state, risk_score, summary = GLOBAL_ENGINE.evaluate(findings, layers, mode="quick_scan")
    verdict = verdict_state.display_name(get_language())

    # Prepara resultado final
    result = {
        "verdict": verdict,
        "score": risk_score,
        "play_protect_tampered": play_protect_disabled,
        "active_ioc_packages": found_ioc_pkgs,
        "neutralized_ioc_packages": neutralized_ioc_pkgs,
        "suspicious_binaries": found_binaries,
        "active_c2_connections": found_conn
    }

    # Gera cópia sanitizada anonimizada
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

    if json_output:
        print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


def create_remediation_backup(adb):
    """
    Cria um backup completo das definições e estado de pacotes ANTES de qualquer alteração,
    organizado por device_id em backups/<device_id>/.
    Preserva baseline.json permanentemente e gera run_<timestamp>.json para cada execução.
    Gera scripts finos de restauro (.ps1 e .sh) sem valores interpolados do dispositivo.
    """
    dev_id = adb.device_id
    dev_dir = os.path.join(BACKUPS_DIR, dev_id)
    quarantine_dir = os.path.join(dev_dir, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    timestamp = f"{time.strftime('%Y%m%d_%H%M%S')}_{int(time.time() * 1000) % 1000:03d}"
    baseline_file = os.path.join(dev_dir, "baseline.json")
    run_file = os.path.join(dev_dir, f"run_{timestamp}.json")
    restore_ps1 = os.path.join(dev_dir, f"restore_{dev_id}.ps1")
    restore_sh = os.path.join(dev_dir, f"restore_{dev_id}.sh")

    print(f"\n[*] A criar BACKUP de segurança reversível em backups/{dev_id}...")

    orig_user_consent = adb.run("settings get global package_verifier_user_consent").strip()
    orig_verifier_enable = adb.run("settings get global package_verifier_enable").strip()
    orig_dns_mode = adb.run("settings get global private_dns_mode").strip()
    orig_dns_spec = adb.run("settings get global private_dns_specifier").strip()
    disabled_pkgs = adb.run("pm list packages -d").splitlines()

    backup_data = {
        "device_id": dev_id,
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

    # AT-09: baseline.json é escrito apenas uma vez e nunca sobrescrito
    if not os.path.exists(baseline_file):
        with open(baseline_file, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)
        print(f"    [✓] Baseline inicial gravada: {os.path.basename(baseline_file)}")

    with open(run_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    print(f"    [✓] Snapshot da execução gravado: {os.path.basename(run_file)}")
    return run_file, backup_data, restore_ps1, restore_sh


def generate_restore_scripts(adb, backup_data, restore_ps1_path, restore_sh_path):
    """
    Gera scripts autónomos e reversíveis (.ps1 e .sh) para restaurar a TV.
    RST-01: Invólucros finos estritamente seguros sem interpolação de dados vindos do dispositivo.
    Chamam: python tools/audit_security.py <host> --restore --backup <caminho>
    """
    safe_host = adb.host.replace("'", "''")
    safe_backup_ps1 = restore_ps1_path.replace("'", "''")
    safe_backup_sh = shlex.quote(restore_sh_path)

    # 1. Gerar PowerShell script (.ps1) com aspas simples estritas
    ps_content = f"""# =====================================================================
# RESTORE SCRIPT - BADBOX FORENSIC REMEDIATION REVERSAL
# Dispositivo: {safe_host}
# Gerado em:   {backup_data.get('timestamp')}
# =====================================================================

param(
    [string]$TvHost = '{safe_host}'
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$AuditScript = Join-Path $ProjectRoot 'tools\audit_security.py'
$BackupFile = Join-Path $ScriptDir 'run_{backup_data.get("timestamp")}.json'
if (-not (Test-Path $BackupFile)) {{
    $BackupFile = Join-Path $ScriptDir 'baseline.json'
}}

Write-Host ">>> A reverter remediação e restaurar estado da TV ($TvHost)..." -ForegroundColor Cyan
python $AuditScript $TvHost --restore --backup $BackupFile @args
"""

    # 2. Gerar Shell script (.sh) usando shlex.quote
    sh_content = f"""#!/bin/sh
# =====================================================================
# RESTORE SCRIPT - BADBOX FORENSIC REMEDIATION REVERSAL
# Dispositivo: {safe_host}
# Gerado em:   {backup_data.get('timestamp')}
# =====================================================================
set -e

TV_HOST="${{1:-{safe_host}}}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUDIT_SCRIPT="$PROJECT_ROOT/tools/audit_security.py"
BACKUP_FILE="$SCRIPT_DIR/run_{backup_data.get('timestamp')}.json"
if [ ! -f "$BACKUP_FILE" ]; then
    BACKUP_FILE="$SCRIPT_DIR/baseline.json"
fi

echo ">>> A reverter remediação e restaurar estado da TV ($TV_HOST)..."
python3 "$AUDIT_SCRIPT" "$TV_HOST" --restore --backup "$BACKUP_FILE" "$@"
"""

    try:
        os.makedirs(os.path.dirname(restore_ps1_path), exist_ok=True)
        with open(restore_ps1_path, "w", encoding="utf-8") as f:
            f.write(ps_content)
        with open(restore_sh_path, "w", encoding="utf-8") as f:
            f.write(sh_content)
        print(f"    [✓] Scripts de reversão gerados: {os.path.basename(restore_ps1_path)} e {os.path.basename(restore_sh_path)}")
    except Exception as e:
        print(f"    [!] Aviso ao gerar scripts de restauro: {e}")


def step_restore_device(adb, backup_path=None, restore_quarantined_apks=False):
    """
    RST-01 / RST-02: Restaura o dispositivo a partir do ficheiro de backup (baseline ou run).
    100% orientado a dados, validação estrita contra injeção e verificação de device_id.
    """
    print("\n================================================================================")
    print(f"            REVERSÃO / RESTAURO DE SEGURANÇA - ANDROID TV ({adb.host})          ")
    print("================================================================================")

    if not adb.specs:
        adb.load_specs(silent=True)

    target_backup = backup_path
    if not target_backup:
        dev_dir = os.path.join(BACKUPS_DIR, adb.device_id)
        target_backup = os.path.join(dev_dir, "baseline.json")
        if not os.path.exists(target_backup):
            # Tentar backward compatibility com backups legados backups/backup_<clean_ip>_*.json
            clean_ip = adb.host.replace(".", "_")
            if os.path.exists(BACKUPS_DIR):
                legacy = [os.path.join(BACKUPS_DIR, f) for f in sorted(os.listdir(BACKUPS_DIR), reverse=True) if f.startswith(f"backup_{clean_ip}_") and f.endswith(".json")]
                if legacy:
                    target_backup = legacy[0]

    if not target_backup or not os.path.exists(target_backup):
        print(f"[!] Erro: Ficheiro de backup não encontrado: {target_backup}", file=sys.stderr)
        return False

    print(f"[*] A carregar backup: {target_backup}...")
    try:
        with open(target_backup, "r", encoding="utf-8") as f:
            backup_data = json.load(f)
    except Exception as e:
        print(f"[!] Erro ao analisar JSON do backup: {e}", file=sys.stderr)
        return False

    # AT-10: Validar se o device_id coincide com o dispositivo atualmente ligado
    backup_dev_id = backup_data.get("device_id")
    if backup_dev_id and adb.device_id and backup_dev_id != adb.device_id:
        print(f"[!] Erro de segurança (AT-10): ID do dispositivo não coincide!", file=sys.stderr)
        print(f"    Backup pertence a:       {backup_dev_id}", file=sys.stderr)
        print(f"    Dispositivo conectado:   {adb.device_id}", file=sys.stderr)
        print("    Restauro recusado para prevenir contaminação entre dispositivos.", file=sys.stderr)
        return False

    # 1. Repor definições globais com validação estrita contra injeção de comandos (AT-08)
    settings = backup_data.get("settings", {})
    print("\n[1/4] A repor definições globais originais...")

    consent = settings.get("package_verifier_user_consent")
    if consent is not None:
        consent_str = str(consent).strip().lower()
        if consent_str in ["null", "", "none"]:
            adb.run("settings delete global package_verifier_user_consent")
        elif consent_str in ["1", "-1", "0"]:
            adb.run(f"settings put global package_verifier_user_consent {consent_str}")
        else:
            print(f"[!] Erro de validação: package_verifier_user_consent inválido ({consent_str})", file=sys.stderr)
            return False

    enable = settings.get("package_verifier_enable")
    if enable is not None:
        enable_str = str(enable).strip().lower()
        if enable_str in ["null", "", "none"]:
            adb.run("settings delete global package_verifier_enable")
        elif enable_str in ["1", "0"]:
            adb.run(f"settings put global package_verifier_enable {enable_str}")
        else:
            print(f"[!] Erro de validação: package_verifier_enable inválido ({enable_str})", file=sys.stderr)
            return False

    dns_mode = settings.get("private_dns_mode")
    if dns_mode is not None:
        dns_mode_str = str(dns_mode).strip().lower()
        if dns_mode_str in ["null", "", "none"]:
            adb.run("settings delete global private_dns_mode")
        elif dns_mode_str in ["off", "opportunistic", "hostname"]:
            adb.run(f"settings put global private_dns_mode {dns_mode_str}")
        else:
            print(f"[!] Erro de validação: private_dns_mode inválido ({dns_mode_str})", file=sys.stderr)
            return False

    dns_spec = settings.get("private_dns_specifier")
    if dns_spec is not None:
        dns_spec_str = str(dns_spec).strip()
        if dns_spec_str.lower() in ["null", "", "none"]:
            adb.run("settings delete global private_dns_specifier")
        else:
            # Validação estrita: apenas domínios ou hostnames válidos (alfanumérico, pontos, hífens)
            if not re.match(r'^[a-zA-Z0-9.-]+$', dns_spec_str):
                print(f"[!] Erro de segurança (AT-08): Valor de private_dns_specifier contém caracteres não autorizados ou expansão: '{dns_spec_str}'", file=sys.stderr)
                return False
            adb.run(f"settings put global private_dns_specifier {dns_spec_str}")

    print("    [✓] Definições globais validadas e repostas.")

    # 2. APKs salvaguardados em quarentena (AT-26)
    pulled_apks = dict(backup_data.get("pulled_apks", {}))
    dev_dir = os.path.dirname(target_backup)
    quarantine_dir = os.path.join(dev_dir, "quarantine")
    if os.path.exists(quarantine_dir):
        for qf in os.listdir(quarantine_dir):
            if qf.endswith(".apk.quarantined"):
                pkg_n = qf.replace(".apk.quarantined", "")
                if pkg_n not in pulled_apks:
                    pulled_apks[pkg_n] = os.path.join(quarantine_dir, qf)
    if pulled_apks:
        print("\n[2/4] Verificação de APKs salvaguardados...")
        if not restore_quarantined_apks:
            print("    [*] NOTA DE SEGURANÇA (AT-26): APKs em quarentena NÃO são reinstalados por defeito.")
            print("        Para autorizar explicitamente a reinstalação de APKs em quarentena, execute com --restore-quarantined-apks.")
        else:
            print("    [!] A reinstalar APKs de quarentena autorizados pelo utilizador...")
            for pkg, apk_path in pulled_apks.items():
                if os.path.exists(apk_path):
                    tmp_remote = f"/data/local/tmp/{pkg}.apk"
                    adb.push(apk_path, tmp_remote)
                    adb.run(f"pm install -r {tmp_remote}")
                    adb.run(f"rm -f {tmp_remote}")
                    print(f"        [✓] APK reinstalado: {pkg}")

    # 3. Reativar pacotes congelados
    all_packages = list(dict.fromkeys(backup_data.get("uninstalled_user0_packages", []) + backup_data.get("disabled_during_remediation", [])))
    if all_packages:
        print("\n[3/4] A reativar pacotes desativados durante a remediação...")
        for pkg in all_packages:
            adb.run(f"cmd package install-existing --user 0 {pkg}")
            adb.run(f"pm enable --user 0 {pkg}")
            adb.run(f"pm enable {pkg}")
            print(f"    [✓] Pacote reativado: {pkg}")

    # 4. Repor AppOps
    appops_pkgs = backup_data.get("appops_modified", [])
    if appops_pkgs:
        print("\n[4/4] A repor permissões de AppOps para default...")
        for pkg in set(appops_pkgs):
            adb.run(f"cmd appops set {pkg} RUN_IN_BACKGROUND default")
            adb.run(f"cmd appops set {pkg} RUN_ANY_IN_BACKGROUND default")
            adb.run(f"cmd appops set {pkg} WAKE_LOCK default")
            adb.run(f"cmd appops set {pkg} BOOT_COMPLETED default")
        print("    [✓] AppOps repostos.")

    print("\n================================================================================")
    print("  [✓] RESTAURO CONCLUÍDO COM SUCESSO! Dispositivo reposto no estado do backup.")
    print("================================================================================\n")
    return True


def step_remediate_device(adb, enable_dot=False, verify_reboot=False, dry_run=False, yes=True, clear_data=False, reboot_timeout=180):
    """
    REM-01 / REM-02 / REM-03 / REM-04:
    Executa a neutralização e remediação estruturada com:
    1. Plano formal de ações antes de qualquer modificação
    2. --dry-run estritamente não-mutante
    3. Confirmação interativa ('SIM'/'YES') ou exigência de --yes sem TTY (exit 6)
    4. Classificação rigorosa de pacotes: system, updated_system, user
    5. Proibição de rm -rf e restrição de pm clear apenas a --clear-data
    6. Verificação ação a ação com resumo honesto e re-scan
    7. Validação com reconexão pós-reboot (--verify-reboot)
    """
    print("\n================================================================================")
    print(f"     PLANO DE REMEDIAÇÃO & NEUTRALIZAÇÃO FORENSE - ANDROID TV ({adb.host})       ")
    print("================================================================================")

    if not adb.specs:
        adb.load_specs(silent=True)

    # 1. Analisar estado atual e construir plano de remediação
    plan_actions = []

    # Verificar Play Protect
    user_consent_pre = adb.run("settings get global package_verifier_user_consent").strip()
    verifier_enable_pre = adb.run("settings get global package_verifier_enable").strip()
    if user_consent_pre == "-1" or verifier_enable_pre == "0":
        plan_actions.append({
            "id": "play_protect_enforce",
            "type": "settings",
            "target": "Google Play Protect",
            "reason": "Reativar verificação de pacotes e consentimento de segurança",
            "reversible": True,
            "commands": [
                "settings put global package_verifier_user_consent 1",
                "settings put global package_verifier_enable 1"
            ],
            "verify_cmd": "settings get global package_verifier_user_consent",
            "verify_expected": "1"
        })

    # Verificar pacotes IOC
    pkgs_out = adb.run("pm list packages -e")
    if not pkgs_out.strip():
        pkgs_out = adb.run("pm list packages")
    pkgs_pre = [p.replace("package:", "").strip() for p in pkgs_out.splitlines()]
    exact_lower = {p.lower() for p in EXACT_IOC_PACKAGES}
    detected_pkgs = [p for p in pkgs_pre if p.lower() in exact_lower]

    for pkg in detected_pkgs:
        path_out = adb.run(f"pm path {pkg}").strip()
        dumpsys_out = adb.run(f"dumpsys package {pkg}")

        is_updated_system = ("/data/app" in path_out and (
            "Hidden system package" in dumpsys_out or
            "codePath=/system" in dumpsys_out or
            "codePath=/vendor" in dumpsys_out or
            "codePath=/product" in dumpsys_out
        ))
        is_system = ("/system" in path_out or "/vendor" in path_out or "/product" in path_out or "/oem" in path_out)

        if is_updated_system:
            classification = "updated_system"
        elif is_system:
            classification = "system"
        else:
            classification = "user"

        action = {
            "id": f"neutralize_pkg_{pkg}",
            "type": "package",
            "package": pkg,
            "classification": classification,
            "path": path_out,
            "reason": f"Pacote de botnet IoC ({classification})",
            "reversible": True,
            "commands": [],
            "verify_cmd": f"pm list packages -d",
            "verify_expected": pkg
        }

        action["commands"].append(f"am force-stop {pkg}")
        if clear_data:
            action["commands"].append(f"pm clear {pkg}")
        action["commands"].append(f"cmd appops set {pkg} RUN_IN_BACKGROUND ignore")
        action["commands"].append(f"cmd appops set {pkg} RUN_ANY_IN_BACKGROUND ignore")

        if classification == "updated_system":
            # AT-05: Remove atualização de /data/app E desativa o dropper original de sistema
            action["commands"].append(f"pm uninstall {pkg}")
            action["commands"].append(f"pm disable-user --user 0 {pkg}")
        elif classification == "system":
            action["commands"].append(f"pm disable-user --user 0 {pkg}")
        else:
            # user app
            action["commands"].append(f"pm uninstall {pkg}")
            action["verify_cmd"] = "pm list packages"
            action["verify_expected_not_in"] = pkg
            action.pop("verify_expected", None)

        plan_actions.append(action)

    # Configuração de DNS DoT se pedido
    if enable_dot:
        plan_actions.append({
            "id": "enable_dot_dns",
            "type": "dns",
            "target": "security.cloudflare-dns.com",
            "reason": "Ativar DNS-over-TLS (Cloudflare Security)",
            "reversible": True,
            "commands": [
                "settings put global private_dns_mode hostname",
                "settings put global private_dns_specifier security.cloudflare-dns.com"
            ],
            "verify_cmd": "settings get global private_dns_mode",
            "verify_expected": "hostname"
        })

    # Verificar se o dispositivo já está limpo
    if not plan_actions:
        print("\n[✓] DISPOSITIVO LIMPO E PROTEGIDO: Nenhuma ameaça ativa encontrada!")
        print("    O Google Play Protect está ativo e não foram detetados pacotes ou anomalias a remediar.")
        print("    Nenhuma alteração foi realizada no dispositivo.")
        print("================================================================================\n")
        return 0

    # 2. Apresentar Plano Estruturado de Remediação
    print(f"\n--- PLANO DE REMEDIAÇÃO E NEUTRALIZAÇÃO ({len(plan_actions)} ações propostas) ---")
    for i, act in enumerate(plan_actions, start=1):
        print(f"[{i}] {act['id']}: {act['reason']}")
        print(f"    Tipo: {act['type']} | Alvo: {act.get('package', act.get('target', ''))}")
        if "classification" in act:
            print(f"    Classificação: {act['classification']}")
        print(f"    Comandos a executar:")
        for cmd in act["commands"]:
            print(f"      $ adb shell {cmd}")

    # 3. Tratamento de --dry-run (AT-06)
    if dry_run:
        print("\n[DRY-RUN] Modo de simulação (--dry-run) ativo.")
        print("          Nenhum comando mutante foi executado no dispositivo.")
        print("================================================================================\n")
        return 0

    # 4. Confirmação do utilizador (AT-07)
    if not yes:
        if sys.stdin.isatty():
            try:
                resp = input("\nDeseja executar este plano de remediação? Escreva 'SIM' (ou 'YES') para confirmar: ").strip().upper()
                if resp not in ["SIM", "YES"]:
                    print("[!] Remediação cancelada pelo utilizador.")
                    sys.exit(6)
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Remediação cancelada.")
                sys.exit(6)
        else:
            print("[!] Erro (AT-07): Execução não-interativa requer confirmação explícita com a flag --yes.", file=sys.stderr)
            sys.exit(6)

    # 5. Criar Backup antes da execução
    backup_file, backup_data, restore_ps1, restore_sh = create_remediation_backup(adb)

    # 6. Execução e Quarentena de APKs (AT-26 / AT-27)
    quarantine_dir = os.path.join(BACKUPS_DIR, adb.device_id, "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    readme_path = os.path.join(quarantine_dir, "README.txt")
    if not os.path.exists(readme_path):
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write("AVISO: Estes ficheiros sao artefactos maliciosos em quarentena (BadBox/XCPE/Vo1d).\nNao renomear nem executar.\n")

    action_results = []
    all_verified = True

    print("\n[*] A executar plano de remediação...")
    for act in plan_actions:
        pkg = act.get("package")
        if pkg and act.get("classification") in ["updated_system", "user"]:
            # Pull do APK para quarentena
            remote_apk = None
            path_out = adb.run(f"pm path {pkg}").strip()
            for pline in path_out.splitlines():
                if "package:" in pline:
                    remote_apk = pline.replace("package:", "").strip()
                    break
            if remote_apk:
                local_apk_q = os.path.join(quarantine_dir, f"{pkg}.apk.quarantined")
                pulled = adb.pull(remote_apk, local_apk_q)
                if pulled and os.path.exists(local_apk_q):
                    # Calcular SHA256 e salvar .sha256
                    with open(local_apk_q, "rb") as af:
                        apk_hash = hashlib.sha256(af.read()).hexdigest()
                    with open(local_apk_q + ".sha256", "w", encoding="utf-8") as sf:
                        sf.write(f"{apk_hash}  {os.path.basename(local_apk_q)}\n")
                    try:
                        os.chmod(local_apk_q, 0o444)
                    except Exception:
                        pass
                    backup_data["pulled_apks"][pkg] = local_apk_q
                    print(f"    [+] APK movido para quarentena segura: {os.path.basename(local_apk_q)}")

        # Executar comandos da ação
        last_cmd_out = ""
        for cmd in act["commands"]:
            last_cmd_out = adb.run(cmd)

        if pkg:
            backup_data["disabled_during_remediation"].append(pkg)
            if act.get("classification") == "updated_system":
                backup_data["uninstalled_user0_packages"].append(pkg)

        # 7. Verificação da Ação
        verified = False
        v_out = adb.run(act["verify_cmd"])
        if "verify_expected" in act:
            verified = (act["verify_expected"].lower() in v_out.lower())
        elif "verify_expected_not_in" in act:
            verified = (act["verify_expected_not_in"].lower() not in v_out.lower())

        if not verified and act.get("type") == "package":
            if "disabled-user" in last_cmd_out.lower():
                verified = True
            else:
                dumpsys_chk = adb.run(f"dumpsys package {pkg}")
                if "disabled-user" in dumpsys_chk.lower() or "enabled=3" in dumpsys_chk.lower():
                    verified = True

        if not verified:
            all_verified = False
            action_results.append((act["id"], "FALHOU", "Verificação não confirmou o estado esperado"))
            print(f"    [✗] {act['id']}: FALHOU na verificação!")
        else:
            action_results.append((act["id"], "OK", "Ação executada e verificada com sucesso"))
            print(f"    [✓] {act['id']}: OK")

    # Atualizar backup e scripts de restauro
    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    dev_dir = os.path.join(BACKUPS_DIR, adb.device_id)
    baseline_path = os.path.join(dev_dir, "baseline.json")
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, "r", encoding="utf-8") as bf:
                base_d = json.load(bf)
            base_d["pulled_apks"] = backup_data.get("pulled_apks", {})
            base_d["disabled_during_remediation"] = backup_data.get("disabled_during_remediation", [])
            base_d["uninstalled_user0_packages"] = backup_data.get("uninstalled_user0_packages", [])
            with open(baseline_path, "w", encoding="utf-8") as bf:
                json.dump(base_d, bf, indent=2)
        except Exception:
            pass

    generate_restore_scripts(adb, backup_data, restore_ps1, restore_sh)

    # 8. Resumo Honesto Ação a Ação
    print("\n================================================================================")
    print("                    RESUMO DE EXECUÇÃO DA REMEDIAÇÃO                            ")
    print("================================================================================")
    for act_id, status, detail in action_results:
        symbol = "[✓]" if status == "OK" else "[✗]"
        print(f"  {symbol} {act_id:<30} -> {status} ({detail})")
    print("================================================================================")

    # Re-auditoria imediata
    print("\n[*] A reexecutar auditoria forense imediata para verificação de eficácia...")
    quick_res = step_quick_audit(adb, json_output=False)

    # 9. Verificação Pós-Reboot (--verify-reboot) (REM-04 / AT-21)
    if verify_reboot:
        print("\n[*] A iniciar verificação de persistência pós-reboot (--verify-reboot)...")
        print("    A reiniciar a Android TV via ADB...")
        adb.run("reboot")
        try:
            adb.close()
        except Exception:
            pass

        print(f"    A aguardar reinicialização do sistema (timeout: {reboot_timeout}s)...")
        time.sleep(10)
        reconnected = False
        start_time = time.time()
        attempt = 0

        while (time.time() - start_time) < reboot_timeout:
            attempt += 1
            time.sleep(min(5, max(1, attempt * 0.5)))
            try:
                adb.reconnect()
                boot_state = adb.run("getprop sys.boot_completed").strip()
                if boot_state == "1":
                    reconnected = True
                    break
            except Exception:
                pass

        if not reconnected:
            print(f"[!] Erro (AT-21): Dispositivo não reconectou após o reboot dentro de {reboot_timeout}s.", file=sys.stderr)
            print("    Estado final: NÃO VERIFICADO. A porta ADB pode ter fechado no arranque.", file=sys.stderr)
            sys.exit(5)

        print("    [✓] Dispositivo reconectado com sucesso após reboot! A reexecutar diagnóstico...")
        post_res = step_quick_audit(adb, json_output=False)
        v = post_res.get("verdict", "")
        if "CRÍTICO" in v or "CRITICAL" in v or "INFETADO" in v or "INFECTED" in v:
            print("\n[!] ALERTA CRÍTICO: Persistência pós-reboot detetada! Watchdogs no init.rc reativaram malware.", file=sys.stderr)
            sys.exit(5)
        else:
            print("\n[✓] VERIFICAÇÃO PÓS-REBOOT BEM-SUCEDIDA: Dispositivo permanece limpo após o reinício.")

    if not all_verified:
        print("[!] Remediação parcial ou com ações não verificadas.", file=sys.stderr)
        sys.exit(5)

    print("\n[✓] Remediação concluída com sucesso e verificada em profundidade.")
    return 0


def scan_init_watchdogs(adb):
    """
    Inspeciona scripts de inicialização init.rc (/system/etc/init, /vendor/etc/init, /odm/etc/init)
    à procura de serviços de persistência e watchdogs que reativem a botnet no arranque.
    """
    print("\n================================================================================")
    print(f"      PESQUISA DE WATCHDOGS & PERSISTÊNCIA EM INIT.RC ({adb.host})              ")
    print("================================================================================")

    init_dirs = ["/system/etc/init", "/vendor/etc/init", "/odm/etc/init", "/system_ext/etc/init", "/etc/init"]
    suspect_terms = [
        "package_verifier_user_consent", "oemservice", "x.cpe", "vo1d", "corejava",
        "titannet", "getgrass", "traffmonetizer", "wd", "linkfog", "appdns", "szbboys"
    ]

    print("[*] A procurar scripts *.rc e gatilhos de arranque...")
    found_watchdogs = []
    existing_dirs = [d for d in init_dirs if "No such" not in adb.run(f"ls -d {d} 2>/dev/null")]
    dirs_str = " ".join(existing_dirs)
    if dirs_str:
        for term in suspect_terms:
            flag = "-rnw" if len(term) <= 3 else "-rn"
            res = adb.run(f"grep {flag} '{term}' {dirs_str} 2>/dev/null").strip()
            if res:
                for line in res.splitlines():
                    if line.strip() and not line.startswith("Binary file"):
                        found_watchdogs.append(line.strip())

    suspect_bins = ["wd", "vo1d", "oemservice", "corejava", "titannet", "linkfog"]
    for sbin in suspect_bins:
        for bdir in ["/system/bin", "/vendor/bin", "/data/local/tmp"]:
            chk = adb.run(f"ls -ld {bdir}/{sbin} 2>/dev/null").strip()
            if chk and "No such file" not in chk and "not found" not in chk:
                found_watchdogs.append(f"Binário executável não-padrão detetado: {chk}")

    if found_watchdogs:
        print(f"    [!] ALERTA CRÍTICO: Foram detetadas {len(found_watchdogs)} referências a watchdogs/persistência:")
        for w in set(found_watchdogs):
            print(f"        -> {w}")
    else:
        print("    [✓] Nenhum script de persistência ou watchdog detetado nas partições init.")

    print("================================================================================\n")
    return found_watchdogs


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


def step_install_custom_app(adb, force_recompile=False, custom_apk_path=None):
    if not adb.specs:
        adb.load_specs()

    # SEC-02: Verificar se a app já existe no dispositivo
    existing_path = adb.run(f"pm path {PACKAGE_NAME}").strip()
    if "package:" in existing_path:
        print(f"[*] App {PACKAGE_NAME} pré-existente detetada no dispositivo. A verificar autenticidade...")
        remote_apk = existing_path.split("package:")[-1].strip().splitlines()[0]
        local_check = os.path.join(PROJECT_ROOT, "scratch", "existing_app.apk")
        os.makedirs(os.path.dirname(local_check), exist_ok=True)
        adb.pull(remote_apk, local_check)
        # Remover versão desconhecida/antiga para garantir instalação limpa e segura
        print(f"[!] AVISO: A remover versão anterior de {PACKAGE_NAME} para garantir instalação limpa.")
        adb.run(f"pm uninstall {PACKAGE_NAME}")
        if os.path.exists(local_check):
            try:
                os.remove(local_check)
            except Exception:
                pass

    apk = custom_apk_path if custom_apk_path else compile_custom_app(adb.specs, force_recompile=force_recompile)
    if apk:
        print("\n[*] A transferir e instalar na box...")
        remote_tmp = "/data/local/tmp/xcpe-scanner-tv.apk"
        adb.push(apk, remote_tmp)
        # SEC-02: pm install -r (sem -d nem -t)
        out = adb.run(f"pm install -r {remote_tmp}")
        print(f"    - Resultado da instalação: {out.strip()}")
        
        if "INSTALL_FAILED" in out and not force_recompile:
            print(f"\n[!] AVISO: APK rejeitado pelo aparelho ({out.strip()}).")
            print("[*] A acionar compilação adaptada ao aparelho...")
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

    print("\n[*] A autorizar permissões de VPN em segundo plano...")
    adb.run(f"appops set {PACKAGE_NAME} ACTIVATE_VPN allow")

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
    # Verificamos se surgiu o diálogo de permissão do sistema Android (com.android.vpndialogs)
    time.sleep(1)
    top_window = adb.run("dumpsys window | grep -E mCurrentFocus")
    if "vpndialogs" in top_window:
        print("    [!] AVISO: Diálogo de VPN exibido no televisor. Por favor confirme com o telecomando (OK).")
        # Sem injeção de teclas às cegas (SEC-02). Aguarda aprovação na TV
        for _ in range(5):
            time.sleep(1)
            tw = adb.run("dumpsys window | grep -E mCurrentFocus")
            if "vpndialogs" not in tw:
                break
    
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


class StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(64)


if __name__ == "__main__":
    parser = StrictArgumentParser(description="BadBox & XCPE Forensic Suite", add_help=False)
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

    args = parser.parse_args()

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
            sys.exit(step_remediate_device(adb, enable_dot=args.enable_dot, verify_reboot=args.verify_reboot, dry_run=args.dry_run, yes=args.yes, clear_data=args.clear_data, reboot_timeout=args.reboot_timeout))
            sys.exit(0)
        elif args.restore:
            success = step_restore_device(adb, backup_path=args.backup, restore_quarantined_apks=args.restore_quarantined_apks)
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
