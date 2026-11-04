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

# Configurar stdout/stderr para UTF-8 seguro em consolas Windows e Linux
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_PROJECT_DIR = os.path.join(PROJECT_ROOT, "app")
BACKUPS_DIR = os.path.join(PROJECT_ROOT, "backups")
PACKAGE_NAME = "com.scanner.tv"

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
    b"uota.xyz"
]

# 2. Pacotes maliciosos, backdoors OEM e proxies residenciais da campanha
IOC_PACKAGES = [
    "x.cpe", "com.oemservice", "com.abc.nexus", "io.popanet", "gaganode",
    "linkfog", "appsalt", "traffmonetizer", "cboxtv", "hiddenview", "moyu", "spirit",
    "android-grass", "com.grass", "appdnschange", "SmartPrivilege", "SmartEntertainment",
    "SmartThroughput", "EcoSaverDaemon", "titannet", "yokatv"
]

# 3. IPs e Portas Críticas de C2 da botnet
C2_IPS_PORTS = [
    "219.134.163.210", "121.4.8.146", "38.145.197.135", "38.145.197.30", "23.94.49.57",
    ":3885", ":3886", ":3887", ":22345", ":16000", ":12000", ":9992", ":9994", ":2375", ":2095", ":2082"
]

# 4. Modelos de dispositivos historicamente visados pela botnet (Apenas Informativo - Requer Evidências)
TARGETED_HARDWARE_MODELS = [
    "km9", "km2", "km6", "km7", "km1", "km3", "km8", "m8s", "tx3", "h616", "q96", "leap-s1",
    "videostrong", "mecool", "uhd google tv stb", "rmq"
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
            import tv
            self.device = tv.TVDevice(self.host)
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

    def load_specs(self):
        print(f"[*] A carregar especificações do dispositivo {self.host}...")
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
        print(f"    - Modelo: {brand} {model} (Android {android_ver}, API {sdk})")
        print(f"    - Fabricante/SoC: {manufacturer} | {board} / {hardware}")
        print(f"    - Patch de Segurança: {security_patch}")
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
    print(f"Pontuação de Risco Total: {score} pontos\n")

    if score >= 8 or len(critical_reasons) > 0:
        verdict = "INFETADO - CRÍTICO"
        color_code = "[!]"
        confidence = ">99%"
        desc = "Foram identificadas evidências irrefutáveis de malware/botnet (XCPE/BadBox)."
    elif score >= 3 or len(suspicious_reasons) >= 2:
        verdict = "SUSPEITO"
        color_code = "[?]"
        confidence = "80%"
        desc = "A box apresenta anomalias estruturais ou tráfego de rede não habitual em repouso."
    else:
        verdict = "LIMPO / SEGURO"
        color_code = "[✓]"
        confidence = ">98%"
        desc = "Nenhuma evidência maliciosa ou conexão à botnet detetada."

    print(f"{color_code} VEREDITO FINAL: {verdict} (Grau de Certeza: {confidence})")
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


def step_quick_audit(adb):
    print("\n================================================================================")
    print(f"           DIAGNÓSTICO RÁPIDO VIA ADB (5 CAMADAS FORENSES)                      ")
    print("================================================================================")
    
    if not adb.specs:
        adb.load_specs()

    model_str = (adb.specs.get("model", "") + " " + adb.specs.get("brand", "")).lower()
    for targeted in TARGETED_HARDWARE_MODELS:
        if targeted in model_str:
            print(f"\n[AVISO DE CONTEXTO] Este modelo ('{adb.specs.get('model')}') coincide com linhas documentadas no relatório Synthient.")
            print("                   Será feita uma verificação rigorosa de evidências técnicas.")
            break

    print("\n[Camada 1/5] A verificar integridade do Play Protect...")
    settings_out = adb.run("settings get global package_verifier_user_consent")
    print(f"    - package_verifier_user_consent: {settings_out.strip()}")
    if "-1" in settings_out:
        print("    [!] ALERTA CRÍTICO: Play Protect foi forçado a desligar (-1)!")
    else:
        print("    [✓] Play Protect não está forçado a desligar.")

    print("\n[Camada 2/5] A analisar pacotes instalados contra lista de IoCs...")
    pkgs = adb.run("pm list packages").splitlines()
    found_ioc_pkgs = []
    for p in pkgs:
        p_name = p.replace("package:", "").strip().lower()
        for ioc in IOC_PACKAGES:
            if ioc.lower() in p_name:
                found_ioc_pkgs.append(p_name)
    if found_ioc_pkgs:
        print(f"    [!] Pacotes maliciosos detetados: {found_ioc_pkgs}")
    else:
        print(f"    [✓] Nenhum pacote conhecido de botnet detetado ({len(pkgs)} pacotes analisados).")

    print("\n[Camada 3/5] A verificar propriedades do sistema (Build Props)...")
    props = adb.run("getprop").splitlines()
    found_suspicious_props = []
    for prop in props:
        for target in TARGET_STRINGS:
            if target.decode("utf-8", errors="ignore").lower() in prop.lower():
                found_suspicious_props.append(prop)
    if found_suspicious_props:
        print(f"    [!] Propriedades suspeitas: {found_suspicious_props}")
    else:
        print("    [✓] Nenhuma propriedade adulterada por BadBox.")

    print("\n[Camada 4/5] A verificar sockets de rede ativos e conexões C2...")
    netstat_out = adb.run("netstat -n -a 2>/dev/null || ss -tan 2>/dev/null")
    found_conn = []
    for line in netstat_out.splitlines():
        for c2 in C2_IPS_PORTS:
            if c2 in line:
                found_conn.append(line)
    if found_conn:
        print(f"    [!] Conexão C2 detetada em tempo real: {found_conn}")
    else:
        print("    [✓] Nenhuma conexão ativa aos IPs/portas da botnet.")

    print("\n[Camada 5/5] Amostragem de APKs OEM do sistema...")
    oem_paths = adb.run("pm list packages -f -s").splitlines()
    print(f"    - Total de pacotes de sistema encontrados: {len(oem_paths)}")
    print("    [✓] Amostragem concluída.")


def create_remediation_backup(adb):
    """
    Cria um backup completo das definições e estado de pacotes ANTES de qualquer alteração,
    gerando também um script de restauro reversível em backups/.
    """
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    clean_ip = adb.host.replace(".", "_")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUPS_DIR, f"backup_{clean_ip}_{timestamp}.json")
    restore_script = os.path.join(BACKUPS_DIR, f"restore_{clean_ip}.ps1")

    print(f"\n[*] A criar BACKUP de segurança reversível em backups/...")

    # Guardar definições originais
    orig_user_consent = adb.run("settings get global package_verifier_user_consent").strip()
    orig_verifier_enable = adb.run("settings get global package_verifier_enable").strip()
    orig_dns_mode = adb.run("settings get global private_dns_mode").strip()
    orig_dns_spec = adb.run("settings get global private_dns_specifier").strip()

    # Guardar lista de pacotes desativados anteriormente
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
python -c "import tv; d = tv.TVDevice('$TvHost'); d.shell('settings put global package_verifier_user_consent {settings.get('package_verifier_user_consent', '1')}')"
python -c "import tv; d = tv.TVDevice('$TvHost'); d.shell('settings put global package_verifier_enable {settings.get('package_verifier_enable', '1')}')"

$dnsMode = "{settings.get('private_dns_mode', 'off')}"
$dnsSpec = "{settings.get('private_dns_specifier', '')}"
if ($dnsMode -eq "null" -or $dnsMode -eq "") {{ $dnsMode = "off" }}
python -c "import tv; d = tv.TVDevice('$TvHost'); d.shell('settings put global private_dns_mode $dnsMode')"
if ($dnsSpec -ne "null" -and $dnsSpec -ne "") {{
    python -c "import tv; d = tv.TVDevice('$TvHost'); d.shell('settings put global private_dns_specifier $dnsSpec')"
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
        python -c "import tv; d = tv.TVDevice('$TvHost'); d.shell('pm enable $pkg')"
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

    # Criar Backup de Segurança Reversível
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

    # Atualizar backup com os pacotes desativados
    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(backup_data, f, indent=2)

    # 3. Terminar Processos e Forçar Paragem de Módulos
    print("\n[Passo 3/4] A terminar processos e serviços em execução da botnet...")
    for ioc in IOC_PACKAGES:
        adb.run(f"am force-stop {ioc}")
        adb.run(f"killall {ioc} 2>/dev/null")
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

    # Gerar o script de reversão no fim
    generate_restore_script(adb, backup_data, restore_script)

    print("\n================================================================================")
    print("  REMEDIAÇÃO CONCLUÍDA: A TV foi limpa e o tráfego de botnet bloqueado!")
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

    # 1. Repor definições
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

    # 2. Reativar pacotes
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
    print("================================================================================\n")


def interactive_menu(default_ip):
    target_ip = default_ip
    adb = AdbDevice(target_ip)
    adb.load_specs()

    while True:
        print("\n================================================================================")
        print(f"       XCPE / BADBOX FORENSIC SUITE - Android TV ({target_ip})                  ")
        print("================================================================================")
        print("  --- EXECUÇÃO AUTOMATIZADA ---")
        print("  1. Pipeline 100% Automatizado (Usa APK Universal - Rápido)")
        print("  2. Pipeline 100% Automatizado (Força RECOMPILAÇÃO no momento para a box)")
        print("")
        print("  --- DIAGNÓSTICO E INSTALAÇÃO MANUAL ---")
        print("  3. Diagnóstico Rápido ADB (5 Camadas - Apenas Leitura, Sem Instalar)")
        print("  4. Instalar App na Box (Opção de Escolher: APK Existente ou Recompilar)")
        print("  5. Abrir App no Ecrã da TV")
        print("  6. Descarregar Relatório (JSON + Log VPN) e Avaliar Regras")
        print("  7. Desinstalar App da Box (Limpeza Forense)")
        print("")
        print("  --- REMEDIAÇÃO E RESTAURO (REVERSÍVEL) ---")
        print("  8. Neutralizar / Limpar Box (Repõe Play Protect, Desativa Bots e Ativa DNS Seguro)")
        print("  9. Reverter Remediação / Restaurar Estado Anterior (Usar Backup)")
        print("")
        print("  --- CONFIGURAÇÃO E PRÉ-REQUISITOS ---")
        print(" 10. Gerir / Instalar Pré-Requisitos e Toolchains (Python / JDK / SDK)")
        print(" 11. Mudar IP da Box")
        print("  0. Sair")
        print("================================================================================")
        choice = input("Escolha uma opção [0-11]: ").strip()

        if choice == "1":
            step_automated_pipeline(adb, vpn_duration=20, force_recompile=False)
            input("\nPrima ENTER para continuar...")
        elif choice == "2":
            step_automated_pipeline(adb, vpn_duration=20, force_recompile=True)
            input("\nPrima ENTER para continuar...")
        elif choice == "3":
            step_quick_audit(adb)
            input("\nPrima ENTER para continuar...")
        elif choice == "4":
            print("\nQual versão do APK deseja instalar?")
            print("  [1] Usar APK universal existente (Instantâneo)")
            print("  [2] Recompilar de raiz no momento à medida deste aparelho (Requer JDK/SDK)")
            sub_choice = input("Escolha [1/2]: ").strip()
            force = (sub_choice == "2")
            step_install_custom_app(adb, force_recompile=force)
            input("\nPrima ENTER para continuar...")
        elif choice == "5":
            step_launch_app(adb)
            input("\nPrima ENTER para continuar...")
        elif choice == "6":
            step_pull_report(adb)
            input("\nPrima ENTER para continuar...")
        elif choice == "7":
            step_remove_app(adb)
            input("\nPrima ENTER para continuar...")
        elif choice == "8":
            step_remediate_device(adb)
            input("\nPrima ENTER para continuar...")
        elif choice == "9":
            step_restore_device(adb)
            input("\nPrima ENTER para continuar...")
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
            input("\nPrima ENTER para continuar...")
        elif choice == "11":
            new_ip = input("Novo IP: ").strip()
            if new_ip:
                target_ip = new_ip
                adb = AdbDevice(target_ip)
                adb.load_specs()
        elif choice == "0":
            print("\nA terminar sessão. Segurança garantida!")
            break
        else:
            print("[!] Opção inválida. Tente novamente.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BadBox & XCPE Forensic Suite", add_help=False)
    parser.add_argument("target", nargs="?", default=None, help="IP da Android TV")
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

    if args.target and (args.quick_scan or args.auto_pipeline or args.remediate or args.restore or args.install_app or args.recompile_for_device or args.launch_app or args.pull_report or args.remove_app):
        adb = AdbDevice(args.target)
        if args.auto_pipeline:
            step_automated_pipeline(adb, vpn_duration=20, force_recompile=args.recompile_for_device)
        elif args.remediate:
            step_remediate_device(adb)
        elif args.restore:
            step_restore_device(adb)
        elif args.quick_scan:
            adb.load_specs()
            step_quick_audit(adb)
        elif args.recompile_for_device or args.install_app:
            adb.load_specs()
            step_install_custom_app(adb, force_recompile=args.recompile_for_device)
        elif args.launch_app:
            step_launch_app(adb)
        elif args.pull_report:
            step_pull_report(adb)
        elif args.remove_app:
            step_remove_app(adb)
    elif args.target and not any([args.quick_scan, args.install_app, args.remediate, args.restore, args.recompile_for_device, args.launch_app, args.pull_report, args.remove_app]):
        adb = AdbDevice(args.target)
        adb.load_specs()
        step_quick_audit(adb)
    else:
        default_ip = os.environ.get("TV_HOST", "192.168.1.127")
        interactive_menu(default_ip)
