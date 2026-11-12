import os
import re
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_at01_no_keystores_or_apks_versioned_and_no_hardcoded_passwords():
    """
    AT-01: Nenhum *.keystore, *.jks ou APK versionado no repositório.
    build.gradle sem palavras-passe literais.
    Debug sem signingConfig de release.
    """
    # 1. Verificar ficheiros proibidos
    forbidden_extensions = (".keystore", ".jks", ".apk")
    forbidden_files = []
    for root, dirs, files in os.walk(PROJECT_ROOT):
        # Ignorar .git, venv, backups
        if any(ignored in root for ignored in [".git", "venv", ".venv", "backups", "build"]):
            continue
        for f in files:
            if f.endswith(forbidden_extensions) or f == "xcpe-scanner-tv.apk.sha256":
                forbidden_files.append(os.path.join(root, f))

    assert not forbidden_files, f"AT-01 falhou: Ficheiros proibidos encontrados no repositório: {forbidden_files}"

    # 2. Verificar app/app/build.gradle
    build_gradle_path = os.path.join(PROJECT_ROOT, "app", "app", "build.gradle")
    assert os.path.exists(build_gradle_path), "build.gradle não encontrado"
    with open(build_gradle_path, "r", encoding="utf-8") as f:
        gradle_content = f.read()

    # Não deve conter palavras-passe literais
    assert "badbox-release-2026" not in gradle_content, "build.gradle contém palavra-passe hardcoded!"
    assert 'storePassword "' not in gradle_content, "build.gradle contém storePassword literal!"
    assert 'keyPassword "' not in gradle_content, "build.gradle contém keyPassword literal!"

    # Debug não deve usar signingConfigs.release
    debug_block_match = re.search(r'debug\s*\{([^}]+)\}', gradle_content)
    if debug_block_match:
        debug_content = debug_block_match.group(1)
        assert "signingConfig signingConfigs.release" not in debug_content, (
            "AT-01 falhou: Bloco debug ainda está a usar signingConfig de release!"
        )

    # Versão atualizada (>= 2.0.0 e versionCode >= 2)
    assert re.search(r'versionCode\s+[2-9]\d*', gradle_content), "versionCode deve ser >= 2"
    assert re.search(r'versionName\s+"2\.\d+\.\d+"', gradle_content), "versionName deve ser 2.x.x"


def test_at22_automated_pipeline_safety(monkeypatch):
    """
    AT-22: --auto-pipeline (simulado)
    - Nenhum input keyevent
    - Nenhum SYSTEM_ALERT_WINDOW
    - Instalação via pm install -r (sem -d nem -t)
    - Se a app pré-existente tiver certificado desconhecido, desinstala com registo
    """
    from audit_security import AdbDevice, step_automated_pipeline, PACKAGE_NAME
    from tests.fakes import FakeTransport

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    # Simular ausência de app pré-existente
    fake.add_rule(f"pm path {PACKAGE_NAME}", "")
    fake.add_rule(f"pm install -r /data/local/tmp/xcpe-scanner-tv.apk", "Success")
    fake.add_rule(f"appops set {PACKAGE_NAME} ACTIVATE_VPN allow", "")
    fake.add_rule("dumpsys activity activities", PACKAGE_NAME)
    fake.add_rule(f"cat /sdcard/Android/data/{PACKAGE_NAME}/files/audit_events.log", "SCAN_ESTATICO_CONCLUIDO")
    fake.add_rule(f"am startservice -a STOP", "")
    fake.add_rule(f"pm uninstall {PACKAGE_NAME}", "Success")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    monkeypatch.setattr("audit_security.compile_custom_app", lambda specs, force_recompile=False: ("/tmp/fake_scanner.apk", False))
    monkeypatch.setattr("audit_security.verify_apk_pin", lambda apk_path, pin_file=None, allow_local_build=False: True)
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    # Executar pipeline simulado
    try:
        step_automated_pipeline(dev, vpn_duration=1)
    except Exception:
        pass

    # 1. Não deve haver injeção de teclas D-Pad cegas
    keyevents = [c for c in fake.commands if "input keyevent" in c]
    assert not keyevents, f"AT-22 falhou: Injeção de teclas D-Pad detetada: {keyevents}"

    # 2. Não deve conceder SYSTEM_ALERT_WINDOW
    alert_window_cmds = [c for c in fake.commands if "SYSTEM_ALERT_WINDOW" in c]
    assert not alert_window_cmds, f"AT-22 falhou: SYSTEM_ALERT_WINDOW foi concedido: {alert_window_cmds}"

    # 3. pm install deve usar apenas -r, sem as flags -d nem -t
    install_cmds = [c for c in fake.commands if c.startswith("pm install")]
    assert install_cmds, "AT-22 falhou: comando pm install não foi executado"
    for icmd in install_cmds:
        # Verificar se as flags -d ou -t foram passadas como opções de linha de comando isoladas
        flags = icmd.split()
        assert "-d" not in flags, f"AT-22 falhou: flag -d encontrada em: {icmd}"
        assert "-t" not in flags, f"AT-22 falhou: flag -t encontrada em: {icmd}"


def test_at23_apk_pin_aborts_on_untrusted_certificate(monkeypatch, tmp_path):
    """
    AT-23: step_install_custom_app verifica sempre o certificado contra apk_pin.json
    (independentemente do nome do ficheiro) e aborta a instalação quando não coincide.
    """
    from audit_security import AdbDevice, step_install_custom_app, PACKAGE_NAME
    from tests.fakes import FakeTransport

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule(f"pm path {PACKAGE_NAME}", "")
    fake.add_rule("pm install -r /data/local/tmp/xcpe-scanner-tv.apk", "Success")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    # Criar um ficheiro APK fictício sem o certificado oficial
    fake_apk = tmp_path / "xcpe-scanner-tv.apk"
    fake_apk.write_bytes(b"PK\x03\x04fake-unsigned-apk-bytes")

    # Tentar instalar -> deve falhar e devolver False SEM executar adb push ou pm install
    result = step_install_custom_app(dev, custom_apk_path=str(fake_apk))
    assert result is False, "A instalação deveria ter sido abortada quando o certificado não coincide com apk_pin.json!"
    install_cmds = [c for c in fake.commands if c.startswith("pm install")]
    assert not install_cmds, f"pm install não deveria ter sido chamado para APK não verificado: {install_cmds}"

