import os
import sys
import json
import pytest
import tempfile
import subprocess
from tests.fakes import FakeTransport, is_mutating


def test_at05_updated_system_app_remediation(monkeypatch):
    """
    AT-05: Pacote com.oemservice atualizado (/data/app + 'Hidden system package').
    O plano deve conter 'pm disable-user --user 0 com.oemservice' e ser verificado.
    """
    from audit_security import AdbDevice, step_remediate_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice\npackage:com.google.android.youtube")
    fake.add_rule("pm path com.oemservice", "package:/data/app/~~xyz==/com.oemservice-1/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "Hidden system package:\n  Package [com.oemservice]\n  codePath=/system/priv-app/OEMService")
    fake.add_rule("pm uninstall com.oemservice", "Success")
    fake.add_rule("pm disable-user --user 0 com.oemservice", "Package com.oemservice new state: disabled-user")
    fake.add_rule("pm list packages -d", "package:com.oemservice")
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    res = step_remediate_device(dev, yes=True)
    assert res == 0

    # Verificar se ambos os comandos foram executados
    uninst_cmds = [c for c in fake.commands if "pm uninstall" in c and "com.oemservice" in c]
    disable_cmds = [c for c in fake.commands if "pm disable-user" in c and "com.oemservice" in c]
    assert len(uninst_cmds) > 0, "pm uninstall deve ser executado para remover update de /data/app"
    assert len(disable_cmds) > 0, "pm disable-user deve ser executado para congelar dropper em /system"


def test_at06_dry_run_is_non_mutating(monkeypatch):
    """
    AT-06: --remediate --dry-run gera plano mas tem zero comandos mutantes.
    """
    from audit_security import AdbDevice, step_remediate_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice")
    fake.add_rule("pm path com.oemservice", "package:/system/priv-app/com.oemservice/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "Package [com.oemservice]")
    fake.add_rule("settings get global package_verifier_user_consent", "-1")
    fake.add_rule("settings get global package_verifier_enable", "0")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    res = step_remediate_device(dev, dry_run=True, yes=True)
    assert res == 0

    mutating = [c for c in fake.commands if is_mutating(c)]
    assert mutating == [], f"Comandos mutantes foram executados durante --dry-run: {mutating}"


def test_at07_remediation_without_tty_and_without_yes_refuses(monkeypatch):
    """
    AT-07: --remediate sem TTY e sem --yes recusa com exit 6 e zero comandos mutantes.
    """
    from audit_security import AdbDevice, step_remediate_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice")
    fake.add_rule("pm path com.oemservice", "package:/system/priv-app/com.oemservice/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "Package [com.oemservice]")
    fake.add_rule("settings get global package_verifier_user_consent", "-1")
    fake.add_rule("settings get global package_verifier_enable", "0")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    # Simular ambiente não-interativo (sem TTY)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    with pytest.raises(SystemExit) as exc_info:
        step_remediate_device(dev, yes=False)

    assert exc_info.value.code == 6
    mutating = [c for c in fake.commands if is_mutating(c)]
    assert mutating == [], f"Comandos mutantes foram executados ao recusar sem TTY/sem --yes: {mutating}"


def test_at08_restore_script_injection_prevention(monkeypatch):
    """
    AT-08: Backup com private_dns_specifier = '$(touch PWNED)'.
    O restauro rejeita o valor e os scripts .sh/.ps1 NÃO contêm o payload.
    """
    from audit_security import AdbDevice, generate_restore_scripts, step_restore_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    with tempfile.TemporaryDirectory() as tmpdir:
        restore_ps1 = os.path.join(tmpdir, "restore.ps1")
        restore_sh = os.path.join(tmpdir, "restore.sh")
        backup_json = os.path.join(tmpdir, "backup.json")

        backup_data = {
            "device_id": dev.device_id,
            "host": "192.168.1.50",
            "timestamp": "20261108_000000",
            "settings": {
                "package_verifier_user_consent": "1",
                "package_verifier_enable": "1",
                "private_dns_mode": "hostname",
                "private_dns_specifier": "$(touch PWNED)",  # Injeção maliciosa
            },
            "disabled_during_remediation": [],
            "uninstalled_user0_packages": [],
            "pulled_apks": {},
            "appops_modified": []
        }

        with open(backup_json, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2)

        generate_restore_scripts(dev, backup_data, restore_ps1, restore_sh)

        with open(restore_sh, "r", encoding="utf-8") as f:
            sh_content = f.read()
        with open(restore_ps1, "r", encoding="utf-8") as f:
            ps_content = f.read()

        assert "$(touch PWNED)" not in sh_content, "restore.sh não deve conter dados do dispositivo"
        assert "$(touch PWNED)" not in ps_content, "restore.ps1 não deve conter dados do dispositivo"

        # Tentar restaurar o backup com o payload
        res = step_restore_device(dev, backup_path=backup_json)
        assert res is False, "O restauro deve rejeitar valores com comandos maliciosos em private_dns_specifier"


def test_at09_baseline_preserved_across_remediations(monkeypatch):
    """
    AT-09: Duas execuções de --remediate preservam o baseline.json intacto.
    """
    from audit_security import AdbDevice, create_remediation_backup

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("settings get global package_verifier_user_consent", "-1")
    fake.add_rule("settings get global package_verifier_enable", "0")
    fake.add_rule("settings get global private_dns_mode", "off")
    fake.add_rule("settings get global private_dns_specifier", "")
    fake.add_rule("pm list packages -d", "")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    with tempfile.TemporaryDirectory() as tmp_backups:
        monkeypatch.setattr("audit_security.BACKUPS_DIR", tmp_backups)

        # Execução 1: cria baseline.json com consent = -1
        run1, data1, _, _ = create_remediation_backup(dev)
        dev_dir = os.path.join(tmp_backups, dev.device_id)
        baseline_path = os.path.join(dev_dir, "baseline.json")

        with open(baseline_path, "r", encoding="utf-8") as f:
            base_data1 = json.load(f)
        assert base_data1["settings"]["package_verifier_user_consent"] == "-1"

        # Simular estado modificado e avanco no tempo
        import time
        base_t = time.time()
        monkeypatch.setattr(time, "time", lambda: base_t + 5.0)
        fake.add_rule("settings get global package_verifier_user_consent", "1")
        fake.add_rule("settings get global package_verifier_enable", "1")

        # Execução 2: não deve sobrescrever baseline.json!
        run2, data2, _, _ = create_remediation_backup(dev)
        assert run1 != run2

        with open(baseline_path, "r", encoding="utf-8") as f:
            base_data2 = json.load(f)
        assert base_data2["settings"]["package_verifier_user_consent"] == "-1", "baseline.json não pode ser sobrescrito"


def test_at10_restore_refuses_different_device(monkeypatch):
    """
    AT-10: --restore com outro dispositivo conectado (device_id diferente) recusa.
    """
    from audit_security import AdbDevice, step_restore_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake
    dev.specs = {
        "brand": "BrandB",
        "model": "ModelB",
        "serial": "DEVICE_B_SERIAL",
        "build_fingerprint": "BrandB/ModelB/fake:14/UKQ1/1:user/release-keys"
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        backup_json = os.path.join(tmpdir, "backup.json")
        backup_data = {
            "device_id": "DEVICE_A_DIFFERENT_HASH",
            "host": "192.168.1.50",
            "settings": {"package_verifier_user_consent": "1"}
        }
        with open(backup_json, "w", encoding="utf-8") as f:
            json.dump(backup_data, f)

        res = step_restore_device(dev, backup_path=backup_json)
        assert res is False, "Restauro deve recusar restaurar num dispositivo com device_id diferente"
        mutating = [c for c in fake.commands if is_mutating(c)]
        assert mutating == [], "Zero comandos mutantes devem ser executados se device_id não coincidir"


def test_at24_strict_argparse_exits_64():
    """
    AT-24: Flags desconhecidas ou inválidas (--dry-runn, --lang fr) saem com 64 sem ligar à TV.
    """
    audit_script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "audit_security.py")

    # Teste 1: Flag desconhecida
    res = subprocess.run([sys.executable, audit_script, "192.168.1.50", "--dry-runn"], capture_output=True, text=True)
    assert res.returncode == 64, f"Esperado exit 64 para --dry-runn, obtido {res.returncode}"

    # Teste 2: Idioma inválido
    res2 = subprocess.run([sys.executable, audit_script, "192.168.1.50", "--lang", "fr"], capture_output=True, text=True)
    assert res2.returncode == 64, f"Esperado exit 64 para --lang fr, obtido {res2.returncode}"


def test_at25_remediation_without_clear_data_has_no_pm_clear(monkeypatch):
    """
    AT-25: Sem --clear-data, nenhum 'pm clear' é executado. Nunca executar 'rm -rf'.
    """
    from audit_security import AdbDevice, step_remediate_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice")
    fake.add_rule("pm path com.oemservice", "package:/system/priv-app/com.oemservice/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "Package [com.oemservice]")
    fake.add_rule("pm disable-user --user 0 com.oemservice", "Package com.oemservice new state: disabled-user")
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    step_remediate_device(dev, clear_data=False, yes=True)

    pm_clears = [c for c in fake.commands if "pm clear" in c]
    rm_rfs = [c for c in fake.commands if "rm -rf" in c]

    assert pm_clears == [], "pm clear não pode ser executado sem a flag --clear-data"
    assert rm_rfs == [], "rm -rf é estritamente proibido"


def test_at26_at27_quarantine_apk_and_restore_behavior(monkeypatch):
    """
    AT-26 / AT-27: APKs são guardados em quarantine/ com extensão .apk.quarantined e .sha256.
    --restore não reinstala sem --restore-quarantined-apks.
    """
    from audit_security import AdbDevice, step_remediate_device, step_restore_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice")
    fake.add_rule("pm path com.oemservice", "package:/data/app/~~xyz==/com.oemservice-1/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "codePath=/data/app/com.oemservice")
    fake.add_rule("pm uninstall com.oemservice", "Success")
    fake.add_rule("pm list packages", "")
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    with tempfile.TemporaryDirectory() as tmp_backups:
        monkeypatch.setattr("audit_security.BACKUPS_DIR", tmp_backups)

        step_remediate_device(dev, yes=True)

        quarantine_dir = os.path.join(tmp_backups, dev.device_id, "quarantine")
        expected_apk = os.path.join(quarantine_dir, "com.oemservice.apk.quarantined")
        expected_sha = os.path.join(quarantine_dir, "com.oemservice.apk.quarantined.sha256")

        assert os.path.exists(expected_apk), f"APK em quarentena deve existir: {expected_apk}"
        assert os.path.exists(expected_sha), f"SHA-256 do APK em quarentena deve existir: {expected_sha}"

        # Teste AT-26: Restauro sem flag não deve reinstalar o APK
        fake.commands.clear()
        step_restore_device(dev, restore_quarantined_apks=False)
        installs = [c for c in fake.commands if "pm install" in c]
        assert installs == [], "Restauro padrão não deve reinstalar APKs em quarentena"

        # Teste AT-26 com flag: reinstala
        fake.commands.clear()
        step_restore_device(dev, restore_quarantined_apks=True)
        installs_allowed = [c for c in fake.commands if "pm install" in c]
        assert len(installs_allowed) > 0, "Com --restore-quarantined-apks, o APK deve ser reinstalado"
