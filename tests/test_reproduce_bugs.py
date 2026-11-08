import os
import sys
import json
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from tests.fakes import FakeTransport


def test_at02_reproduce_app_report_with_system_implant_gives_infected():
    """
    AT-02: Relatório da app com implante de sistema com.oemservice deve dar INFETADO (exit 1).
    Bug atual: No motor atual, "[CRÍTICO]" in f falha com "[CRÍTICO - IMPLANTE DE SISTEMA]",
    dando veredito "LIMPO / SEGURO" (score 0).
    """
    from audit_security import evaluate_forensic_results

    json_data = {
        "play_protect": "user_consent=1, enable=1",
        "findings": [
            "[CRÍTICO - IMPLANTE DE SISTEMA] Pacote de fábrica pré-instalado em /system ou /vendor: com.oemservice"
        ],
        "device": "Skyworth HP46BY4"
    }
    vpn_lines = []

    verdict = evaluate_forensic_results(json_data, vpn_lines)
    
    # Prova do bug: No código atual, verdict é "LIMPO / SEGURO"
    assert "CRÍTICO" in verdict or "INFETADO" in verdict or "INFECTED" in verdict, (
        f"BUG VER-01 / AT-02 reproduzido: Implante com.oemservice foi classificado como '{verdict}' em vez de INFETADO"
    )


def test_at03_reproduce_missing_or_corrupt_report_gives_inconclusive():
    """
    AT-03: Relatório em falta, JSON inválido ou vazio deve dar INCONCLUSIVE (exit 4).
    Bug atual: Sem dados (json_data=None, vpn_lines=None), o score fica em 0
    e o veredito atual é "LIMPO / SEGURO", mascarando a falha na recolha de evidência.
    """
    from audit_security import evaluate_forensic_results

    verdict = evaluate_forensic_results(None, None)

    # Prova do bug: No código atual, verdict é "LIMPO / SEGURO" (score 0)
    assert "INCONCLUSIVE" in verdict or "INCONCLUSIVO" in verdict, (
        f"BUG VER-02 / AT-03 reproduzido: Ausência de dados deu '{verdict}' em vez de INCONCLUSIVO"
    )


def test_at05_reproduce_remediation_of_updated_system_app_leaves_dropper_active(monkeypatch):
    """
    AT-05: Pacote com.oemservice atualizado (/data/app + 'Hidden system package').
    O plano deve conter 'pm disable-user --user 0 com.oemservice'.
    Bug atual: pm uninstall na app atualizada devolve 'Success' e o script salta
    o pm disable-user, deixando o dropper de sistema original ativo na ROM.
    """
    from audit_security import AdbDevice, step_remediate_device

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("pm list packages -e", "package:com.oemservice\npackage:com.google.android.youtube")
    fake.add_rule("pm path com.oemservice", "package:/data/app/~~xyz==/com.oemservice-1/base.apk")
    fake.add_rule("dumpsys package com.oemservice", "Hidden system package:\n  Package [com.oemservice]\n  codePath=/system/priv-app/OEMService")
    fake.add_rule("pm uninstall com.oemservice", "Success")
    fake.add_rule("pm disable-user --user 0 com.oemservice", "Package com.oemservice new state: disabled-user")
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    step_remediate_device(dev)

    # Prova do bug: No código atual, como pm uninstall deu Success, pm disable-user NUNCA é executado!
    disable_cmds = [c for c in fake.commands if "pm disable-user" in c and "com.oemservice" in c]
    assert len(disable_cmds) > 0, (
        "BUG REM-01 / AT-05 reproduzido: pm disable-user não foi executado para app de sistema atualizada!"
    )


def test_at08_reproduce_restore_script_command_injection(monkeypatch):
    """
    AT-08: Backup com private_dns_specifier = '$(touch PWNED)'.
    O restauro deve validar/rejeitar o valor e os scripts .sh/.ps1 NÃO podem expandir o comando.
    Bug atual: generate_restore_scripts insere DNS_SPEC="$(touch PWNED)" em aspas duplas,
    permitindo execução arbitrária de comandos ao correr o script de restauro.
    """
    import tempfile
    from audit_security import generate_restore_scripts, AdbDevice

    fake = FakeTransport("192.168.1.50")
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    with tempfile.TemporaryDirectory() as tmpdir:
        restore_ps1 = os.path.join(tmpdir, "restore.ps1")
        restore_sh = os.path.join(tmpdir, "restore.sh")

        backup_data = {
            "device_id": "test_device",
            "host": "192.168.1.50",
            "timestamp": "20261108_000000",
            "settings": {
                "package_verifier_user_consent": "1",
                "package_verifier_enable": "1",
                "private_dns_mode": "hostname",
                "private_dns_specifier": "$(touch PWNED)",  # Payload malicioso
            },
            "disabled_during_remediation": [],
            "uninstalled_user0_packages": [],
            "pulled_apks": {},
            "appops_modified": []
        }

        generate_restore_scripts(dev, backup_data, restore_ps1, restore_sh)

        with open(restore_sh, "r", encoding="utf-8") as f:
            sh_content = f.read()

        # Prova do bug: No código atual, sh_content embute DNS_SPEC="$(touch PWNED)" dentro de aspas duplas!
        # O novo design exige invólucros finos sem dados brutos interpolados em strings de comando.
        assert 'DNS_SPEC="$(touch PWNED)"' not in sh_content, (
            "BUG RST-01 / AT-08 reproduzido: restore.sh contém payload expansível em aspas duplas: DNS_SPEC=\"$(touch PWNED)\"!"
        )


def test_at11_reproduce_second_adb_device_talks_to_first_tv(monkeypatch):
    """
    AT-11: Dois AdbDevice com hosts diferentes devem ligar cada um ao seu host.
    Bug atual: tv.py lê TV_HOST na importação e fixa a constante global HOST.
    Quando AdbDevice("192.168.1.200") é criado, import tv reutiliza o módulo em cache
    e dev2 conecta-se ao host de dev1 (ou default).
    """
    import tv
    from audit_security import AdbDevice

    connected_hosts = []
    class MockTcpDevice:
        def __init__(self, host, port, **kwargs):
            self.host = host
            connected_hosts.append(host)
        def connect(self, *args, **kwargs):
            return True
        def shell(self, *args, **kwargs):
            return ""

    monkeypatch.setattr(tv, "AdbDeviceTcp", MockTcpDevice)
    monkeypatch.setattr(tv, "get_signer", lambda: None)
    monkeypatch.setattr(tv, "stock_signer", lambda: None)

    # Simular primeiro dispositivo
    dev1 = AdbDevice("192.168.1.100")
    # Simular segundo dispositivo
    dev2 = AdbDevice("192.168.1.200")

    assert dev1.host != dev2.host
    # Prova do bug: No código atual, tv.HOST foi fixado na primeira importação
    # e MockTcpDevice foi instanciado com o host de dev1 (ou default), NUNCA com 192.168.1.200!
    assert "192.168.1.200" in connected_hosts, (
        f"BUG PY-02 / AT-11 reproduzido: dev2 não conectou a 192.168.1.200; hosts conectados: {connected_hosts}"
    )


def test_at12_reproduce_scan_subnet_name_error():
    """
    AT-12: --scan-subnet deve executar descoberta de rede privada.
    Bug atual: audit_security.py l. 1575 chama 'discover_subnet_tvs', que não existe
    e lança NameError.
    """
    import audit_security
    # Prova do bug: discover_subnet_tvs não está definido
    assert hasattr(audit_security, "discover_subnet_tvs"), (
        "BUG FEAT-01 / AT-12 reproduzido: discover_subnet_tvs não está definido em audit_security.py!"
    )


def test_at13_reproduce_quick_scan_json_stdout_is_pure_json(capsys, monkeypatch):
    """
    AT-13: --quick-scan --json deve emitir estritamente JSON válido no stdout.
    Bug atual: DualLogger e banners de terminal imprimem linhas antes do JSON,
    corrompendo a saída para parsers automáticos.
    """
    from audit_security import AdbDevice, step_quick_audit

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")
    fake.add_rule("pm list packages", "package:com.google.android.youtube")
    fake.add_rule("pm list packages -d", "")
    fake.add_rule("netstat -n -a", "")
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    capsys.readouterr()
    step_quick_audit(dev, json_output=True)
    captured = capsys.readouterr()

    # Prova do bug: captured.out contém texto/banners antes do JSON
    stdout_clean = captured.out.strip()
    try:
        parsed = json.loads(stdout_clean)
        assert isinstance(parsed, dict)
    except json.JSONDecodeError:
        pytest.fail(f"BUG FEAT-02 / AT-13 reproduzido: stdout não é JSON puro:\n{stdout_clean[:200]}")


def test_at14_reproduce_public_ip_on_port_2095_is_not_critical(monkeypatch):
    """
    AT-14: Ligação a um IP público fora da base na porta 2095 (Cloudflare/IPTV).
    Deve ser SUSPICIOUS_PORT_ONLY (LOW) e dar veredito CLEAN.
    Bug atual: remote_port in C2_REMOTE_PORTS adiciona +10 pontos e dá CRÍTICO.
    """
    from audit_security import AdbDevice, step_quick_audit

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")
    fake.add_rule("pm list packages", "package:com.google.android.youtube")
    fake.add_rule("pm list packages -d", "")
    fake.add_rule(
        "netstat -n -a",
        "Proto Recv-Q Send-Q Local Address          Foreign Address        State\n"
        "tcp        0      0 192.168.1.50:45678     104.16.123.96:2095     ESTABLISHED"
    )
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    res = step_quick_audit(dev, json_output=False)
    verdict = res.get("verdict", "")

    # Prova do bug: No código atual, a porta 2095 dá CRÍTICO!
    assert "CRÍTICO" not in verdict and "CRITICAL" not in verdict, (
        f"BUG RUL-01 / AT-14 reproduzido: Porta 2095 isolada deu veredito '{verdict}'"
    )


def test_at15_reproduce_skyworth_chip_id_and_vendor_model_are_only_info(monkeypatch):
    """
    AT-15: Propriedades do fabricante (chip ID Skyworth e ro.mecool.device.model).
    Devem ser classificadas como INFO e não pontuar risco nem dar SUSPEITO.
    Bug atual: SUSPICIOUS_SYSTEM_PROPS soma pontos e torna o dispositivo SUSPEITO.
    """
    from audit_security import AdbDevice, step_quick_audit

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")
    fake.add_rule("pm list packages", "package:com.google.android.youtube")
    fake.add_rule("pm list packages -d", "")
    fake.add_rule("netstat -n -a", "")
    fake.add_rule(
        "getprop",
        "[ro.hardware.skyworthdigital.soc.chipid]: [HP46BY4_AMLOGIC_S905Y4]\n"
        "[ro.mecool.device.model]: [KM2_PLUS]\n"
        "[ro.build.tags]: [release-keys]"
    )
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    res = step_quick_audit(dev, json_output=False)
    verdict = res.get("verdict", "")
    score = res.get("score", 0)

    # Prova do bug: No código atual, estas propriedades dão score > 0 e SUSPEITO!
    assert "SUSPEITO" not in verdict and "SUSPICIOUS" not in verdict and score == 0, (
        f"BUG RUL-02 / AT-15 reproduzido: Propriedades de fabricante deram score {score} e '{verdict}'"
    )
