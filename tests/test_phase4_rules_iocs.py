import os
import sys
import json
import pytest
import subprocess
from tests.fakes import FakeTransport
from iocs import parse_socket_address, IOC_DB
from validate_iocs import validate_iocs_database, validate_entry


def test_at14_port_2095_isolated_is_not_critical(monkeypatch):
    """
    AT-14: Ligação a um IP público fora da base na porta 2095 (Cloudflare/IPTV)
    deve ser SUSPICIOUS_PORT_ONLY (LOW) e dar veredito CLEAN.
    Ligação a um IP da base na mesma porta dá C2_IP_CONNECTION (CRITICAL).
    """
    from audit_security import AdbDevice, step_quick_audit

    # 1. IP fora da base na porta 2095
    fake1 = FakeTransport("192.168.1.50")
    fake1.set_specs()
    fake1.add_rule("settings get global package_verifier_user_consent", "1")
    fake1.add_rule("settings get global package_verifier_enable", "1")
    fake1.add_rule("pm list packages", "package:com.google.android.youtube")
    fake1.add_rule("pm list packages -d", "")
    fake1.add_rule(
        "netstat -n -a",
        "Proto Recv-Q Send-Q Local Address          Foreign Address        State\n"
        "tcp        0      0 192.168.1.50:45678     104.16.123.96:2095     ESTABLISHED"
    )
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake1))
    dev1 = AdbDevice("192.168.1.50")
    dev1.device = fake1

    res1 = step_quick_audit(dev1, json_output=False)
    v1 = res1.get("verdict", "")
    assert "CRÍTICO" not in v1 and "CRITICAL" not in v1
    assert "LIMPO" in v1 or "CLEAN" in v1

    # 2. IP conhecido de C2 (ex: 219.134.163.210) na porta 2095 -> CRITICAL
    fake2 = FakeTransport("192.168.1.50")
    fake2.set_specs()
    fake2.add_rule("settings get global package_verifier_user_consent", "1")
    fake2.add_rule("settings get global package_verifier_enable", "1")
    fake2.add_rule("pm list packages", "package:com.google.android.youtube")
    fake2.add_rule("pm list packages -d", "")
    fake2.add_rule(
        "netstat -n -a",
        "Proto Recv-Q Send-Q Local Address          Foreign Address        State\n"
        "tcp        0      0 192.168.1.50:45678     219.134.163.210:2095   ESTABLISHED"
    )
    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake2))
    dev2 = AdbDevice("192.168.1.50")
    dev2.device = fake2

    res2 = step_quick_audit(dev2, json_output=False)
    v2 = res2.get("verdict", "")
    assert "CRÍTICO" in v2 or "CRITICAL" in v2 or "INFETADO" in v2 or "INFECTED" in v2


def test_at15_vendor_properties_do_not_increase_risk_score(monkeypatch):
    """
    AT-15: getprop com chip ID Skyworth e ro.mecool.device.model são apenas INFO e dão CLEAN.
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
    v = res.get("verdict", "")
    score = res.get("score", 0)

    assert score == 0, f"Propriedades do fabricante pontuaram risco ({score})"
    assert "LIMPO" in v or "CLEAN" in v


def test_at16_socket_address_parser_ipv4_ipv6_and_mapped():
    """
    AT-16: netstat com IPv6 nativo, IPv4 e IPv4 mapeado em IPv6 (::ffff:).
    Host e porta remotos devem ser extraídos corretamente nos 3 casos.
    """
    # 1. IPv4 standard
    h1, p1 = parse_socket_address("192.168.1.50:45678")
    assert h1 == "192.168.1.50"
    assert p1 == 45678

    # 2. IPv6 nativo
    h2, p2 = parse_socket_address("[2001:db8::1]:8080")
    assert h2 == "2001:db8::1"
    assert p2 == 8080

    # 3. IPv4 mapeado em IPv6 (::ffff:x.x.x.x)
    h3, p3 = parse_socket_address("::ffff:104.16.123.96:2095")
    assert h3 == "104.16.123.96"
    assert p3 == 2095

    # 4. IPv4 mapeado entre parênteses retos [::ffff:x.x.x.x]:port
    h4, p4 = parse_socket_address("[::ffff:38.145.197.135]:3885")
    assert h4 == "38.145.197.135"
    assert p4 == 3885


def test_at18_validate_iocs_script_rules():
    """
    AT-18: validate_iocs.py rejeita entradas sem source, tipo inválido, [REDACTED ou duplicados.
    A base de dados atual passa na validação integral.
    """
    # 1. Base atual passa 100%
    assert validate_iocs_database() is True

    # 2. Entrada com [REDACTED deve falhar
    err_redacted = validate_entry({"type": "domain", "value": "[REDACTED].com", "source": "test"}, 1)
    assert any("[REDACTED" in e for e in err_redacted)

    # 3. Entrada sem source deve falhar
    err_no_source = validate_entry({"type": "domain", "value": "clean.com", "source": ""}, 2)
    assert any("source" in e for e in err_no_source)

    # 4. Tipo inválido deve falhar
    err_bad_type = validate_entry({"type": "unknown_type", "value": "val", "source": "test"}, 3)
    assert any("inválido" in e or "invalid" in e.lower() for e in err_bad_type)


def test_at19_rule_engine_consistency():
    """
    AT-19: Todos os códigos de findings declarados em rules.json existem e têm severidade/peso definidos.
    """
    rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rules.json")
    with open(rules_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules = data.get("rules", {})
    assert len(rules) >= 20

    for code, rdef in rules.items():
        assert "severity" in rdef
        assert rdef["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert "weight" in rdef
        assert isinstance(rdef["weight"], int)


def test_at28_neutralized_state_when_ioc_package_is_disabled(monkeypatch):
    """
    AT-28: Pacote IoC presente mas desativado, sem mais nada -> NEUTRALIZED, exit 0.
    """
    from audit_security import AdbDevice, step_quick_audit

    fake = FakeTransport("192.168.1.50")
    fake.set_specs()
    fake.add_rule("settings get global package_verifier_user_consent", "1")
    fake.add_rule("settings get global package_verifier_enable", "1")
    # Pacote com.oemservice instalado e desativado (-d)
    fake.add_rule("pm list packages", "package:com.oemservice")
    fake.add_rule("pm list packages -d", "package:com.oemservice")
    fake.add_rule("netstat -n -a", "")
    fake.add_rule("getprop", "")

    monkeypatch.setattr(AdbDevice, "_init_connection", lambda self: setattr(self, "device", fake))
    dev = AdbDevice("192.168.1.50")
    dev.device = fake

    res = step_quick_audit(dev, json_output=False)
    v = res.get("verdict", "")
    assert "NEUTRALIZADO" in v or "NEUTRALIZED" in v
