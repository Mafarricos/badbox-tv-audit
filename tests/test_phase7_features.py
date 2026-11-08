# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from export_blocklist import extract_domains, export_hosts, export_dnsmasq, export_adguard
import deep_forensics
from tests.fakes import FakeTransport


def test_at20_export_blocklist(tmp_path):
    """Test blocklist export in hosts, dnsmasq, and adguard formats (VPN-06)."""
    iocs_file = os.path.join(PROJECT_ROOT, "data", "iocs_database.json")
    domains = extract_domains(iocs_file)
    assert len(domains) > 50

    hosts_file = str(tmp_path / "hosts.txt")
    export_hosts(domains, hosts_file)
    with open(hosts_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "0.0.0.0 bestipip.com" in content
    assert content.startswith("# BadBox / XCPE Malicious Domains - Hosts Format")

    dnsmasq_file = str(tmp_path / "dnsmasq.conf")
    export_dnsmasq(domains, dnsmasq_file)
    with open(dnsmasq_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "address=/bestipip.com/0.0.0.0" in content

    adguard_file = str(tmp_path / "adguard.txt")
    export_adguard(domains, adguard_file)
    with open(adguard_file, "r", encoding="utf-8") as f:
        content = f.read()
    assert "||bestipip.com^" in content


def test_at23_deep_forensics_quarantine(tmp_path, monkeypatch):
    """Test deep forensics quarantine path and sha256 creation (FOR-01)."""
    monkeypatch.setattr(deep_forensics, "PROJECT_ROOT", str(tmp_path))

    class MockAdb:
        def __init__(self):
            self.host = "192.168.1.61"
            self.device_id = "test_device_123"

        def pull(self, remote, local):
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, "wb") as f:
                f.write(b"PK\x03\x04mock_apk_content")
            return True

    adb = MockAdb()
    deep_forensics.pull_and_analyze_apk(adb, "/system/priv-app/com.oemservice/com.oemservice.apk")

    quarantine_dir = tmp_path / "backups" / "test_device_123" / "quarantine"
    assert quarantine_dir.exists()
    quarantined_apk = quarantine_dir / "com.oemservice.apk.quarantined"
    sha256_file = quarantine_dir / "com.oemservice.apk.quarantined.sha256"

    assert quarantined_apk.exists()
    assert sha256_file.exists()
    with open(sha256_file, "r", encoding="utf-8") as f:
        sha_content = f.read()
    assert "com.oemservice.apk.quarantined" in sha_content
