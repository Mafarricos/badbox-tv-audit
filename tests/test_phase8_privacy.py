# -*- coding: utf-8 -*-
"""
Privacy and Sanitization Tests (PRIV-01, PRIV-02).
Verifies that community submissions strictly strip IP addresses, MAC addresses, serial numbers, chip IDs, and PII.
"""

import os
import re
import sys
import json
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from audit_security import generate_sanitized_community_submission, sanitize_community_data


def test_at17_community_submission_strips_pii(tmp_path):
    """Test AT-17: Community submission output contains no IP, MAC, serial, chip ID, or PII."""
    raw_specs = {
        "manufacturer": "Videostrong",
        "brand": "MECOOL",
        "model": "KM2 Plus at 192.168.1.55",
        "serial": "SN1234567890ABCDEF",
        "serialno": "SN987654321",
        "ro.serialno": "SN11223344",
        "wifi_mac": "00:1A:2B:3C:4D:5E",
        "eth_mac": "aa:bb:cc:dd:ee:ff",
        "ip": "192.168.1.61",
        "public_ip": "203.0.113.195",
        "ipv6": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "chip_id": "CHIP-SKYWORTH-998877",
        "ro.vendor.skyworth.chipid": "SW-CHIP-445566",
        "imei": "123456789012345",
        "android_version": "11",
        "sdk_version": "30"
    }

    raw_findings = [
        "Conexão ativa com C2 em 192.168.1.61:3885 (MAC: 00:1A:2B:3C:4D:5E)",
        {"code": "C2_ACTIVE_FLOW", "subject": "TCP:203.0.113.195:3885", "severity": "CRITICAL"}
    ]

    out_file = str(tmp_path / "sanitized_submission.json")
    report = generate_sanitized_community_submission(
        json_data={"findings": raw_findings},
        vpn_log_lines=["raw log"],
        device_specs=raw_specs,
        verdict="INFETADO_CRITICO",
        score=25,
        out_path=out_file
    )

    assert os.path.exists(out_file)
    with open(out_file, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Regex check: NO raw IPv4 address (e.g. 192.168.1.x, 203.0.113.x)
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    assert not ipv4_pattern.findall(content), f"Found IPv4 in sanitized output: {ipv4_pattern.findall(content)}"

    # 2. Regex check: NO MAC address
    mac_pattern = re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b')
    assert not mac_pattern.findall(content), f"Found MAC in sanitized output: {mac_pattern.findall(content)}"

    # 3. Specific identifier checks: NO serials, chip IDs, or IMEIs
    assert "SN1234567890ABCDEF" not in content
    assert "SN987654321" not in content
    assert "SN11223344" not in content
    assert "CHIP-SKYWORTH" not in content
    assert "SW-CHIP" not in content
    assert "123456789012345" not in content
    assert "2001:0db8" not in content

    # 4. Whitelisted specs are preserved
    parsed = json.loads(content)
    device = parsed["device"]
    assert device["manufacturer"] == "Videostrong"
    assert device["brand"] == "MECOOL"
    assert device["android_version"] == "11"
    assert device["sdk_version"] == "30"
    assert "[REDACTED_IP]" in device["model"]
