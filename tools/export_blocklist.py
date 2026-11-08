# -*- coding: utf-8 -*-
"""
Blocklist Exporter for badbox-tv-audit (VPN-06).
Exports malicious domains from the canonical IoC database (data/iocs_database.json)
into industry standard blocklist formats:
  - /etc/hosts (0.0.0.0 domain)
  - dnsmasq (address=/domain/0.0.0.0)
  - AdGuard / Pi-hole (||domain^)
"""

import os
import sys
import json
import argparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_IOCS = os.path.join(PROJECT_ROOT, "data", "iocs_database.json")
DEFAULT_OUT_DIR = os.path.join(PROJECT_ROOT, "blocklists")


def extract_domains(iocs_path):
    if not os.path.exists(iocs_path):
        raise FileNotFoundError(f"IoC database not found: {iocs_path}")

    with open(iocs_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    entries = data.get("entries", [])
    domains = set()
    for entry in entries:
        if isinstance(entry, dict) and entry.get("type") == "domain":
            val = entry.get("value", "").strip().lower()
            if val and not val.startswith("*."):
                domains.add(val)
            elif val.startswith("*."):
                domains.add(val[2:])
    return sorted(list(domains))


def export_hosts(domains, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# BadBox / XCPE Malicious Domains - Hosts Format\n")
        f.write(f"# Total Domains: {len(domains)}\n\n")
        for d in domains:
            f.write(f"0.0.0.0 {d}\n")


def export_dnsmasq(domains, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# BadBox / XCPE Malicious Domains - Dnsmasq Format\n")
        f.write(f"# Total Domains: {len(domains)}\n\n")
        for d in domains:
            f.write(f"address=/{d}/0.0.0.0\n")


def export_adguard(domains, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("! Title: BadBox & XCPE C2 Domain Blocklist\n")
        f.write(f"! Total Rules: {len(domains)}\n\n")
        for d in domains:
            f.write(f"||{d}^\n")


def main():
    parser = argparse.ArgumentParser(description="Export C2 domains into hosts/dnsmasq/AdGuard blocklists")
    parser.add_argument("--format", choices=["hosts", "dnsmasq", "adguard", "all"], default="all", help="Output format")
    parser.add_argument("--output-dir", default=DEFAULT_OUT_DIR, help="Destination directory")
    parser.add_argument("--input", default=DEFAULT_IOCS, help="Path to iocs_database.json")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")

    args = parser.parse_args()
    domains = extract_domains(args.input)

    if not args.quiet:
        print(f"[*] Loaded {len(domains)} unique malicious domains from {args.input}")

    os.makedirs(args.output_dir, exist_ok=True)

    if args.format in ("hosts", "all"):
        p = os.path.join(args.output_dir, "badbox_hosts.txt")
        export_hosts(domains, p)
        if not args.quiet:
            print(f"    [✓] Exported hosts blocklist: {p}")

    if args.format in ("dnsmasq", "all"):
        p = os.path.join(args.output_dir, "badbox_dnsmasq.conf")
        export_dnsmasq(domains, p)
        if not args.quiet:
            print(f"    [✓] Exported dnsmasq blocklist: {p}")

    if args.format in ("adguard", "all"):
        p = os.path.join(args.output_dir, "badbox_adguard.txt")
        export_adguard(domains, p)
        if not args.quiet:
            print(f"    [✓] Exported AdGuard/Pi-hole blocklist: {p}")


if __name__ == "__main__":
    main()
