#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo centralizado de carregamento e consulta determinística de IoCs (IOC-01, IOC-03).
Carrega data/iocs_database.json uma única vez e expõe lookups O(1) e parsing de endereços (AT-16).
"""

import os
import json
import ipaddress
from typing import Set, List, Optional, Tuple, Dict, Any

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IOCS_DATABASE_FILE = os.path.join(PROJECT_ROOT, "data", "iocs_database.json")


def parse_socket_address(addr_str: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Parser robusto de endereços de sockets Android (netstat e ss).
    Separa host e porta com rsplit(':', 1), remove chavetas e normaliza:
    - IPv4: '192.168.1.50:45678' -> ('192.168.1.50', 45678)
    - IPv6 nativo: '[2001:db8::1]:8080' ou '2001:db8::1:8080' -> ('2001:db8::1', 8080)
    - IPv4 mapeado em IPv6: '::ffff:104.16.123.96:2095' -> ('104.16.123.96', 2095)
    Aceitação: AT-16.
    """
    s = addr_str.strip()
    if not s or s in ("*", "0.0.0.0:*", "[::]:*", ":::*"):
        return None, None

    if ":" not in s:
        return None, None

    # Se estiver no formato [host]:port
    if s.startswith("[") and "]:" in s:
        host_part, port_part = s[1:].split("]:", 1)
    else:
        host_part, port_part = s.rsplit(":", 1)

    host_part = host_part.strip("[]").strip()
    try:
        port = int(port_part)
    except ValueError:
        return None, None

    # Tratar IPv4 mapeado em IPv6 (::ffff:192.0.2.1)
    if host_part.lower().startswith("::ffff:"):
        host_part = host_part[7:]

    # Normalizar IP através do módulo ipaddress
    try:
        ip_obj = ipaddress.ip_address(host_part)
        return str(ip_obj), port
    except ValueError:
        # Se for hostname ou string literal (ex: 'localhost', '*')
        return host_part, port


class IOCDatabase:
    """Base de dados em memória com índices rápidos para correspondência de IoCs."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or IOCS_DATABASE_FILE
        self.packages: Set[str] = set()
        self.domains: Set[str] = set()
        self.ips: Set[str] = set()
        self.cidrs: List[Any] = []
        self.hashes: Set[str] = set()
        self.binary_paths: Set[str] = set()
        self.content_providers: Set[str] = set()
        self.ports: Set[int] = set()
        self.entries_count: int = 0
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return

        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = data.get("entries", [])
        self.entries_count = len(entries)

        for e in entries:
            t = e.get("type")
            v = str(e.get("value", "")).strip()
            if not v:
                continue

            v_lower = v.lower()

            if t == "package":
                self.packages.add(v_lower)
            elif t == "domain":
                self.domains.add(v_lower)
            elif t == "ip":
                try:
                    ip_obj = ipaddress.ip_address(v)
                    self.ips.add(str(ip_obj))
                except ValueError:
                    self.ips.add(v_lower)
            elif t == "cidr":
                try:
                    self.cidrs.append(ipaddress.ip_network(v, strict=False))
                except ValueError:
                    pass
            elif t in ("sha256", "md5"):
                self.hashes.add(v_lower)
            elif t == "file_path":
                self.binary_paths.add(v)
            elif t == "content_provider":
                self.content_providers.add(v)
            elif t == "port":
                try:
                    self.ports.add(int(v))
                except ValueError:
                    pass

        # Carregar listas auxiliares se existirem no objeto raiz
        for p in data.get("botnet_packages", []):
            if isinstance(p, str):
                self.packages.add(p.strip().lower())
        for d in data.get("c2_domains", []):
            if isinstance(d, str):
                self.domains.add(d.strip().lower())
        for prov in data.get("content_providers", []):
            if isinstance(prov, str):
                self.content_providers.add(prov.strip())
        for port in data.get("suspicious_ports", []):
            try:
                self.ports.add(int(port))
            except (ValueError, TypeError):
                pass

    def is_c2_package(self, pkg_name: str) -> bool:
        """Verifica se um nome de pacote coincide exatamente com a base de IoCs."""
        return pkg_name.strip().lower() in self.packages

    def is_c2_domain(self, domain: str) -> bool:
        """Verifica se um domínio coincide exatamente ou como sufixo de C2."""
        d = domain.strip().lower().rstrip(".")
        if d in self.domains:
            return True
        for c2_dom in self.domains:
            if d.endswith("." + c2_dom):
                return True
        return False

    def is_c2_ip(self, ip_str: str) -> bool:
        """Verifica se um IP coincide por igualdade ou inclusão num CIDR da botnet."""
        ip_clean = ip_str.strip().lower()
        if ip_clean.startswith("::ffff:"):
            ip_clean = ip_clean[7:]

        if ip_clean in self.ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_clean)
            for cidr in self.cidrs:
                if ip_obj in cidr:
                    return True
        except ValueError:
            pass

        return False


# Instância global singleton
IOC_DB = IOCDatabase()
