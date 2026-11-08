#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validador formal e determinístico da base de dados de IoCs (data/iocs_database.json).
Verifica a integridade, esquema de tipos, ausência de duplicados, presença de fontes e marcadores proibidos.
"""

import sys
import os
import re
import json
import ipaddress

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_IOCS_PATH = os.path.join(PROJECT_ROOT, "data", "iocs_database.json")

VALID_TYPES = {
    "domain", "ip", "cidr", "package", "sha256", "md5",
    "file_path", "sdk_id", "dex_signature", "app_label", "device_model", "port"
}

PACKAGE_REGEX = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+)+$')
HEX64_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
HEX32_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def validate_entry(entry: dict, index: int) -> list:
    """Valida uma entrada individual de IoC. Retorna lista de erros encontrados."""
    errors = []

    # 1. Validação de marcadores proibidos (AT-18)
    for k, v in entry.items():
        v_str = str(v)
        if "[REDACTED" in v_str or "TODO" in v_str:
            errors.append(f"Entrada #{index}: Campo '{k}' contém marcador proibido ('{v_str}')")

    # 2. Fonte obrigatória
    source = entry.get("source")
    if not source or not str(source).strip():
        errors.append(f"Entrada #{index}: Campo 'source' é obrigatório e está ausente ou vazio")

    # 3. Tipo válido
    ioc_type = entry.get("type")
    if not ioc_type or ioc_type not in VALID_TYPES:
        errors.append(f"Entrada #{index}: Tipo '{ioc_type}' inválido. Tipos permitidos: {sorted(VALID_TYPES)}")
        return errors

    # 4. Valor do IoC
    val = entry.get("value")
    if val is None or str(val).strip() == "":
        errors.append(f"Entrada #{index}: 'value' não pode ser nulo ou vazio")
        return errors

    val_str = str(val).strip()

    if ioc_type == "domain":
        if not DOMAIN_REGEX.match(val_str):
            errors.append(f"Entrada #{index}: Domínio FQDN inválido '{val_str}'")
    elif ioc_type == "ip":
        try:
            ipaddress.ip_address(val_str)
        except ValueError:
            errors.append(f"Entrada #{index}: Endereço IP inválido '{val_str}'")
    elif ioc_type == "cidr":
        try:
            ipaddress.ip_network(val_str, strict=False)
        except ValueError:
            errors.append(f"Entrada #{index}: Bloco CIDR inválido '{val_str}'")
    elif ioc_type == "sha256":
        if not HEX64_REGEX.match(val_str):
            errors.append(f"Entrada #{index}: Hash SHA-256 deve ter 64 caracteres hexadecimais: '{val_str}'")
    elif ioc_type == "md5":
        if not HEX32_REGEX.match(val_str):
            errors.append(f"Entrada #{index}: Hash MD5 deve ter 32 caracteres hexadecimais: '{val_str}'")
    elif ioc_type == "package":
        if not PACKAGE_REGEX.match(val_str):
            errors.append(f"Entrada #{index}: Nome de pacote Android/Java inválido: '{val_str}'")
    elif ioc_type == "port":
        try:
            port_num = int(val_str)
            if port_num < 1 or port_num > 65535:
                errors.append(f"Entrada #{index}: Porta fora de intervalo (1-65535): '{val_str}'")
        except ValueError:
            errors.append(f"Entrada #{index}: Porta não numérica: '{val_str}'")

    return errors


def validate_iocs_database(path: str = DEFAULT_IOCS_PATH) -> bool:
    """Valida a base de dados de IoCs completa."""
    if not os.path.exists(path):
        print(f"[!] Erro: Ficheiro não encontrado: {path}", file=sys.stderr)
        return False

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Erro ao analisar JSON de {path}: {e}", file=sys.stderr)
        return False

    entries = data.get("entries")
    if not isinstance(entries, list):
        print(f"[!] Erro: Campo 'entries' deve ser uma lista", file=sys.stderr)
        return False

    print(f"[*] A validar base de dados de IoCs: {path} ({len(entries)} entradas)...")

    all_errors = []
    seen_keys = set()
    duplicate_count = 0

    for i, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            all_errors.append(f"Entrada #{i} não é um objeto JSON")
            continue

        # Verificar duplicados
        ioc_type = entry.get("type", "")
        ioc_val = str(entry.get("value", "")).strip().lower()
        key = (ioc_type, ioc_val)
        if key in seen_keys:
            all_errors.append(f"Entrada #{i}: Duplicado de ({ioc_type}: {ioc_val})")
            duplicate_count += 1
        else:
            seen_keys.add(key)

        entry_errors = validate_entry(entry, i)
        all_errors.extend(entry_errors)

    if all_errors:
        print(f"\\n[✗] FALHA NA VALIDAÇÃO: {len(all_errors)} erros encontrados:", file=sys.stderr)
        for err in all_errors[:20]:
            print(f"    - {err}", file=sys.stderr)
        if len(all_errors) > 20:
            print(f"    ... e mais {len(all_errors) - 20} erros.", file=sys.stderr)
        return False

    print(f"[✓] VALIDAÇÃO BEM-SUCEDIDA: {len(entries)} entradas validadas sem erros ou duplicados.")
    return True


if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IOCS_PATH
    success = validate_iocs_database(target_path)
    sys.exit(0 if success else 1)
