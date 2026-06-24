#!/usr/bin/env python3
"""Validate the rskrb5 Active Directory integration environment."""

from __future__ import annotations

import base64
import binascii
import os
import socket
import sys
from pathlib import Path


ENDPOINTS = [
    (
        "USER realm KDC",
        ("TEST_AD_USER_KDC_ADDR", "TEST_AD_KDC_ADDR"),
        "192.168.88.100:88",
        True,
    ),
    (
        "RESOURCE realm KDC",
        ("TEST_AD_RESOURCE_KDC_ADDR", "TEST_AD_RES_KDC_ADDR"),
        "192.168.88.101:88",
        True,
    ),
    (
        "USER realm admin server",
        ("TEST_AD_USER_ADMIN_ADDR", "TEST_AD_ADMIN_ADDR"),
        "192.168.88.100:464",
        False,
    ),
    (
        "RESOURCE realm admin server",
        ("TEST_AD_RESOURCE_ADMIN_ADDR", "TEST_AD_RES_ADMIN_ADDR"),
        "192.168.88.101:464",
        False,
    ),
]

KEYTABS = [
    (
        "testuser1@USER.GOKRB5",
        "TEST_AD_TESTUSER1_KEYTAB_PATH",
        "TEST_AD_TESTUSER1_KEYTAB_HEX",
        "TEST_AD_TESTUSER1_KEYTAB_BASE64",
    ),
    (
        "testuser2@USER.GOKRB5",
        "TEST_AD_TESTUSER2_KEYTAB_PATH",
        "TEST_AD_TESTUSER2_KEYTAB_HEX",
        "TEST_AD_TESTUSER2_KEYTAB_BASE64",
    ),
    (
        "testuser3@USER.GOKRB5",
        "TEST_AD_TESTUSER3_KEYTAB_PATH",
        "TEST_AD_TESTUSER3_KEYTAB_HEX",
        "TEST_AD_TESTUSER3_KEYTAB_BASE64",
    ),
    (
        "sysHTTP@RES.GOKRB5",
        "TEST_AD_SYSHTTP_KEYTAB_PATH",
        "TEST_AD_SYSHTTP_KEYTAB_HEX",
        "TEST_AD_SYSHTTP_KEYTAB_BASE64",
    ),
]


def main() -> int:
    errors: list[str] = []

    require_explicit_endpoints = env_flag("TEST_AD_REQUIRE_EXPLICIT_ENDPOINTS")
    require_keytabs = env_flag("TEST_AD_REQUIRE_KEYTAB_OVERRIDES")
    skip_reachability = env_flag("TEST_AD_SKIP_REACHABILITY")
    check_admin_reachability = env_flag("TEST_AD_CHECK_ADMIN_REACHABILITY")
    timeout = float(os.environ.get("TEST_AD_CONNECT_TIMEOUT_SECS", "2"))

    require_value("TESTAD", "1", errors)
    require_value("TESTAD_REQUIRED", "1", errors)

    print("AD integration environment:")
    for label, names, default, required_reachability in ENDPOINTS:
        value, source = first_env_value(names, default)
        if require_explicit_endpoints and source == "default":
            errors.append(
                f"{label} must be explicit; set one of {', '.join(names)}"
            )
        print(f"  {label}: {value} ({source})")

        should_check = required_reachability or check_admin_reachability
        if should_check and not skip_reachability:
            error = check_tcp(label, value, timeout)
            if error:
                errors.append(error)

    print("AD keytab sources:")
    for label, path_var, hex_var, base64_var in KEYTABS:
        source, data, error = load_keytab_override(path_var, hex_var, base64_var)
        if error:
            errors.append(f"{label}: {error}")
            continue
        if data is None:
            if require_keytabs:
                errors.append(
                    f"{label}: set one of {path_var}, {hex_var}, or {base64_var}"
                )
            print(f"  {label}: embedded test fixture")
            continue
        keytab_error = validate_keytab_header(data)
        if keytab_error:
            errors.append(f"{label}: {source} {keytab_error}")
            continue
        print(f"  {label}: {source} ({len(data)} bytes)")

    if errors:
        sys.stdout.flush()
        print("\nAD integration environment is not ready:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("AD integration environment is ready.")
    return 0


def env_flag(name: str) -> bool:
    return os.environ.get(name, "") == "1"


def require_value(name: str, expected: str, errors: list[str]) -> None:
    actual = os.environ.get(name, "")
    if actual != expected:
        errors.append(f"{name} must be {expected!r}, got {actual!r}")


def first_env_value(names: tuple[str, ...], default: str) -> tuple[str, str]:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value, name
    return default, "default"


def check_tcp(label: str, endpoint: str, timeout: float) -> str | None:
    try:
        host, port = split_host_port(endpoint)
    except ValueError as error:
        return f"{label} endpoint {endpoint!r} is invalid: {error}"

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return None
    except OSError as error:
        return f"cannot reach {label} at {endpoint}: {error}"


def split_host_port(endpoint: str) -> tuple[str, int]:
    host, sep, port_text = endpoint.rpartition(":")
    if not sep or not host or not port_text:
        raise ValueError("expected host:port")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("port is not numeric") from error
    if port < 1 or port > 65535:
        raise ValueError("port is outside 1..65535")
    return host.strip("[]"), port


def load_keytab_override(
    path_var: str, hex_var: str, base64_var: str
) -> tuple[str, bytes | None, str | None]:
    path = os.environ.get(path_var, "")
    if path:
        try:
            return path_var, Path(path).read_bytes(), None
        except OSError as error:
            return path_var, None, f"{path_var}={path}: {error}"

    hex_value = os.environ.get(hex_var, "")
    if hex_value:
        compact = "".join(hex_value.split())
        try:
            return hex_var, bytes.fromhex(compact), None
        except ValueError as error:
            return hex_var, None, f"{hex_var} is not valid hex: {error}"

    base64_value = os.environ.get(base64_var, "")
    if base64_value:
        compact = "".join(base64_value.split())
        try:
            return base64_var, base64.b64decode(compact, validate=True), None
        except binascii.Error as error:
            return base64_var, None, f"{base64_var} is not valid base64: {error}"

    return "embedded", None, None


def validate_keytab_header(data: bytes) -> str | None:
    if len(data) < 2:
        return "is too short for a keytab"
    if data[0] != 5:
        return f"has invalid first byte 0x{data[0]:02x}"
    if data[1] not in (1, 2):
        return f"has invalid keytab version {data[1]}"
    return None


if __name__ == "__main__":
    raise SystemExit(main())
