#!/usr/bin/env python3
"""Check whether this host is plausible for a Samba AD lab spike."""

from __future__ import annotations

import argparse
import platform
import shutil
import socket
import subprocess
import sys


LOW_PORTS = [
    (53, "DNS"),
    (88, "Kerberos"),
    (135, "RPC endpoint mapper"),
    (139, "NetBIOS session"),
    (389, "LDAP"),
    (445, "SMB"),
    (464, "kpasswd"),
    (636, "LDAPS"),
    (3268, "Global Catalog"),
    (3269, "Global Catalog TLS"),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preflight local prerequisites for a Samba AD feasibility spike."
    )
    parser.add_argument(
        "--check-ports",
        action="store_true",
        help="Also try binding the common AD TCP ports on 127.0.0.1.",
    )
    args = parser.parse_args()

    blockers: list[str] = []
    warnings: list[str] = []

    print("Samba AD feasibility preflight")
    print(f"Host: {platform.system()} {platform.release()} ({platform.machine()})")

    docker = shutil.which("docker")
    if docker is None:
        blockers.append("docker CLI is not installed or not on PATH")
    else:
        print(f"docker: {docker}")
        server_version = run([docker, "version", "--format", "{{.Server.Version}}"])
        if server_version.returncode == 0:
            print(f"docker server: {server_version.stdout.strip()}")
        else:
            blockers.append("docker CLI exists but cannot reach a Docker daemon")
            if server_version.stderr.strip():
                warnings.append(server_version.stderr.strip())

        compose_version = run([docker, "compose", "version", "--short"])
        if compose_version.returncode == 0:
            print(f"docker compose: {compose_version.stdout.strip()}")
        else:
            blockers.append("docker compose plugin is unavailable")

    if platform.system() != "Linux":
        warnings.append(
            "local Docker Desktop can help prototype Samba AD, but strict "
            "GitHub-hosted parity still needs endpoints reachable from "
            "GitHub-hosted runners"
        )

    if args.check_ports:
        check_ports(blockers, warnings)
    else:
        print("port binding: skipped; pass --check-ports for a local TCP probe")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  - {warning}")

    if blockers:
        print("\nFeasibility blockers:")
        for blocker in blockers:
            print(f"  - {blocker}")
        return 1

    print("\nFeasibility preflight passed.")
    print("Next: follow docs/samba-ad-feasibility.md for the spike plan.")
    return 0


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def check_ports(blockers: list[str], warnings: list[str]) -> None:
    print("port binding:")
    for port, label in LOW_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
            except PermissionError as error:
                warnings.append(
                    f"127.0.0.1:{port} ({label}) requires elevated privileges: {error}"
                )
                print(f"  - {port}/tcp {label}: permission denied")
            except OSError as error:
                warnings.append(f"127.0.0.1:{port} ({label}) is unavailable: {error}")
                print(f"  - {port}/tcp {label}: unavailable")
            else:
                print(f"  - {port}/tcp {label}: available")


if __name__ == "__main__":
    raise SystemExit(main())
