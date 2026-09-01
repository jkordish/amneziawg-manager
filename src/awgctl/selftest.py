"""Opt-in, ephemeral network-namespace handshake test."""

from __future__ import annotations

import base64
import os
import pathlib
import secrets
import subprocess
import tempfile
from collections.abc import Mapping, Sequence

from .diagnostics import sanitize_cps_text


class SelfTestError(RuntimeError):
    """The isolated AmneziaWG self-test failed."""


def render_peer_configs(
    *,
    server_private: str,
    server_public: str,
    client_private: str,
    client_public: str,
    psk: str,
    obfuscation: Mapping[str, object],
    header_protection_key: bytes | None = None,
    port: int,
) -> tuple[str, str]:
    from .core import AwgctlError, canonical_obfuscation_lines

    try:
        rendered = canonical_obfuscation_lines(
            {"obfuscation": dict(obfuscation)},
            header_protection_key=header_protection_key,
        )
    except AwgctlError as exc:
        raise SelfTestError("self-test received invalid obfuscation state") from exc
    native = "\n".join(rendered)
    server = (
        f"[Interface]\nPrivateKey = {server_private}\nListenPort = {port}\n{native}\n\n"
        f"[Peer]\nPublicKey = {client_public}\nPresharedKey = {psk}\nAllowedIPs = 10.200.0.2/32\n"
    )
    client = (
        f"[Interface]\nPrivateKey = {client_private}\n{native}\n\n"
        f"[Peer]\nPublicKey = {server_public}\nPresharedKey = {psk}\n"
        f"Endpoint = 192.0.2.1:{port}\nAllowedIPs = 10.200.0.1/32\nPersistentKeepalive = 5\n"
    )
    return server, client


def _run(argv: Sequence[str], *, input_data: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(argv), input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SelfTestError(f"could not run self-test command: {argv[0]}") from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        suffix = ": " + sanitize_cps_text(detail[-1]) if detail else ""
        raise SelfTestError(f"self-test command failed: {argv[0]}{suffix}")
    return result


def _key(command: str) -> str:
    result = _run(["awg", command]).stdout.decode("ascii").strip()
    try:
        if len(base64.b64decode(result, validate=True)) != 32:
            raise ValueError
    except ValueError as exc:
        raise SelfTestError(f"awg {command} returned an invalid key") from exc
    return result


def _public(private: str) -> str:
    return _run(["awg", "pubkey"], input_data=(private + "\n").encode("ascii")).stdout.decode("ascii").strip()


def run_namespace_selftest(
    obfuscation: Mapping[str, object], *, header_protection_key: bytes | None = None
) -> dict[str, object]:
    if os.geteuid() != 0:
        raise SelfTestError("namespace self-test requires root")
    token = secrets.token_hex(3)
    server_ns = f"awgs-{token}"
    client_ns = f"awgc-{token}"
    server_veth = f"avs{token}"[:15]
    client_veth = f"avc{token}"[:15]
    created: list[str] = []
    with tempfile.TemporaryDirectory(prefix="awgctl-selftest-") as directory:
        root = pathlib.Path(directory)
        server_private = _key("genkey")
        client_private = _key("genkey")
        psk = _key("genpsk")
        server_public = _public(server_private)
        client_public = _public(client_private)
        server_config, client_config = render_peer_configs(
            server_private=server_private,
            server_public=server_public,
            client_private=client_private,
            client_public=client_public,
            psk=psk,
            obfuscation=obfuscation,
            header_protection_key=header_protection_key,
            port=51871,
        )
        server_path = root / "server.conf"
        client_path = root / "client.conf"
        server_path.write_text(server_config, encoding="utf-8")
        client_path.write_text(client_config, encoding="utf-8")
        os.chmod(server_path, 0o600)
        os.chmod(client_path, 0o600)
        try:
            for namespace in (server_ns, client_ns):
                _run(["ip", "netns", "add", namespace])
                created.append(namespace)
            _run(["ip", "link", "add", server_veth, "type", "veth", "peer", "name", client_veth])
            _run(["ip", "link", "set", server_veth, "netns", server_ns])
            _run(["ip", "link", "set", client_veth, "netns", client_ns])
            for namespace, veth, underlay, tunnel in (
                (server_ns, server_veth, "192.0.2.1/30", "10.200.0.1/24"),
                (client_ns, client_veth, "192.0.2.2/30", "10.200.0.2/24"),
            ):
                _run(["ip", "-n", namespace, "link", "set", "lo", "up"])
                _run(["ip", "-n", namespace, "address", "add", underlay, "dev", veth])
                _run(["ip", "-n", namespace, "link", "set", veth, "up"])
                _run(["ip", "-n", namespace, "link", "add", "awgt", "type", "amneziawg"])
                _run(["ip", "-n", namespace, "address", "add", tunnel, "dev", "awgt"])
            _run(["ip", "netns", "exec", server_ns, "awg", "setconf", "awgt", str(server_path)])
            _run(["ip", "netns", "exec", client_ns, "awg", "setconf", "awgt", str(client_path)])
            _run(["ip", "-n", server_ns, "link", "set", "awgt", "up"])
            _run(["ip", "-n", client_ns, "link", "set", "awgt", "up"])
            ping = _run(["ip", "netns", "exec", client_ns, "ping", "-n", "-c", "2", "-W", "3", "10.200.0.1"])
            return {
                "ok": True,
                "isolation": "temporary Linux network namespaces",
                "packet_test": "2 ICMP echo replies through ephemeral AmneziaWG tunnel",
                "output": ping.stdout.decode("utf-8", "replace").splitlines()[-1] if ping.stdout else "success",
            }
        finally:
            for namespace in reversed(created):
                _run(["ip", "netns", "delete", namespace], check=False)
