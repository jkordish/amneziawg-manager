#!/usr/bin/env python3
"""Small, root-operated AmneziaWG manager for one awg-quick interface."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any, Iterable, Iterator, Sequence

from .version import VERSION


ROOT = pathlib.Path("/opt/amneziawg")
CONFIG_FILE = ROOT / "config/server.json"
SERVER_PRIVATE = ROOT / "keys/server/private"
SERVER_PUBLIC = ROOT / "keys/server/public"
CLIENT_KEYS = ROOT / "keys/clients"
CLIENTS = ROOT / "clients"
REVOKED = ROOT / "revoked"
GENERATED = ROOT / "generated"
GENERATED_CONFIG = GENERATED / "awg0.conf"
GENERATED_NFT = GENERATED / "nftables.nft"
BACKUPS = ROOT / "backups"
RUNTIME_CONFIG = pathlib.Path("/etc/amnezia/amneziawg/awg0.conf")
LOCK_FILE = pathlib.Path("/run/lock/awgctl.lock")
SERVICE_TEMPLATE = "awg-quick@{interface}.service"
OBFUSCATION_FIELDS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
BLOCKED_FORWARD_IPV4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
LEGACY_FIREWALL_MARKERS = (
    "amneziawg-awg0-egress",
    "amneziawg-awg0-return",
    "amneziawg-awg0-no-lateral-forwarding",
)
FIREWALL_MARKER_PREFIX = "awgctl-"

os.umask(0o077)


class AwgctlError(RuntimeError):
    """A safe, user-facing manager error."""


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(public_key: str) -> str:
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]


def audit(message: str) -> None:
    """Write a non-secret management event to journald/syslog."""
    try:
        subprocess.run(
            ["logger", "-t", "awgctl", "--", message],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def run(
    argv: Sequence[str],
    *,
    input_data: bytes | None = None,
    check: bool = True,
    timeout: float = 15,
) -> subprocess.CompletedProcess[bytes]:
    """Run a command without a shell; secrets may be supplied only on stdin."""
    try:
        result = subprocess.run(
            list(argv),
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise AwgctlError(f"required command not found: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise AwgctlError(f"command timed out: {argv[0]}") from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise AwgctlError(f"command failed: {argv[0]}{suffix}")
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise AwgctlError("run awgctl with sudo (root access is required)")


@contextlib.contextmanager
def mutation_lock() -> Iterator[None]:
    require_root()
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def fsync_directory(path: pathlib.Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: pathlib.Path, data: bytes | str, mode: int = 0o600) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, mode)
        fsync_directory(path.parent)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()
        raise


def atomic_json(path: pathlib.Path, value: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def ensure_layout() -> None:
    directory_modes = {
        ROOT: 0o755,
        ROOT / "bin": 0o755,
        ROOT / "config": 0o700,
        ROOT / "keys": 0o700,
        ROOT / "keys/server": 0o700,
        CLIENT_KEYS: 0o700,
        CLIENTS: 0o700,
        REVOKED: 0o700,
        GENERATED: 0o700,
        BACKUPS: 0o700,
    }
    for path, mode in directory_modes.items():
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        if os.geteuid() == 0:
            os.chown(path, 0, 0)


def validate_client_name(name: str) -> str:
    if not CLIENT_NAME_RE.fullmatch(name):
        raise AwgctlError("client name must match [A-Za-z0-9][A-Za-z0-9_-]{0,31}")
    return name


def validate_endpoint(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253 or "://" in value or ":" in value or any(c.isspace() for c in value):
        raise AwgctlError("endpoint must be a hostname or IPv4 address without a port")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise AwgctlError("invalid endpoint hostname")
    else:
        if address.version != 4:
            raise AwgctlError("only IPv4 endpoint addresses are supported by this installation")
    return value


def validate_key(value: str, label: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AwgctlError(f"invalid {label}") from exc
    if len(decoded) != 32:
        raise AwgctlError(f"invalid {label}")
    return value


def validate_dns(values: Sequence[str]) -> list[str]:
    if not values:
        raise AwgctlError("at least one DNS server is required")
    result: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise AwgctlError(f"invalid DNS address: {value}") from exc
        if address.version != 4:
            raise AwgctlError("only IPv4 DNS servers are supported by this installation")
        normalized = str(address)
        if normalized not in result:
            result.append(normalized)
    return result


def validate_server_config(config: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "interface",
        "subnet",
        "server_address",
        "endpoint",
        "listen_port",
        "external_interface",
        "dns",
        "mtu",
        "keepalive",
        "use_psk",
        "obfuscation",
        "blocked_forward_ipv4",
        "paths",
    }
    missing = sorted(required - config.keys())
    if missing:
        raise AwgctlError(f"server configuration missing fields: {', '.join(missing)}")
    if config["schema_version"] != 1:
        raise AwgctlError("unsupported server configuration schema")
    if not INTERFACE_RE.fullmatch(str(config["interface"])):
        raise AwgctlError("invalid interface name")
    if not INTERFACE_RE.fullmatch(str(config["external_interface"])):
        raise AwgctlError("invalid external interface name")
    try:
        subnet = ipaddress.ip_network(config["subnet"], strict=True)
        server = ipaddress.ip_interface(config["server_address"])
    except ValueError as exc:
        raise AwgctlError("invalid managed subnet or server address") from exc
    if subnet.version != 4 or server.version != 4 or server.ip not in subnet or server.network != subnet:
        raise AwgctlError("server address must use the managed IPv4 subnet prefix")
    validate_endpoint(str(config["endpoint"]))
    port = config["listen_port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise AwgctlError("listen_port must be an integer from 1 to 65535")
    mtu = config["mtu"]
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not 576 <= mtu <= 9000:
        raise AwgctlError("mtu must be an integer from 576 to 9000")
    keepalive = config["keepalive"]
    if not isinstance(keepalive, int) or isinstance(keepalive, bool) or not 0 <= keepalive <= 65535:
        raise AwgctlError("keepalive must be an integer from 0 to 65535")
    validate_dns(config["dns"])
    if not isinstance(config["use_psk"], bool):
        raise AwgctlError("use_psk must be boolean")
    obfuscation = config["obfuscation"]
    if set(obfuscation) != set(OBFUSCATION_FIELDS):
        raise AwgctlError("classic AmneziaWG obfuscation fields are incomplete or unexpected")
    for field in OBFUSCATION_FIELDS:
        value = obfuscation[field]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
            raise AwgctlError(f"invalid obfuscation value: {field}")
    if obfuscation["Jmin"] > obfuscation["Jmax"]:
        raise AwgctlError("Jmin must not exceed Jmax")
    blocked = tuple(str(ipaddress.ip_network(value, strict=True)) for value in config["blocked_forward_ipv4"])
    if blocked != BLOCKED_FORWARD_IPV4:
        raise AwgctlError("blocked_forward_ipv4 does not match the managed isolation policy")
    expected_paths = {
        "runtime_config": str(RUNTIME_CONFIG),
        "generated_config": str(GENERATED_CONFIG),
        "server_private_key": str(SERVER_PRIVATE),
        "server_public_key": str(SERVER_PUBLIC),
        "clients": str(CLIENTS),
        "client_keys": str(CLIENT_KEYS),
        "revoked": str(REVOKED),
        "backups": str(BACKUPS),
    }
    if config["paths"] != expected_paths:
        raise AwgctlError("managed paths differ from the fixed production layout")
    return config


def load_config() -> dict[str, Any]:
    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AwgctlError("management state is not initialized") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AwgctlError("cannot read managed server configuration") from exc
    return validate_server_config(config)


def parse_awg_config(text: str) -> dict[str, list[dict[str, str]]]:
    sections: dict[str, list[dict[str, str]]] = {}
    current: dict[str, str] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if not name:
                raise AwgctlError(f"empty section at line {number}")
            current = {}
            sections.setdefault(name, []).append(current)
            continue
        if current is None or "=" not in line:
            raise AwgctlError(f"invalid configuration syntax at line {number}")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            raise AwgctlError(f"empty key at line {number}")
        current[key] = value
    return sections


def next_client_address(
    subnet: ipaddress.IPv4Network,
    server: ipaddress.IPv4Interface,
    allocated: set[ipaddress.IPv4Interface],
) -> ipaddress.IPv4Interface:
    allocated_ips = {item.ip for item in allocated}
    for host in subnet.hosts():
        if host == server.ip or host in allocated_ips:
            continue
        return ipaddress.ip_interface(f"{host}/32")
    raise AwgctlError("no unused client addresses remain in the managed subnet")


def find_duplicate_client_state(clients: Sequence[dict[str, Any]]) -> list[str]:
    address_names: dict[str, list[str]] = {}
    key_names: dict[str, list[str]] = {}
    for client in clients:
        address_names.setdefault(client["address"], []).append(client["name"])
        key_names.setdefault(client["public_key"], []).append(client["name"])
    problems: list[str] = []
    for address, names in sorted(address_names.items()):
        if len(names) > 1:
            problems.append(f"duplicate client address: {address} ({', '.join(sorted(names))})")
    for names in sorted((names for names in key_names.values() if len(names) > 1), key=lambda values: sorted(values)):
        problems.append(f"duplicate client public key ({', '.join(sorted(names))})")
    return problems


def render_server_config(
    config: dict[str, Any], server_private: str, clients: Sequence[dict[str, Any]]
) -> str:
    validate_server_config({"schema_version": 1, "blocked_forward_ipv4": list(BLOCKED_FORWARD_IPV4), "paths": {
        "runtime_config": str(RUNTIME_CONFIG), "generated_config": str(GENERATED_CONFIG),
        "server_private_key": str(SERVER_PRIVATE), "server_public_key": str(SERVER_PUBLIC),
        "clients": str(CLIENTS), "client_keys": str(CLIENT_KEYS), "revoked": str(REVOKED),
        "backups": str(BACKUPS)}, **config}) if "schema_version" not in config else validate_server_config(config)
    validate_key(server_private, "server private key")
    lines = [
        "[Interface]",
        f"Address = {config['server_address']}",
        f"ListenPort = {config['listen_port']}",
        f"PrivateKey = {server_private}",
        f"MTU = {config['mtu']}",
    ]
    lines.extend(f"{field} = {config['obfuscation'][field]}" for field in OBFUSCATION_FIELDS)
    lines.extend([
        "PostUp = /opt/amneziawg/bin/awgctl _firewall up",
        "PostDown = /opt/amneziawg/bin/awgctl _firewall down",
    ])
    for client in clients:
        validate_client_name(client["name"])
        validate_key(client["public_key"], "client public key")
        address = ipaddress.ip_interface(client["address"])
        if address.version != 4 or address.network.prefixlen != 32:
            raise AwgctlError(f"invalid client address for {client['name']}")
        lines.extend(["", "[Peer]", f"# {client['name']}", f"PublicKey = {client['public_key']}"])
        if config["use_psk"]:
            psk = client.get("psk")
            if not psk:
                raise AwgctlError(f"missing preshared key for {client['name']}")
            validate_key(psk, "client preshared key")
            lines.append(f"PresharedKey = {psk}")
        lines.append(f"AllowedIPs = {address}")
    return "\n".join(lines) + "\n"


def render_client_config(
    config: dict[str, Any], private_key: str, psk: str | None, server_public: str, address: str
) -> str:
    validate_key(private_key, "client private key")
    validate_key(server_public, "server public key")
    if config["use_psk"]:
        if psk is None:
            raise AwgctlError("missing client preshared key")
        validate_key(psk, "client preshared key")
    interface_address = ipaddress.ip_interface(address)
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {interface_address}",
        f"DNS = {', '.join(config['dns'])}",
        f"MTU = {config['mtu']}",
    ]
    lines.extend(f"{field} = {config['obfuscation'][field]}" for field in OBFUSCATION_FIELDS)
    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_public}",
    ])
    if config["use_psk"]:
        lines.append(f"PresharedKey = {psk}")
    lines.extend([
        f"Endpoint = {config['endpoint']}:{config['listen_port']}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"PersistentKeepalive = {config['keepalive']}",
    ])
    return "\n".join(lines) + "\n"


def render_nftables_config(config: dict[str, Any]) -> str:
    interface = config["interface"]
    external = config["external_interface"]
    subnet = config["subnet"]
    blocked = ", ".join(config.get("blocked_forward_ipv4", BLOCKED_FORWARD_IPV4))
    return f'''table ip amneziawg_forward {{
  chain forward {{
    type filter hook forward priority filter - 10; policy accept;
    iifname "{external}" oifname "{interface}" ip daddr {subnet} ct state established,related counter accept comment "awgctl-return-is-established-only"
    oifname "{interface}" counter drop comment "awgctl-block-non-return-to-tunnel"
    iifname "{interface}" ip saddr != {subnet} counter drop comment "awgctl-block-spoofed-tunnel-source"
    iifname "{interface}" ip daddr {{ {blocked} }} counter drop comment "awgctl-block-private-reserved-destinations"
    iifname "{interface}" oifname != "{external}" counter drop comment "awgctl-block-lateral-forwarding"
    iifname "{interface}" ip saddr {subnet} oifname "{external}" counter accept comment "awgctl-allow-public-internet"
    iifname "{interface}" counter drop comment "awgctl-default-tunnel-forward-drop"
  }}
}}

table ip amneziawg_nat {{
  chain postrouting {{
    type nat hook postrouting priority srcnat + 10; policy accept;
    ip saddr {subnet} oifname "{external}" counter masquerade comment "awgctl-tunnel-masquerade"
  }}
}}
'''


def read_secret(path: pathlib.Path, label: str) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise AwgctlError(f"cannot read {label}") from exc
    return validate_key(value, label)


def load_clients(*, include_secrets: bool = False) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not CLIENTS.exists():
        return records
    for directory in CLIENTS.iterdir():
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        validate_client_name(directory.name)
        metadata_path = directory / "metadata.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AwgctlError(f"cannot read client metadata: {directory.name}") from exc
        if metadata.get("name") != directory.name or metadata.get("status") != "active":
            raise AwgctlError(f"invalid active client metadata: {directory.name}")
        validate_key(metadata.get("public_key", ""), "client public key")
        try:
            address = ipaddress.ip_interface(metadata["address"])
        except (KeyError, ValueError) as exc:
            raise AwgctlError(f"invalid client address: {directory.name}") from exc
        if address.version != 4 or address.network.prefixlen != 32:
            raise AwgctlError(f"invalid client address: {directory.name}")
        record = dict(metadata)
        if include_secrets:
            key_dir = CLIENT_KEYS / directory.name
            public_file = read_secret(key_dir / "public", "client public key")
            if public_file != record["public_key"]:
                raise AwgctlError(f"client public key metadata drift: {directory.name}")
            record["private_key"] = read_secret(key_dir / "private", "client private key")
            record["psk"] = read_secret(key_dir / "psk", "client preshared key") if record.get("use_psk") else None
        records.append(record)
    records.sort(key=lambda item: int(ipaddress.ip_interface(item["address"]).ip))
    duplicates = find_duplicate_client_state(records)
    if duplicates:
        raise AwgctlError("; ".join(duplicates))
    return records


def server_private_key() -> str:
    return read_secret(SERVER_PRIVATE, "server private key")


def server_public_key() -> str:
    return read_secret(SERVER_PUBLIC, "server public key")


def server_records_for_render(clients: Sequence[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    return list(clients) if clients is not None else load_clients(include_secrets=True)


def render_current_server(clients: Sequence[dict[str, Any]] | None = None) -> str:
    return render_server_config(load_config(), server_private_key(), server_records_for_render(clients))


def semantic_signature(text: str) -> dict[str, Any]:
    parsed = parse_awg_config(text)
    interfaces = parsed.get("Interface", [])
    if len(interfaces) != 1:
        raise AwgctlError("server configuration must contain exactly one Interface section")
    interface = {key: value for key, value in interfaces[0].items() if key not in {"PostUp", "PostDown", "PreUp", "PreDown"}}
    peers = sorted((tuple(sorted(peer.items())) for peer in parsed.get("Peer", [])))
    return {"interface": tuple(sorted(interface.items())), "peers": peers}


def ensure_no_drift() -> None:
    expected = render_current_server().encode("utf-8")
    try:
        generated = GENERATED_CONFIG.read_bytes()
        runtime = RUNTIME_CONFIG.read_bytes()
    except OSError as exc:
        raise AwgctlError("cannot read generated/runtime server configuration") from exc
    if generated != expected:
        raise AwgctlError(
            f"managed-state drift: generated config is {sha256_bytes(generated)[:12]}, expected {sha256_bytes(expected)[:12]}"
        )
    if runtime != generated:
        raise AwgctlError(
            f"manual runtime drift detected: runtime is {sha256_bytes(runtime)[:12]}, managed is {sha256_bytes(generated)[:12]}"
        )


def is_service_active(interface: str) -> bool:
    result = run(["systemctl", "is-active", "--quiet", SERVICE_TEMPLATE.format(interface=interface)], check=False)
    return result.returncode == 0


def safe_awg_query(interface: str, field: str) -> str:
    # Deliberately limited: never add I1-I5 to this allowlist; querying unset values can crash awg 3.1.
    if field not in {"public-key", "listen-port", "peers", "latest-handshakes"}:
        raise AwgctlError("unsupported safe awg query")
    return run(["awg", "show", interface, field]).stdout.decode("utf-8", "replace").strip()


def live_peers(interface: str) -> set[str]:
    output = safe_awg_query(interface, "peers")
    return {line.strip() for line in output.splitlines() if line.strip()}


def validate_native_server(text: str) -> None:
    GENERATED.mkdir(parents=True, exist_ok=True)
    # awg-quick derives an interface name from the filename and enforces Linux's
    # 15-character interface-name limit, even for the non-mutating strip action.
    config_fd, config_name = tempfile.mkstemp(prefix="awgv", suffix=".conf", dir=GENERATED)
    stripped_fd, stripped_name = tempfile.mkstemp(prefix=".validate-strip-", dir=GENERATED)
    os.close(stripped_fd)
    config_path = pathlib.Path(config_name)
    stripped_path = pathlib.Path(stripped_name)
    interface = f"awgv{os.getpid() % 100000:05d}"[:15]
    created = False
    try:
        os.fchmod(config_fd, 0o600)
        with os.fdopen(config_fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        stripped = run(["awg-quick", "strip", str(config_path)]).stdout
        atomic_write(stripped_path, stripped, 0o600)
        run(["ip", "link", "add", "dev", interface, "type", "amneziawg"])
        created = True
        run(["awg", "setconf", interface, str(stripped_path)])
    except AwgctlError as exc:
        audit("failed native server configuration validation")
        raise AwgctlError("native AmneziaWG configuration validation failed") from exc
    finally:
        if created:
            run(["ip", "link", "del", "dev", interface], check=False)
        with contextlib.suppress(FileNotFoundError):
            config_path.unlink()
        with contextlib.suppress(FileNotFoundError):
            stripped_path.unlink()


def validate_nftables_text(text: str) -> None:
    suffix = f"_check_{os.getpid()}"
    check_text = text.replace("amneziawg_forward", f"amneziawg_forward{suffix}").replace(
        "amneziawg_nat", f"amneziawg_nat{suffix}"
    )
    fd, name = tempfile.mkstemp(prefix=".nft-check-", suffix=".nft", dir=GENERATED)
    path = pathlib.Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(check_text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        run(["nft", "-c", "-f", str(path)])
    except AwgctlError as exc:
        audit("failed nftables configuration validation")
        raise AwgctlError("AmneziaWG nftables configuration validation failed") from exc
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def docker_user_chain_exists() -> bool:
    return run(["nft", "list", "chain", "ip", "filter", "DOCKER-USER"], check=False).returncode == 0


def tagged_docker_handles() -> list[int]:
    result = run(["nft", "-j", "-a", "list", "chain", "ip", "filter", "DOCKER-USER"], check=False)
    if result.returncode != 0:
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AwgctlError("cannot inspect Docker forwarding integration rules") from exc
    handles: list[int] = []
    for item in data.get("nftables", []):
        rule = item.get("rule")
        if not rule:
            continue
        comment = str(rule.get("comment", ""))
        if comment.startswith(FIREWALL_MARKER_PREFIX) or comment in LEGACY_FIREWALL_MARKERS:
            handles.append(int(rule["handle"]))
    return handles


def firewall_cleanup() -> None:
    for handle in tagged_docker_handles():
        run(["nft", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", str(handle)], check=False)
    for table in ("amneziawg_forward", "amneziawg_nat"):
        run(["nft", "delete", "table", "ip", table], check=False)


def docker_integration_text(config: dict[str, Any]) -> str:
    interface = config["interface"]
    external = config["external_interface"]
    subnet = config["subnet"]
    # Insert in reverse desired order: each nft 'insert' becomes the first rule.
    return (
        f'insert rule ip filter DOCKER-USER iifname "{interface}" counter drop comment "awgctl-default-tunnel-forward-drop"\n'
        f'insert rule ip filter DOCKER-USER iifname "{external}" oifname "{interface}" ip daddr {subnet} ct state established,related counter accept comment "awgctl-established-return"\n'
        f'insert rule ip filter DOCKER-USER iifname "{interface}" oifname "{external}" ip saddr {subnet} counter accept comment "awgctl-public-egress"\n'
    )


def apply_firewall() -> None:
    config = load_config()
    nft_text = render_nftables_config(config)
    validate_nftables_text(nft_text)
    if not docker_user_chain_exists():
        raise AwgctlError("Docker DOCKER-USER chain is absent; refusing to bypass the host FORWARD policy")
    integration = docker_integration_text(config)
    fd, integration_name = tempfile.mkstemp(prefix=".docker-integration-", suffix=".nft", dir=GENERATED)
    integration_path = pathlib.Path(integration_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(integration.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        run(["nft", "-c", "-f", str(integration_path)])
        firewall_cleanup()
        atomic_write(GENERATED_NFT, nft_text, 0o600)
        run(["nft", "-f", str(GENERATED_NFT)])
        try:
            run(["nft", "-f", str(integration_path)])
        except Exception:
            firewall_cleanup()
            raise
    finally:
        with contextlib.suppress(FileNotFoundError):
            integration_path.unlink()


def service_action(action: str, interface: str) -> None:
    if action not in {"start", "stop", "restart", "reload"}:
        raise AwgctlError("invalid service action")
    service = SERVICE_TEMPLATE.format(interface=interface)
    run(["systemctl", action, service], timeout=45)
    if action in {"start", "restart", "reload"} and not is_service_active(interface):
        raise AwgctlError(f"service did not remain active after {action}")


def commit_server_config(text: str, *, runtime_action: str | None = "reload") -> bool:
    validate_native_server(text)
    old_generated = GENERATED_CONFIG.read_bytes() if GENERATED_CONFIG.exists() else None
    old_runtime = RUNTIME_CONFIG.read_bytes()
    config = load_config()
    active = is_service_active(config["interface"])
    atomic_write(GENERATED_CONFIG, text, 0o600)
    atomic_write(RUNTIME_CONFIG, text, 0o600)
    try:
        if active and runtime_action:
            service_action(runtime_action, config["interface"])
    except Exception as original:
        atomic_write(RUNTIME_CONFIG, old_runtime, 0o600)
        if old_generated is None:
            with contextlib.suppress(FileNotFoundError):
                GENERATED_CONFIG.unlink()
        else:
            atomic_write(GENERATED_CONFIG, old_generated, 0o600)
        rollback_ok = True
        if active and runtime_action:
            try:
                service_action(runtime_action, config["interface"])
            except Exception:
                rollback_ok = False
        audit(f"runtime {runtime_action} failed; rollback {'succeeded' if rollback_ok else 'failed'}")
        status = "rollback verified" if rollback_ok else "ROLLBACK COULD NOT BE VERIFIED"
        raise AwgctlError(f"server configuration {runtime_action} failed; {status}") from original
    return active


def generate_key_material(use_psk: bool) -> tuple[str, str, str | None]:
    private = run(["awg", "genkey"]).stdout.decode("ascii").strip()
    validate_key(private, "generated private key")
    public = run(["awg", "pubkey"], input_data=(private + "\n").encode("ascii")).stdout.decode("ascii").strip()
    validate_key(public, "generated public key")
    psk = run(["awg", "genpsk"]).stdout.decode("ascii").strip() if use_psk else None
    if psk is not None:
        validate_key(psk, "generated preshared key")
    return private, public, psk


def generate_qr(profile: str, output: pathlib.Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{output.stem}.", suffix=".png", dir=output.parent)
    os.close(fd)
    temporary = pathlib.Path(name)
    try:
        run(["qrencode", "-t", "PNG", "-o", str(temporary)], input_data=profile.encode("utf-8"))
        os.chmod(temporary, 0o600)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        os.chmod(output, 0o600)
        fsync_directory(output.parent)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise


def write_client_state(
    config: dict[str, Any],
    name: str,
    address: str,
    private: str,
    public: str,
    psk: str | None,
    *,
    created_at: str | None = None,
    imported_from: str | None = None,
    profile_text: str | None = None,
) -> dict[str, Any]:
    client_dir = CLIENTS / name
    key_dir = CLIENT_KEYS / name
    if client_dir.exists() or key_dir.exists():
        raise AwgctlError(f"client already exists: {name}")
    client_dir.mkdir(mode=0o700)
    key_dir.mkdir(mode=0o700)
    now = iso_now()
    metadata = {
        "schema_version": 1,
        "name": name,
        "status": "active",
        "address": str(ipaddress.ip_interface(address)),
        "public_key": public,
        "public_key_fingerprint": fingerprint(public),
        "use_psk": bool(psk),
        "created_at": created_at or now,
        "updated_at": now,
    }
    if imported_from:
        metadata["imported_from"] = imported_from
    atomic_write(key_dir / "private", private + "\n", 0o600)
    atomic_write(key_dir / "public", public + "\n", 0o600)
    if psk:
        atomic_write(key_dir / "psk", psk + "\n", 0o600)
    profile = profile_text or render_client_config(config, private, psk, server_public_key(), address)
    atomic_write(client_dir / f"{name}.conf", profile, 0o600)
    generate_qr(profile, client_dir / f"{name}.png")
    atomic_json(client_dir / "metadata.json", metadata, 0o600)
    return {**metadata, "private_key": private, "psk": psk}


def remove_client_state(name: str) -> None:
    shutil.rmtree(CLIENTS / name, ignore_errors=True)
    shutil.rmtree(CLIENT_KEYS / name, ignore_errors=True)


def chmod_secret_tree(path: pathlib.Path) -> None:
    for root, directories, files in os.walk(path):
        os.chmod(root, 0o700)
        for directory in directories:
            os.chmod(pathlib.Path(root) / directory, 0o700)
        for filename in files:
            os.chmod(pathlib.Path(root) / filename, 0o600)
        if os.geteuid() == 0:
            os.chown(root, 0, 0)
            for directory in directories:
                os.chown(pathlib.Path(root) / directory, 0, 0)
            for filename in files:
                os.chown(pathlib.Path(root) / filename, 0, 0)


def unique_timestamped_directory(parent: pathlib.Path, prefix: str = "") -> pathlib.Path:
    base = prefix + utc_timestamp()
    candidate = parent / base
    counter = 1
    while candidate.exists():
        candidate = parent / f"{base}-{counter:02d}"
        counter += 1
    candidate.mkdir(parents=True, mode=0o700)
    return candidate


def create_backup() -> pathlib.Path:
    ensure_layout()
    destination = unique_timestamped_directory(BACKUPS)
    for source, relative in (
        (ROOT / "config", pathlib.Path("config")),
        (ROOT / "keys", pathlib.Path("keys")),
        (ROOT / "clients", pathlib.Path("clients")),
        (ROOT / "generated", pathlib.Path("generated")),
    ):
        if source.exists():
            shutil.copytree(source, destination / relative, dirs_exist_ok=True)
    state = destination / "state"
    state.mkdir(mode=0o700)
    if CONFIG_FILE.exists():
        config = load_config()
        service = run(
            ["systemctl", "show", SERVICE_TEMPLATE.format(interface=config["interface"]), "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState", "--no-pager"],
            check=False,
        ).stdout
        atomic_write(state / "systemd.txt", service, 0o600)
    nft_output = run(["nft", "-a", "list", "ruleset"], check=False).stdout
    atomic_write(state / "nftables.ruleset", nft_output, 0o600)
    chmod_secret_tree(destination)
    audit(f"backup created: {destination.name}")
    return destination


def format_age(timestamp: int, *, now: int | None = None) -> str:
    if timestamp <= 0:
        return "never"
    current = int(time.time()) if now is None else now
    seconds = max(0, current - timestamp)
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def suspicious_wildcard_listeners(ss_output: str, *, vpn_port: int) -> list[str]:
    listeners: list[str] = []
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        protocol = fields[0]
        local = fields[4]
        wildcard = local.startswith("0.0.0.0:") or local.startswith("[::]:") or local.startswith("*:")
        if not wildcard:
            continue
        port_text = local.rsplit(":", 1)[-1]
        try:
            port = int(port_text)
        except ValueError:
            continue
        if protocol == "udp" and port == vpn_port:
            continue
        process = " ".join(fields[6:]) if len(fields) > 6 else "unattributed"
        listeners.append(f"{protocol}/{port} ({process})")
    return listeners


def extract_legacy_state(server_text: str, client_text: str, external_interface: str) -> dict[str, Any]:
    server_sections = parse_awg_config(server_text)
    client_sections = parse_awg_config(client_text)
    if len(server_sections.get("Interface", [])) != 1 or len(server_sections.get("Peer", [])) != 1:
        raise AwgctlError("migration expects one server Interface and the existing Kat peer")
    if len(client_sections.get("Interface", [])) != 1 or len(client_sections.get("Peer", [])) != 1:
        raise AwgctlError("migration expects one client Interface and one server peer")
    server_interface = server_sections["Interface"][0]
    server_peer = server_sections["Peer"][0]
    client_interface = client_sections["Interface"][0]
    client_peer = client_sections["Peer"][0]
    try:
        server_address = ipaddress.ip_interface(server_interface["Address"])
        client_address = ipaddress.ip_interface(client_interface["Address"])
        listen_port = int(server_interface["ListenPort"])
        mtu = int(server_interface["MTU"])
        keepalive = int(client_peer["PersistentKeepalive"])
        endpoint_host, endpoint_port_text = client_peer["Endpoint"].rsplit(":", 1)
        endpoint_port = int(endpoint_port_text)
        obfuscation = {field: int(server_interface[field]) for field in OBFUSCATION_FIELDS}
        client_obfuscation = {field: int(client_interface[field]) for field in OBFUSCATION_FIELDS}
        server_private = server_interface["PrivateKey"]
        client_private = client_interface["PrivateKey"]
        client_public = server_peer["PublicKey"]
        server_public = client_peer["PublicKey"]
        client_psk = server_peer.get("PresharedKey")
    except (KeyError, ValueError) as exc:
        raise AwgctlError("legacy configuration is missing required classic AmneziaWG fields") from exc
    if server_address.version != 4 or client_address.version != 4 or client_address.ip not in server_address.network:
        raise AwgctlError("legacy server/client addresses do not share the expected IPv4 subnet")
    if server_peer.get("AllowedIPs") != str(client_address):
        raise AwgctlError("legacy Kat AllowedIPs does not match her client address")
    if endpoint_port != listen_port:
        raise AwgctlError("legacy client endpoint port differs from the server listen port")
    if int(client_interface.get("MTU", "-1")) != mtu:
        raise AwgctlError("legacy client MTU differs from the server MTU")
    if client_obfuscation != obfuscation:
        raise AwgctlError("legacy client obfuscation differs from the server")
    if client_peer.get("PresharedKey") != client_psk:
        raise AwgctlError("legacy Kat preshared keys do not match")
    validate_key(server_private, "legacy server private key")
    validate_key(server_public, "legacy server public key")
    validate_key(client_private, "legacy client private key")
    validate_key(client_public, "legacy client public key")
    if client_psk:
        validate_key(client_psk, "legacy client preshared key")
    paths = {
        "runtime_config": str(RUNTIME_CONFIG),
        "generated_config": str(GENERATED_CONFIG),
        "server_private_key": str(SERVER_PRIVATE),
        "server_public_key": str(SERVER_PUBLIC),
        "clients": str(CLIENTS),
        "client_keys": str(CLIENT_KEYS),
        "revoked": str(REVOKED),
        "backups": str(BACKUPS),
    }
    config = {
        "schema_version": 1,
        "interface": "awg0",
        "subnet": str(server_address.network),
        "server_address": str(server_address),
        "endpoint": validate_endpoint(endpoint_host),
        "listen_port": listen_port,
        "external_interface": external_interface,
        "dns": validate_dns([value.strip() for value in client_interface["DNS"].split(",")]),
        "mtu": mtu,
        "keepalive": keepalive,
        "use_psk": client_psk is not None,
        "obfuscation": obfuscation,
        "blocked_forward_ipv4": list(BLOCKED_FORWARD_IPV4),
        "paths": paths,
    }
    validate_server_config(config)
    return {
        "config": config,
        "server_private": server_private,
        "server_public": server_public,
        "client_private": client_private,
        "client_public": client_public,
        "client_psk": client_psk,
        "client_address": str(client_address),
    }


def endpoint_ipv4s(host: str) -> list[str]:
    try:
        entries = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror:
        return []
    return sorted({entry[4][0] for entry in entries}, key=lambda value: int(ipaddress.ip_address(value)))


def imds_value(path: str) -> str | None:
    try:
        token_request = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        )
        with urllib.request.urlopen(token_request, timeout=1.5) as response:
            token = response.read().decode("ascii").strip()
        request = urllib.request.Request(
            f"http://169.254.169.254/latest/meta-data/{path}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(request, timeout=1.5) as response:
            return response.read().decode("ascii").strip()
    except (OSError, UnicodeError):
        return None


def systemctl_state(interface: str) -> tuple[str, str]:
    service = SERVICE_TEMPLATE.format(interface=interface)
    active = run(["systemctl", "is-active", service], check=False).stdout.decode().strip() or "unknown"
    enabled = run(["systemctl", "is-enabled", service], check=False).stdout.decode().strip() or "unknown"
    return active, enabled


def handshake_map(interface: str) -> dict[str, int]:
    output = safe_awg_query(interface, "latest-handshakes")
    result: dict[str, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 2:
            with contextlib.suppress(ValueError):
                result[fields[0]] = int(fields[1])
    return result


def nft_table_active(table: str) -> bool:
    return run(["nft", "list", "table", "ip", table], check=False).returncode == 0


def cmd_aws_rule(config: dict[str, Any] | None = None) -> None:
    config = config or load_config()
    print("AWS Lightsail inbound requirement")
    print(f"  Custom / UDP / {config['listen_port']} / 0.0.0.0/0")


def cmd_status(_: argparse.Namespace) -> int:
    config = load_config()
    active, enabled = systemctl_state(config["interface"])
    link_result = run(["ip", "-brief", "link", "show", config["interface"]], check=False)
    link_up = link_result.returncode == 0 and "UP" in link_result.stdout.decode("utf-8", "replace")
    public_ip = imds_value("public-ipv4") or "unavailable"
    forwarding = pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    peers: set[str] = set()
    handshakes: dict[str, int] = {}
    if active and link_up:
        with contextlib.suppress(AwgctlError):
            peers = live_peers(config["interface"])
            handshakes = handshake_map(config["interface"])
    clients = load_clients()
    print("AmneziaWG")
    print(f"  service:        {active}")
    print(f"  boot:           {enabled}")
    print(f"  interface:      {config['interface']} {'UP' if link_up else 'DOWN'}")
    print(f"  endpoint:       {config['endpoint']}:{config['listen_port']}")
    print(f"  public IPv4:    {public_ip}")
    print(f"  subnet:         {config['subnet']}")
    print(f"  forwarding:     {'enabled' if forwarding else 'disabled'}")
    print(f"  NAT:            {'active' if nft_table_active('amneziawg_nat') else 'inactive'}")
    print(f"  isolation:      {'active' if nft_table_active('amneziawg_forward') else 'inactive'}")
    print(f"  peers:          {len(peers) if active else 0}")
    print("Clients")
    if not clients:
        print("  none")
    for client in clients:
        seen = format_age(handshakes.get(client["public_key"], 0))
        print(f"  {client['name']:<20} {str(ipaddress.ip_interface(client['address']).ip):<15} {seen}")
    cmd_aws_rule(config)
    return 0


def permission_problem(path: pathlib.Path, expected_mode: int, *, secret: bool = True) -> str | None:
    try:
        metadata = path.stat()
    except OSError:
        return f"missing {path}"
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        return f"{path} is not root:root"
    if secret and mode != expected_mode:
        return f"{path} mode is {mode:04o}, expected {expected_mode:04o}"
    return None


def cmd_health(_: argparse.Namespace) -> int:
    config = load_config()
    checks: list[tuple[str, str, str]] = []

    def add(level: str, name: str, detail: str) -> None:
        checks.append((level, name, detail))

    active, enabled = systemctl_state(config["interface"])
    add("PASS" if active == "active" else "FAIL", "service", active)
    add("PASS" if enabled == "enabled" else "FAIL", "boot", enabled)
    link = run(["ip", "-brief", "link", "show", config["interface"]], check=False)
    link_up = link.returncode == 0 and "UP" in link.stdout.decode("utf-8", "replace")
    add("PASS" if link_up else "FAIL", "interface", "UP" if link_up else "missing or down")
    address = run(["ip", "-4", "-brief", "address", "show", config["interface"]], check=False).stdout.decode()
    add("PASS" if config["server_address"] in address else "FAIL", "tunnel address", config["server_address"])
    live_port = ""
    if active and link_up:
        with contextlib.suppress(AwgctlError):
            live_port = safe_awg_query(config["interface"], "listen-port")
    add("PASS" if live_port == str(config["listen_port"]) else "FAIL", "UDP listener", live_port or "not verified")
    module_loaded = pathlib.Path("/sys/module/amneziawg").exists()
    add("PASS" if module_loaded else "FAIL", "kernel module", "amneziawg loaded" if module_loaded else "not loaded")
    kernel = os.uname().release
    dkms = run(["dkms", "status"], check=False).stdout.decode("utf-8", "replace")
    dkms_current = "amneziawg" in dkms and kernel in dkms and "installed" in dkms
    add("PASS" if dkms_current else "FAIL", "DKMS", f"current kernel {kernel} {'supported' if dkms_current else 'not supported'}")
    forwarding = pathlib.Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    add("PASS" if forwarding else "FAIL", "IPv4 forwarding", "enabled" if forwarding else "disabled")
    add("PASS" if nft_table_active("amneziawg_nat") else "FAIL", "VPN NAT", "table ip amneziawg_nat")
    add("PASS" if nft_table_active("amneziawg_forward") else "FAIL", "VPN isolation", "table ip amneziawg_forward")
    docker_markers = tagged_docker_handles()
    add("PASS" if len(docker_markers) == 3 else "FAIL", "Docker forwarding bridge", f"{len(docker_markers)} tagged rules")

    for path, mode, label in (
        (RUNTIME_CONFIG, 0o600, "runtime config permissions"),
        (GENERATED_CONFIG, 0o600, "generated config permissions"),
        (SERVER_PRIVATE, 0o600, "server private-key permissions"),
        (CONFIG_FILE, 0o600, "manager config permissions"),
    ):
        problem = permission_problem(path, mode)
        add("FAIL" if problem else "PASS", label, problem or f"root:root {mode:04o}")

    try:
        expected = render_current_server().encode()
        generated = GENERATED_CONFIG.read_bytes()
        runtime = RUNTIME_CONFIG.read_bytes()
        add("PASS" if generated == expected else "FAIL", "managed state", "generated config matches state" if generated == expected else "generated config drift")
        add("PASS" if runtime == generated else "FAIL", "runtime drift", "runtime config matches generated" if runtime == generated else "manual runtime drift detected")
    except (AwgctlError, OSError) as exc:
        add("FAIL", "configuration consistency", str(exc))

    try:
        clients = load_clients(include_secrets=True)
        duplicates = find_duplicate_client_state(clients)
        add("FAIL" if duplicates else "PASS", "client uniqueness", "; ".join(duplicates) if duplicates else f"{len(clients)} unique active clients")
        profile_drift: list[str] = []
        server_public = server_public_key()
        for client in clients:
            expected_profile = render_client_config(
                config, client["private_key"], client.get("psk"), server_public, client["address"]
            ).encode()
            actual_profile = (CLIENTS / client["name"] / f"{client['name']}.conf").read_bytes()
            if expected_profile != actual_profile:
                profile_drift.append(client["name"])
        add("FAIL" if profile_drift else "PASS", "client profile consistency", ", ".join(profile_drift) if profile_drift else "profiles match managed state")
    except (AwgctlError, OSError) as exc:
        add("FAIL", "client state", str(exc))

    addresses = endpoint_ipv4s(config["endpoint"])
    add("PASS" if addresses else "FAIL", "endpoint DNS", ", ".join(addresses) if addresses else "resolution failed")
    public_ip = imds_value("public-ipv4")
    if public_ip and addresses:
        add("PASS" if public_ip in addresses else "FAIL", "endpoint/public IPv4", f"endpoint={','.join(addresses)} public={public_ip}")
    else:
        add("WARN", "endpoint/public IPv4", "comparison unavailable")
    add(
        "WARN",
        "Lightsail static IP",
        "No stable Lightsail public IP was verified. A stop/start can change the instance public IPv4 and break the VPN endpoint DNS record.",
    )

    disk = os.statvfs("/")
    total = disk.f_blocks * disk.f_frsize
    available = disk.f_bavail * disk.f_frsize
    used_percent = 100.0 * (total - available) / total if total else 100.0
    disk_level = "WARN" if used_percent >= 90 or available < 5 * 1024**3 else "PASS"
    add(disk_level, "root filesystem", f"{used_percent:.1f}% used, {available / 1024**3:.2f} GiB available")
    memory: dict[str, int] = {}
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if value:
            memory[key] = int(value.strip().split()[0]) * 1024
    available_memory = memory.get("MemAvailable", 0)
    add("WARN" if available_memory < 256 * 1024**2 else "PASS", "available memory", f"{available_memory / 1024**3:.2f} GiB")
    swap_lines = pathlib.Path("/proc/swaps").read_text().splitlines()
    add("WARN" if len(swap_lines) <= 1 else "PASS", "swap", "none configured" if len(swap_lines) <= 1 else "configured")
    if disk_level == "WARN" and "amneziawg" in dkms:
        add("WARN", "package upgrade/DKMS risk", "low disk space may prevent a future kernel/DKMS upgrade; no cleanup was performed")

    ss_output = run(["ss", "-H", "-lntup"]).stdout.decode("utf-8", "replace")
    listeners = suspicious_wildcard_listeners(ss_output, vpn_port=config["listen_port"])
    if listeners:
        add("WARN", "host listeners reachable through awg0", "; ".join(listeners))
    else:
        add("PASS", "host listeners reachable through awg0", "none besides AmneziaWG")
    prometheus = [value for value in listeners if "prometheus" in value.lower() or "/9090" in value or "/9100" in value]
    add("WARN" if prometheus else "PASS", "Prometheus/node-exporter exposure", "; ".join(prometheus) if prometheus else "not detected")
    ufw = run(["ufw", "status"], check=False).stdout.decode("utf-8", "replace")
    add("WARN" if "Status: active" in ufw else "PASS", "UFW", "active (unexpected)" if "Status: active" in ufw else "inactive; Lightsail remains public-ingress firewall")

    print("AmneziaWG health")
    for level, name, detail in checks:
        print(f"  {level:<4} {name}: {detail}")
    failures = sum(1 for level, _, _ in checks if level == "FAIL")
    warnings = sum(1 for level, _, _ in checks if level == "WARN")
    print(f"Summary: {failures} failure(s), {warnings} warning(s)")
    return 1 if failures else 0


def verify_peer_state(interface: str, public_key: str, *, present: bool) -> None:
    peers = live_peers(interface)
    actual = public_key in peers
    if actual != present:
        expectation = "appear" if present else "disappear"
        raise AwgctlError(f"peer did not {expectation} in the running interface")


def cmd_client_list(_: argparse.Namespace) -> int:
    config = load_config()
    clients = load_clients()
    handshakes: dict[str, int] = {}
    if is_service_active(config["interface"]):
        with contextlib.suppress(AwgctlError):
            handshakes = handshake_map(config["interface"])
    print(f"{'NAME':<22} {'ADDRESS':<15} {'LAST HANDSHAKE'}")
    for client in clients:
        print(
            f"{client['name']:<22} {str(ipaddress.ip_interface(client['address']).ip):<15} "
            f"{format_age(handshakes.get(client['public_key'], 0))}"
        )
    if not clients:
        print("No active clients.")
    return 0


def cmd_client_show(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    clients = {client["name"]: client for client in load_clients()}
    if name not in clients:
        raise AwgctlError(f"unknown active client: {name}")
    client = clients[name]
    config = load_config()
    handshake = 0
    if is_service_active(config["interface"]):
        with contextlib.suppress(AwgctlError):
            handshake = handshake_map(config["interface"]).get(client["public_key"], 0)
    print(f"Client: {name}")
    print(f"  status:                 {client['status']}")
    print(f"  address:                {client['address']}")
    print(f"  public key fingerprint: {client['public_key_fingerprint']}")
    print(f"  created:                {client['created_at']}")
    print(f"  last handshake:         {format_age(handshake)}")
    print(f"  config:                 {CLIENTS / name / (name + '.conf')}")
    print(f"  QR:                     {CLIENTS / name / (name + '.png')}")
    return 0


def cmd_client_add(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
        old_clients = load_clients(include_secrets=True)
        if any(client["name"] == name for client in old_clients) or (CLIENTS / name).exists() or (CLIENT_KEYS / name).exists():
            raise AwgctlError(f"client already exists: {name}")
        allocated = {ipaddress.ip_interface(client["address"]) for client in old_clients}
        address = next_client_address(
            ipaddress.ip_network(config["subnet"]), ipaddress.ip_interface(config["server_address"]), allocated
        )
        backup = create_backup()
        private, public, psk = generate_key_material(config["use_psk"])
        committed = False
        try:
            write_client_state(config, name, str(address), private, public, psk)
            new_clients = load_clients(include_secrets=True)
            new_server = render_server_config(config, server_private_key(), new_clients)
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                verify_peer_state(config["interface"], public, present=True)
        except Exception:
            if committed:
                rollback_text = render_server_config(config, server_private_key(), old_clients)
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            remove_client_state(name)
            audit(f"client creation failed: {name}")
            raise
        audit(f"client created: {name} address={address.ip}")
        print(f"Created client: {name}")
        print(f"Address: {address.ip}")
        print(f"Config: {CLIENTS / name / (name + '.conf')}")
        print(f"QR: {CLIENTS / name / (name + '.png')}")
        print(f"Pre-change backup: {backup}")
        print("Server configuration reloaded successfully." if active else "Server configuration installed; service is stopped.")
    return 0


def archive_client_copy(name: str, *, rotation: bool = False) -> pathlib.Path:
    prefix = f"{name}-rotated-" if rotation else f"{name}-"
    archive = unique_timestamped_directory(REVOKED, prefix)
    shutil.copytree(CLIENTS / name, archive / "client")
    shutil.copytree(CLIENT_KEYS / name, archive / "keys")
    metadata_path = archive / "client/metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["status"] = "rotated" if rotation else "revoked"
    metadata["revoked_at"] = iso_now()
    atomic_json(metadata_path, metadata, 0o600)
    chmod_secret_tree(archive)
    return archive


def cmd_client_revoke(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
        old_clients = load_clients(include_secrets=True)
        target = next((client for client in old_clients if client["name"] == name), None)
        if target is None:
            raise AwgctlError(f"unknown active client: {name}")
        backup = create_backup()
        archive = archive_client_copy(name)
        remaining = [client for client in old_clients if client["name"] != name]
        committed = False
        try:
            new_server = render_server_config(config, server_private_key(), remaining)
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                verify_peer_state(config["interface"], target["public_key"], present=False)
        except Exception:
            if committed:
                rollback_text = render_server_config(config, server_private_key(), old_clients)
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            shutil.rmtree(archive, ignore_errors=True)
            audit(f"client revocation failed: {name}")
            raise
        remove_client_state(name)
        audit(f"client revoked: {name}")
        print(f"Revoked client: {name}")
        print(f"Archived credentials: {archive}")
        print(f"Pre-change backup: {backup}")
        print("Peer removed from the running server." if active else "Peer removed from managed configuration; service is stopped.")
    return 0


def restore_client_from_archive(name: str, archive: pathlib.Path) -> None:
    remove_client_state(name)
    shutil.copytree(archive / "client", CLIENTS / name)
    shutil.copytree(archive / "keys", CLIENT_KEYS / name)
    metadata_path = CLIENTS / name / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["status"] = "active"
    metadata.pop("revoked_at", None)
    atomic_json(metadata_path, metadata, 0o600)
    chmod_secret_tree(CLIENTS / name)
    chmod_secret_tree(CLIENT_KEYS / name)


def cmd_client_rotate(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
        old_clients = load_clients(include_secrets=True)
        target = next((client for client in old_clients if client["name"] == name), None)
        if target is None:
            raise AwgctlError(f"unknown active client: {name}")
        backup = create_backup()
        archive = archive_client_copy(name, rotation=True)
        private, public, psk = generate_key_material(config["use_psk"])
        committed = False
        try:
            remove_client_state(name)
            write_client_state(
                config,
                name,
                target["address"],
                private,
                public,
                psk,
                created_at=target["created_at"],
            )
            metadata_path = CLIENTS / name / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["rotated_at"] = iso_now()
            metadata["previous_public_key_fingerprint"] = target["public_key_fingerprint"]
            atomic_json(metadata_path, metadata, 0o600)
            new_clients = load_clients(include_secrets=True)
            new_server = render_server_config(config, server_private_key(), new_clients)
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                peers = live_peers(config["interface"])
                if public not in peers or target["public_key"] in peers:
                    raise AwgctlError("rotated peer state did not verify in the running interface")
        except Exception:
            if committed:
                rollback_text = render_server_config(config, server_private_key(), old_clients)
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            restore_client_from_archive(name, archive)
            shutil.rmtree(archive, ignore_errors=True)
            audit(f"client rotation failed: {name}")
            raise
        audit(f"client rotated: {name}")
        print(f"Rotated client: {name}")
        print(f"Address: {ipaddress.ip_interface(target['address']).ip}")
        print(f"Config: {CLIENTS / name / (name + '.conf')}")
        print(f"QR: {CLIENTS / name / (name + '.png')}")
        print(f"Prior credentials archived: {archive}")
        print(f"Pre-change backup: {backup}")
        print("Old profile is no longer accepted by the server." if active else "Rotation is staged; service is stopped.")
    return 0


def cmd_client_export(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    profile = CLIENTS / name / f"{name}.conf"
    if not profile.is_file():
        raise AwgctlError(f"unknown active client: {name}")
    if args.stdout:
        print("WARNING: the following profile contains credentials; protect terminal scrollback and logs.", file=sys.stderr)
        sys.stdout.write(profile.read_text(encoding="utf-8"))
        return 0
    if args.output is None:
        print(f"Protected profile: {profile}")
        print("Use --output PATH to copy it, or explicit --stdout only when secret output is intended.")
        return 0
    output = args.output.expanduser()
    if output.exists():
        raise AwgctlError(f"refusing to overwrite existing output: {output}")
    if not output.parent.exists():
        raise AwgctlError(f"output directory does not exist: {output.parent}")
    atomic_write(output, profile.read_bytes(), 0o600)
    if os.geteuid() == 0:
        os.chown(output, 0, 0)
    audit(f"client profile exported: {name}")
    print(f"Exported client profile: {output}")
    print("The file contains credentials and is mode 0600.")
    return 0


def cmd_client_qr(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    profile_path = CLIENTS / name / f"{name}.conf"
    if not profile_path.is_file():
        raise AwgctlError(f"unknown active client: {name}")
    with mutation_lock():
        output = CLIENTS / name / f"{name}.png"
        generate_qr(profile_path.read_text(encoding="utf-8"), output)
        audit(f"client QR regenerated: {name}")
        print(f"Protected QR image: {output}")
        print("The QR was not displayed in terminal output.")
    return 0


def cmd_config_show(_: argparse.Namespace) -> int:
    print(json.dumps(load_config(), indent=2, sort_keys=True))
    return 0


def snapshot_client_artifacts(clients: Sequence[dict[str, Any]]) -> dict[pathlib.Path, bytes]:
    snapshot: dict[pathlib.Path, bytes] = {}
    for client in clients:
        directory = CLIENTS / client["name"]
        for suffix in (".conf", ".png"):
            path = directory / f"{client['name']}{suffix}"
            snapshot[path] = path.read_bytes()
    return snapshot


def restore_artifacts(snapshot: dict[pathlib.Path, bytes]) -> None:
    for path, data in snapshot.items():
        atomic_write(path, data, 0o600)


def cmd_config_set(args: argparse.Namespace) -> int:
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
        old_config_bytes = CONFIG_FILE.read_bytes()
        old_nft = GENERATED_NFT.read_bytes()
        clients = load_clients(include_secrets=True)
        artifacts = snapshot_client_artifacts(clients)
        new_config = json.loads(json.dumps(config))
        old_display: str
        new_display: str
        if args.key == "endpoint":
            old_display = config["endpoint"]
            new_config["endpoint"] = validate_endpoint(args.value)
            new_display = new_config["endpoint"]
            runtime_action = None
        elif args.key == "dns":
            old_display = ",".join(config["dns"])
            new_config["dns"] = validate_dns(args.value.split(","))
            new_display = ",".join(new_config["dns"])
            runtime_action = None
        elif args.key == "mtu":
            try:
                new_config["mtu"] = int(args.value)
            except ValueError as exc:
                raise AwgctlError("mtu must be an integer") from exc
            old_display = str(config["mtu"])
            new_display = str(new_config["mtu"])
            runtime_action = "restart"
        elif args.key == "listen-port":
            try:
                new_config["listen_port"] = int(args.value)
            except ValueError as exc:
                raise AwgctlError("listen-port must be an integer") from exc
            old_display = str(config["listen_port"])
            new_display = str(new_config["listen_port"])
            runtime_action = "restart"
        else:
            raise AwgctlError("unsupported managed configuration key")
        validate_server_config(new_config)
        if new_config == config:
            print(f"No change: {args.key} is already {new_display}")
            return 0
        backup = create_backup()
        server_public = server_public_key()
        new_profiles = {
            client["name"]: render_client_config(
                new_config, client["private_key"], client.get("psk"), server_public, client["address"]
            )
            for client in clients
        }
        new_server = render_server_config(new_config, server_private_key(), clients)
        new_nft = render_nftables_config(new_config)
        validate_nftables_text(new_nft)
        try:
            atomic_json(CONFIG_FILE, new_config, 0o600)
            for client in clients:
                directory = CLIENTS / client["name"]
                profile = new_profiles[client["name"]]
                atomic_write(directory / f"{client['name']}.conf", profile, 0o600)
                generate_qr(profile, directory / f"{client['name']}.png")
            atomic_write(GENERATED_NFT, new_nft, 0o600)
            active = commit_server_config(new_server, runtime_action=runtime_action)
        except Exception:
            atomic_write(CONFIG_FILE, old_config_bytes, 0o600)
            atomic_write(GENERATED_NFT, old_nft, 0o600)
            restore_artifacts(artifacts)
            audit(f"configuration change failed: {args.key}")
            raise
        audit(f"configuration changed: {args.key} {old_display} -> {new_display}")
        print(f"Updated {args.key}: {old_display} -> {new_display}")
        print(f"Pre-change backup: {backup}")
        if runtime_action and active:
            print(f"Interface {runtime_action} completed and verified.")
        elif runtime_action:
            print("Configuration updated; interface is stopped, so no restart was attempted.")
        else:
            print("Client profiles updated; no tunnel restart was required.")
        if args.key == "listen-port":
            print("AWS LIGHTSAIL FIREWALL UPDATE REQUIRED")
            print(f"  old: Custom / UDP / {old_display} / 0.0.0.0/0")
            print(f"  new: Custom / UDP / {new_display} / 0.0.0.0/0")
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    config = load_config()
    with mutation_lock():
        if args.command in {"start", "restart", "reload"}:
            ensure_no_drift()
        service_action(args.command, config["interface"])
        audit(f"service {args.command}: {config['interface']}")
        print(f"{SERVICE_TEMPLATE.format(interface=config['interface'])}: {args.command} successful")
    return 0


def cmd_backup(_: argparse.Namespace) -> int:
    with mutation_lock():
        path = create_backup()
        print(f"Created protected backup: {path}")
    return 0


def cmd_firewall(args: argparse.Namespace) -> int:
    require_root()
    if args.firewall_action == "up":
        apply_firewall()
    else:
        firewall_cleanup()
    return 0


def cleanup_failed_migration() -> None:
    for path in (CONFIG_FILE, GENERATED_CONFIG, GENERATED_NFT):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    remove_client_state("kat")
    for path in (SERVER_PRIVATE, SERVER_PUBLIC):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def cmd_migrate_existing(args: argparse.Namespace) -> int:
    with mutation_lock():
        if CONFIG_FILE.exists():
            raise AwgctlError("management state is already initialized")
        server_path: pathlib.Path = args.server_config
        client_path: pathlib.Path = args.client_config
        try:
            original_server = server_path.read_bytes()
            original_client = client_path.read_bytes()
        except OSError as exc:
            raise AwgctlError("cannot read existing server or Kat configuration") from exc
        try:
            server_text = original_server.decode("utf-8")
            client_text = original_client.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AwgctlError("existing configurations are not UTF-8 text") from exc
        imported = extract_legacy_state(server_text, client_text, args.external_interface)
        if imported["config"]["interface"] != args.interface:
            imported["config"]["interface"] = args.interface
            validate_server_config(imported["config"])
        derived_server = run(
            ["awg", "pubkey"], input_data=(imported["server_private"] + "\n").encode("ascii")
        ).stdout.decode("ascii").strip()
        derived_client = run(
            ["awg", "pubkey"], input_data=(imported["client_private"] + "\n").encode("ascii")
        ).stdout.decode("ascii").strip()
        if derived_server != imported["server_public"]:
            raise AwgctlError("existing server keypair does not match")
        if derived_client != imported["client_public"]:
            raise AwgctlError("existing Kat keypair does not match the server peer")
        live_server_before = safe_awg_query(args.interface, "public-key")
        live_peers_before = live_peers(args.interface)
        if live_server_before != derived_server or derived_client not in live_peers_before:
            raise AwgctlError("live server/Kat identity differs from the files; migration stopped")
        ensure_layout()
        old_runtime = RUNTIME_CONFIG.read_bytes()
        try:
            atomic_json(CONFIG_FILE, imported["config"], 0o600)
            atomic_write(SERVER_PRIVATE, imported["server_private"] + "\n", 0o600)
            atomic_write(SERVER_PUBLIC, imported["server_public"] + "\n", 0o600)
            client_record = write_client_state(
                imported["config"],
                "kat",
                imported["client_address"],
                imported["client_private"],
                imported["client_public"],
                imported["client_psk"],
                imported_from=str(client_path),
                profile_text=client_text,
            )
            metadata_path = CLIENTS / "kat/metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["import_source_sha256"] = sha256_bytes(original_client)
            atomic_json(metadata_path, metadata, 0o600)
            existing_png = client_path.with_suffix(".png")
            if existing_png.is_file():
                atomic_write(CLIENTS / "kat/kat.png", existing_png.read_bytes(), 0o600)
            rendered = render_server_config(imported["config"], imported["server_private"], [client_record])
            if semantic_signature(server_text) != semantic_signature(rendered):
                raise AwgctlError("generated server configuration does not preserve existing semantics")
            nft_text = render_nftables_config(imported["config"])
            validate_native_server(rendered)
            validate_nftables_text(nft_text)
            atomic_write(GENERATED_CONFIG, rendered, 0o600)
            atomic_write(GENERATED_NFT, nft_text, 0o600)
            atomic_write(RUNTIME_CONFIG, rendered, 0o600)
            apply_firewall()
            service_action("reload", args.interface)
            live_server_after = safe_awg_query(args.interface, "public-key")
            peers_after = live_peers(args.interface)
            if live_server_after != live_server_before or derived_client not in peers_after:
                raise AwgctlError("post-migration live identity verification failed")
        except Exception as original:
            atomic_write(RUNTIME_CONFIG, old_runtime, 0o600)
            firewall_cleanup()
            legacy_helper = pathlib.Path("/usr/local/libexec/amneziawg-firewall")
            if legacy_helper.is_file():
                run([str(legacy_helper), "up"], check=False)
            run(["systemctl", "reload", SERVICE_TEMPLATE.format(interface=args.interface)], check=False, timeout=45)
            cleanup_failed_migration()
            audit("existing installation migration failed; legacy runtime restored")
            raise AwgctlError("migration failed; legacy runtime/configuration rollback was attempted") from original
        chmod_secret_tree(ROOT / "config")
        chmod_secret_tree(ROOT / "keys")
        chmod_secret_tree(ROOT / "clients")
        chmod_secret_tree(ROOT / "generated")
        audit("existing server and Kat profile imported without credential rotation")
        print("Imported existing AmneziaWG server and Kat profile.")
        print(f"Server identity fingerprint: {fingerprint(derived_server)}")
        print(f"Kat identity fingerprint: {fingerprint(derived_client)}")
        print("Existing credentials were preserved; the running interface was reloaded, not restarted.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="awgctl", description="Manage the host's AmneziaWG installation")
    parser.add_argument("--version", action="version", version=f"awgctl {VERSION}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "health", "check", "start", "stop", "restart", "reload", "backup", "aws-rule"):
        subcommands.add_parser(name)

    config_parser = subcommands.add_parser("config")
    config_commands = config_parser.add_subparsers(dest="config_command", required=True)
    config_commands.add_parser("show")
    config_set = config_commands.add_parser("set")
    config_set.add_argument("key", choices=("endpoint", "dns", "mtu", "listen-port"))
    config_set.add_argument("value")

    client_parser = subcommands.add_parser("client")
    client_commands = client_parser.add_subparsers(dest="client_command", required=True)
    client_commands.add_parser("list")
    for name in ("add", "show", "qr", "revoke", "rotate"):
        command = client_commands.add_parser(name)
        command.add_argument("client_name", metavar="NAME")
    export = client_commands.add_parser("export")
    export.add_argument("client_name", metavar="NAME")
    export_group = export.add_mutually_exclusive_group()
    export_group.add_argument("--output", type=pathlib.Path)
    export_group.add_argument("--stdout", action="store_true")

    firewall = subcommands.add_parser("_firewall", help=argparse.SUPPRESS)
    firewall.add_argument("firewall_action", choices=("up", "down"))
    migrate = subcommands.add_parser("_migrate-existing", help=argparse.SUPPRESS)
    migrate.add_argument("--server-config", type=pathlib.Path, required=True)
    migrate.add_argument("--client-config", type=pathlib.Path, required=True)
    migrate.add_argument("--interface", default="awg0")
    migrate.add_argument("--external-interface", default="ens5")
    return parser


def dispatch(args: argparse.Namespace) -> int:
    require_root()
    if args.command == "status":
        return cmd_status(args)
    if args.command in {"health", "check"}:
        return cmd_health(args)
    if args.command in {"start", "stop", "restart", "reload"}:
        return cmd_service(args)
    if args.command == "backup":
        return cmd_backup(args)
    if args.command == "aws-rule":
        cmd_aws_rule()
        return 0
    if args.command == "config":
        return cmd_config_show(args) if args.config_command == "show" else cmd_config_set(args)
    if args.command == "client":
        handlers = {
            "list": cmd_client_list,
            "add": cmd_client_add,
            "show": cmd_client_show,
            "export": cmd_client_export,
            "qr": cmd_client_qr,
            "revoke": cmd_client_revoke,
            "rotate": cmd_client_rotate,
        }
        return handlers[args.client_command](args)
    if args.command == "_firewall":
        return cmd_firewall(args)
    if args.command == "_migrate-existing":
        return cmd_migrate_existing(args)
    raise AwgctlError("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return dispatch(args)
    except AwgctlError as exc:
        audit(f"command failed: {args.command}")
        print(f"awgctl: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("awgctl: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
