#!/usr/bin/env python3
"""Small, root-operated AmneziaWG manager for one awg-quick interface."""

from __future__ import annotations

import argparse
import base64
import copy
import contextlib
import datetime as dt
import fcntl
import grp
import hashlib
import ipaddress
import io
import json
import os
import pathlib
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from typing import Any, Iterable, Iterator, Sequence, TextIO

from .backups import BackupError, create_manifest as create_backup_manifest, verify_backup
from .contracts import (
    ContractError,
    health_envelope,
    json_envelope,
    mark_profile_regenerated,
    mark_profile_rotated,
    normalize_client_metadata,
)
from .diagnostics import (
    DiagnosticsError,
    create_bundle as create_diagnostic_bundle,
    redact_awg_config,
    sanitize_cps_text,
)
from .releases import ReleaseError, discover_release_tag, fetch_verified_release, version_key
from .selftest import SelfTestError, run_namespace_selftest
from .version import VERSION
from awginstall.installer import InstallerError, upgrade_product
from awginstall.platform import PlatformError, read_os_release, validate_platform
from awginstall.identity import effective_group_members, render_sudoers
from awginstall.sandbox import render_module_load, render_service_hardening
from awginstall.settings import (
    SettingsError,
    dns_policy_name,
    resolve_installation_settings,
    validate_dns_setting,
)


ROOT = pathlib.Path("/opt/amneziawg")
CONFIG_FILE = ROOT / "config/server.json"
INSTALLATION_CONFIG = ROOT / "config/installation.json"
SERVER_PRIVATE = ROOT / "keys/server/private"
SERVER_PUBLIC = ROOT / "keys/server/public"
HEADER_PROTECTION_KEY = ROOT / "keys/server/header-protection"
CLIENT_KEYS = ROOT / "keys/clients"
CLIENTS = ROOT / "clients"
REVOKED = ROOT / "revoked"
GENERATED = ROOT / "generated"
GENERATED_CONFIG = GENERATED / "awg0.conf"
GENERATED_NFT = GENERATED / "nftables.nft"
BACKUPS = ROOT / "backups"
DIAGNOSTICS = ROOT / "diagnostics"
RUNTIME_CONFIG = pathlib.Path("/etc/amnezia/amneziawg/awg0.conf")
LOCK_FILE = pathlib.Path("/run/lock/awgctl.lock")
PUBLIC_ENTRYPOINT = pathlib.Path("/usr/local/sbin/awgctl")
INTERNAL_ENTRYPOINT = ROOT / "libexec/awgctl-internal"
SUDOERS_CONFIG = pathlib.Path("/etc/sudoers.d/amneziawg-manager")
SERVICE_HARDENING = pathlib.Path(
    "/etc/systemd/system/awg-quick@awg0.service.d/20-awgctl-hardening.conf"
)
MODULE_LOAD_CONFIG = pathlib.Path("/etc/modules-load.d/amneziawg-manager.conf")
SYSCTL_CONFIG = pathlib.Path("/etc/sysctl.d/90-amneziawg-forward.conf")
SERVICE_TEMPLATE = "awg-quick@{interface}.service"
OBFUSCATION_FIELDS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")
AWG31_INTEGER_FIELDS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4")
AWG31_HEADER_FIELDS = ("H1", "H2", "H3", "H4")
AWG31_CPS_FIELDS = ("I1", "I2", "I3", "I4", "I5")
AWG31_RANGE_FIELDS = (
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
)
AWG31_BOOLEAN_FIELDS = ("RandomTrailers", "DisableCookies")
AWG31_PARAMETER_FIELDS = (
    *AWG31_INTEGER_FIELDS,
    *AWG31_HEADER_FIELDS,
    *AWG31_CPS_FIELDS,
    *AWG31_RANGE_FIELDS,
    *AWG31_BOOLEAN_FIELDS,
)
AWG31_QUALIFICATION_POLICY_VERSION = 1
# Qualification is intentionally empty until a server pair completes the external
# compatibility process. Tests inject this impossible future fixture explicitly.
AWG31_QUALIFIED_PAIRS_V1: frozenset[tuple[str, str]] = frozenset()
AWG31_TEST_FIXTURE_PAIR = ("3.1.20990101", "3.1.20990102")
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


def header_protection_fingerprint(material: bytes) -> str:
    if not isinstance(material, bytes) or len(material) != 32:
        raise AwgctlError("invalid header-protection key material")
    return hashlib.sha256(material).hexdigest()[:12]


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


_AWG_TOOLS_VERSION = re.compile(
    r"amneziawg-tools v(?P<version>[0-9]+\.[0-9]+\.[0-9]+) - https://amnezia\.org\n?"
)
_AWG_MODULE_VERSION = re.compile(r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\n?")


def parse_awg_tools_version(output: str) -> str:
    match = _AWG_TOOLS_VERSION.fullmatch(output)
    if match is None:
        raise AwgctlError("unrecognized awg tools version output")
    return match.group("version")


def parse_awg_module_version(output: str) -> str:
    match = _AWG_MODULE_VERSION.fullmatch(output)
    if match is None:
        raise AwgctlError("unrecognized AmneziaWG module version output")
    return match.group("version")


def _loaded_awg_module_version() -> str:
    try:
        return pathlib.Path("/sys/module/amneziawg/version").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise AwgctlError("loaded AmneziaWG module version is unavailable") from exc


def require_awg31_capability(
    *,
    command_runner: Any = run,
    loaded_version_reader: Any = _loaded_awg_module_version,
    qualified_pairs: set[tuple[str, str]] | frozenset[tuple[str, str]] = AWG31_QUALIFIED_PAIRS_V1,
) -> dict[str, Any]:
    """Fail closed unless exact tools and loaded/packaged module versions are qualified."""
    try:
        tools_result = command_runner(["awg", "--version"])
        module_result = command_runner(["modinfo", "-F", "version", "amneziawg"])
        if tools_result.returncode != 0 or module_result.returncode != 0:
            raise AwgctlError("AWG 3.1 capability inspection command failed")
        tools_output = tools_result.stdout.decode("ascii")
        module_output = module_result.stdout.decode("ascii")
        loaded_output = loaded_version_reader()
    except AwgctlError:
        raise
    except (AttributeError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise AwgctlError("AWG 3.1 capability inspection failed") from exc
    tools_version = parse_awg_tools_version(tools_output)
    packaged_module_version = parse_awg_module_version(module_output)
    loaded_module_version = parse_awg_module_version(loaded_output)
    if packaged_module_version != loaded_module_version:
        raise AwgctlError("loaded and packaged AmneziaWG module versions do not match")
    pair = (tools_version, loaded_module_version)
    if pair not in qualified_pairs:
        raise AwgctlError("installed AWG 3.1 tools/module pair is not qualified")
    return {
        "policy_version": AWG31_QUALIFICATION_POLICY_VERSION,
        "tools_version": tools_version,
        "module_version": loaded_module_version,
        "qualified": True,
    }


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


def write_header_protection_key(
    path: pathlib.Path = HEADER_PROTECTION_KEY,
    *,
    token_bytes: Any = secrets.token_bytes,
    owner_uid: int = 0,
    owner_gid: int = 0,
) -> str:
    """Atomically create fresh raw key material without returning the secret."""
    material = token_bytes(32)
    if not isinstance(material, bytes) or len(material) != 32:
        raise AwgctlError("CSPRNG returned invalid header-protection key material")
    parent_fd = -1
    descriptor = -1
    temporary_name: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        parent_metadata = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or (parent_metadata.st_uid, parent_metadata.st_gid) != (owner_uid, owner_gid)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            raise AwgctlError("header-protection key parent is not a private owned directory")
        for _ in range(128):
            temporary_name = f".{path.name}.{secrets.token_hex(16)}"
            try:
                descriptor = os.open(
                    temporary_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                break
            except FileExistsError:
                temporary_name = None
        if descriptor < 0 or temporary_name is None:
            raise AwgctlError("cannot allocate protected header-protection key file")
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, owner_uid, owner_gid)
        view = memoryview(material)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
        os.fsync(parent_fd)
    except AwgctlError:
        raise
    except OSError as exc:
        raise AwgctlError("cannot store header-protection key") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None and parent_fd >= 0:
            with contextlib.suppress(OSError):
                os.unlink(temporary_name, dir_fd=parent_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
    return header_protection_fingerprint(material)


def read_header_protection_key(
    path: pathlib.Path = HEADER_PROTECTION_KEY,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> bytes:
    """Read exactly one private key through the descriptor whose metadata was checked."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AwgctlError("cannot read protected header-protection key") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AwgctlError("header-protection key must be one regular non-linked file")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise AwgctlError("header-protection key has invalid ownership")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise AwgctlError("header-protection key must have mode 0600")
        material = b""
        while len(material) <= 32:
            chunk = os.read(descriptor, 33 - len(material))
            if not chunk:
                break
            material += chunk
    except OSError as exc:
        raise AwgctlError("cannot read protected header-protection key") from exc
    finally:
        os.close(descriptor)
    if len(material) != 32:
        raise AwgctlError("header-protection key must contain exactly 32 bytes")
    return material


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
        DIAGNOSTICS: 0o700,
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


def _wizard_prompt(input_stream: TextIO, output_stream: TextIO, prompt: str) -> str:
    output_stream.write(prompt)
    output_stream.flush()
    value = input_stream.readline()
    if value == "":
        raise EOFError
    return value.strip()


def suggest_client_name(owner: str, device: str) -> str:
    suggestion = re.sub(r"[^a-z0-9]+", "-", f"{owner}-{device}".lower()).strip("-")
    return suggestion[:32].rstrip("-")


def _wizard_metadata(owner: str, device: str, expires: str | None) -> dict[str, Any]:
    return normalize_client_metadata({
        "schema_version": 3,
        "management": "managed",
        "owner": owner,
        "device": device,
        "expires": expires,
        "profile_revision": 1,
        "profile_generated_at": "2000-01-01T00:00:00Z",
        "profile_change_reason": "created",
        "distribution_status": "pending",
        "distributed_at": None,
    })


def _prompt_required_profile_field(
    input_stream: TextIO,
    output_stream: TextIO,
    field: str,
) -> str:
    label = field.title()
    while True:
        value = _wizard_prompt(input_stream, output_stream, f"{label}: ")
        if not value:
            output_stream.write(f"{label} is required.\n")
            continue
        try:
            metadata = _wizard_metadata(
                value if field == "owner" else "recipient",
                value if field == "device" else "device",
                None,
            )
        except ContractError:
            output_stream.write(f"{label} must be 1-64 printable characters.\n")
            continue
        return metadata[field]


def _prompt_profile_expiration(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    owner: str,
    device: str,
) -> str | None:
    while True:
        value = _wizard_prompt(
            input_stream,
            output_stream,
            "Expiration date (YYYY-MM-DD, optional): ",
        ) or None
        try:
            metadata = _wizard_metadata(owner, device, value)
        except ContractError:
            output_stream.write("Enter a date as YYYY-MM-DD, or leave it blank for no expiration.\n")
            continue
        return metadata["expires"]


def collect_client_add_wizard(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    dry_run: bool = False,
) -> dict[str, str | None] | None:
    try:
        return _collect_client_add_wizard(input_stream, output_stream, dry_run=dry_run)
    except EOFError:
        output_stream.write("\nCancelled. No changes were made.\n")
        return None


def _collect_client_add_wizard(
    input_stream: TextIO,
    output_stream: TextIO,
    *,
    dry_run: bool,
) -> dict[str, str | None] | None:
    output_stream.write("Add a new client profile\n\n")
    owner = _prompt_required_profile_field(input_stream, output_stream, "owner")
    device = _prompt_required_profile_field(input_stream, output_stream, "device")
    suggested_name = suggest_client_name(owner, device)
    name_prompt = f"Profile name [{suggested_name}]: "
    while True:
        name = _wizard_prompt(input_stream, output_stream, name_prompt) or suggested_name
        try:
            validate_client_name(name)
            break
        except AwgctlError:
            output_stream.write(
                "Use 1-32 letters, numbers, underscores, or hyphens; "
                "begin with a letter or number.\n"
            )
            name_prompt = "Profile name: "
    expires = _prompt_profile_expiration(
        input_stream,
        output_stream,
        owner=owner,
        device=device,
    )

    action_description = (
        "This preview will validate profile creation and allocate the next available address.\n"
        "No credentials, backups, files, or service reloads will be created.\n"
        if dry_run
        else (
            "Creating this profile will generate unique credentials and reload "
            "the AmneziaWG server configuration.\n"
        )
    )
    output_stream.write(
        "\nReview profile\n"
        f"  Name:    {name}\n"
        f"  Owner:   {owner}\n"
        f"  Device:  {device}\n"
        f"  Expires: {expires or 'never'}\n\n"
        f"{action_description}"
    )
    confirmation_prompt = (
        "Run this preview? [y/N]: " if dry_run else "Create this profile? [y/N]: "
    )
    confirmed = _wizard_prompt(input_stream, output_stream, confirmation_prompt).lower()
    if confirmed not in {"y", "yes"}:
        output_stream.write("Cancelled. No changes were made.\n")
        return None
    return {"client_name": name, "owner": owner, "device": device, "expires": expires}


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
    if not isinstance(values, (list, tuple)) or not values:
        raise AwgctlError("at least one DNS server is required")
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise AwgctlError("DNS addresses must be text")
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


def parse_dns_value(value: str) -> list[str]:
    """Resolve a named DNS policy or validate a comma-separated IPv4 list."""
    try:
        return list(validate_dns_setting(value))
    except SettingsError as exc:
        raise AwgctlError(str(exc)) from exc


def _reject_unknown_fields(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise AwgctlError(f"{label} has unexpected fields: {', '.join(unknown)}")


def _strict_integer(value: Any, field: str, *, minimum: int = 0, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise AwgctlError(f"invalid obfuscation value: {field}")
    return value


def normalize_closed_range(value: Any, *, field: str, maximum: int) -> int | dict[str, int]:
    """Normalize one native scalar or inclusive range without accepting bools."""
    if isinstance(value, int) and not isinstance(value, bool):
        return _strict_integer(value, field, maximum=maximum)
    if not isinstance(value, dict):
        raise AwgctlError(f"invalid obfuscation range: {field}")
    _reject_unknown_fields(value, {"min", "max"}, f"obfuscation range {field}")
    if set(value) != {"min", "max"}:
        raise AwgctlError(f"invalid obfuscation range: {field}")
    lower = _strict_integer(value["min"], field, maximum=maximum)
    upper = _strict_integer(value["max"], field, maximum=maximum)
    if lower > upper:
        raise AwgctlError(f"invalid obfuscation range: {field}")
    return {"min": lower, "max": upper}


def _range_bounds(value: int | dict[str, int]) -> tuple[int, int]:
    return (value, value) if isinstance(value, int) else (value["min"], value["max"])


def validate_header_ranges(parameters: dict[str, Any]) -> dict[str, int | dict[str, int]]:
    result = {
        field: normalize_closed_range(parameters[field], field=field, maximum=0xFFFFFFFF)
        for field in AWG31_HEADER_FIELDS
    }
    for index, left_name in enumerate(AWG31_HEADER_FIELDS):
        left_min, left_max = _range_bounds(result[left_name])
        for right_name in AWG31_HEADER_FIELDS[index + 1:]:
            right_min, right_max = _range_bounds(result[right_name])
            if max(left_min, right_min) <= min(left_max, right_max):
                raise AwgctlError("obfuscation header ranges overlap")
    return result


_CPS_TAG = re.compile(
    r"<(?:b 0x(?P<bytes>[0-9a-fA-F]+)|(?P<timestamp>t)|(?P<random>r|rc|rd) (?P<size>[1-9][0-9]{0,3}))>"
)


def validate_cps(value: Any, *, field: str, mtu: int) -> str:
    """Validate one canonical custom-packet specification without echoing it."""
    if not isinstance(value, str) or not value:
        raise AwgctlError(f"invalid custom packet specification: {field}")
    position = 0
    rendered_size = 0
    while position < len(value):
        match = _CPS_TAG.match(value, position)
        if match is None:
            raise AwgctlError(f"invalid custom packet specification: {field}")
        if match.group("bytes") is not None:
            encoded = match.group("bytes")
            if len(encoded) % 2:
                raise AwgctlError(f"invalid custom packet specification: {field}")
            contribution = len(encoded) // 2
            if contribution == 0 or contribution > 1000:
                raise AwgctlError(f"invalid custom packet specification: {field}")
        elif match.group("timestamp") is not None:
            contribution = 4
        else:
            contribution = int(match.group("size"))
            if contribution > 1000:
                raise AwgctlError(f"invalid custom packet specification: {field}")
        rendered_size += contribution
        if rendered_size > 1000:
            raise AwgctlError(f"custom packet specification exceeds size limit: {field}")
        position = match.end()
    if rendered_size >= mtu:
        raise AwgctlError(f"custom packet specification exceeds configured MTU: {field}")
    return value


def _classic_profile(parameters: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parameters, dict):
        raise AwgctlError("classic obfuscation parameters must be an object")
    if set(parameters) != set(OBFUSCATION_FIELDS):
        raise AwgctlError("classic AmneziaWG obfuscation fields are incomplete or unexpected")
    result = {
        field: _strict_integer(
            parameters[field],
            field,
            maximum=0xFFFFFFFF,
        )
        for field in OBFUSCATION_FIELDS
    }
    if result["Jmin"] > result["Jmax"]:
        raise AwgctlError("Jmin must not exceed Jmax")
    validate_header_ranges(result)
    if result["S1"] + 56 == result["S2"]:
        raise AwgctlError("classic handshake packet lengths are ambiguous")
    return {
        "schema_version": 1,
        "name": "classic-v1",
        "parameters": result,
    }


def _normalize_awg31_profile(profile: dict[str, Any], *, mtu: int) -> dict[str, Any]:
    if not isinstance(profile, dict):
        raise AwgctlError("obfuscation profile must be an object")
    allowed = {"schema_version", "name", "parameters", "header_protection_key_path"}
    _reject_unknown_fields(profile, allowed, "obfuscation profile")
    profile_schema = profile.get("schema_version")
    if (
        set(profile) != allowed
        or not isinstance(profile_schema, int)
        or isinstance(profile_schema, bool)
        or profile_schema != 1
    ):
        raise AwgctlError("invalid AWG 3.1 obfuscation profile contract")
    if profile.get("name") != "russia-ios-v1":
        raise AwgctlError("unsupported AWG 3.1 obfuscation profile")
    if profile.get("header_protection_key_path") != str(HEADER_PROTECTION_KEY):
        raise AwgctlError("AWG 3.1 header-protection key path is outside the protected layout")
    parameters = profile.get("parameters")
    if not isinstance(parameters, dict):
        raise AwgctlError("AWG 3.1 obfuscation parameters must be an object")
    _reject_unknown_fields(parameters, set(AWG31_PARAMETER_FIELDS), "AWG 3.1 parameters")
    if set(parameters) != set(AWG31_PARAMETER_FIELDS):
        raise AwgctlError("AWG 3.1 obfuscation fields are incomplete")
    result: dict[str, Any] = {
        field: _strict_integer(parameters[field], field, maximum=0xFFFF)
        for field in AWG31_INTEGER_FIELDS
    }
    if result["Jmin"] > result["Jmax"]:
        raise AwgctlError("Jmin must not exceed Jmax")
    result.update(validate_header_ranges(parameters))
    for field in AWG31_CPS_FIELDS:
        value = parameters[field]
        result[field] = None if value is None else validate_cps(value, field=field, mtu=mtu)
    if result["I1"] is None:
        raise AwgctlError("russia-ios-v1 requires nonempty I1")
    for field in AWG31_RANGE_FIELDS:
        result[field] = normalize_closed_range(parameters[field], field=field, maximum=0xFFFF)
    for field in AWG31_BOOLEAN_FIELDS:
        if not isinstance(parameters[field], bool):
            raise AwgctlError(f"invalid obfuscation switch: {field}")
        result[field] = parameters[field]
    if result["RandomTrailers"] or not result["DisableCookies"]:
        raise AwgctlError("russia-ios-v1 requires trailers off and cookies disabled")
    required_bounds = {
        "Jc": (6, 12),
        "S1": (20, 120),
        "S2": (20, 120),
        "S3": (12, 60),
        "S4": (12, 30),
    }
    if any(not lower <= result[field] <= upper for field, (lower, upper) in required_bounds.items()):
        raise AwgctlError("russia-ios-v1 randomized value is outside its profile bounds")
    if result["S1"] + 56 == result["S2"]:
        raise AwgctlError("classic handshake packet lengths are ambiguous")
    if (result["Jmin"], result["Jmax"]) != (8, 80):
        raise AwgctlError("russia-ios-v1 requires fixed junk-size bounds")
    if [
        _range_bounds(result[field]) for field in AWG31_HEADER_FIELDS
    ] != [(1, 1), (2, 2), (3, 3), (4, 4)]:
        raise AwgctlError("russia-ios-v1 requires fixed header values")
    if any(result[field] is not None for field in AWG31_CPS_FIELDS[1:]):
        raise AwgctlError("russia-ios-v1 leaves I2-I5 unset")
    required_ranges = {
        "ContentPaddingAddition": {"min": 0, "max": 64},
        "RekeyAfterTime": {"min": 105, "max": 135},
        "RekeyTimeout": {"min": 4, "max": 7},
        "RejectAfterTime": {"min": 165, "max": 195},
        "KeepaliveTimeout": {"min": 8, "max": 12},
        "MaxHandshakeAttempts": {"min": 15, "max": 21},
    }
    if any(result[field] != expected for field, expected in required_ranges.items()):
        raise AwgctlError("russia-ios-v1 timing or padding range differs from policy")
    return {
        "schema_version": 1,
        "name": "russia-ios-v1",
        "parameters": result,
        "header_protection_key_path": str(HEADER_PROTECTION_KEY),
    }


def _normalize_obfuscation(value: Any, *, mtu: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AwgctlError("obfuscation must be an object")
    _reject_unknown_fields(value, {"mode", "profile"}, "obfuscation")
    if set(value) != {"mode", "profile"}:
        raise AwgctlError("obfuscation mode and profile are required")
    mode = value.get("mode")
    profile = value.get("profile")
    if mode == "classic":
        if not isinstance(profile, dict):
            raise AwgctlError("obfuscation profile must be an object")
        _reject_unknown_fields(profile, {"schema_version", "name", "parameters"}, "obfuscation profile")
        if set(profile) != {"schema_version", "name", "parameters"}:
            raise AwgctlError("invalid classic obfuscation profile contract")
        profile_schema = profile.get("schema_version")
        if (
            not isinstance(profile_schema, int)
            or isinstance(profile_schema, bool)
            or profile_schema != 1
            or profile.get("name") != "classic-v1"
        ):
            raise AwgctlError("unsupported classic obfuscation profile")
        return {"mode": "classic", "profile": _classic_profile(profile["parameters"])}
    if mode == "awg31":
        return {"mode": "awg31", "profile": _normalize_awg31_profile(profile, mtu=mtu)}
    raise AwgctlError("obfuscation mode must be classic or awg31")


def normalize_server_config(config: dict[str, Any]) -> dict[str, Any]:
    """Normalize historical server state into the strict schema-2 contract."""
    if not isinstance(config, dict):
        raise AwgctlError("server configuration must be an object")
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
    _reject_unknown_fields(config, required, "server configuration")
    missing = sorted(required - config.keys())
    if missing:
        raise AwgctlError(f"server configuration missing fields: {', '.join(missing)}")
    schema = config["schema_version"]
    if not isinstance(schema, int) or isinstance(schema, bool) or schema not in {1, 2}:
        raise AwgctlError("unsupported server configuration schema")
    result = copy.deepcopy(config)
    if not isinstance(result["interface"], str) or not INTERFACE_RE.fullmatch(result["interface"]):
        raise AwgctlError("invalid interface name")
    if not isinstance(result["external_interface"], str) or not INTERFACE_RE.fullmatch(result["external_interface"]):
        raise AwgctlError("invalid external interface name")
    if not isinstance(result["blocked_forward_ipv4"], list) or any(
        not isinstance(value, str) for value in result["blocked_forward_ipv4"]
    ):
        raise AwgctlError("blocked_forward_ipv4 must be a list of networks")
    if not isinstance(result["subnet"], str) or not isinstance(result["server_address"], str):
        raise AwgctlError("managed subnet and server address must be text")
    try:
        subnet = ipaddress.ip_network(result["subnet"], strict=True)
        server = ipaddress.ip_interface(result["server_address"])
    except (TypeError, ValueError) as exc:
        raise AwgctlError("invalid managed subnet or server address") from exc
    if subnet.version != 4 or server.version != 4 or server.ip not in subnet or server.network != subnet:
        raise AwgctlError("server address must use the managed IPv4 subnet prefix")
    if not isinstance(result["endpoint"], str):
        raise AwgctlError("endpoint must be text")
    validate_endpoint(result["endpoint"])
    port = result["listen_port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise AwgctlError("listen_port must be an integer from 1 to 65535")
    mtu = result["mtu"]
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not 576 <= mtu <= 9000:
        raise AwgctlError("mtu must be an integer from 576 to 9000")
    keepalive = result["keepalive"]
    if not isinstance(keepalive, int) or isinstance(keepalive, bool) or not 0 <= keepalive <= 65535:
        raise AwgctlError("keepalive must be an integer from 0 to 65535")
    if not isinstance(result["dns"], list):
        raise AwgctlError("dns must be a list")
    result["dns"] = validate_dns(result["dns"])
    if not isinstance(result["use_psk"], bool):
        raise AwgctlError("use_psk must be boolean")
    if schema == 1:
        result["obfuscation"] = {
            "mode": "classic",
            "profile": _classic_profile(result["obfuscation"]),
        }
    else:
        result["obfuscation"] = _normalize_obfuscation(result["obfuscation"], mtu=mtu)
    try:
        blocked = tuple(str(ipaddress.ip_network(value, strict=True)) for value in result["blocked_forward_ipv4"])
    except (TypeError, ValueError) as exc:
        raise AwgctlError("blocked_forward_ipv4 is invalid") from exc
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
    if not isinstance(result["paths"], dict) or result["paths"] != expected_paths:
        raise AwgctlError("managed paths differ from the fixed production layout")
    result["schema_version"] = 2
    return result


def validate_server_config(config: dict[str, Any]) -> dict[str, Any]:
    return normalize_server_config(config)


def build_russia_ios_obfuscation(
    header_protection_key_path: pathlib.Path,
    *,
    random_source: Any | None = None,
    token_bytes: Any = secrets.token_bytes,
    mtu: int,
) -> dict[str, Any]:
    """Create the initial AWG 3.1 profile using only CSPRNG-derived variation."""
    source = random_source or secrets.SystemRandom()
    entropy = token_bytes(32)
    if not isinstance(entropy, bytes) or len(entropy) != 32:
        raise AwgctlError("CSPRNG returned invalid profile entropy")
    transaction_id = entropy[:2]
    label = bytes(ord("a") + (value % 26) for value in entropy[2:10])
    address = entropy[-4:]
    qname = bytes([len(label)]) + label + b"\x03cdn\x00"
    dns_packet = (
        transaction_id
        + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        + qname
        + b"\x00\x01\x00\x01"
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        + address
    )
    jc = source.randint(6, 12)
    s1 = source.randint(20, 120)
    s2 = source.randint(20, 120)
    while s1 + 56 == s2:
        s2 = source.randint(20, 120)
    parameters: dict[str, Any] = {
        "Jc": jc,
        "Jmin": 8,
        "Jmax": 80,
        "S1": s1,
        "S2": s2,
        "S3": source.randint(12, 60),
        "S4": source.randint(12, 30),
        "H1": 1,
        "H2": 2,
        "H3": 3,
        "H4": 4,
        "I1": f"<b 0x{dns_packet.hex()}>",
        "I2": None,
        "I3": None,
        "I4": None,
        "I5": None,
        "ContentPaddingAddition": {"min": 0, "max": 64},
        "RekeyAfterTime": {"min": 105, "max": 135},
        "RekeyTimeout": {"min": 4, "max": 7},
        "RejectAfterTime": {"min": 165, "max": 195},
        "KeepaliveTimeout": {"min": 8, "max": 12},
        "MaxHandshakeAttempts": {"min": 15, "max": 21},
        "RandomTrailers": False,
        "DisableCookies": True,
    }
    value = {
        "mode": "awg31",
        "profile": {
            "schema_version": 1,
            "name": "russia-ios-v1",
            "parameters": parameters,
            "header_protection_key_path": str(header_protection_key_path),
        },
    }
    return _normalize_obfuscation(value, mtu=mtu)


def prepare_awg31_profile(
    *,
    key_path: pathlib.Path = HEADER_PROTECTION_KEY,
    mtu: int,
    capability_checker: Any = require_awg31_capability,
    random_source: Any | None = None,
    profile_token_bytes: Any = secrets.token_bytes,
    key_token_bytes: Any = secrets.token_bytes,
) -> tuple[dict[str, Any], str]:
    """Prepare validated non-live profile material after the source-policy gate."""
    capability_checker()
    obfuscation = build_russia_ios_obfuscation(
        key_path,
        random_source=random_source,
        token_bytes=profile_token_bytes,
        mtu=mtu,
    )
    fingerprint_value = write_header_protection_key(
        key_path,
        token_bytes=key_token_bytes,
    )
    return obfuscation, fingerprint_value


def generate_classic_obfuscation(random_source: Any | None = None) -> dict[str, int]:
    """Generate classic, interoperable AmneziaWG parameters for a new server."""
    source = random_source or secrets.SystemRandom()
    s1 = source.randint(15, 150)
    s2 = source.randint(15, 150)
    while s1 + 56 == s2:
        s2 = source.randint(15, 150)
    headers: list[int] = []
    while len(headers) < 4:
        candidate = source.randint(5, 2_147_483_647)
        if candidate not in headers:
            headers.append(candidate)
    h1, h2, h3, h4 = headers
    return {
        "Jc": source.randint(4, 12),
        "Jmin": 8,
        "Jmax": 80,
        "S1": s1,
        "S2": s2,
        "H1": h1,
        "H2": h2,
        "H3": h3,
        "H4": h4,
    }


def build_fresh_server_config(
    *,
    endpoint: str,
    subnet: str,
    listen_port: int,
    external_interface: str,
    dns: str,
    mtu: int,
    keepalive: int,
    obfuscation: dict[str, int],
) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except ValueError as exc:
        raise AwgctlError("fresh-install subnet must be a canonical IPv4 network") from exc
    if network.version != 4 or network.prefixlen < 16 or network.prefixlen > 30:
        raise AwgctlError("fresh-install subnet must be IPv4 with a /16 through /30 prefix")
    server_ip = next(network.hosts())
    config = {
        "schema_version": 1,
        "interface": "awg0",
        "subnet": str(network),
        "server_address": f"{server_ip}/{network.prefixlen}",
        "endpoint": validate_endpoint(endpoint),
        "listen_port": listen_port,
        "external_interface": external_interface,
        "dns": parse_dns_value(dns),
        "mtu": mtu,
        "keepalive": keepalive,
        "use_psk": True,
        "obfuscation": obfuscation,
        "blocked_forward_ipv4": list(BLOCKED_FORWARD_IPV4),
        "paths": {
            "runtime_config": str(RUNTIME_CONFIG),
            "generated_config": str(GENERATED_CONFIG),
            "server_private_key": str(SERVER_PRIVATE),
            "server_public_key": str(SERVER_PUBLIC),
            "clients": str(CLIENTS),
            "client_keys": str(CLIENT_KEYS),
            "revoked": str(REVOKED),
            "backups": str(BACKUPS),
        },
    }
    return validate_server_config(config)


def load_config() -> dict[str, Any]:
    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AwgctlError("management state is not initialized") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise AwgctlError("cannot read managed server configuration") from exc
    return validate_server_config(config)


def _render_config(config: dict[str, Any]) -> dict[str, Any]:
    if "schema_version" in config:
        return normalize_server_config(config)
    legacy = {
        "schema_version": 1,
        "interface": "awg0",
        "subnet": "10.0.0.0/24",
        "server_address": "10.0.0.1/24",
        "external_interface": "eth0",
        "use_psk": True,
        "blocked_forward_ipv4": list(BLOCKED_FORWARD_IPV4),
        "paths": {
            "runtime_config": str(RUNTIME_CONFIG),
            "generated_config": str(GENERATED_CONFIG),
            "server_private_key": str(SERVER_PRIVATE),
            "server_public_key": str(SERVER_PUBLIC),
            "clients": str(CLIENTS),
            "client_keys": str(CLIENT_KEYS),
            "revoked": str(REVOKED),
            "backups": str(BACKUPS),
        },
        **config,
    }
    return normalize_server_config(legacy)


def _native_range(value: int | dict[str, int]) -> str:
    if isinstance(value, int):
        return str(value)
    return f"{value['min']}-{value['max']}"


def effective_obfuscation(
    config: dict[str, Any], *, header_protection_key: bytes | None = None
) -> dict[str, str]:
    """Return the single canonical native model shared by every renderer."""
    if set(config) == {"obfuscation"}:
        supplied = config["obfuscation"]
        if isinstance(supplied, dict) and set(supplied) == set(OBFUSCATION_FIELDS):
            obfuscation = {"mode": "classic", "profile": _classic_profile(supplied)}
        else:
            obfuscation = _normalize_obfuscation(supplied, mtu=1280)
    else:
        obfuscation = _render_config(config)["obfuscation"]
    parameters = obfuscation["profile"]["parameters"]
    if obfuscation["mode"] == "classic":
        if header_protection_key is not None:
            raise AwgctlError("classic mode cannot use a header-protection key")
        return {field: str(parameters[field]) for field in OBFUSCATION_FIELDS}
    if header_protection_key is None:
        raise AwgctlError("AWG 3.1 rendering requires explicit header-protection key material")
    if not isinstance(header_protection_key, bytes) or len(header_protection_key) != 32:
        raise AwgctlError("invalid explicit header-protection key material")
    result: dict[str, str] = {
        field: str(parameters[field]) for field in AWG31_INTEGER_FIELDS
    }
    result.update({field: _native_range(parameters[field]) for field in AWG31_HEADER_FIELDS})
    result.update(
        {
            field: parameters[field]
            for field in AWG31_CPS_FIELDS
            if parameters[field] is not None
        }
    )
    result["HeaderProtectionKey"] = base64.b64encode(header_protection_key).decode("ascii")
    result.update({field: _native_range(parameters[field]) for field in AWG31_RANGE_FIELDS})
    result.update(
        {field: "on" if parameters[field] else "off" for field in AWG31_BOOLEAN_FIELDS}
    )
    return result


def canonical_obfuscation_lines(
    config: dict[str, Any], *, header_protection_key: bytes | None = None
) -> list[str]:
    return [
        f"{field} = {value}"
        for field, value in effective_obfuscation(
            config, header_protection_key=header_protection_key
        ).items()
    ]


def header_protection_key_for_config(config: dict[str, Any]) -> bytes | None:
    normalized = _render_config(config)
    if normalized["obfuscation"]["mode"] == "classic":
        return None
    path = pathlib.Path(
        normalized["obfuscation"]["profile"]["header_protection_key_path"]
    )
    return read_header_protection_key(path)


def obfuscation_status(config: dict[str, Any]) -> dict[str, str]:
    normalized = _render_config(config)
    profile = normalized["obfuscation"]["profile"]
    result = {"mode": normalized["obfuscation"]["mode"], "profile": profile["name"]}
    if normalized["obfuscation"]["mode"] == "awg31":
        material = read_header_protection_key(pathlib.Path(profile["header_protection_key_path"]))
        result["header_protection_key_fingerprint"] = header_protection_fingerprint(material)
    return result


def public_server_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return the one secret-safe server-state representation for public output."""
    result = normalize_server_config(config)
    if result["obfuscation"]["mode"] == "awg31":
        parameters = result["obfuscation"]["profile"]["parameters"]
        for field in AWG31_CPS_FIELDS:
            if parameters[field] is not None:
                parameters[field] = "[redacted]"
    return result


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
        if key in current:
            raise AwgctlError(f"duplicate key {key} at line {number}")
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


def effective_client_status(
    client: dict[str, Any], *, now: dt.datetime | None = None
) -> str:
    """Return fail-closed runtime eligibility status at the current UTC instant."""
    stored_status = str(client.get("status", "active"))
    if stored_status != "active":
        return stored_status
    expires = client.get("expires")
    if expires is None:
        return "active"
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    expiry = dt.datetime.combine(dt.date.fromisoformat(expires), dt.time.min, dt.timezone.utc)
    return "expired" if current.astimezone(dt.timezone.utc) >= expiry else "active"


def client_is_server_eligible(
    client: dict[str, Any], *, now: dt.datetime | None = None
) -> bool:
    """Central peer eligibility predicate for all server configuration renders."""
    return effective_client_status(client, now=now) == "active"


def render_server_config(
    config: dict[str, Any],
    server_private: str,
    clients: Sequence[dict[str, Any]],
    *,
    now: dt.datetime | None = None,
    header_protection_key: bytes | None = None,
) -> str:
    config = _render_config(config)
    validate_key(server_private, "server private key")
    lines = [
        "[Interface]",
        f"Address = {config['server_address']}",
        f"ListenPort = {config['listen_port']}",
        f"PrivateKey = {server_private}",
        f"MTU = {config['mtu']}",
    ]
    lines.extend(
        canonical_obfuscation_lines(
            config, header_protection_key=header_protection_key
        )
    )
    lines.extend([
        "PostUp = /opt/amneziawg/libexec/awgctl-internal _firewall up",
        "PostDown = /opt/amneziawg/libexec/awgctl-internal _firewall down",
    ])
    render_now = now or dt.datetime.now(dt.timezone.utc)
    for client in clients:
        if not client_is_server_eligible(client, now=render_now):
            continue
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
    config: dict[str, Any],
    private_key: str,
    psk: str | None,
    server_public: str,
    address: str,
    *,
    header_protection_key: bytes | None = None,
) -> str:
    config = _render_config(config)
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
    lines.extend(
        canonical_obfuscation_lines(
            config, header_protection_key=header_protection_key
        )
    )
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
        try:
            metadata = normalize_client_metadata(metadata)
        except ContractError as exc:
            raise AwgctlError(f"invalid client metadata: {directory.name}: {exc}") from exc
        if metadata.get("name") != directory.name or metadata.get("status") not in {"active", "expired"}:
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
            if record.get("management", "managed") == "managed":
                record["private_key"] = read_secret(key_dir / "private", "client private key")
            else:
                record["private_key"] = None
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


def render_current_server(
    clients: Sequence[dict[str, Any]] | None = None,
    *,
    now: dt.datetime | None = None,
) -> str:
    config = load_config()
    return render_server_config(
        config,
        server_private_key(),
        server_records_for_render(clients),
        now=now,
        header_protection_key=header_protection_key_for_config(config),
    )


def semantic_signature(text: str) -> dict[str, Any]:
    parsed = parse_awg_config(text)
    interfaces = parsed.get("Interface", [])
    if len(interfaces) != 1:
        raise AwgctlError("server configuration must contain exactly one Interface section")
    interface = {key: value for key, value in interfaces[0].items() if key not in {"PostUp", "PostDown", "PreUp", "PreDown"}}
    peers = sorted((tuple(sorted(peer.items())) for peer in parsed.get("Peer", [])))
    return {"interface": tuple(sorted(interface.items())), "peers": peers}


def legacy_lifecycle_hook_drift(expected: bytes, actual: bytes) -> bool:
    """Recognize only the beta.2 public-hook to internal-hook migration."""
    legacy = expected.replace(
        b"/opt/amneziawg/libexec/awgctl-internal _firewall",
        b"/opt/amneziawg/bin/awgctl _firewall",
    )
    return legacy != expected and actual == legacy


def ensure_no_drift() -> None:
    expected = render_current_server().encode("utf-8")
    try:
        generated = GENERATED_CONFIG.read_bytes()
        runtime = RUNTIME_CONFIG.read_bytes()
    except OSError as exc:
        raise AwgctlError("cannot read generated/runtime server configuration") from exc
    if generated != expected and not legacy_lifecycle_hook_drift(expected, generated):
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
    use_docker_integration = docker_user_chain_exists()
    integration = docker_integration_text(config) if use_docker_integration else ""
    fd, integration_name = tempfile.mkstemp(prefix=".docker-integration-", suffix=".nft", dir=GENERATED)
    integration_path = pathlib.Path(integration_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(integration.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        if use_docker_integration:
            run(["nft", "-c", "-f", str(integration_path)])
        firewall_cleanup()
        atomic_write(GENERATED_NFT, nft_text, 0o600)
        run(["nft", "-f", str(GENERATED_NFT)])
        try:
            if use_docker_integration:
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
    owner: str | None = None,
    device: str | None = None,
    expires: str | None = None,
) -> dict[str, Any]:
    client_dir = CLIENTS / name
    key_dir = CLIENT_KEYS / name
    if client_dir.exists() or key_dir.exists():
        raise AwgctlError(f"client already exists: {name}")
    client_dir.mkdir(mode=0o700)
    key_dir.mkdir(mode=0o700)
    now = iso_now()
    metadata = normalize_client_metadata({
        "schema_version": 3,
        "name": name,
        "status": "active",
        "management": "managed",
        "address": str(ipaddress.ip_interface(address)),
        "public_key": public,
        "public_key_fingerprint": fingerprint(public),
        "use_psk": bool(psk),
        "created_at": created_at or now,
        "updated_at": now,
        "owner": owner,
        "device": device,
        "expires": expires,
        "profile_revision": 1,
        "profile_generated_at": now,
        "profile_change_reason": "imported" if imported_from else "created",
        "distribution_status": "pending",
        "distributed_at": None,
    })
    if imported_from:
        metadata["imported_from"] = imported_from
    atomic_write(key_dir / "private", private + "\n", 0o600)
    atomic_write(key_dir / "public", public + "\n", 0o600)
    if psk:
        atomic_write(key_dir / "psk", psk + "\n", 0o600)
    profile = profile_text or render_client_config(
        config,
        private,
        psk,
        server_public_key(),
        address,
        header_protection_key=header_protection_key_for_config(config),
    )
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
        (ROOT / "revoked", pathlib.Path("revoked")),
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
    manifest = create_backup_manifest(destination, product_version=VERSION, created_at=iso_now())
    atomic_json(destination / "manifest.json", manifest, 0o600)
    chmod_secret_tree(destination)
    verify_backup(destination, expected_uid=os.geteuid(), expected_gid=os.getegid())
    audit(f"backup created: {destination.name}")
    return destination


def resolve_backup_path(value: pathlib.Path) -> pathlib.Path:
    backup_root = BACKUPS.resolve()
    candidate = value if value.is_absolute() else BACKUPS / value
    if candidate.is_symlink():
        raise AwgctlError("backup path must not be a symbolic link")
    resolved = candidate.resolve()
    if resolved.parent != backup_root:
        raise AwgctlError("backup must name one direct child of the managed backup directory")
    if not resolved.is_dir():
        raise AwgctlError(f"backup directory not found: {value}")
    return resolved


def verify_managed_backup(value: pathlib.Path) -> tuple[pathlib.Path, dict[str, Any]]:
    path = resolve_backup_path(value)
    try:
        report = verify_backup(path, expected_uid=os.geteuid(), expected_gid=os.getegid())
    except BackupError as exc:
        raise AwgctlError(f"backup verification failed: {exc}") from exc
    return path, report


RESTORE_COMPONENTS = ("config", "keys", "clients", "revoked", "generated")


def _restore_inventory(directory: pathlib.Path, *, directories: bool) -> set[str]:
    """List one protected restore directory through its validated descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        raise AwgctlError("backup client artifact directory is missing or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid())
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AwgctlError("backup client artifact directory is not protected")
        names = set(os.listdir(descriptor))
        for name in names:
            item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            expected_type = stat.S_ISDIR(item.st_mode) if directories else stat.S_ISREG(item.st_mode)
            expected_mode = 0o700 if directories else 0o600
            if (
                not expected_type
                or (not directories and item.st_nlink != 1)
                or (item.st_uid, item.st_gid) != (os.geteuid(), os.getegid())
                or stat.S_IMODE(item.st_mode) != expected_mode
            ):
                raise AwgctlError("backup client artifact inventory is unsafe")
        return names
    except OSError as exc:
        raise AwgctlError("cannot inspect backup client artifact inventory") from exc
    finally:
        os.close(descriptor)


def _read_restore_artifact(
    path: pathlib.Path,
    *,
    label: str,
    maximum: int,
) -> bytes:
    """Read one staged private artifact through its validated descriptor."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AwgctlError(f"cannot read backup {label}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid())
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > maximum
        ):
            raise AwgctlError(f"backup {label} is not one protected bounded file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(16 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AwgctlError(f"backup {label} is unexpectedly large")
        return b"".join(chunks)
    except OSError as exc:
        raise AwgctlError(f"cannot read backup {label}") from exc
    finally:
        os.close(descriptor)


def _restore_text(path: pathlib.Path, *, label: str, maximum: int = 64 * 1024) -> str:
    try:
        return _read_restore_artifact(path, label=label, maximum=maximum).decode("utf-8")
    except UnicodeError as exc:
        raise AwgctlError(f"backup {label} is not valid UTF-8") from exc


def _validate_restore_clients(
    stage: pathlib.Path,
    config: dict[str, Any],
    *,
    server_public: str,
    header_key: bytes | None,
) -> list[dict[str, Any]]:
    clients_root = stage / "clients"
    keys_root = stage / "keys/clients"
    client_names = _restore_inventory(clients_root, directories=True)
    key_names = _restore_inventory(keys_root, directories=True)
    if client_names != key_names:
        raise AwgctlError("backup client metadata and key inventories differ")
    records: list[dict[str, Any]] = []
    for name in sorted(client_names):
        validate_client_name(name)
        client_dir = clients_root / name
        key_dir = keys_root / name
        client_files = _restore_inventory(client_dir, directories=False)
        key_files = _restore_inventory(key_dir, directories=False)
        try:
            metadata = json.loads(
                _restore_text(client_dir / "metadata.json", label=f"client metadata: {name}")
            )
            metadata = normalize_client_metadata(metadata)
        except (json.JSONDecodeError, ContractError) as exc:
            raise AwgctlError(f"invalid backup client metadata: {name}") from exc
        if metadata.get("name") != name or metadata.get("status") not in {"active", "expired"}:
            raise AwgctlError(f"invalid backup client metadata identity: {name}")
        public = validate_key(metadata.get("public_key", ""), "backup client public key")
        try:
            address = ipaddress.ip_interface(metadata["address"])
        except (KeyError, ValueError) as exc:
            raise AwgctlError(f"invalid backup client address: {name}") from exc
        if address.version != 4 or address.network.prefixlen != 32:
            raise AwgctlError(f"invalid backup client address: {name}")
        managed = metadata.get("management", "managed") == "managed"
        expected_client_files = {"metadata.json"}
        if managed:
            expected_client_files.update({f"{name}.conf", f"{name}.png"})
        expected_key_files = {"public"}
        if managed:
            expected_key_files.add("private")
        if metadata.get("use_psk"):
            expected_key_files.add("psk")
        if client_files != expected_client_files or key_files != expected_key_files:
            raise AwgctlError(f"backup client artifact inventory differs from metadata: {name}")
        public_file = validate_key(
            _restore_text(key_dir / "public", label=f"client public key: {name}", maximum=256).strip(),
            "backup client public key",
        )
        if public_file != public:
            raise AwgctlError(f"backup client public key metadata drift: {name}")
        psk = None
        if metadata.get("use_psk"):
            psk = validate_key(
                _restore_text(key_dir / "psk", label=f"client preshared key: {name}", maximum=256).strip(),
                "backup client preshared key",
            )
        record = dict(metadata)
        record["psk"] = psk
        if managed:
            private = validate_key(
                _restore_text(key_dir / "private", label=f"client private key: {name}", maximum=256).strip(),
                "backup client private key",
            )
            derived = run(
                ["awg", "pubkey"], input_data=(private + "\n").encode("ascii")
            ).stdout.decode("ascii").strip()
            if derived != public:
                raise AwgctlError(f"backup client keypair does not match: {name}")
            profile = _restore_text(client_dir / f"{name}.conf", label=f"client profile: {name}")
            expected_profile = render_client_config(
                config,
                private,
                psk,
                server_public,
                str(address),
                header_protection_key=header_key,
            )
            if profile != expected_profile:
                raise AwgctlError(f"backup client profile differs from managed state: {name}")
            record["private_key"] = private
        else:
            record["private_key"] = None
        records.append(record)
    duplicates = find_duplicate_client_state(records)
    if duplicates:
        raise AwgctlError("backup contains duplicate client identity or address")
    return records


def validate_restore_stage(stage: pathlib.Path) -> dict[str, Any]:
    try:
        config = json.loads((stage / "config/server.json").read_text(encoding="utf-8"))
        server_private = (stage / "keys/server/private").read_text(encoding="ascii").strip()
        server_public = (stage / "keys/server/public").read_text(encoding="ascii").strip()
        generated_server = (stage / "generated/awg0.conf").read_text(encoding="utf-8")
        generated_nft = (stage / "generated/nftables.nft").read_text(encoding="utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AwgctlError("backup is missing required managed state") from exc
    config = validate_server_config(config)
    restore_now = dt.datetime.now(dt.timezone.utc)
    validate_key(server_private, "server private key")
    validate_key(server_public, "server public key")
    derived_public = run(["awg", "pubkey"], input_data=(server_private + "\n").encode("ascii")).stdout.decode().strip()
    if derived_public != server_public:
        raise AwgctlError("backup server keypair does not match")
    parsed = parse_awg_config(generated_server)
    unknown_sections = sorted(set(parsed) - {"Interface", "Peer"})
    if unknown_sections:
        raise AwgctlError("backup generated configuration has unsupported sections")
    interface_sections = parsed.get("Interface", [])
    if len(interface_sections) != 1 or interface_sections[0].get("PrivateKey") != server_private:
        raise AwgctlError("backup generated configuration does not use the backed-up server key")
    header_key = None
    if config["obfuscation"]["mode"] == "awg31":
        header_key = read_header_protection_key(
            stage / "keys/server/header-protection",
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
    expected_obfuscation = effective_obfuscation(
        config,
        header_protection_key=header_key,
    )
    server_interface_fields = {
        "Address",
        "ListenPort",
        "PrivateKey",
        "MTU",
        "PostUp",
        "PostDown",
        *expected_obfuscation,
    }
    server_peer_fields = {"PublicKey", "PresharedKey", "AllowedIPs"}
    if set(interface_sections[0]) - server_interface_fields or any(
        set(peer) - server_peer_fields for peer in parsed.get("Peer", [])
    ):
        raise AwgctlError("backup generated configuration has unsupported directives")
    rendered_obfuscation = {
        field: interface_sections[0].get(field) for field in expected_obfuscation
    }
    if rendered_obfuscation != expected_obfuscation:
        raise AwgctlError(
            "backup generated configuration header-protection or obfuscation differs from managed state"
        )
    clients = _validate_restore_clients(
        stage,
        config,
        server_public=server_public,
        header_key=header_key,
    )
    expected_server = render_server_config(
        config,
        server_private,
        clients,
        now=restore_now,
        header_protection_key=header_key,
    )
    expected_parsed = parse_awg_config(expected_server)

    def complete_signature(value: dict[str, list[dict[str, str]]]) -> tuple[Any, ...]:
        interface = tuple(sorted(value["Interface"][0].items()))
        peers = tuple(sorted(tuple(sorted(peer.items())) for peer in value.get("Peer", [])))
        return interface, peers

    if complete_signature(parsed) != complete_signature(expected_parsed):
        raise AwgctlError("backup generated server differs from managed client and interface state")
    validate_native_server(generated_server)
    validate_nftables_text(generated_nft)
    return config


def restore_backup_transaction(backup: pathlib.Path) -> tuple[pathlib.Path, bool]:
    """Restore manager-owned state, rolling back both disk and runtime on failure."""
    safety_backup = create_backup()
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".restore-stage-", dir=ROOT))
    rollback = pathlib.Path(tempfile.mkdtemp(prefix=".restore-rollback-", dir=ROOT))
    old_runtime = RUNTIME_CONFIG.read_bytes() if RUNTIME_CONFIG.exists() else None
    active = False
    moved_old: list[str] = []
    moved_new: list[str] = []
    try:
        for component in RESTORE_COMPONENTS:
            source = backup / component
            destination = stage / component
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                destination.mkdir(parents=True, mode=0o700)
        chmod_secret_tree(stage)
        config = validate_restore_stage(stage)
        active = is_service_active(config["interface"])
        for component in RESTORE_COMPONENTS:
            current = ROOT / component
            if current.exists():
                os.replace(current, rollback / component)
                moved_old.append(component)
            os.replace(stage / component, current)
            moved_new.append(component)
        fsync_directory(ROOT)
        atomic_write(RUNTIME_CONFIG, GENERATED_CONFIG.read_bytes(), 0o600)
        if active:
            service_action("restart", config["interface"])
            expected_server = SERVER_PUBLIC.read_text(encoding="ascii").strip()
            if safe_awg_query(config["interface"], "public-key") != expected_server:
                raise AwgctlError("restored runtime server identity verification failed")
        chmod_secret_tree(ROOT / "config")
        chmod_secret_tree(ROOT / "keys")
        chmod_secret_tree(ROOT / "clients")
        chmod_secret_tree(ROOT / "revoked")
        chmod_secret_tree(ROOT / "generated")
        return safety_backup, active
    except Exception as original:
        for component in reversed(moved_new):
            current = ROOT / component
            if current.exists():
                shutil.rmtree(current)
        for component in reversed(moved_old):
            archived = rollback / component
            if archived.exists():
                os.replace(archived, ROOT / component)
        if old_runtime is None:
            with contextlib.suppress(FileNotFoundError):
                RUNTIME_CONFIG.unlink()
        else:
            atomic_write(RUNTIME_CONFIG, old_runtime, 0o600)
        if active:
            with contextlib.suppress(Exception):
                old_config = load_config()
                service_action("restart", old_config["interface"])
        audit(f"restore failed and rollback attempted: {backup.name}")
        raise AwgctlError("restore failed; pre-restore state rollback was attempted") from original
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(rollback, ignore_errors=True)


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


def suspicious_wildcard_listeners(
    ss_output: str,
    *,
    vpn_port: int,
    vpn_addresses: Iterable[str] = (),
) -> list[str]:
    managed_addresses: set[str] = set()
    for value in vpn_addresses:
        try:
            managed_addresses.add(str(ipaddress.ip_interface(value).ip))
        except ValueError:
            continue
    listeners: list[str] = []
    for line in ss_output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        protocol = fields[0]
        local = fields[4]
        wildcard = local.startswith("0.0.0.0:") or local.startswith("[::]:") or local.startswith("*:")
        host = local.rsplit(":", 1)[0].strip("[]")
        try:
            bound_address = ipaddress.ip_address(host)
        except ValueError:
            bound_address = None
        vpn_reachable = (
            wildcard
            or (
                bound_address is not None
                and not bound_address.is_loopback
                and str(bound_address) in managed_addresses
            )
        )
        if not vpn_reachable:
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
        raise AwgctlError("migration expects one server Interface and one existing client peer")
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
        raise AwgctlError("legacy client AllowedIPs does not match its client address")
    if endpoint_port != listen_port:
        raise AwgctlError("legacy client endpoint port differs from the server listen port")
    if int(client_interface.get("MTU", "-1")) != mtu:
        raise AwgctlError("legacy client MTU differs from the server MTU")
    if client_obfuscation != obfuscation:
        raise AwgctlError("legacy client obfuscation differs from the server")
    if client_peer.get("PresharedKey") != client_psk:
        raise AwgctlError("legacy client preshared keys do not match")
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
    config = validate_server_config(config)
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


def parse_import_profile(
    profile_text: str,
    config: dict[str, Any],
    *,
    expected_server_public: str,
    derive_public: Any | None = None,
    header_protection_key: bytes | None = None,
) -> dict[str, Any]:
    """Validate a client profile against managed server semantics."""
    config = _render_config(config)
    expected_obfuscation = effective_obfuscation(
        config, header_protection_key=header_protection_key
    )
    parsed = parse_awg_config(profile_text)
    unknown_sections = sorted(set(parsed) - {"Interface", "Peer"})
    if unknown_sections:
        raise AwgctlError(f"unsupported client profile section: {unknown_sections[0]}")
    interfaces = parsed.get("Interface", [])
    peers = parsed.get("Peer", [])
    if len(interfaces) != 1 or len(peers) != 1:
        raise AwgctlError("client profile must contain exactly one Interface and one Peer")
    interface = interfaces[0]
    peer = peers[0]
    interface_fields = {"PrivateKey", "Address", "DNS", "MTU", *expected_obfuscation}
    peer_fields = {"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}
    unknown_interface = sorted(set(interface) - interface_fields)
    unknown_peer = sorted(set(peer) - peer_fields)
    if unknown_interface:
        raise AwgctlError(f"unsupported client Interface directive: {unknown_interface[0]}")
    if unknown_peer:
        raise AwgctlError(f"unsupported client Peer directive: {unknown_peer[0]}")
    try:
        private = validate_key(interface["PrivateKey"], "client private key")
        address = ipaddress.ip_interface(interface["Address"])
        mtu = int(interface["MTU"])
        profile_obfuscation = {field: interface[field] for field in expected_obfuscation}
        server_public = validate_key(peer["PublicKey"], "server public key")
        endpoint_host, endpoint_port_text = peer["Endpoint"].rsplit(":", 1)
        endpoint_port = int(endpoint_port_text)
        keepalive = int(peer["PersistentKeepalive"])
    except (KeyError, ValueError) as exc:
        raise AwgctlError("client profile is missing required AmneziaWG fields") from exc
    if address.version != 4 or address.network.prefixlen != 32:
        raise AwgctlError("client profile address must be an IPv4 /32")
    if validate_dns([value.strip() for value in interface["DNS"].split(",")]) != config["dns"]:
        raise AwgctlError("client profile DNS differs from managed state")
    if mtu != config["mtu"]:
        raise AwgctlError("client profile MTU differs from managed state")
    if profile_obfuscation != expected_obfuscation:
        raise AwgctlError("client profile obfuscation differs from managed state")
    if server_public != expected_server_public:
        raise AwgctlError("client profile server public key differs from managed identity")
    if validate_endpoint(endpoint_host) != config["endpoint"] or endpoint_port != config["listen_port"]:
        raise AwgctlError("client profile endpoint differs from managed state")
    if keepalive != config["keepalive"]:
        raise AwgctlError("client profile keepalive differs from managed state")
    if peer.get("AllowedIPs", "").replace(" ", "") != "0.0.0.0/0,::/0":
        raise AwgctlError("client profile must route IPv4 and IPv6 defaults through the tunnel")
    psk_value = peer.get("PresharedKey")
    psk = validate_key(psk_value, "client preshared key") if psk_value else None
    if bool(psk) != bool(config.get("use_psk", True)):
        raise AwgctlError("client profile preshared-key policy differs from managed state")
    if derive_public is None:
        def derive_public(value: str) -> str:
            return validate_key(
                run(["awg", "pubkey"], input_data=(value + "\n").encode()).stdout.decode().strip(),
                "derived client public key",
            )
    public = validate_key(derive_public(private), "derived client public key")
    canonical_config = {**config, "use_psk": bool(config.get("use_psk", True))}
    return {
        "private_key": private,
        "public_key": public,
        "psk": psk,
        "address": str(address),
        "profile": render_client_config(
            canonical_config,
            private,
            psk,
            server_public,
            str(address),
            header_protection_key=header_protection_key,
        ),
    }


def nft_table_active(table: str) -> bool:
    return run(["nft", "list", "table", "ip", table], check=False).returncode == 0


def ingress_boundary_attestation() -> str | None:
    try:
        return resolve_installation_settings(
            settings_path=INSTALLATION_CONFIG,
            sudo_user=None,
        ).ingress_boundary
    except SettingsError:
        return None


def cmd_aws_rule(config: dict[str, Any] | None = None, *, as_json: bool = False) -> None:
    config = config or load_config()
    boundary = ingress_boundary_attestation()
    data = {
        "ingress_boundary": boundary,
        "type": "Custom",
        "protocol": "UDP",
        "port": config["listen_port"],
        "source": "0.0.0.0/0",
    }
    if as_json:
        print(json.dumps(json_envelope("aws-rule", data=data), indent=2, sort_keys=True))
        return
    print(f"Inbound requirement (attested boundary: {boundary or 'missing'})")
    print(f"  Custom / UDP / {config['listen_port']} / 0.0.0.0/0")


def cmd_status(args: argparse.Namespace) -> int:
    config = load_config()
    obfuscation_data = obfuscation_status(config)
    boundary = ingress_boundary_attestation()
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
    client_rows = [
        {
            "name": client["name"],
            "address": str(ipaddress.ip_interface(client["address"]).ip),
            "status": effective_client_status(client),
            "management": client.get("management", "managed"),
            "last_handshake": format_age(handshakes.get(client["public_key"], 0)),
        }
        for client in clients
    ]
    status_data = {
        "service": active,
        "boot": enabled,
        "interface": {"name": config["interface"], "up": link_up},
        "endpoint": {"host": config["endpoint"], "port": config["listen_port"]},
        "public_ipv4": public_ip,
        "subnet": config["subnet"],
        "obfuscation": obfuscation_data,
        "forwarding": forwarding,
        "nat": nft_table_active("amneziawg_nat"),
        "isolation": nft_table_active("amneziawg_forward"),
        "ingress_boundary": boundary,
        "peer_count": len(peers) if active else 0,
        "clients": client_rows,
        "ingress_rule": {
            "boundary": boundary,
            "type": "Custom",
            "protocol": "UDP",
            "port": config["listen_port"],
            "source": "0.0.0.0/0",
        },
    }
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("status", data=status_data), indent=2, sort_keys=True))
        return 0
    print("AmneziaWG")
    print(f"  service:        {active}")
    print(f"  boot:           {enabled}")
    print(f"  interface:      {config['interface']} {'UP' if link_up else 'DOWN'}")
    print(f"  endpoint:       {config['endpoint']}:{config['listen_port']}")
    print(f"  public IPv4:    {public_ip}")
    print(f"  subnet:         {config['subnet']}")
    print(
        f"  obfuscation:    {obfuscation_data['mode']} "
        f"({obfuscation_data['profile']})"
    )
    if "header_protection_key_fingerprint" in obfuscation_data:
        print(
            "  header key:     sha256:"
            + obfuscation_data["header_protection_key_fingerprint"]
        )
    print(f"  forwarding:     {'enabled' if forwarding else 'disabled'}")
    print(f"  NAT:            {'active' if nft_table_active('amneziawg_nat') else 'inactive'}")
    print(f"  isolation:      {'active' if nft_table_active('amneziawg_forward') else 'inactive'}")
    print(f"  peers:          {len(peers) if active else 0}")
    print("Clients")
    if not clients:
        print("  none")
    for client in client_rows:
        print(
            f"  {client['name']:<20} {client['address']:<15} "
            f"{client['status']:<9} {client['last_handshake']}"
        )
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


def management_security_checks() -> list[tuple[str, str, str]]:
    """Validate the installed privilege boundary without exposing identity secrets."""
    if not INSTALLATION_CONFIG.is_file():
        return [("FAIL", "manager privilege policy", f"missing {INSTALLATION_CONFIG}")]
    checks: list[tuple[str, str, str]] = []

    def add(level: str, name: str, detail: str) -> None:
        checks.append((level, name, detail))

    problem = permission_problem(INSTALLATION_CONFIG, 0o600)
    add("FAIL" if problem else "PASS", "installation settings permissions", problem or "root:root 0600")
    try:
        settings = resolve_installation_settings(
            settings_path=INSTALLATION_CONFIG,
            sudo_user=None,
        )
    except SettingsError as exc:
        add("FAIL", "manager privilege policy", str(exc))
        return checks
    if settings.ingress_boundary is None:
        add(
            "FAIL",
            "ingress boundary attestation",
            "missing; run install.py configure --ingress-boundary VALUE --yes",
        )
    else:
        add(
            "PASS",
            "ingress boundary attestation",
            settings.ingress_boundary,
        )

    try:
        user = pwd.getpwnam(settings.staging_user)
        staging_group = grp.getgrnam(settings.staging_group)
    except KeyError as exc:
        add("FAIL", "staging identity", f"missing account or group: {exc}")
    else:
        supplemental = sorted(
            record.gr_name
            for record in grp.getgrall()
            if settings.staging_user in record.gr_mem and record.gr_gid != user.pw_gid
        )
        identity_ok = (
            user.pw_gid == staging_group.gr_gid
            and user.pw_dir == str(settings.staging_root)
            and user.pw_shell == "/usr/sbin/nologin"
            and not supplemental
        )
        password = run(["passwd", "--status", settings.staging_user], check=False)
        fields = password.stdout.decode("utf-8", "replace").split()
        locked = password.returncode == 0 and len(fields) >= 2 and fields[1] in {"L", "LK"}
        identity_ok = identity_ok and locked
        add(
            "PASS" if identity_ok else "FAIL",
            "staging identity",
            "locked nologin account with no supplemental groups"
            if identity_ok else "identity differs from installed policy",
        )
        try:
            root_metadata = settings.staging_root.stat()
        except OSError:
            root_ok = False
        else:
            root_ok = (
                stat.S_ISDIR(root_metadata.st_mode)
                and root_metadata.st_uid == user.pw_uid
                and root_metadata.st_gid == user.pw_gid
                and stat.S_IMODE(root_metadata.st_mode) == 0o700
            )
        add("PASS" if root_ok else "FAIL", "staging root", f"{settings.staging_root} owner/mode policy")

    try:
        operator_group = grp.getgrnam(settings.operator_group)
    except KeyError:
        add("FAIL", "operator group", f"missing {settings.operator_group}")
    else:
        actual_operators = set(
            effective_group_members(
                operator_group.gr_gid,
                operator_group.gr_mem,
                ((record.pw_name, record.pw_gid) for record in pwd.getpwall()),
            )
        )
        missing_operators = sorted(set(settings.operators) - actual_operators)
        extra_operators = sorted(actual_operators - set(settings.operators))
        membership_problem = missing_operators or extra_operators
        membership_detail = settings.operator_group
        if missing_operators:
            membership_detail = f"missing members: {', '.join(missing_operators)}"
        elif extra_operators:
            membership_detail = f"undeclared members: {', '.join(extra_operators)}"
        add(
            "FAIL" if membership_problem else "PASS",
            "operator group",
            membership_detail,
        )

    expected_sudoers = render_sudoers(settings.operator_group, settings.sudo_policy)
    actual_sudoers = SUDOERS_CONFIG.read_text(encoding="utf-8") if SUDOERS_CONFIG.is_file() else ""
    sudo_problem = permission_problem(SUDOERS_CONFIG, 0o440) if expected_sudoers else None
    sudo_ok = actual_sudoers == expected_sudoers and not sudo_problem
    add("PASS" if sudo_ok else "FAIL", "scoped sudo policy", "matches installed policy" if sudo_ok else (sudo_problem or "content drift"))

    entrypoint_problems: list[str] = []
    for path, expected_link in (
        (PUBLIC_ENTRYPOINT, str(ROOT / "bin/awgctl")),
        (INTERNAL_ENTRYPOINT, "../bin/awgctl"),
    ):
        if not path.is_symlink() or os.readlink(path) != expected_link:
            entrypoint_problems.append(str(path))
            continue
        target = path.resolve()
        metadata = target.stat() if target.is_file() else None
        if metadata is None or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755:
            entrypoint_problems.append(str(path))
    add(
        "FAIL" if entrypoint_problems else "PASS",
        "manager entrypoints",
        ", ".join(entrypoint_problems) if entrypoint_problems else "public and internal boundaries installed",
    )

    expected_hardening = render_service_hardening(settings.systemd_hardening)
    actual_hardening = SERVICE_HARDENING.read_text(encoding="utf-8") if SERVICE_HARDENING.is_file() else ""
    add(
        "PASS" if actual_hardening == expected_hardening else "FAIL",
        "systemd hardening policy",
        "matches installed policy" if actual_hardening == expected_hardening else "content drift",
    )
    actual_module_load = MODULE_LOAD_CONFIG.read_text(encoding="utf-8") if MODULE_LOAD_CONFIG.is_file() else ""
    add(
        "PASS" if actual_module_load == render_module_load() else "FAIL",
        "module preload policy",
        "amneziawg" if actual_module_load == render_module_load() else "content drift",
    )
    return checks


def cmd_health(args: argparse.Namespace) -> int:
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
    checks.extend(management_security_checks())
    if docker_user_chain_exists():
        docker_markers = tagged_docker_handles()
        add("PASS" if len(docker_markers) == 3 else "FAIL", "Docker forwarding bridge", f"{len(docker_markers)} tagged rules")
    else:
        add("PASS", "Docker forwarding bridge", "Docker DOCKER-USER chain absent; integration not required")

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
        if generated == expected:
            add("PASS", "managed state", "generated config matches state")
        elif legacy_lifecycle_hook_drift(expected, generated):
            add("WARN", "managed state", "legacy lifecycle hooks will be reconciled by the next managed commit")
        else:
            add("FAIL", "managed state", "generated config drift")
        add("PASS" if runtime == generated else "FAIL", "runtime drift", "runtime config matches generated" if runtime == generated else "manual runtime drift detected")
    except (AwgctlError, OSError) as exc:
        add("FAIL", "configuration consistency", str(exc))

    try:
        clients = load_clients(include_secrets=True)
        duplicates = find_duplicate_client_state(clients)
        add("FAIL" if duplicates else "PASS", "client uniqueness", "; ".join(duplicates) if duplicates else f"{len(clients)} unique active clients")
        checks.append(client_expiry_health_check(clients))
        profile_drift: list[str] = []
        external_count = 0
        server_public = server_public_key()
        header_key = header_protection_key_for_config(config)
        for client in clients:
            if client.get("management", "managed") != "managed":
                external_count += 1
                continue
            expected_profile = render_client_config(
                config,
                client["private_key"],
                client.get("psk"),
                server_public,
                client["address"],
                header_protection_key=header_key,
            ).encode()
            actual_profile = (CLIENTS / client["name"] / f"{client['name']}.conf").read_bytes()
            if expected_profile != actual_profile:
                profile_drift.append(client["name"])
        detail = ", ".join(profile_drift) if profile_drift else "managed profiles match state"
        if external_count:
            detail += f"; {external_count} external peer(s) have no locally managed profile"
        add("FAIL" if profile_drift else "PASS", "client profile consistency", detail)
        pending_profiles = [
            client["name"]
            for client in clients
            if client.get("management", "managed") == "managed"
            and client_is_server_eligible(client)
            and client.get("distribution_status") in {"pending", "unknown"}
        ]
        add(
            "WARN" if pending_profiles else "PASS",
            "client profile delivery",
            f"pending or unknown: {', '.join(pending_profiles)}" if pending_profiles else "all active profile revisions marked distributed",
        )
    except (AwgctlError, OSError) as exc:
        add("FAIL", "client state", str(exc))

    addresses = endpoint_ipv4s(config["endpoint"])
    add("PASS" if addresses else "FAIL", "endpoint DNS", ", ".join(addresses) if addresses else "resolution failed")
    public_ip = imds_value("public-ipv4")
    if public_ip and addresses:
        add("PASS" if public_ip in addresses else "FAIL", "endpoint/public IPv4", f"endpoint={','.join(addresses)} public={public_ip}")
    else:
        add("WARN", "endpoint/public IPv4", "comparison unavailable")
    boundary = ingress_boundary_attestation()
    if boundary == "lightsail":
        add(
            "WARN",
            "Lightsail static IP",
            "No stable Lightsail public IP was verified. A stop/start can change the instance public IPv4 and break the VPN endpoint DNS record.",
        )
    elif boundary == "equivalent-external-firewall":
        add("PASS", "external ingress boundary", boundary)
    configured_dns_policy = dns_policy_name(config["dns"])
    add(
        "PASS" if configured_dns_policy != "custom" else "WARN",
        "client DNS policy",
        f"{configured_dns_policy}: {','.join(config['dns'])}",
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
    listeners = suspicious_wildcard_listeners(
        ss_output,
        vpn_port=config["listen_port"],
        vpn_addresses=(config["server_address"],),
    )
    if listeners:
        add("WARN", "host listeners reachable through awg0", "; ".join(listeners))
    else:
        add("PASS", "host listeners reachable through awg0", "none besides AmneziaWG")
    prometheus = [value for value in listeners if "prometheus" in value.lower() or "/9090" in value or "/9100" in value]
    add("WARN" if prometheus else "PASS", "Prometheus/node-exporter exposure", "; ".join(prometheus) if prometheus else "not detected")
    ufw = run(["ufw", "status"], check=False).stdout.decode("utf-8", "replace")
    add(
        "WARN" if "Status: active" in ufw else "PASS",
        "UFW",
        "active (unexpected)"
        if "Status: active" in ufw
        else f"inactive; attested ingress boundary: {boundary or 'missing'}",
    )

    failures = sum(1 for level, _, _ in checks if level == "FAIL")
    warnings = sum(1 for level, _, _ in checks if level == "WARN")
    if getattr(args, "json", False):
        print(json.dumps(health_envelope(checks), indent=2, sort_keys=True))
        return 3 if failures else 0
    print("AmneziaWG health")
    for level, name, detail in checks:
        print(f"  {level:<4} {name}: {detail}")
    print(f"Summary: {failures} failure(s), {warnings} warning(s)")
    return 3 if failures else 0


def verify_peer_state(interface: str, public_key: str, *, present: bool) -> None:
    peers = live_peers(interface)
    actual = public_key in peers
    if actual != present:
        expectation = "appear" if present else "disappear"
        raise AwgctlError(f"peer did not {expectation} in the running interface")


def clients_due_for_expiry(
    clients: Sequence[dict[str, Any]], *, now: dt.datetime | None = None
) -> list[dict[str, Any]]:
    return [
        client
        for client in clients
        if client.get("status", "active") == "active"
        and effective_client_status(client, now=now) == "expired"
    ]


def clients_requiring_expiry_reconciliation(
    clients: Sequence[dict[str, Any]], *, now: dt.datetime
) -> list[dict[str, Any]]:
    """Return every peer that must be absent, including terminal expiry records."""
    return [client for client in clients if effective_client_status(client, now=now) == "expired"]


def bind_expiry_records(
    selected: Sequence[dict[str, Any]], reloaded: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Bind secret-bearing records to the identities selected at transaction start."""
    by_name = {client["name"]: client for client in reloaded}
    bound: list[dict[str, Any]] = []
    identity_fields = ("name", "address", "public_key", "expires", "status")
    for original in selected:
        current = by_name.get(original["name"])
        if current is None or any(current.get(field) != original.get(field) for field in identity_fields):
            raise AwgctlError(
                f"client identity changed during expiry: {original['name']}"
            )
        bound.append(current)
    return bound


def client_expiry_health_check(clients: Sequence[dict[str, Any]]) -> tuple[str, str, str]:
    expired = [client["name"] for client in clients if effective_client_status(client) == "expired"]
    return (
        "PASS",
        "client expiry",
        "expired: " + ", ".join(expired) if expired else "no expired clients",
    )


def ensure_expiry_reconcilable(
    generated_text: str,
    config: dict[str, Any],
    clients: Sequence[dict[str, Any]],
    due: Sequence[dict[str, Any]],
    *,
    now: dt.datetime,
) -> None:
    """Allow either exact pre-expiry peers or the already-filtered retry state."""
    expected = semantic_signature(render_current_server(clients, now=now))
    actual = semantic_signature(generated_text)
    due_peers: list[tuple[tuple[str, str], ...]] = []
    for client in due:
        peer = {
            "PublicKey": client["public_key"],
            "AllowedIPs": str(ipaddress.ip_interface(client["address"])),
        }
        if config.get("use_psk", True):
            peer["PresharedKey"] = client["psk"]
        due_peers.append(tuple(sorted(peer.items())))
    pre_expiry_peers = sorted([*expected["peers"], *due_peers])
    if actual["interface"] != expected["interface"] or actual["peers"] not in (
        expected["peers"],
        pre_expiry_peers,
    ):
        raise AwgctlError("managed-state drift detected before client expiry")


def cmd_client_expire(args: argparse.Namespace) -> int:
    argv = [str(INTERNAL_ENTRYPOINT), "_expire-clients"]
    if getattr(args, "dry_run", False):
        argv.append("--dry-run")
    if getattr(args, "json", False):
        argv.append("--json")
    result = run(argv, timeout=90)
    sys.stdout.write(result.stdout.decode("utf-8", "replace"))
    return 0


def cmd_expire_clients(args: argparse.Namespace) -> int:
    if getattr(args, "dry_run", False):
        transaction_now = dt.datetime.now(dt.timezone.utc)
        clients = load_clients()
        due = clients_due_for_expiry(clients, now=transaction_now)
        data = {
            "dry_run": True,
            "due_clients": [client["name"] for client in due],
            "runtime_action": "reload" if due else "none",
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client expire", data=data), indent=2, sort_keys=True))
        else:
            print("Due clients: " + (", ".join(data["due_clients"]) or "none"))
            print("No state was changed.")
        return 0
    with mutation_lock():
        transaction_now = dt.datetime.now(dt.timezone.utc)
        clients = load_clients()
        selected = clients_requiring_expiry_reconciliation(clients, now=transaction_now)
        due = [client for client in selected if client.get("status", "active") == "active"]
        try:
            generated = GENERATED_CONFIG.read_bytes()
            runtime = RUNTIME_CONFIG.read_bytes()
        except OSError as exc:
            raise AwgctlError("cannot read generated/runtime server configuration") from exc
        if runtime != generated:
            raise AwgctlError("manual runtime drift detected before client expiry")
        config = load_config()
        if not selected:
            data = {"expired_clients": [], "runtime_action": "none", "changed": False}
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client expire", data=data), indent=2, sort_keys=True))
            else:
                print("No clients are due for expiry.")
            return 0
        clients = load_clients(include_secrets=True)
        selected = bind_expiry_records(selected, clients)
        due = [client for client in selected if client.get("status", "active") == "active"]
        ensure_expiry_reconcilable(
            generated.decode("utf-8"), config, clients, selected, now=transaction_now
        )
        backup = create_backup() if due else None
        metadata_snapshots = {
            CLIENTS / client["name"] / "metadata.json":
            (CLIENTS / client["name"] / "metadata.json").read_bytes()
            for client in due
        }
        timestamp = transaction_now.isoformat()
        committed = False
        try:
            for client in due:
                metadata_path = CLIENTS / client["name"] / "metadata.json"
                metadata = json.loads(metadata_snapshots[metadata_path])
                metadata.update(status="expired", expired_at=timestamp, updated_at=timestamp)
                atomic_json(metadata_path, metadata, 0o600)
                client.update(status="expired", expired_at=timestamp, updated_at=timestamp)
            new_server = render_current_server(clients, now=transaction_now)
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                stopped_for_postcondition = False
                try:
                    live = live_peers(config["interface"])
                    remaining = [
                        client["name"]
                        for client in selected
                        if client["public_key"] in live
                    ]
                    if remaining:
                        active = commit_server_config(new_server, runtime_action="reload")
                        if active:
                            live = live_peers(config["interface"])
                            remaining = [
                                client["name"]
                                for client in selected
                                if client["public_key"] in live
                            ]
                    if active and remaining:
                        stopped_for_postcondition = True
                        service_action("stop", config["interface"])
                        raise AwgctlError(
                            "expired peers remain in the running interface: "
                            + ", ".join(remaining)
                        )
                except Exception:
                    if not stopped_for_postcondition:
                        service_action("stop", config["interface"])
                    raise
        except Exception:
            if not committed:
                for path, content in metadata_snapshots.items():
                    atomic_write(path, content, 0o600)
            audit("client expiry failed")
            raise
        names = [client["name"] for client in due]
        audit("clients expired: " + ",".join(names))
        data = {
            "expired_clients": names,
            "runtime_action": "reload" if active else "none-service-stopped",
            "changed": bool(due),
        }
        if backup is not None:
            data["backup"] = str(backup)
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client expire", data=data), indent=2, sort_keys=True))
        else:
            print("Expired clients: " + ", ".join(names))
            if backup is not None:
                print(f"Pre-change backup: {backup}")
            print(
                "Expired peers removed from the running server."
                if active else "Expired peers removed from managed configuration; service is stopped."
            )
        return 0


def cmd_client_list(args: argparse.Namespace) -> int:
    config = load_config()
    clients = load_clients()
    handshakes: dict[str, int] = {}
    if is_service_active(config["interface"]):
        with contextlib.suppress(AwgctlError):
            handshakes = handshake_map(config["interface"])
    rows = []
    for client in clients:
        rows.append(
            {
                "name": client["name"],
                "address": str(ipaddress.ip_interface(client["address"]).ip),
                "status": effective_client_status(client),
                "management": client.get("management", "managed"),
                "owner": client.get("owner"),
                "device": client.get("device"),
                "expires": client.get("expires"),
                "profile_revision": client.get("profile_revision"),
                "distribution_status": client.get("distribution_status", "unknown"),
                "last_handshake": format_age(handshakes.get(client["public_key"], 0)),
            }
        )
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("client list", data={"clients": rows}), indent=2, sort_keys=True))
        return 0
    print(f"{'NAME':<22} {'ADDRESS':<15} {'STATUS':<9} {'LAST HANDSHAKE'}")
    for client in rows:
        print(
            f"{client['name']:<22} {client['address']:<15} {client['status']:<9} {client['last_handshake']}"
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
    data = {
        "name": name,
        "status": effective_client_status(client),
        "management": client.get("management", "managed"),
        "address": client["address"],
        "public_key_fingerprint": client["public_key_fingerprint"],
        "created_at": client["created_at"],
        "owner": client.get("owner"),
        "device": client.get("device"),
        "expires": client.get("expires"),
        "profile_revision": client.get("profile_revision"),
        "profile_generated_at": client.get("profile_generated_at"),
        "profile_change_reason": client.get("profile_change_reason"),
        "distribution_status": client.get("distribution_status", "unknown"),
        "distributed_at": client.get("distributed_at"),
        "last_handshake": format_age(handshake),
        "config": str(CLIENTS / name / (name + ".conf")) if client.get("management", "managed") == "managed" else None,
        "qr": str(CLIENTS / name / (name + ".png")) if client.get("management", "managed") == "managed" else None,
    }
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("client show", data=data), indent=2, sort_keys=True))
        return 0
    print(f"Client: {name}")
    print(f"  status:                 {data['status']}")
    print(f"  address:                {client['address']}")
    print(f"  public key fingerprint: {client['public_key_fingerprint']}")
    print(f"  created:                {client['created_at']}")
    print(f"  last handshake:         {format_age(handshake)}")
    print(f"  profile revision:       {client.get('profile_revision', 'unknown')}")
    print(f"  distribution:           {client.get('distribution_status', 'unknown')}")
    if client.get("management", "managed") == "managed":
        print(f"  config:                 {CLIENTS / name / (name + '.conf')}")
        print(f"  QR:                     {CLIENTS / name / (name + '.png')}")
    else:
        print("  config:                 external (import profile to manage locally)")
        print("  QR:                     unavailable")
    return 0


def cmd_client_add(args: argparse.Namespace) -> int:
    if args.client_name is None and getattr(args, "json", False):
        raise AwgctlError("client add --json requires NAME")
    if args.client_name is None and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise AwgctlError("client add without NAME requires an interactive terminal")
    if args.client_name is None:
        values = collect_client_add_wizard(
            sys.stdin,
            sys.stdout,
            dry_run=getattr(args, "dry_run", False),
        )
        if values is None:
            return 0
        for field, value in values.items():
            setattr(args, field, value)
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
        try:
            proposed_at = iso_now()
            proposed_metadata = normalize_client_metadata(
                {
                    "schema_version": 3,
                    "management": "managed",
                    "owner": getattr(args, "owner", None),
                    "device": getattr(args, "device", None),
                    "expires": getattr(args, "expires", None),
                    "profile_revision": 1,
                    "profile_generated_at": proposed_at,
                    "profile_change_reason": "created",
                    "distribution_status": "pending",
                    "distributed_at": None,
                }
            )
        except ContractError as exc:
            raise AwgctlError(str(exc)) from exc
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "name": name,
                "address": str(address.ip),
                "owner": proposed_metadata["owner"],
                "device": proposed_metadata["device"],
                "expires": proposed_metadata["expires"],
                "runtime_action": "reload",
                "backup": "created at execution",
                "files": [
                    str(CLIENT_KEYS / name),
                    str(CLIENTS / name),
                    str(GENERATED_CONFIG),
                    str(RUNTIME_CONFIG),
                ],
                "rollback": "remove the staged client and restore the pre-change server configuration",
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client add", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: create client {name}")
                print(f"  address: {address.ip}")
                print("  runtime action: reload")
                print("  credentials: generated only during execution")
                print("No state was changed.")
            return 0
        backup = create_backup()
        private, public, psk = generate_key_material(config["use_psk"])
        committed = False
        try:
            write_client_state(
                config,
                name,
                str(address),
                private,
                public,
                psk,
                owner=getattr(args, "owner", None),
                device=getattr(args, "device", None),
                expires=getattr(args, "expires", None),
            )
            new_clients = load_clients(include_secrets=True)
            new_server = render_server_config(
                config,
                server_private_key(),
                new_clients,
                header_protection_key=header_protection_key_for_config(config),
            )
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                verify_peer_state(config["interface"], public, present=True)
        except Exception:
            if committed:
                rollback_text = render_server_config(
                    config,
                    server_private_key(),
                    old_clients,
                    header_protection_key=header_protection_key_for_config(config),
                )
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            remove_client_state(name)
            audit(f"client creation failed: {name}")
            raise
        audit(f"client created: {name} address={address.ip}")
        data = {
            "name": name,
            "address": str(address.ip),
            "config": str(CLIENTS / name / (name + ".conf")),
            "qr": str(CLIENTS / name / (name + ".png")),
            "backup": str(backup),
            "runtime_action": "reload" if active else "none-service-stopped",
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client add", data=data), indent=2, sort_keys=True))
        else:
            print(f"Created client: {name}")
            print(f"Address: {address.ip}")
            print(f"Config: {data['config']}")
            print(f"QR: {data['qr']}")
            print(f"Pre-change backup: {backup}")
            print("Server configuration reloaded successfully." if active else "Server configuration installed; service is stopped.")
            print("Next steps:")
            print(f"  sudo awgctl client export {name} --output /home/OPERATOR/{name}.conf")
            print(f"  sudo awgctl client qr {name} --output /home/OPERATOR/{name}.png")
            print(
                "Replace OPERATOR with the invoking operator's home directory "
                "and use one delivery format."
            )
    return 0


def _server_peer_for_public(public_key: str) -> dict[str, str]:
    try:
        text = GENERATED_CONFIG.read_text(encoding="utf-8")
    except OSError as exc:
        raise AwgctlError("cannot read generated server configuration") from exc
    matches = [
        peer for peer in parse_awg_config(text).get("Peer", [])
        if peer.get("PublicKey") == public_key
    ]
    if len(matches) != 1:
        raise AwgctlError("client profile does not match exactly one server peer")
    return matches[0]


def read_client_profile(path: pathlib.Path, *, maximum: int = 64 * 1024) -> str:
    """Read one private regular file through the descriptor that was validated."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AwgctlError(f"cannot read client profile: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AwgctlError("client profile must be a regular non-linked file")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AwgctlError("client profile must not be accessible by group or other users")
        if metadata.st_size > maximum:
            raise AwgctlError("client profile is unexpectedly large")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(16 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise AwgctlError("client profile is unexpectedly large")
        data = b"".join(chunks)
    except OSError as exc:
        raise AwgctlError(f"cannot read client profile: {path}") from exc
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AwgctlError("client profile is not valid UTF-8") from exc


def cmd_client_import(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    profile_path = args.profile.expanduser()
    profile_text = read_client_profile(profile_path)
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
        imported = parse_import_profile(
            profile_text,
            config,
            expected_server_public=server_public_key(),
            header_protection_key=header_protection_key_for_config(config),
        )
        peer = _server_peer_for_public(imported["public_key"])
        if peer.get("AllowedIPs") != imported["address"]:
            raise AwgctlError("client profile address differs from the matching server peer")
        if peer.get("PresharedKey") != imported["psk"]:
            raise AwgctlError("client profile PSK differs from the matching server peer")
        clients = load_clients(include_secrets=True)
        same_name = next((client for client in clients if client["name"] == name), None)
        same_public = next((client for client in clients if client["public_key"] == imported["public_key"]), None)
        if same_name and same_name.get("management", "managed") == "managed":
            raise AwgctlError(f"client is already managed: {name}")
        if same_name and same_name["public_key"] != imported["public_key"]:
            raise AwgctlError(f"external peer identity differs from imported profile: {name}")
        if same_public and same_public["name"] != name:
            raise AwgctlError(f"matching external peer is named {same_public['name']}; import using that name")
        try:
            proposed_at = iso_now()
            proposed = normalize_client_metadata(
                {
                    "schema_version": 3,
                    "management": "managed",
                    "owner": getattr(args, "owner", None) if not same_name else same_name.get("owner"),
                    "device": getattr(args, "device", None) if not same_name else same_name.get("device"),
                    "expires": getattr(args, "expires", None) if not same_name else same_name.get("expires"),
                    "profile_revision": same_name.get("profile_revision", 1) if same_name else 1,
                    "profile_generated_at": (
                        same_name.get("profile_generated_at", proposed_at) if same_name else proposed_at
                    ),
                    "profile_change_reason": (
                        same_name.get("profile_change_reason", "imported") if same_name else "imported"
                    ),
                    "distribution_status": (
                        same_name.get("distribution_status", "pending") if same_name else "pending"
                    ),
                    "distributed_at": same_name.get("distributed_at") if same_name else None,
                }
            )
        except ContractError as exc:
            raise AwgctlError(str(exc)) from exc
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "name": name,
                "address": str(ipaddress.ip_interface(imported["address"]).ip),
                "public_key_fingerprint": fingerprint(imported["public_key"]),
                "converts_external_peer": bool(same_name),
                "runtime_action": "none",
                "backup": "created at execution",
                "profile": str(profile_path),
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client import", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: import existing client profile as {name}")
                print(f"  address: {data['address']}")
                print("  matching server peer: verified")
                print("  runtime action: none")
                print("No state was changed.")
            return 0
        backup = create_backup()
        with tempfile.TemporaryDirectory(prefix="awgctl-import-") as temporary_text:
            temporary = pathlib.Path(temporary_text)
            if same_name:
                shutil.copytree(CLIENTS / name, temporary / "client")
                shutil.copytree(CLIENT_KEYS / name, temporary / "keys")
                remove_client_state(name)
            try:
                write_client_state(
                    config,
                    name,
                    imported["address"],
                    imported["private_key"],
                    imported["public_key"],
                    imported["psk"],
                    created_at=same_name.get("created_at") if same_name else None,
                    imported_from=str(profile_path),
                    profile_text=imported["profile"],
                    owner=proposed["owner"],
                    device=proposed["device"],
                    expires=proposed["expires"],
                )
                if semantic_signature(render_current_server()) != semantic_signature(GENERATED_CONFIG.read_text()):
                    raise AwgctlError("imported client does not reproduce the existing server peer semantics")
            except Exception:
                remove_client_state(name)
                if same_name:
                    shutil.copytree(temporary / "client", CLIENTS / name)
                    shutil.copytree(temporary / "keys", CLIENT_KEYS / name)
                    chmod_secret_tree(CLIENTS / name)
                    chmod_secret_tree(CLIENT_KEYS / name)
                audit(f"client import failed: {name}")
                raise
        audit(f"client imported: {name}")
        data = {
            "name": name,
            "address": str(ipaddress.ip_interface(imported["address"]).ip),
            "config": str(CLIENTS / name / f"{name}.conf"),
            "qr": str(CLIENTS / name / f"{name}.png"),
            "backup": str(backup),
            "runtime_action": "none",
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client import", data=data), indent=2, sort_keys=True))
        else:
            print(f"Imported client: {name}")
            print(f"Address: {data['address']}")
            print(f"Config: {data['config']}")
            print(f"QR: {data['qr']}")
            print(f"Pre-change backup: {backup}")
            print("Matching server peer was preserved; no reload was required.")
    return 0


def cmd_client_edit(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    supplied = {field for field in ("owner", "device", "expires") if hasattr(args, field)}
    mark_distributed = bool(getattr(args, "mark_distributed", False))
    if mark_distributed:
        supplied.update({"distribution_status", "distributed_at"})
    if not supplied:
        raise AwgctlError("client edit requires --owner, --device, --expires, or --mark-distributed")
    with mutation_lock():
        ensure_no_drift()
        clients = {client["name"]: client for client in load_clients()}
        if name not in clients:
            raise AwgctlError(f"unknown active client: {name}")
        old = clients[name]
        proposed = dict(old)
        for field in supplied - {"distribution_status", "distributed_at"}:
            value = getattr(args, field)
            if field == "expires" and isinstance(value, str) and value.lower() == "none":
                value = None
            proposed[field] = value
        if mark_distributed:
            distributed_at = iso_now()
            proposed["distribution_status"] = "distributed"
            proposed["distributed_at"] = distributed_at
        try:
            proposed = normalize_client_metadata(proposed)
        except ContractError as exc:
            raise AwgctlError(str(exc)) from exc
        changes = {
            field: {"old": old.get(field), "new": proposed.get(field)}
            for field in sorted(supplied)
            if old.get(field) != proposed.get(field)
        }
        data = {"dry_run": bool(getattr(args, "dry_run", False)), "name": name, "changes": changes}
        if getattr(args, "dry_run", False):
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client edit", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: edit client metadata for {name}")
                for field, change in changes.items():
                    print(f"  {field}: {change['old']!r} -> {change['new']!r}")
                print("No state was changed.")
            return 0
        if not changes:
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client edit", data=data), indent=2, sort_keys=True))
            else:
                print(f"No change: client metadata for {name} already matches")
            return 0
        backup = create_backup()
        proposed["updated_at"] = iso_now()
        atomic_json(CLIENTS / name / "metadata.json", proposed, 0o600)
        audit(f"client metadata changed: {name} fields={','.join(sorted(changes))}")
        data.update({"backup": str(backup), "dry_run": False})
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client edit", data=data), indent=2, sort_keys=True))
        else:
            print(f"Updated client metadata: {name}")
            print(f"Pre-change backup: {backup}")
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
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "name": name,
                "address": str(ipaddress.ip_interface(target["address"]).ip),
                "management": target.get("management", "managed"),
                "runtime_action": "reload",
                "archive": "created at execution",
                "backup": "created at execution",
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client revoke", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: revoke client {name}")
                print("  runtime action: reload")
                print("  credentials: archive retained; nothing permanently deleted")
                print("No state was changed.")
            return 0
        backup = create_backup()
        archive = archive_client_copy(name)
        remaining = [client for client in old_clients if client["name"] != name]
        committed = False
        try:
            new_server = render_server_config(
                config,
                server_private_key(),
                remaining,
                header_protection_key=header_protection_key_for_config(config),
            )
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                verify_peer_state(config["interface"], target["public_key"], present=False)
        except Exception:
            if committed:
                rollback_text = render_server_config(
                    config,
                    server_private_key(),
                    old_clients,
                    header_protection_key=header_protection_key_for_config(config),
                )
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            shutil.rmtree(archive, ignore_errors=True)
            audit(f"client revocation failed: {name}")
            raise
        remove_client_state(name)
        audit(f"client revoked: {name}")
        data = {
            "name": name,
            "archive": str(archive),
            "backup": str(backup),
            "runtime_action": "reload" if active else "none-service-stopped",
            "peer_removed": True,
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client revoke", data=data), indent=2, sort_keys=True))
        else:
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
        if target.get("management", "managed") != "managed":
            raise AwgctlError("external client cannot be rotated; import its profile first")
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "name": name,
                "address": str(ipaddress.ip_interface(target["address"]).ip),
                "runtime_action": "reload",
                "old_credentials": "archived at execution",
                "new_credentials": "generated only at execution",
                "backup": "created at execution",
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client rotate", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: rotate client {name}")
                print("  runtime action: reload")
                print("  prior credentials: archived, not deleted")
                print("No state was changed.")
            return 0
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
                owner=target.get("owner"),
                device=target.get("device"),
                expires=target.get("expires"),
            )
            metadata_path = CLIENTS / name / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            rotation_timestamp = iso_now()
            metadata = mark_profile_rotated(
                target,
                metadata,
                timestamp=rotation_timestamp,
            )
            metadata["rotated_at"] = rotation_timestamp
            metadata["previous_public_key_fingerprint"] = target["public_key_fingerprint"]
            atomic_json(metadata_path, metadata, 0o600)
            new_clients = load_clients(include_secrets=True)
            new_server = render_server_config(
                config,
                server_private_key(),
                new_clients,
                header_protection_key=header_protection_key_for_config(config),
            )
            active = commit_server_config(new_server, runtime_action="reload")
            committed = True
            if active:
                peers = live_peers(config["interface"])
                if public not in peers or target["public_key"] in peers:
                    raise AwgctlError("rotated peer state did not verify in the running interface")
        except Exception:
            if committed:
                rollback_text = render_server_config(
                    config,
                    server_private_key(),
                    old_clients,
                    header_protection_key=header_protection_key_for_config(config),
                )
                with contextlib.suppress(Exception):
                    commit_server_config(rollback_text, runtime_action="reload")
            restore_client_from_archive(name, archive)
            shutil.rmtree(archive, ignore_errors=True)
            audit(f"client rotation failed: {name}")
            raise
        audit(f"client rotated: {name}")
        data = {
            "name": name,
            "address": str(ipaddress.ip_interface(target["address"]).ip),
            "config": str(CLIENTS / name / (name + ".conf")),
            "qr": str(CLIENTS / name / (name + ".png")),
            "archive": str(archive),
            "backup": str(backup),
            "runtime_action": "reload" if active else "none-service-stopped",
            "old_profile_revoked": active,
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client rotate", data=data), indent=2, sort_keys=True))
        else:
            print(f"Rotated client: {name}")
            print(f"Address: {data['address']}")
            print(f"Config: {data['config']}")
            print(f"QR: {data['qr']}")
            print(f"Prior credentials archived: {archive}")
            print(f"Pre-change backup: {backup}")
            print("Old profile is no longer accepted by the server." if active else "Rotation is staged; service is stopped.")
    return 0


def cmd_client_export(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    profile = CLIENTS / name / f"{name}.conf"
    if not profile.is_file():
        clients = {client["name"]: client for client in load_clients()}
        if name in clients and clients[name].get("management", "managed") == "external":
            raise AwgctlError("external client has no local profile; use client import first")
        raise AwgctlError(f"unknown active client: {name}")
    if args.stdout:
        if getattr(args, "json", False):
            raise AwgctlError("--stdout cannot be combined with --json because the profile is secret data")
        print("WARNING: the following profile contains credentials; protect terminal scrollback and logs.", file=sys.stderr)
        sys.stdout.write(profile.read_text(encoding="utf-8"))
        return 0
    if args.output is None:
        data = {"name": name, "profile": str(profile), "copied": False}
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client export", data=data), indent=2, sort_keys=True))
        else:
            print(f"Protected profile: {profile}")
            print("Use --output PATH to copy it, or explicit --stdout only when secret output is intended.")
        return 0
    output = write_operator_secret(args.output, profile.read_bytes())
    audit(f"client profile exported: {name}")
    data = {"name": name, "profile": str(output), "copied": True, "mode": "0600"}
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("client export", data=data), indent=2, sort_keys=True))
    else:
        print(f"Exported client profile: {output}")
        print("The file contains credentials and is mode 0600.")
    return 0


def write_operator_secret(output: pathlib.Path, data: bytes) -> pathlib.Path:
    """Atomically create a 0600 delivery copy owned by the sudo invoker."""
    requested = output.expanduser()
    if not requested.is_absolute() or requested.name in {"", ".", ".."}:
        raise AwgctlError("secret output path must be an absolute file path")
    try:
        parent = requested.parent.resolve(strict=True)
        parent_metadata = parent.stat()
    except OSError as exc:
        raise AwgctlError(f"output directory does not exist: {requested.parent}") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise AwgctlError("secret output parent must be a directory")
    invoker = os.environ.get("SUDO_USER")
    try:
        recipient = pwd.getpwnam(invoker) if invoker else pwd.getpwuid(os.geteuid())
    except KeyError as exc:
        raise AwgctlError("could not resolve the output file owner") from exc
    if parent_metadata.st_uid != recipient.pw_uid:
        raise AwgctlError("secret output directory must be owned by the invoking operator")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        raise AwgctlError("secret output directory must not be group/world writable")

    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary_name = f".{requested.name}.{secrets.token_hex(8)}"
    descriptor = -1
    try:
        try:
            os.stat(requested.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AwgctlError(f"refusing to overwrite existing output: {parent / requested.name}")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, recipient.pw_uid, recipient.pw_gid)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        current_parent = os.fstat(directory_fd)
        if (
            current_parent.st_uid != recipient.pw_uid
            or stat.S_IMODE(current_parent.st_mode) & 0o022
        ):
            raise AwgctlError("secret output directory changed during export")
        os.replace(
            temporary_name,
            requested.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary_name, dir_fd=directory_fd)
        os.close(directory_fd)
    return parent / requested.name


def cmd_client_qr(args: argparse.Namespace) -> int:
    name = validate_client_name(args.client_name)
    profile_path = CLIENTS / name / f"{name}.conf"
    if not profile_path.is_file():
        clients = {client["name"]: client for client in load_clients()}
        if name in clients and clients[name].get("management", "managed") == "external":
            raise AwgctlError("external client has no local profile; use client import first")
        raise AwgctlError(f"unknown active client: {name}")
    with mutation_lock():
        protected_output = CLIENTS / name / f"{name}.png"
        requested_output = getattr(args, "output", None)
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "name": name,
                "output": str(requested_output or protected_output),
                "protected_qr": str(protected_output),
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("client qr", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: regenerate protected QR image at {output}")
                print("No state was changed.")
            return 0
        generate_qr(profile_path.read_text(encoding="utf-8"), protected_output)
        output = (
            write_operator_secret(requested_output, protected_output.read_bytes())
            if requested_output is not None
            else protected_output
        )
        audit(f"client QR regenerated: {name}")
        data = {"name": name, "qr": str(output), "displayed": False}
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("client qr", data=data), indent=2, sort_keys=True))
        else:
            print(f"Protected QR image: {output}")
            print("The QR was not displayed in terminal output.")
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    config = public_server_config(load_config())
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("config show", data=config), indent=2, sort_keys=True))
    else:
        print(json.dumps(config, indent=2, sort_keys=True))
    return 0


def snapshot_client_artifacts(clients: Sequence[dict[str, Any]]) -> dict[pathlib.Path, bytes]:
    snapshot: dict[pathlib.Path, bytes] = {}
    for client in clients:
        if client.get("management", "managed") != "managed":
            continue
        directory = CLIENTS / client["name"]
        for path in (
            directory / f"{client['name']}.conf",
            directory / f"{client['name']}.png",
            directory / "metadata.json",
        ):
            snapshot[path] = path.read_bytes()
    return snapshot


def restore_artifacts(snapshot: dict[pathlib.Path, bytes]) -> None:
    for path, data in snapshot.items():
        atomic_write(path, data, 0o600)


def cmd_config_set(args: argparse.Namespace) -> int:
    with mutation_lock():
        ensure_no_drift()
        config = load_config()
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
            new_config["dns"] = parse_dns_value(args.value)
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
            data = {"key": args.key, "old": old_display, "new": new_display, "changed": False}
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("config set", data=data), indent=2, sort_keys=True))
            else:
                print(f"No change: {args.key} is already {new_display}")
            return 0
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "key": args.key,
                "old": old_display,
                "new": new_display,
                "runtime_action": runtime_action or "none",
                "profiles": "managed client profiles would be regenerated",
                "backup": "created at execution",
            }
            if args.key == "listen-port":
                data["ingress_firewall_update_required"] = True
                data["ingress_boundary"] = ingress_boundary_attestation()
                data["old_ingress_rule"] = f"Custom / UDP / {old_display} / 0.0.0.0/0"
                data["new_ingress_rule"] = f"Custom / UDP / {new_display} / 0.0.0.0/0"
            if getattr(args, "json", False):
                print(json.dumps(json_envelope("config set", data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: set {args.key}: {old_display} -> {new_display}")
                print(f"  runtime action: {runtime_action or 'none'}")
                if args.key == "listen-port":
                    print(
                        "INGRESS FIREWALL UPDATE REQUIRED "
                        f"({data['ingress_boundary'] or 'boundary attestation missing'})"
                    )
                print("No state was changed.")
            return 0
        old_config_bytes = CONFIG_FILE.read_bytes()
        old_nft = GENERATED_NFT.read_bytes()
        clients = load_clients(include_secrets=True)
        artifacts = snapshot_client_artifacts(clients)
        backup = create_backup()
        server_public = server_public_key()
        header_key = header_protection_key_for_config(new_config)
        new_profiles = {
            client["name"]: render_client_config(
                new_config,
                client["private_key"],
                client.get("psk"),
                server_public,
                client["address"],
                header_protection_key=header_key,
            )
            for client in clients
            if client.get("management", "managed") == "managed"
        }
        profile_timestamp = iso_now()
        new_metadata = {
            client["name"]: mark_profile_regenerated(
                client,
                reason=f"config:{args.key}",
                timestamp=profile_timestamp,
            )
            for client in clients
            if client.get("management", "managed") == "managed"
        }
        new_server = render_server_config(
            new_config,
            server_private_key(),
            clients,
            header_protection_key=header_key,
        )
        new_nft = render_nftables_config(new_config)
        validate_nftables_text(new_nft)
        try:
            atomic_json(CONFIG_FILE, new_config, 0o600)
            for client in clients:
                if client.get("management", "managed") != "managed":
                    continue
                directory = CLIENTS / client["name"]
                profile = new_profiles[client["name"]]
                atomic_write(directory / f"{client['name']}.conf", profile, 0o600)
                generate_qr(profile, directory / f"{client['name']}.png")
                atomic_json(directory / "metadata.json", new_metadata[client["name"]], 0o600)
            atomic_write(GENERATED_NFT, new_nft, 0o600)
            active = commit_server_config(new_server, runtime_action=runtime_action)
        except Exception:
            atomic_write(CONFIG_FILE, old_config_bytes, 0o600)
            atomic_write(GENERATED_NFT, old_nft, 0o600)
            restore_artifacts(artifacts)
            audit(f"configuration change failed: {args.key}")
            raise
        audit(f"configuration changed: {args.key} {old_display} -> {new_display}")
        data = {
            "key": args.key,
            "old": old_display,
            "new": new_display,
            "changed": True,
            "backup": str(backup),
            "runtime_action": runtime_action if runtime_action and active else "none",
            "service_stopped": bool(runtime_action and not active),
        }
        if args.key == "listen-port":
            data.update(
                ingress_firewall_update_required=True,
                ingress_boundary=ingress_boundary_attestation(),
                old_ingress_rule=f"Custom / UDP / {old_display} / 0.0.0.0/0",
                new_ingress_rule=f"Custom / UDP / {new_display} / 0.0.0.0/0",
            )
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("config set", data=data), indent=2, sort_keys=True))
        else:
            print(f"Updated {args.key}: {old_display} -> {new_display}")
            print(f"Pre-change backup: {backup}")
            if runtime_action and active:
                print(f"Interface {runtime_action} completed and verified.")
            elif runtime_action:
                print("Configuration updated; interface is stopped, so no restart was attempted.")
            else:
                print("Client profiles updated; no tunnel restart was required.")
            if args.key == "listen-port":
                print(
                    "INGRESS FIREWALL UPDATE REQUIRED "
                    f"({data['ingress_boundary'] or 'boundary attestation missing'})"
                )
                print(f"  old: {data['old_ingress_rule']}")
                print(f"  new: {data['new_ingress_rule']}")
    return 0


def cmd_service(args: argparse.Namespace) -> int:
    config = load_config()
    with mutation_lock():
        if args.command in {"start", "restart", "reload"}:
            ensure_no_drift()
        if getattr(args, "dry_run", False):
            data = {
                "dry_run": True,
                "action": args.command,
                "service": SERVICE_TEMPLATE.format(interface=config["interface"]),
            }
            if getattr(args, "json", False):
                print(json.dumps(json_envelope(args.command, data=data), indent=2, sort_keys=True))
            else:
                print(f"Dry run: systemctl {args.command} {data['service']}")
                print("No state was changed.")
            return 0
        service_action(args.command, config["interface"])
        audit(f"service {args.command}: {config['interface']}")
        data = {
            "action": args.command,
            "service": SERVICE_TEMPLATE.format(interface=config["interface"]),
            "successful": True,
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope(args.command, data=data), indent=2, sort_keys=True))
        else:
            print(f"{data['service']}: {args.command} successful")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    operation = args.backup_command
    if operation == "list":
        if args.backup is not None:
            raise AwgctlError("backup list does not accept a backup name")
        entries: list[dict[str, Any]] = []
        if BACKUPS.is_dir():
            for path in sorted(BACKUPS.iterdir(), reverse=True):
                if not path.is_dir() or path.is_symlink():
                    continue
                entry: dict[str, Any] = {"name": path.name, "verified": False, "legacy": True}
                if (path / "manifest.json").is_file():
                    entry["legacy"] = False
                    try:
                        report = verify_backup(path)
                    except BackupError as exc:
                        entry["error"] = str(exc)
                    else:
                        entry.update(
                            verified=True,
                            created_at=report["created_at"],
                            product_version=report["product_version"],
                            file_count=report["file_count"],
                        )
                entries.append(entry)
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("backup list", data={"backups": entries}), indent=2, sort_keys=True))
        elif not entries:
            print("No managed backups found.")
        else:
            for entry in entries:
                state = "verified" if entry["verified"] else ("legacy/unverified" if entry["legacy"] else "INVALID")
                version = f"  {entry.get('product_version')}" if entry.get("product_version") else ""
                print(f"{entry['name']}  {state}{version}")
        return 0
    if operation == "verify":
        if args.backup is None:
            raise AwgctlError("backup verify requires a backup name")
        path, report = verify_managed_backup(args.backup)
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("backup verify", data=report), indent=2, sort_keys=True))
        else:
            print(f"Verified backup: {path}")
            print(f"Files: {report['file_count']}")
            print(f"Created: {report['created_at']}")
            print(f"Product version: {report['product_version']}")
        return 0
    if args.backup is not None:
        raise AwgctlError("use 'awgctl backup verify NAME' to verify a backup")
    if args.dry_run:
        data = {"dry_run": True, "would_create": str(BACKUPS / utc_timestamp())}
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("backup", data=data), indent=2, sort_keys=True))
        else:
            print("Backup dry run: managed configuration, keys, clients, revoked clients, and generated state would be copied.")
            print("A SHA-256 manifest would be created and verified before success is reported.")
        return 0
    with mutation_lock():
        path = create_backup()
    data = {"path": str(path), "verified": True}
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("backup", data=data), indent=2, sort_keys=True))
    else:
        print(f"Created and verified protected backup: {path}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    backup, report = verify_managed_backup(args.backup)
    if args.dry_run:
        data = {
            "dry_run": True,
            "backup": str(backup),
            "verified_files": report["file_count"],
            "components": list(RESTORE_COMPONENTS),
            "runtime_action": "restart-if-running",
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("restore", data=data), indent=2, sort_keys=True))
        else:
            print(f"Restore dry run: verified {backup.name} ({report['file_count']} files).")
            print("Would create a pre-restore backup, atomically replace managed state, and restart awg0 only if running.")
        return 0
    with mutation_lock():
        safety_backup, was_active = restore_backup_transaction(backup)
    audit(f"backup restored: {backup.name}; safety backup: {safety_backup.name}")
    data = {
        "backup": str(backup),
        "pre_restore_backup": str(safety_backup),
        "interface_restarted": was_active,
    }
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("restore", data=data), indent=2, sort_keys=True))
    else:
        print(f"Restored verified backup: {backup}")
        print(f"Pre-restore rollback point: {safety_backup}")
        print("Running interface restarted and verified." if was_active else "Interface was stopped; it was not started.")
    return 0


def redact_diagnostic_text(text: str) -> str:
    text = redact_awg_config(text)
    return re.sub(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])",
        lambda match: f"[redacted-key sha256:{sha256_bytes(match.group(0).encode())[:16]}]",
        text,
    )


def diagnostic_command(argv: Sequence[str]) -> bytes:
    result = run(argv, check=False, timeout=30)
    combined = result.stdout.decode("utf-8", "replace")
    if result.stderr:
        combined += "\n[stderr]\n" + result.stderr.decode("utf-8", "replace")
    combined += f"\n[exit_status={result.returncode}]\n"
    return redact_diagnostic_text(combined).encode("utf-8")


def cmd_diagnose(args: argparse.Namespace) -> int:
    config = load_config()
    parent = args.output.expanduser().absolute() if args.output else DIAGNOSTICS
    if args.dry_run:
        data = {
            "dry_run": True,
            "output_parent": str(parent),
            "contents": [
                "redacted manager configuration and client metadata",
                "redacted generated/runtime configuration",
                "systemd, network, nftables, DKMS, disk, memory, listeners, and recent service journal",
            ],
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("diagnose", data=data), indent=2, sort_keys=True))
        else:
            print(f"Diagnostics dry run: would create a protected redacted bundle under {parent}")
            print("No state was changed.")
        return 0
    with mutation_lock():
        ensure_layout()
        client_rows = []
        for client in load_clients():
            client_rows.append(
                {
                    key: value
                    for key, value in client.items()
                    if key not in {"public_key", "private_key", "psk"}
                }
            )
        safe_config = public_server_config(config)
        files: dict[str, bytes] = {
            "manager/server.json": (json.dumps(safe_config, indent=2, sort_keys=True) + "\n").encode(),
            "manager/clients.json": (json.dumps(client_rows, indent=2, sort_keys=True) + "\n").encode(),
            "system/uname.txt": diagnostic_command(["uname", "-a"]),
            "system/systemd.txt": diagnostic_command(
                ["systemctl", "show", SERVICE_TEMPLATE.format(interface=config["interface"]), "--no-pager"]
            ),
            "system/ip-link.txt": diagnostic_command(["ip", "-brief", "link"]),
            "system/ip-address.txt": diagnostic_command(["ip", "-4", "-brief", "address"]),
            "system/ip-route.txt": diagnostic_command(["ip", "-4", "route"]),
            "system/dkms.txt": diagnostic_command(["dkms", "status"]),
            "system/disk.txt": diagnostic_command(["df", "-h", "/"]),
            "system/memory.txt": diagnostic_command(["free", "-h"]),
            "system/listeners.txt": diagnostic_command(["ss", "-H", "-lntup"]),
            "system/nft-forward.txt": diagnostic_command(["nft", "-a", "list", "table", "ip", "amneziawg_forward"]),
            "system/nft-nat.txt": diagnostic_command(["nft", "-a", "list", "table", "ip", "amneziawg_nat"]),
            "system/journal.txt": diagnostic_command(
                ["journalctl", "-u", SERVICE_TEMPLATE.format(interface=config["interface"]), "-n", "200", "--no-pager"]
            ),
        }
        for source, name in ((GENERATED_CONFIG, "manager/generated-awg0.conf"), (RUNTIME_CONFIG, "manager/runtime-awg0.conf")):
            try:
                files[name] = redact_diagnostic_text(source.read_text(encoding="utf-8")).encode()
            except OSError as exc:
                files[name] = f"unavailable: {exc}\n".encode()
        bundle = create_diagnostic_bundle(parent, product_version=VERSION, created_at=iso_now(), files=files)
    audit(f"redacted diagnostics created: {bundle.name}")
    data = {"path": str(bundle), "redacted": True, "manifest": str(bundle / "manifest.json")}
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("diagnose", data=data), indent=2, sort_keys=True))
    else:
        print(f"Created protected redacted diagnostics: {bundle}")
        print("Review the directory before sharing it; it contains host metadata but no managed VPN keys or profiles.")
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    platform_info = validate_platform(read_os_release())
    platform_name = f"ubuntu-{platform_info['version']}-{platform_info['architecture']}"
    tag = discover_release_tag(channel=args.channel)
    include_artifact = args.update_action == "apply" or args.dry_run
    manifest, artifact = fetch_verified_release(
        tag,
        expected_platform=platform_name,
        include_artifact=include_artifact,
    )
    latest = manifest["version"]
    comparison = (version_key(latest) > version_key(VERSION)) - (version_key(latest) < version_key(VERSION))
    data: dict[str, Any] = {
        "current_version": VERSION,
        "available_version": latest,
        "channel": args.channel,
        "tag": tag,
        "signature_verified": True,
        "artifact_verified": artifact is not None,
        "update_available": comparison > 0,
    }
    if args.update_action == "check":
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("update check", data=data), indent=2, sort_keys=True))
        else:
            print(f"Installed: {VERSION}")
            print(f"Published: {latest} ({args.channel}, signed manifest verified)")
            print("Update available." if comparison > 0 else "Already current." if comparison == 0 else "Installed version is newer than published release.")
        return 0
    if comparison < 0:
        raise AwgctlError("refusing to downgrade to an older published release")
    if comparison == 0:
        data["changed"] = False
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("update", data=data), indent=2, sort_keys=True))
        else:
            print(f"Already current: awgctl {VERSION}")
        return 0
    if artifact is None:
        raise AwgctlError("verified release artifact was not downloaded")
    if args.dry_run:
        data.update(dry_run=True, changed=False, runtime_action="none", rollback="previous release selector")
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("update", data=data), indent=2, sort_keys=True))
        else:
            print(f"Update dry run: verified signed awgctl {latest} for {platform_name}")
            print("Would install an immutable release, run health, and restore the prior selector on failure.")
            print("No state was changed.")
        return 0
    with mutation_lock(), tempfile.TemporaryDirectory(prefix="awgctl-update-") as directory:
        backup = create_backup()
        artifact_path = pathlib.Path(directory) / "awgctl"
        atomic_write(artifact_path, artifact, 0o755)

        def health_check(executable: pathlib.Path) -> int:
            return run([str(executable), "health", "--json"], check=False, timeout=90).returncode

        upgrade_product(
            root=ROOT,
            artifact=artifact_path,
            version=latest,
            health_check=health_check,
        )
    audit(f"product updated: {VERSION} -> {latest}")
    data.update(changed=True, backup=str(backup), runtime_action="none")
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("update", data=data), indent=2, sort_keys=True))
    else:
        print(f"Updated awgctl: {VERSION} -> {latest}")
        print(f"Pre-update state backup: {backup}")
        print("VPN runtime was not restarted; the new manager passed health verification.")
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    if not args.experimental:
        raise AwgctlError("namespace self-test is experimental; rerun with --experimental")
    config = load_config()
    if args.dry_run:
        data = {
            "dry_run": True,
            "experimental": True,
            "host_interface_unchanged": config["interface"],
            "steps": [
                "create two temporary Linux network namespaces",
                "create ephemeral keys and a state-derived AmneziaWG tunnel",
                "send ICMP echo traffic through the isolated tunnel",
                "delete both namespaces and all ephemeral credentials",
            ],
        }
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("self-test", data=data), indent=2, sort_keys=True))
        else:
            print("Experimental self-test dry run: awg0 and host nftables would remain unchanged.")
            print("No state was changed.")
        return 0
    with mutation_lock():
        if config["obfuscation"]["mode"] == "awg31":
            require_awg31_capability()
        report = run_namespace_selftest(
            config["obfuscation"],
            header_protection_key=header_protection_key_for_config(config),
        )
    audit("experimental namespace self-test passed")
    if getattr(args, "json", False):
        print(json.dumps(json_envelope("self-test", data=report), indent=2, sort_keys=True))
    else:
        print("Experimental namespace self-test: PASS")
        print(f"  isolation: {report['isolation']}")
        print(f"  packet test: {report['packet_test']}")
        print("  cleanup: temporary namespaces and credentials removed")
    return 0


def cmd_firewall(args: argparse.Namespace) -> int:
    require_root()
    if os.environ.get("SUDO_USER"):
        raise AwgctlError("internal firewall lifecycle commands cannot be invoked through sudo")
    if args.firewall_action == "up":
        apply_firewall()
    else:
        firewall_cleanup()
    return 0


def cleanup_failed_fresh_install(client_name: str) -> None:
    for path in (CONFIG_FILE, GENERATED_CONFIG, GENERATED_NFT, SERVER_PRIVATE, SERVER_PUBLIC):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    remove_client_state(client_name)


def cmd_initialize_fresh(args: argparse.Namespace) -> int:
    client_name = validate_client_name(args.first_client)
    with mutation_lock():
        if CONFIG_FILE.exists() or RUNTIME_CONFIG.exists():
            raise AwgctlError("fresh initialization requires no existing managed or awg0 runtime configuration")
        config = build_fresh_server_config(
            endpoint=args.endpoint,
            subnet=args.subnet,
            listen_port=args.listen_port,
            external_interface=args.external_interface,
            dns=args.dns,
            mtu=args.mtu,
            keepalive=args.keepalive,
            obfuscation=generate_classic_obfuscation(),
        )
        previous_sysctl = SYSCTL_CONFIG.read_bytes() if SYSCTL_CONFIG.exists() else None
        service = SERVICE_TEMPLATE.format(interface=config["interface"])
        ensure_layout()
        try:
            server_private, server_public, _ = generate_key_material(False)
            client_private, client_public, client_psk = generate_key_material(True)
            atomic_json(CONFIG_FILE, config, 0o600)
            atomic_write(SERVER_PRIVATE, server_private + "\n", 0o600)
            atomic_write(SERVER_PUBLIC, server_public + "\n", 0o600)
            server_address = ipaddress.ip_interface(config["server_address"])
            client_address = next_client_address(ipaddress.ip_network(config["subnet"]), server_address, set())
            client = write_client_state(
                config,
                client_name,
                str(client_address),
                client_private,
                client_public,
                client_psk,
                owner=getattr(args, "owner", None),
                device=getattr(args, "device", None),
            )
            server_text = render_server_config(
                config,
                server_private,
                [client],
                header_protection_key=header_protection_key_for_config(config),
            )
            nft_text = render_nftables_config(config)
            validate_native_server(server_text)
            validate_nftables_text(nft_text)
            atomic_write(GENERATED_CONFIG, server_text, 0o600)
            atomic_write(GENERATED_NFT, nft_text, 0o600)
            atomic_write(RUNTIME_CONFIG, server_text, 0o600)
            atomic_write(SYSCTL_CONFIG, "net.ipv4.ip_forward = 1\n", 0o644)
            run(["sysctl", "-p", str(SYSCTL_CONFIG)])
            run(["systemctl", "enable", service], timeout=45)
            service_action("start", config["interface"])
            if safe_awg_query(config["interface"], "public-key") != server_public:
                raise AwgctlError("fresh server identity verification failed")
            verify_peer_state(config["interface"], client_public, present=True)
            with contextlib.redirect_stdout(io.StringIO()):
                health_result = cmd_health(argparse.Namespace(json=True))
            if health_result != 0:
                raise AwgctlError("fresh server failed its complete health postcondition")
            backup = create_backup()
        except Exception as original:
            run(["systemctl", "stop", service], check=False, timeout=45)
            run(["systemctl", "disable", service], check=False, timeout=45)
            firewall_cleanup()
            cleanup_failed_fresh_install(client_name)
            with contextlib.suppress(FileNotFoundError):
                RUNTIME_CONFIG.unlink()
            if previous_sysctl is None:
                with contextlib.suppress(FileNotFoundError):
                    SYSCTL_CONFIG.unlink()
            else:
                atomic_write(SYSCTL_CONFIG, previous_sysctl, 0o644)
                run(["sysctl", "-p", str(SYSCTL_CONFIG)], check=False)
            audit("fresh initialization failed; manager and runtime state rollback attempted")
            raise AwgctlError("fresh initialization failed; state rollback was attempted") from original
        audit(f"fresh server initialized: interface=awg0 first_client={client_name}")
        print("Initialized a new AmneziaWG server.")
        print(f"Created first client: {client_name}")
        print(f"Address: {client_address.ip}")
        print(f"Config: {CLIENTS / client_name / (client_name + '.conf')}")
        print(f"QR: {CLIENTS / client_name / (client_name + '.png')}")
        print(f"Initial verified backup: {backup}")
        print(
            "INGRESS RULE REQUIRED "
            f"({ingress_boundary_attestation() or 'boundary attestation missing'}): "
            f"Custom / UDP / {config['listen_port']} / 0.0.0.0/0"
        )
    return 0


def cleanup_failed_migration(client_name: str) -> None:
    for path in (CONFIG_FILE, GENERATED_CONFIG, GENERATED_NFT):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    remove_client_state(client_name)
    for path in (SERVER_PRIVATE, SERVER_PUBLIC):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def cmd_migrate_existing(args: argparse.Namespace) -> int:
    client_name = validate_client_name(getattr(args, "client_name", "kat"))
    with mutation_lock():
        if CONFIG_FILE.exists():
            raise AwgctlError("management state is already initialized")
        server_path: pathlib.Path = args.server_config
        client_path: pathlib.Path = args.client_config
        try:
            original_server = server_path.read_bytes()
            original_client = client_path.read_bytes()
        except OSError as exc:
            raise AwgctlError("cannot read existing server or client configuration") from exc
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
            raise AwgctlError("existing client keypair does not match the server peer")
        live_server_before = safe_awg_query(args.interface, "public-key")
        live_peers_before = live_peers(args.interface)
        if live_server_before != derived_server or derived_client not in live_peers_before:
            raise AwgctlError("live server/client identity differs from the files; migration stopped")
        ensure_layout()
        old_runtime = RUNTIME_CONFIG.read_bytes()
        try:
            atomic_json(CONFIG_FILE, imported["config"], 0o600)
            atomic_write(SERVER_PRIVATE, imported["server_private"] + "\n", 0o600)
            atomic_write(SERVER_PUBLIC, imported["server_public"] + "\n", 0o600)
            client_record = write_client_state(
                imported["config"],
                client_name,
                imported["client_address"],
                imported["client_private"],
                imported["client_public"],
                imported["client_psk"],
                imported_from=str(client_path),
                profile_text=client_text,
            )
            metadata_path = CLIENTS / client_name / "metadata.json"
            metadata = json.loads(metadata_path.read_text())
            metadata["import_source_sha256"] = sha256_bytes(original_client)
            atomic_json(metadata_path, metadata, 0o600)
            existing_png = client_path.with_suffix(".png")
            if existing_png.is_file():
                atomic_write(CLIENTS / client_name / f"{client_name}.png", existing_png.read_bytes(), 0o600)
            rendered = render_server_config(
                imported["config"],
                imported["server_private"],
                [client_record],
                header_protection_key=header_protection_key_for_config(imported["config"]),
            )
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
            cleanup_failed_migration(client_name)
            audit("existing installation migration failed; legacy runtime restored")
            raise AwgctlError("migration failed; legacy runtime/configuration rollback was attempted") from original
        chmod_secret_tree(ROOT / "config")
        chmod_secret_tree(ROOT / "keys")
        chmod_secret_tree(ROOT / "clients")
        chmod_secret_tree(ROOT / "generated")
        audit("existing server and Kat profile imported without credential rotation")
        print(f"Imported existing AmneziaWG server and {client_name} profile.")
        print(f"Server identity fingerprint: {fingerprint(derived_server)}")
        print(f"Client identity fingerprint: {fingerprint(derived_client)}")
        print("Existing credentials were preserved; the running interface was reloaded, not restarted.")
    return 0


def build_parser(*, entrypoint: str = "public") -> argparse.ArgumentParser:
    if entrypoint not in {"public", "internal"}:
        raise ValueError("entrypoint must be public or internal")
    parser = argparse.ArgumentParser(prog="awgctl", description="Manage the host's AmneziaWG installation")
    parser.add_argument("--version", action="version", version=f"awgctl {VERSION}")
    parser.add_argument("--json", action="store_true", help="emit a stable machine-readable response")
    subcommands = parser.add_subparsers(dest="command", required=True)

    if entrypoint == "internal":
        firewall = subcommands.add_parser("_firewall", help=argparse.SUPPRESS)
        firewall.add_argument("firewall_action", choices=("up", "down"))
        migrate = subcommands.add_parser("_migrate-existing", help=argparse.SUPPRESS)
        migrate.add_argument("--server-config", type=pathlib.Path, required=True)
        migrate.add_argument("--client-config", type=pathlib.Path, required=True)
        migrate.add_argument("--interface", default="awg0")
        migrate.add_argument("--external-interface", default="ens5")
        migrate.add_argument("--client-name", default="kat")
        fresh = subcommands.add_parser("_initialize-fresh", help=argparse.SUPPRESS)
        fresh.add_argument("--endpoint", required=True)
        fresh.add_argument("--subnet", default="10.77.42.0/24")
        fresh.add_argument("--listen-port", type=int, default=55323)
        fresh.add_argument("--external-interface", required=True)
        fresh.add_argument("--dns", default="1.1.1.2,1.0.0.2")
        fresh.add_argument("--mtu", type=int, default=1280)
        fresh.add_argument("--keepalive", type=int, default=25)
        fresh.add_argument("--first-client", default="admin-phone")
        fresh.add_argument("--owner")
        fresh.add_argument("--device")
        expire = subcommands.add_parser("_expire-clients", help=argparse.SUPPRESS)
        expire.add_argument("--dry-run", action="store_true")
        expire.add_argument("--json", action="store_true")
        return parser

    def output_flag(command: argparse.ArgumentParser) -> None:
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS)

    def dry_run_flag(command: argparse.ArgumentParser) -> None:
        command.add_argument("--dry-run", action="store_true")

    for name in ("status", "health", "check", "aws-rule", "version"):
        output_flag(subcommands.add_parser(name))
    for name in ("start", "stop", "restart", "reload"):
        command = subcommands.add_parser(name)
        output_flag(command)
        dry_run_flag(command)
    backup_command = subcommands.add_parser("backup")
    backup_command.add_argument("backup_command", nargs="?", choices=("list", "verify"))
    backup_command.add_argument("backup", nargs="?", type=pathlib.Path)
    output_flag(backup_command)
    dry_run_flag(backup_command)
    restore = subcommands.add_parser("restore")
    restore.add_argument("backup", type=pathlib.Path)
    output_flag(restore)
    dry_run_flag(restore)
    diagnose = subcommands.add_parser("diagnose")
    diagnose.add_argument("--output", type=pathlib.Path, help="parent directory for the protected bundle")
    output_flag(diagnose)
    dry_run_flag(diagnose)
    update = subcommands.add_parser("update")
    update.add_argument("update_action", nargs="?", choices=("check", "apply"), default="apply")
    update.add_argument("--channel", choices=("beta", "stable"), default="beta")
    output_flag(update)
    dry_run_flag(update)
    self_test = subcommands.add_parser("self-test")
    self_test.add_argument("--experimental", action="store_true")
    output_flag(self_test)
    dry_run_flag(self_test)

    config_parser = subcommands.add_parser("config")
    config_commands = config_parser.add_subparsers(dest="config_command", required=True)
    output_flag(config_commands.add_parser("show"))
    config_set = config_commands.add_parser("set")
    config_set.add_argument("key", choices=("endpoint", "dns", "mtu", "listen-port"))
    config_set.add_argument("value")
    output_flag(config_set)
    dry_run_flag(config_set)

    client_parser = subcommands.add_parser("client")
    client_commands = client_parser.add_subparsers(dest="client_command", required=True)
    output_flag(client_commands.add_parser("list"))
    client_expire = client_commands.add_parser("expire")
    output_flag(client_expire)
    dry_run_flag(client_expire)
    for name in ("add", "show", "qr", "revoke", "rotate"):
        command = client_commands.add_parser(name)
        if name == "add":
            command.add_argument(
                "client_name",
                metavar="NAME",
                nargs="?",
                help="profile name; omit it to start the interactive wizard",
            )
        else:
            command.add_argument("client_name", metavar="NAME")
        output_flag(command)
        if name != "show":
            dry_run_flag(command)
        if name == "add":
            command.add_argument("--owner")
            command.add_argument("--device")
            command.add_argument("--expires")
        if name == "qr":
            command.add_argument("--output", type=pathlib.Path)
    export = client_commands.add_parser("export")
    export.add_argument("client_name", metavar="NAME")
    output_flag(export)
    export_group = export.add_mutually_exclusive_group()
    export_group.add_argument("--output", type=pathlib.Path)
    export_group.add_argument("--stdout", action="store_true")
    client_import = client_commands.add_parser("import")
    client_import.add_argument("client_name", metavar="NAME")
    client_import.add_argument("--config", dest="profile", type=pathlib.Path, required=True)
    client_import.add_argument("--owner")
    client_import.add_argument("--device")
    client_import.add_argument("--expires")
    output_flag(client_import)
    dry_run_flag(client_import)
    client_edit = client_commands.add_parser("edit")
    client_edit.add_argument("client_name", metavar="NAME")
    client_edit.add_argument("--owner", default=argparse.SUPPRESS)
    client_edit.add_argument("--device", default=argparse.SUPPRESS)
    client_edit.add_argument("--expires", default=argparse.SUPPRESS)
    client_edit.add_argument("--mark-distributed", action="store_true", default=argparse.SUPPRESS)
    output_flag(client_edit)
    dry_run_flag(client_edit)

    firewall = subcommands.add_parser("_firewall", help=argparse.SUPPRESS)
    firewall.add_argument("firewall_action", choices=("up", "down"))
    return parser


def dispatch(args: argparse.Namespace) -> int:
    if args.command == "version":
        data = {"version": VERSION}
        if getattr(args, "json", False):
            print(json.dumps(json_envelope("version", data=data), indent=2, sort_keys=True))
        else:
            print(f"awgctl {VERSION}")
        return 0
    require_root()
    if args.command == "status":
        return cmd_status(args)
    if args.command in {"health", "check"}:
        return cmd_health(args)
    if args.command in {"start", "stop", "restart", "reload"}:
        return cmd_service(args)
    if args.command == "backup":
        return cmd_backup(args)
    if args.command == "restore":
        return cmd_restore(args)
    if args.command == "diagnose":
        return cmd_diagnose(args)
    if args.command == "update":
        return cmd_update(args)
    if args.command == "self-test":
        return cmd_self_test(args)
    if args.command == "aws-rule":
        cmd_aws_rule(as_json=getattr(args, "json", False))
        return 0
    if args.command == "config":
        return cmd_config_show(args) if args.config_command == "show" else cmd_config_set(args)
    if args.command == "client":
        handlers = {
            "list": cmd_client_list,
            "expire": cmd_client_expire,
            "add": cmd_client_add,
            "show": cmd_client_show,
            "export": cmd_client_export,
            "qr": cmd_client_qr,
            "revoke": cmd_client_revoke,
            "rotate": cmd_client_rotate,
            "import": cmd_client_import,
            "edit": cmd_client_edit,
        }
        return handlers[args.client_command](args)
    if args.command == "_firewall":
        return cmd_firewall(args)
    if args.command == "_migrate-existing":
        return cmd_migrate_existing(args)
    if args.command == "_initialize-fresh":
        return cmd_initialize_fresh(args)
    if args.command == "_expire-clients":
        return cmd_expire_clients(args)
    raise AwgctlError("unknown command")


def main(argv: Sequence[str] | None = None, *, entrypoint: str = "public") -> int:
    parser = build_parser(entrypoint=entrypoint)
    args = parser.parse_args(argv)
    try:
        return dispatch(args)
    except (
        AwgctlError, BackupError, ContractError, DiagnosticsError, InstallerError,
        PlatformError, ReleaseError, SelfTestError,
    ) as exc:
        audit(f"command failed: {args.command}")
        public_error = sanitize_cps_text(str(exc))
        if getattr(args, "json", False):
            command = args.command
            for attribute in ("config_command", "client_command", "backup_command", "update_action"):
                value = getattr(args, attribute, None)
                if value:
                    command += f" {value}"
                    break
            print(json.dumps(json_envelope(command, errors=[public_error]), indent=2, sort_keys=True))
        else:
            print(f"awgctl: {public_error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("awgctl: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
