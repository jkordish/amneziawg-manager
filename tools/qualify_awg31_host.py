#!/usr/bin/env python3
"""Qualify an exact AmneziaWG 3.1 pair without touching production state."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import math
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from typing import NoReturn


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.core import AWG31_QUALIFICATION_POLICY_VERSION
from awgctl.diagnostics import redact_awg_config


REQUIRED_CHECKS = (
    "version_parsing",
    "native_validation",
    "classic_traffic",
    "classic_recreation",
    "awg31_traffic",
    "awg31_counters",
    "awg31_recreation",
    "classic_rollback",
    "cleanup",
    "production_invariants",
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "policy_version",
        "started_at",
        "completed_at",
        "source",
        "platform",
        "versions",
        "checks",
        "evidence",
    }
)
EVIDENCE_FLAGS = {
    "disposable_host": False,
    "package_upgrade_test": False,
    "future_kernel_test": False,
    "russia_network": False,
    "physical_device": False,
}
KEY_SHAPED_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"
)
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_PUBLIC_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}")
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_RECEIPT_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.json")
_OPEN_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)


class QualificationError(RuntimeError):
    """The host could not be qualified without weakening a safety invariant."""


@dataclasses.dataclass(frozen=True)
class VersionEvidence:
    tools: str
    loaded_module: str
    packaged_module: str
    dkms: str


@dataclasses.dataclass(frozen=True)
class ProductionSnapshot:
    protected_tree_sha256: str
    interface_sha256: str
    listener_sha256: str
    nftables_sha256: str
    service_state: tuple[str, str]
    package_sha256: str


def safe_error(error: object) -> str:
    """Return a bounded public error with native and bare key material removed."""
    text = redact_awg_config(str(error).replace("\x00", "[invalid byte]"))
    text = KEY_SHAPED_BASE64.sub("[redacted key material]", text)
    text = "".join(
        character
        for character in text
        if character in "\n\r\t" or ord(character) >= 32
    )
    return text[:2048]


def _fail(message: object) -> NoReturn:
    raise QualificationError(safe_error(message))


def run_command(
    argv: Sequence[str],
    *,
    input_data: bytes | None = None,
    timeout: float = 20,
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded command without a shell or secret-bearing argv coercion."""
    if isinstance(argv, (str, bytes)):
        _fail("command arguments must be a non-empty sequence of strings")
    try:
        command = tuple(argv)
    except TypeError:
        _fail("command arguments must be a non-empty sequence of strings")
    if not command or any(type(argument) is not str or not argument for argument in command):
        _fail("command arguments must be non-empty strings")
    if input_data is not None and type(input_data) is not bytes:
        _fail("command input must be bytes")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        _fail("command timeout must be a positive finite number")

    command_name = pathlib.PurePath(command[0]).name or "command"
    try:
        result = subprocess.run(
            command,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise QualificationError(
            safe_error(f"required command not found: {command_name}")
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise QualificationError(
            safe_error(f"command timed out: {command_name}")
        ) from exc
    except OSError as exc:
        raise QualificationError(
            safe_error(f"command could not start: {command_name}: {exc}")
        ) from exc

    if result.returncode != 0:
        decoded = result.stderr.decode("utf-8", "replace").strip().splitlines()
        detail = f": {decoded[-1]}" if decoded else ""
        raise QualificationError(
            safe_error(f"command failed: {command_name}{detail}")
        )
    return result


def _require_public_token(name: str, value: object) -> str:
    if type(value) is not str or _PUBLIC_TOKEN.fullmatch(value) is None:
        _fail(f"invalid {name}")
    return value


def _parse_timestamp(name: str, value: object) -> tuple[str, dt.datetime]:
    if type(value) is not str:
        _fail(f"invalid {name}")
    try:
        parsed = dt.datetime.strptime(value, _TIMESTAMP_FORMAT).replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise QualificationError(f"invalid {name}") from exc
    return value, parsed


def _validated_versions(versions: object) -> dict[str, str]:
    if type(versions) is not VersionEvidence:
        _fail("invalid version evidence")
    values = {
        "tools": versions.tools,
        "loaded_module": versions.loaded_module,
        "packaged_module": versions.packaged_module,
        "dkms": versions.dkms,
    }
    if any(type(value) is not str or _VERSION.fullmatch(value) is None for value in values.values()):
        _fail("invalid version evidence")
    return values


def build_receipt(
    *,
    source_commit: str,
    dirty_worktree: bool,
    os_version: str,
    architecture: str,
    kernel: str,
    versions: VersionEvidence,
    checks: Mapping[str, bool],
    started_at: str,
    completed_at: str,
) -> dict[str, object]:
    """Build the closed, non-secret receipt schema for a passing qualification."""
    if type(source_commit) is not str or _COMMIT.fullmatch(source_commit) is None:
        _fail("invalid source commit")
    if type(dirty_worktree) is not bool:
        _fail("invalid dirty-worktree state")
    public_platform = {
        "os_version": _require_public_token("OS version", os_version),
        "architecture": _require_public_token("architecture", architecture),
        "kernel": _require_public_token("kernel", kernel),
    }
    public_versions = _validated_versions(versions)
    if not isinstance(checks, Mapping) or set(checks) != set(REQUIRED_CHECKS):
        _fail("qualification checks do not match the required policy")
    if any(type(checks[name]) is not bool or not checks[name] for name in REQUIRED_CHECKS):
        _fail("all required qualification checks must pass")
    started_text, started = _parse_timestamp("start timestamp", started_at)
    completed_text, completed = _parse_timestamp("completion timestamp", completed_at)
    if completed < started:
        _fail("qualification completion precedes its start")

    return {
        "schema_version": 1,
        "policy_version": AWG31_QUALIFICATION_POLICY_VERSION,
        "started_at": started_text,
        "completed_at": completed_text,
        "source": {
            "commit": source_commit,
            "dirty_worktree": dirty_worktree,
        },
        "platform": public_platform,
        "versions": public_versions,
        "checks": {name: checks[name] for name in REQUIRED_CHECKS},
        "evidence": dict(EVIDENCE_FLAGS),
    }


def _validate_receipt_for_write(receipt: Mapping[str, object]) -> bytes:
    if not isinstance(receipt, Mapping) or set(receipt) != RECEIPT_FIELDS:
        _fail("receipt does not match the closed qualification schema")
    try:
        encoded = (
            json.dumps(
                receipt,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise QualificationError("receipt is not canonical JSON") from exc
    decoded = encoded.decode("ascii")
    forbidden = (
        KEY_SHAPED_BASE64.search(decoded) is not None
        or re.search(
            r"(?i)privatekey|presharedkey|headerprotectionkey|\bI[1-5]\b|namespace",
            decoded,
        )
        is not None
    )
    if forbidden:
        _fail("receipt contains forbidden qualification material")
    return encoded


def _same_open_directory(path: pathlib.Path, opened: os.stat_result) -> bool:
    try:
        named = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) == (
        opened.st_dev,
        opened.st_ino,
    )


def _require_private_owned_directory(fd: int, description: str) -> os.stat_result:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{description} is not a directory")
    if metadata.st_uid != os.geteuid():
        _fail(f"{description} is not owned by the effective user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        _fail(f"{description} is writable by group or other users")
    return metadata


def atomic_write_receipt(
    receipt: Mapping[str, object],
    output_dir: pathlib.Path,
    filename: str,
) -> pathlib.Path:
    """Write a new private receipt through descriptor-relative, atomic operations."""
    data = _validate_receipt_for_write(receipt)
    if not isinstance(output_dir, pathlib.Path) or not output_dir.name:
        _fail("unsafe qualification output directory")
    if type(filename) is not str or _RECEIPT_FILENAME.fullmatch(filename) is None:
        _fail("unsafe qualification receipt filename")

    parent = output_dir.parent
    try:
        parent_fd = os.open(parent, _OPEN_DIRECTORY_FLAGS)
    except OSError as exc:
        raise QualificationError(
            "qualification output parent is not a safe directory"
        ) from exc
    output_fd: int | None = None
    temporary_fd: int | None = None
    temporary_name = f".{filename}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    linked = False
    try:
        parent_metadata = _require_private_owned_directory(
            parent_fd, "qualification output parent"
        )
        try:
            os.mkdir(output_dir.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        try:
            output_fd = os.open(
                output_dir.name, _OPEN_DIRECTORY_FLAGS, dir_fd=parent_fd
            )
        except OSError as exc:
            raise QualificationError(
                "qualification output is not a safe directory"
            ) from exc
        output_metadata = _require_private_owned_directory(
            output_fd, "qualification output directory"
        )
        if stat.S_IMODE(output_metadata.st_mode) != 0o700:
            _fail("qualification output directory must have mode 0700")

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        temporary_fd = os.open(
            temporary_name, flags, 0o600, dir_fd=output_fd
        )
        temporary_created = True
        os.fchown(temporary_fd, os.geteuid(), os.getegid())
        os.fchmod(temporary_fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                _fail("qualification receipt write did not make progress")
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        try:
            os.link(
                temporary_name,
                filename,
                src_dir_fd=output_fd,
                dst_dir_fd=output_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise QualificationError(
                "qualification receipt already exists"
            ) from exc
        linked = True
        os.unlink(temporary_name, dir_fd=output_fd)
        temporary_created = False
        os.fsync(output_fd)
        os.fsync(parent_fd)

        if not _same_open_directory(parent, parent_metadata):
            _fail("qualification output parent changed during write")
        if not _same_open_directory(output_dir, output_metadata):
            _fail("qualification output directory changed during write")
    except BaseException:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_created and output_fd is not None:
            try:
                os.unlink(temporary_name, dir_fd=output_fd)
                os.fsync(output_fd)
            except FileNotFoundError:
                pass
        if linked and output_fd is not None:
            try:
                os.unlink(filename, dir_fd=output_fd)
                os.fsync(output_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(parent_fd)
    return output_dir / filename
