#!/usr/bin/env python3
"""Qualify an exact AmneziaWG 3.1 pair without touching production state."""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any, Callable, NoReturn, Protocol, TextIO


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.core import (
    AWG31_QUALIFICATION_POLICY_VERSION,
    ACTIVATION_JOURNAL_FILE,
    AwgctlError,
    LOCK_FILE,
    SERVICE_OPERATION_FILE,
    TRANSITION_FILE,
    TRANSITION_OUTCOME_FILE,
    build_russia_ios_obfuscation,
    inspect_awg_versions,
    load_config,
    load_service_operation_intent,
    load_transition_document,
    sha256_bytes,
)
from awgctl.diagnostics import redact_awg_config
from awgctl.selftest import SelfTestError, render_peer_configs


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


class QualificationInterrupted(QualificationError):
    """A handled termination request that must survive verified cleanup."""


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


CommandRunner = Callable[..., subprocess.CompletedProcess[bytes]]


@dataclasses.dataclass
class OwnedResources:
    """Exact resources created by one qualifier process, in creation order."""

    runner: CommandRunner
    namespaces: list[str] = dataclasses.field(default_factory=list)
    host_links: list[str] = dataclasses.field(default_factory=list)


def _namespace_names(output: bytes) -> set[str]:
    try:
        text = output.decode("utf-8")
    except UnicodeError as exc:
        raise QualificationError("invalid namespace inventory output") from exc
    return {
        line.split(maxsplit=1)[0]
        for line in text.splitlines()
        if line.strip()
    }


def _root_link_names(output: bytes) -> set[str]:
    try:
        decoded = json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError("invalid link inventory output") from exc
    if not isinstance(decoded, list):
        _fail("invalid link inventory output")
    names: set[str] = set()
    for entry in decoded:
        if not isinstance(entry, dict) or type(entry.get("ifname")) is not str:
            _fail("invalid link inventory output")
        names.add(entry["ifname"])
    return names


def _runner_output(
    runner: CommandRunner,
    argv: Sequence[str],
    *,
    input_data: bytes | None = None,
    timeout: float = 20,
) -> bytes:
    result = runner(argv, input_data=input_data, timeout=timeout)
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
    ):
        _fail("qualification command runner returned an invalid result")
    return result.stdout


def cleanup_owned_resources(resources: OwnedResources) -> None:
    """Best-effort delete, then prove absence of only the recorded resources."""
    cleanup_errors: list[Exception] = []
    interruption: QualificationInterrupted | None = None
    for link in reversed(resources.host_links):
        try:
            _runner_output(resources.runner, ["ip", "link", "delete", link])
        except QualificationInterrupted as exc:
            interruption = interruption or exc
        except Exception as exc:
            cleanup_errors.append(exc)
    for namespace in reversed(resources.namespaces):
        try:
            _runner_output(
                resources.runner, ["ip", "netns", "delete", namespace]
            )
        except QualificationInterrupted as exc:
            interruption = interruption or exc
        except Exception as exc:
            cleanup_errors.append(exc)

    try:
        remaining_namespaces = _namespace_names(
            _runner_output(resources.runner, ["ip", "netns", "list"])
        )
        remaining_links = _root_link_names(
            _runner_output(resources.runner, ["ip", "-j", "link", "show"])
        )
    except QualificationInterrupted:
        raise
    except Exception as exc:
        raise QualificationError(
            "could not verify isolated qualification cleanup"
        ) from exc
    if set(resources.namespaces) & remaining_namespaces:
        _fail("isolated qualification namespaces remain after cleanup")
    if set(resources.host_links) & remaining_links:
        _fail("isolated qualification links remain after cleanup")

    resources.namespaces.clear()
    resources.host_links.clear()
    if interruption is not None:
        raise interruption
    if cleanup_errors:
        # A moved veth is expected to be absent from the root namespace. Only the
        # post-cleanup inventories decide whether the cleanup succeeded.
        return


def parse_transfer_counters(output: bytes | str) -> tuple[int, int]:
    """Parse one safe `awg show ... transfer` row without retaining its peer key."""
    if type(output) is bytes:
        try:
            text = output.decode("ascii")
        except UnicodeError as exc:
            raise QualificationError("invalid AWG transfer counters") from exc
    elif type(output) is str:
        text = output
    else:
        _fail("invalid AWG transfer counters")
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        _fail("expected exactly one AWG peer transfer row")
    fields = lines[0].split()
    if len(fields) not in {2, 3}:
        _fail("invalid AWG transfer counter row")
    received_text, sent_text = fields[-2:]
    if (
        not received_text.isascii()
        or not sent_text.isascii()
        or not received_text.isdecimal()
        or not sent_text.isdecimal()
        or len(received_text) > 20
        or len(sent_text) > 20
    ):
        _fail("invalid AWG transfer counter values")
    return int(received_text), int(sent_text)


def require_bidirectional_counters(
    server_output: bytes | str,
    client_output: bytes | str,
) -> tuple[tuple[int, int], tuple[int, int]]:
    """Require nonzero receive and transmit evidence from each isolated peer."""
    server = parse_transfer_counters(server_output)
    client = parse_transfer_counters(client_output)
    if any(value <= 0 for value in (*server, *client)):
        _fail("isolated AWG 3.1 transfer counters are not bidirectional")
    return server, client


def _validated_native_key(output: bytes, command: str) -> str:
    try:
        text = output.decode("ascii").strip()
        decoded = base64.b64decode(text, validate=True)
    except (UnicodeError, ValueError, base64.binascii.Error) as exc:
        raise QualificationError(f"{command} returned invalid key material") from exc
    if len(decoded) != 32:
        _fail(f"{command} returned invalid key material")
    return text


def _write_private_config(root: pathlib.Path, name: str, content: str) -> pathlib.Path:
    path = root / name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        data = content.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail("isolated configuration write did not make progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


@contextlib.contextmanager
def _block_cleanup_signals() -> Any:
    """Defer handled termination until a successful create is journaled."""
    previous = signal.pthread_sigmask(
        signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
    )
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class NamespaceQualifier:
    """Exercise classic and AWG 3.1 only inside process-owned namespaces."""

    def __init__(
        self,
        *,
        runner: CommandRunner = run_command,
        token: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], Any] = time.sleep,
    ) -> None:
        selected = token if token is not None else secrets.token_hex(3)
        if type(selected) is not str or re.fullmatch(r"[0-9a-f]{6}", selected) is None:
            _fail("invalid qualification resource token")
        self.runner = runner
        self.token = selected
        self.clock = clock
        self.sleeper = sleeper
        self.server_ns = f"awgq-s-{selected}"
        self.client_ns = f"awgq-c-{selected}"
        self.server_veth = f"awgq-vs-{selected}"
        self.client_veth = f"awgq-vc-{selected}"
        self.resources = OwnedResources(runner=runner)

    def _run(
        self,
        argv: Sequence[str],
        *,
        input_data: bytes | None = None,
        timeout: float = 20,
    ) -> bytes:
        return _runner_output(
            self.runner, argv, input_data=input_data, timeout=timeout
        )

    def _require_candidate_names_absent(self) -> None:
        namespaces = _namespace_names(self._run(["ip", "netns", "list"]))
        links = _root_link_names(self._run(["ip", "-j", "link", "show"]))
        if {self.server_ns, self.client_ns} & namespaces:
            _fail("qualification namespace name already exists")
        if {self.server_veth, self.client_veth} & links:
            _fail("qualification link name already exists")

    def _create_underlay(self) -> None:
        for namespace in (self.server_ns, self.client_ns):
            with _block_cleanup_signals():
                self._run(["ip", "netns", "add", namespace])
                self.resources.namespaces.append(namespace)
        with _block_cleanup_signals():
            self._run(
                [
                    "ip",
                    "link",
                    "add",
                    self.server_veth,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    self.client_veth,
                ]
            )
            self.resources.host_links.extend((self.server_veth, self.client_veth))
        self._run(
            ["ip", "link", "set", self.server_veth, "netns", self.server_ns]
        )
        self._run(
            ["ip", "link", "set", self.client_veth, "netns", self.client_ns]
        )
        for namespace, veth, address in (
            (self.server_ns, self.server_veth, "192.0.2.1/30"),
            (self.client_ns, self.client_veth, "192.0.2.2/30"),
        ):
            self._run(["ip", "-n", namespace, "link", "set", "lo", "up"])
            self._run(
                ["ip", "-n", namespace, "address", "add", address, "dev", veth]
            )
            self._run(["ip", "-n", namespace, "link", "set", veth, "up"])

    def _generate_configs(
        self,
        root: pathlib.Path,
        classic_obfuscation: Mapping[str, object],
        awg31_obfuscation: Mapping[str, object],
        header_protection_key: bytes,
    ) -> dict[str, tuple[pathlib.Path, pathlib.Path]]:
        server_private = _validated_native_key(
            self._run(["awg", "genkey"]), "awg genkey"
        )
        client_private = _validated_native_key(
            self._run(["awg", "genkey"]), "awg genkey"
        )
        psk = _validated_native_key(
            self._run(["awg", "genpsk"]), "awg genpsk"
        )
        server_public = _validated_native_key(
            self._run(
                ["awg", "pubkey"],
                input_data=(server_private + "\n").encode("ascii"),
            ),
            "awg pubkey",
        )
        client_public = _validated_native_key(
            self._run(
                ["awg", "pubkey"],
                input_data=(client_private + "\n").encode("ascii"),
            ),
            "awg pubkey",
        )
        rendered: dict[str, tuple[pathlib.Path, pathlib.Path]] = {}
        for mode, obfuscation, header in (
            ("classic", classic_obfuscation, None),
            ("awg31", awg31_obfuscation, header_protection_key),
        ):
            try:
                server, client = render_peer_configs(
                    server_private=server_private,
                    server_public=server_public,
                    client_private=client_private,
                    client_public=client_public,
                    psk=psk,
                    obfuscation=obfuscation,
                    header_protection_key=header,
                    port=51871,
                )
            except SelfTestError as exc:
                raise QualificationError(
                    f"could not render isolated {mode} configuration"
                ) from exc
            rendered[mode] = (
                _write_private_config(root, f"{mode}-server.conf", server),
                _write_private_config(root, f"{mode}-client.conf", client),
            )
        return rendered

    def _create_and_apply_tunnels(
        self, server_config: pathlib.Path, client_config: pathlib.Path
    ) -> None:
        for namespace, address in (
            (self.server_ns, "10.200.0.1/24"),
            (self.client_ns, "10.200.0.2/24"),
        ):
            self._run(
                ["ip", "-n", namespace, "link", "add", "awgt", "type", "amneziawg"]
            )
            self._run(
                ["ip", "-n", namespace, "address", "add", address, "dev", "awgt"]
            )
        self._run(
            [
                "ip",
                "netns",
                "exec",
                self.server_ns,
                "awg",
                "setconf",
                "awgt",
                str(server_config),
            ]
        )
        self._run(
            [
                "ip",
                "netns",
                "exec",
                self.client_ns,
                "awg",
                "setconf",
                "awgt",
                str(client_config),
            ]
        )
        self._run(
            ["ip", "-n", self.server_ns, "link", "set", "awgt", "up"]
        )
        self._run(
            ["ip", "-n", self.client_ns, "link", "set", "awgt", "up"]
        )

    def _destroy_tunnels(self) -> None:
        for namespace in (self.client_ns, self.server_ns):
            self._run(["ip", "-n", namespace, "link", "delete", "awgt"])

    def _require_ping(self, source_namespace: str, destination: str) -> None:
        deadline = self.clock() + 15
        last_error: QualificationError | None = None
        for attempt in range(5):
            if self.clock() > deadline:
                break
            try:
                self._run(
                    [
                        "ip",
                        "netns",
                        "exec",
                        source_namespace,
                        "ping",
                        "-n",
                        "-c",
                        "1",
                        "-W",
                        "2",
                        destination,
                    ],
                    timeout=4,
                )
                return
            except QualificationError as exc:
                last_error = exc
                if attempt < 4:
                    self.sleeper(0.2)
        raise QualificationError(
            "isolated bidirectional traffic did not complete within its bound"
        ) from last_error

    def _require_bidirectional_ping(self) -> None:
        self._require_ping(self.client_ns, "10.200.0.1")
        self._require_ping(self.server_ns, "10.200.0.2")

    def _require_awg31_counters(self) -> None:
        server = self._run(
            [
                "ip",
                "netns",
                "exec",
                self.server_ns,
                "awg",
                "show",
                "awgt",
                "transfer",
            ]
        )
        client = self._run(
            [
                "ip",
                "netns",
                "exec",
                self.client_ns,
                "awg",
                "show",
                "awgt",
                "transfer",
            ]
        )
        require_bidirectional_counters(server, client)

    def qualify(
        self,
        classic_obfuscation: Mapping[str, object],
        awg31_obfuscation: Mapping[str, object],
        header_protection_key: bytes,
    ) -> dict[str, bool]:
        """Run the complete isolated classic/AWG 3.1/recovery sequence."""
        if type(header_protection_key) is not bytes or len(header_protection_key) != 32:
            _fail("invalid isolated header-protection key material")
        checks: dict[str, bool] = {}
        try:
            self._require_candidate_names_absent()
            with tempfile.TemporaryDirectory(prefix="awgq-config-") as directory:
                root = pathlib.Path(directory)
                root.chmod(0o700)
                configs = self._generate_configs(
                    root,
                    classic_obfuscation,
                    awg31_obfuscation,
                    header_protection_key,
                )
                self._create_underlay()

                self._create_and_apply_tunnels(*configs["classic"])
                checks["native_validation"] = True
                self._require_bidirectional_ping()
                checks["classic_traffic"] = True
                self._destroy_tunnels()

                self._create_and_apply_tunnels(*configs["classic"])
                self._require_bidirectional_ping()
                checks["classic_recreation"] = True
                self._destroy_tunnels()

                self._create_and_apply_tunnels(*configs["awg31"])
                self._require_bidirectional_ping()
                checks["awg31_traffic"] = True
                self._require_awg31_counters()
                checks["awg31_counters"] = True
                self._destroy_tunnels()

                self._create_and_apply_tunnels(*configs["awg31"])
                self._require_bidirectional_ping()
                self._require_awg31_counters()
                checks["awg31_recreation"] = True
                self._destroy_tunnels()

                self._create_and_apply_tunnels(*configs["classic"])
                self._require_bidirectional_ping()
                checks["classic_rollback"] = True
        finally:
            cleanup_owned_resources(self.resources)
        checks["cleanup"] = True
        return checks


PROTECTED_PATHS = (
    pathlib.Path("/opt/amneziawg/config"),
    pathlib.Path("/opt/amneziawg/keys"),
    pathlib.Path("/opt/amneziawg/clients"),
    pathlib.Path("/opt/amneziawg/revoked"),
    pathlib.Path("/opt/amneziawg/generated"),
    pathlib.Path("/opt/amneziawg/transitions"),
    pathlib.Path("/opt/amneziawg/pending"),
    pathlib.Path("/etc/amnezia/amneziawg/awg0.conf"),
)
_VOLATILE_SNAPSHOT_FIELDS = frozenset(
    {
        "bytes",
        "packets",
        "valid_life_time",
        "preferred_life_time",
        "stats",
        "stats64",
        "event",
        "carrier_changes",
    }
)
_CLASSIC_CANDIDATE = {
    "Jc": 6,
    "Jmin": 8,
    "Jmax": 80,
    "S1": 25,
    "S2": 75,
    "H1": 101,
    "H2": 102,
    "H3": 103,
    "H4": 104,
}
_SAFE_STABLE_AWG_FIELDS = (
    "public-key",
    "private-key",
    "listen-port",
    "fwmark",
    "peers",
    "preshared-keys",
    "endpoints",
    "allowed-ips",
    "persistent-keepalive",
)
_SAFE_CLASSIC_AWG_FIELDS = tuple(field.lower() for field in _CLASSIC_CANDIDATE)
RECOVERY_ARTIFACT_PATHS = (
    SERVICE_OPERATION_FILE,
    TRANSITION_FILE,
    TRANSITION_OUTCOME_FILE,
    ACTIVATION_JOURNAL_FILE,
)


class ProtectedReader(Protocol):
    def digest_paths(self, paths: Sequence[pathlib.Path]) -> str: ...

    def read_text(self, path: pathlib.Path) -> str: ...


class ReceiptWriter(Protocol):
    def __call__(self, receipt: Mapping[str, object]) -> pathlib.Path: ...


@dataclasses.dataclass(frozen=True)
class PreflightEvidence:
    source_commit: str
    dirty_worktree: bool
    os_version: str
    architecture: str
    kernel: str
    versions: VersionEvidence


def _decode_json_value(name: str, output: bytes) -> Any:
    try:
        return json.loads(output)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"invalid {name} JSON") from exc


def _decode_json_object(name: str, output: bytes) -> dict[str, Any]:
    value = _decode_json_value(name, output)
    if not isinstance(value, dict):
        _fail(f"invalid {name} JSON")
    return value


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z0-9_]+", name) is None:
            _fail("invalid platform OS release metadata")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[name] = value
    return values


def _managed_listener_lines(output: bytes, port: int) -> tuple[str, ...]:
    try:
        lines = output.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise QualificationError("invalid production listener inventory") from exc
    pattern = re.compile(rf":{port}(?:\s|$)")
    return tuple(sorted(" ".join(line.split()) for line in lines if pattern.search(line)))


def validate_host_preflight(
    *,
    effective_uid: int,
    git_status: bytes,
    head: bytes,
    origin_main: bytes,
    health: bytes,
    status: bytes,
    service_state: bytes,
    boot_state: bytes,
    os_release: str,
    architecture: bytes,
    namespace_inventory: bytes,
    link_inventory: bytes,
    listeners: bytes,
    orphaned_temporary_roots: Sequence[str],
) -> None:
    """Validate all mutation-free host gates before generating any entropy."""
    if effective_uid != 0:
        _fail("non-root qualification is forbidden")
    if git_status:
        _fail("dirty source worktree cannot be qualified")
    try:
        head_text = head.decode("ascii").strip()
        origin_text = origin_main.decode("ascii").strip()
    except UnicodeError as exc:
        raise QualificationError("invalid source revision output") from exc
    if _COMMIT.fullmatch(head_text) is None or _COMMIT.fullmatch(origin_text) is None:
        _fail("invalid source revision output")
    if head_text != origin_text:
        _fail("source HEAD does not match origin/main")

    health_document = _decode_json_object("health", health)
    health_data = health_document.get("data")
    if (
        health_document.get("ok") is not True
        or health_document.get("errors") != []
        or not isinstance(health_data, dict)
        or not isinstance(health_data.get("summary"), dict)
        or type(health_data["summary"].get("failures")) is not int
        or health_data["summary"]["failures"] != 0
        or health_data.get("mode") != "classic"
        or not isinstance(health_data.get("transition"), dict)
        or health_data["transition"].get("state") != "none"
    ):
        _fail("health preflight requires zero failures in classic mode")

    status_document = _decode_json_object("status", status)
    status_data = status_document.get("data")
    if status_document.get("ok") is not True or status_document.get("errors") != []:
        _fail("production status preflight failed")
    if not isinstance(status_data, dict):
        _fail("invalid production status preflight")
    obfuscation = status_data.get("obfuscation")
    if (
        status_data.get("mode") != "classic"
        or not isinstance(obfuscation, dict)
        or obfuscation.get("mode") != "classic"
    ):
        _fail("production is not in classic mode")
    transition = status_data.get("transition")
    if not isinstance(transition, dict) or transition.get("state") != "none":
        _fail("production transition is active")
    interface = status_data.get("interface")
    if (
        not isinstance(interface, dict)
        or interface.get("name") != "awg0"
        or interface.get("up") is not True
    ):
        _fail("production interface is not up")
    if status_data.get("service") != "active" or service_state != b"active\n":
        _fail("production service is not exactly active")
    if status_data.get("boot") != "enabled" or boot_state != b"enabled\n":
        _fail("production boot state is not exactly enabled")

    os_values = _parse_os_release(os_release)
    if os_values.get("ID") != "ubuntu" or os_values.get("VERSION_ID") != "24.04":
        _fail("unsupported platform OS; expected Ubuntu 24.04")
    if architecture != b"amd64\n":
        _fail("unsupported platform architecture; expected amd64")

    namespaces = _namespace_names(namespace_inventory)
    links = _root_link_names(link_inventory)
    if any(name.startswith("awgq-") for name in (*namespaces, *links)):
        _fail("pre-existing qualification resource blocks the run")
    if orphaned_temporary_roots:
        _fail("orphaned qualification resource blocks the run")

    endpoint = status_data.get("endpoint")
    port = endpoint.get("port") if isinstance(endpoint, dict) else None
    if type(port) is not int or not 1 <= port <= 65535:
        _fail("invalid production listener port")
    if not _managed_listener_lines(listeners, port):
        _fail("production listener is unavailable")


def verify_preflight(
    *,
    expected_tools: str,
    expected_module: str,
    command_runner: CommandRunner,
    loaded_version_reader: Callable[[], str] | None = None,
) -> VersionEvidence:
    """Bind qualification to one exact parsed native pair and current DKMS row."""
    if _VERSION.fullmatch(expected_tools) is None or _VERSION.fullmatch(expected_module) is None:
        _fail("invalid expected AWG version")
    loaded_reader = loaded_version_reader or (
        lambda: pathlib.Path("/sys/module/amneziawg/version").read_text(
            encoding="ascii"
        )
    )
    try:
        inspected = inspect_awg_versions(
            command_runner=command_runner,
            loaded_version_reader=loaded_reader,
        )
    except AwgctlError as exc:
        raise QualificationError(safe_error(exc)) from exc
    tools = inspected.get("tools_version")
    module = inspected.get("module_version")
    if tools != expected_tools or module != expected_module:
        _fail("installed native pair does not match the expected qualification pair")

    kernel = _runner_output(command_runner, ["uname", "-r"]).decode(
        "ascii", "strict"
    ).strip()
    dkms_output = _runner_output(command_runner, ["dkms", "status"])
    try:
        dkms_text = dkms_output.decode("utf-8")
    except UnicodeError as exc:
        raise QualificationError("invalid DKMS status output") from exc
    pattern = re.compile(
        rf"^amneziawg/(?P<version>[0-9]+\.[0-9]+\.[0-9]+), "
        rf"{re.escape(kernel)}, [^:]+: installed$"
    )
    matches = [match for line in dkms_text.splitlines() if (match := pattern.fullmatch(line))]
    if len(matches) != 1:
        _fail("current-kernel DKMS module is not exactly installed")
    dkms_version = matches[0].group("version")
    return VersionEvidence(
        tools=tools,
        loaded_module=module,
        packaged_module=module,
        dkms=dkms_version,
    )


def resolve_public_preflight_path(
    path: pathlib.Path,
    *,
    lstat_reader: Callable[[pathlib.Path], Any] = os.lstat,
    link_reader: Callable[[pathlib.Path], str] = os.readlink,
) -> pathlib.Path:
    """Resolve only Ubuntu's canonical os-release symlink without following others."""
    if path != pathlib.Path("/etc/os-release"):
        return path
    try:
        metadata = lstat_reader(path)
    except OSError as exc:
        raise QualificationError("platform OS release metadata is unavailable") from exc
    if not stat.S_ISLNK(metadata.st_mode):
        return path
    try:
        target = link_reader(path)
    except OSError as exc:
        raise QualificationError("platform OS release link is unreadable") from exc
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or target not in {"../usr/lib/os-release", "/usr/lib/os-release"}
    ):
        _fail("platform OS release link is not the trusted system link")
    return pathlib.Path("/usr/lib/os-release")


def present_recovery_artifacts(
    paths: Sequence[pathlib.Path] = RECOVERY_ARTIFACT_PATHS,
) -> tuple[pathlib.Path, ...]:
    """Report exact manager journals without reading or reconciling their contents."""
    present: list[pathlib.Path] = []
    for path in paths:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise QualificationError(
                "manager recovery artifact state cannot be inspected"
            ) from exc
        present.append(path)
    return tuple(present)


def read_only_git_prefix() -> tuple[str, ...]:
    """Build Git commands that cannot opportunistically rewrite the index."""
    return ("git", "--no-optional-locks", "-C", str(REPO_ROOT))


class LiveProtectedReader:
    """Descriptor-safe reader that returns only aggregate protected-state hashes."""

    def __init__(self) -> None:
        self._allowed = frozenset(PROTECTED_PATHS)

    def read_text(self, path: pathlib.Path) -> str:
        if path not in {
            pathlib.Path("/etc/os-release"),
            pathlib.Path("/sys/module/amneziawg/version"),
        }:
            _fail("protected reader received an unsupported public path")
        open_path = resolve_public_preflight_path(path)
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(open_path, flags)
        try:
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size > 65536
            ):
                _fail("public preflight file is not a bounded regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode("utf-8")
        finally:
            os.close(fd)

    def _digest_entry(
        self,
        digest: Any,
        path: pathlib.Path,
        label: str,
    ) -> None:
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            digest.update(f"missing\0{label}\0".encode())
            return
        if stat.S_ISLNK(metadata.st_mode):
            _fail("protected production path contains a symlink")
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        digest.update(
            f"{kind}\0{label}\0{stat.S_IMODE(metadata.st_mode):04o}\0"
            f"{metadata.st_uid}\0{metadata.st_gid}\0".encode()
        )
        if stat.S_ISDIR(metadata.st_mode):
            fd = os.open(path, _OPEN_DIRECTORY_FLAGS)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    _fail("protected production directory changed during snapshot")
                for name in sorted(os.listdir(fd)):
                    child = pathlib.Path(f"/proc/self/fd/{fd}") / name
                    self._digest_entry(digest, child, f"{label}/{name}")
            finally:
                os.close(fd)
            return
        if not stat.S_ISREG(metadata.st_mode):
            _fail("protected production path contains an unsupported file type")
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                _fail("protected production file changed during snapshot")
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(fd)

    def digest_paths(self, paths: Sequence[pathlib.Path]) -> str:
        selected = tuple(paths)
        if set(selected) != set(PROTECTED_PATHS) or len(selected) != len(PROTECTED_PATHS):
            _fail("protected snapshot path set does not match policy")
        digest = hashlib.sha256()
        for path in sorted(selected, key=str):
            if path not in self._allowed:
                _fail("protected snapshot path is outside policy")
            self._digest_entry(digest, path, str(path))
        return digest.hexdigest()


@contextlib.contextmanager
def qualification_mutation_exclusion(
    *, timeout_seconds: float = 60,
) -> Any:
    """Hold the manager's exact flock without invoking mutation reconciliation."""
    if os.geteuid() != 0:
        _fail("non-root qualification is forbidden")
    deadline = time.monotonic() + timeout_seconds
    try:
        parent_fd = os.open(LOCK_FILE.parent, _OPEN_DIRECTORY_FLAGS)
    except OSError as exc:
        raise QualificationError(
            "protected manager mutation lock directory is unavailable"
        ) from exc
    lock_fd = -1
    acquired = False
    try:
        parent = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or (parent.st_uid, parent.st_gid) != (0, 0)
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            _fail("protected manager mutation lock directory is unsafe")
        try:
            lock_fd = os.open(
                LOCK_FILE.name,
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise QualificationError(
                "existing manager mutation lock file is unavailable"
            ) from exc
        opened = os.fstat(lock_fd)
        named = os.stat(
            LOCK_FILE.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_uid, opened.st_gid) != (0, 0)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            _fail("existing manager mutation lock file is unsafe")
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail("manager mutation lock acquisition timed out")
                time.sleep(min(0.05, remaining))
        yield
    finally:
        if acquired:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(parent_fd)


def _without_volatile_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_volatile_fields(item)
            for key, item in sorted(value.items())
            if key not in _VOLATILE_SNAPSHOT_FIELDS
        }
    if isinstance(value, list):
        return [_without_volatile_fields(item) for item in value]
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _normalized_peer_lines(output: bytes, *, handshakes: bool = False) -> list[str]:
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise QualificationError("invalid production peer output") from exc
    normalized: list[str] = []
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        peer = fields[0]
        if KEY_SHAPED_BASE64.fullmatch(peer) is None:
            _fail("invalid production peer output")
        if handshakes and len(fields) != 2:
            _fail("invalid production handshake output")
        normalized.append(peer)
    return sorted(normalized)


def capture_production_snapshot(
    command_runner: CommandRunner,
    protected_reader: ProtectedReader,
) -> ProductionSnapshot:
    """Hash stable production semantics while discarding volatile counters/times."""
    protected_digest = protected_reader.digest_paths(PROTECTED_PATHS)
    interface_document = _decode_json_value(
        "production interface",
        _runner_output(
            command_runner, ["ip", "-j", "address", "show", "dev", "awg0"]
        ),
    )
    stable_live_outputs = {
        field: _runner_output(
            command_runner, ["awg", "show", "awg0", field]
        )
        for field in (*_SAFE_STABLE_AWG_FIELDS, *_SAFE_CLASSIC_AWG_FIELDS)
    }
    stable_live_size = sum(len(output) for output in stable_live_outputs.values())
    if stable_live_size == 0 or stable_live_size > 1024 * 1024:
        _fail("complete safe live AWG state is unavailable or unbounded")
    stable_live_configuration = b"".join(
        field.encode("ascii") + b"\0" + stable_live_outputs[field] + b"\0"
        for field in (*_SAFE_STABLE_AWG_FIELDS, *_SAFE_CLASSIC_AWG_FIELDS)
    )
    peers = _normalized_peer_lines(stable_live_outputs["peers"])
    handshake_peers = _normalized_peer_lines(
        _runner_output(
            command_runner, ["awg", "show", "awg0", "latest-handshakes"]
        ),
        handshakes=True,
    )
    interface_bytes = _canonical_json(
        {
            "address": _without_volatile_fields(interface_document),
            "peers": peers,
            "handshake_peers": handshake_peers,
        }
    ) + b"\0" + stable_live_configuration

    try:
        port = int(stable_live_outputs["listen-port"].decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise QualificationError("invalid production listener port") from exc
    if not 1 <= port <= 65535:
        _fail("invalid production listener port")
    listener_lines = _managed_listener_lines(
        _runner_output(command_runner, ["ss", "-H", "-lunp"]), port
    )
    if not listener_lines:
        _fail("production listener disappeared during snapshot")

    nft_document = _decode_json_value(
        "production nftables",
        _runner_output(command_runner, ["nft", "-j", "list", "ruleset"]),
    )
    service = _runner_output(
        command_runner, ["systemctl", "is-active", "awg-quick@awg0.service"]
    ).decode("ascii").strip()
    boot = _runner_output(
        command_runner, ["systemctl", "is-enabled", "awg-quick@awg0.service"]
    ).decode("ascii").strip()
    if service != "active" or boot != "enabled":
        _fail("production service state changed during snapshot")

    packages = _runner_output(
        command_runner,
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\n",
            "amneziawg",
            "amneziawg-tools",
            "amneziawg-dkms",
        ],
    )
    dkms = _runner_output(command_runner, ["dkms", "status"])
    try:
        loaded_module = protected_reader.read_text(
            pathlib.Path("/sys/module/amneziawg/version")
        ).strip()
    except (OSError, UnicodeError) as exc:
        raise QualificationError(
            "loaded AmneziaWG module version is unavailable during snapshot"
        ) from exc
    if _VERSION.fullmatch(loaded_module) is None:
        _fail("loaded AmneziaWG module version is invalid during snapshot")
    return ProductionSnapshot(
        protected_tree_sha256=protected_digest,
        interface_sha256=sha256_bytes(interface_bytes),
        listener_sha256=sha256_bytes("\n".join(listener_lines).encode()),
        nftables_sha256=sha256_bytes(
            _canonical_json(_without_volatile_fields(nft_document))
        ),
        service_state=(service, boot),
        package_sha256=sha256_bytes(
            packages + b"\0" + dkms + b"\0" + loaded_module.encode("ascii")
        ),
    )


@dataclasses.dataclass
class LiveAdapters:
    command_runner: CommandRunner = run_command
    protected_reader: ProtectedReader = dataclasses.field(
        default_factory=LiveProtectedReader
    )
    namespace_factory: Callable[[CommandRunner], NamespaceQualifier] = (
        lambda runner: NamespaceQualifier(runner=runner)
    )
    clock: Callable[[], str] = lambda: dt.datetime.now(
        dt.timezone.utc
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    effective_uid: Callable[[], int] = os.geteuid
    lock_factory: Callable[[], Any] = qualification_mutation_exclusion
    recovery_artifact_probe: Callable[[], tuple[pathlib.Path, ...]] = (
        present_recovery_artifacts
    )

    def mutation_exclusion(self) -> Any:
        return self.lock_factory()

    def verify_preflight(
        self, *, expected_tools: str, expected_module: str
    ) -> PreflightEvidence:
        if self.effective_uid() != 0:
            _fail("non-root qualification is forbidden")
        if self.recovery_artifact_probe():
            _fail("manager recovery artifact blocks qualification preflight")
        git_prefix = read_only_git_prefix()
        git_status = _runner_output(
            self.command_runner, [*git_prefix, "status", "--porcelain=v1"]
        )
        head = _runner_output(
            self.command_runner, [*git_prefix, "rev-parse", "HEAD"]
        )
        origin_main = _runner_output(
            self.command_runner, [*git_prefix, "rev-parse", "origin/main"]
        )
        health = _runner_output(
            self.command_runner,
            ["/usr/local/sbin/awgctl", "health", "--json"],
            timeout=60,
        )
        status = _runner_output(
            self.command_runner,
            ["/usr/local/sbin/awgctl", "status", "--json"],
            timeout=30,
        )
        if self.recovery_artifact_probe():
            _fail("manager recovery artifact appeared during qualification preflight")
        service = _runner_output(
            self.command_runner,
            ["systemctl", "is-active", "awg-quick@awg0.service"],
        )
        boot = _runner_output(
            self.command_runner,
            ["systemctl", "is-enabled", "awg-quick@awg0.service"],
        )
        os_release = self.protected_reader.read_text(pathlib.Path("/etc/os-release"))
        architecture = _runner_output(
            self.command_runner, ["dpkg", "--print-architecture"]
        )
        namespaces = _runner_output(
            self.command_runner, ["ip", "netns", "list"]
        )
        links = _runner_output(self.command_runner, ["ip", "-j", "link", "show"])
        listeners = _runner_output(self.command_runner, ["ss", "-H", "-lunp"])
        orphans = tuple(
            path.name
            for path in pathlib.Path(tempfile.gettempdir()).glob("awgq-config-*")
        )
        validate_host_preflight(
            effective_uid=self.effective_uid(),
            git_status=git_status,
            head=head,
            origin_main=origin_main,
            health=health,
            status=status,
            service_state=service,
            boot_state=boot,
            os_release=os_release,
            architecture=architecture,
            namespace_inventory=namespaces,
            link_inventory=links,
            listeners=listeners,
            orphaned_temporary_roots=orphans,
        )
        versions = verify_preflight(
            expected_tools=expected_tools,
            expected_module=expected_module,
            command_runner=self.command_runner,
            loaded_version_reader=lambda: self.protected_reader.read_text(
                pathlib.Path("/sys/module/amneziawg/version")
            ),
        )
        kernel = _runner_output(self.command_runner, ["uname", "-r"]).decode(
            "ascii"
        ).strip()
        os_values = _parse_os_release(os_release)
        return PreflightEvidence(
            source_commit=head.decode("ascii").strip(),
            dirty_worktree=False,
            os_version=os_values["VERSION_ID"],
            architecture=architecture.decode("ascii").strip(),
            kernel=kernel,
            versions=versions,
        )

    def verify_locked_state(
        self,
        *,
        preflight: PreflightEvidence,
        expected_tools: str,
        expected_module: str,
    ) -> None:
        """Revalidate non-locking state after the manager flock is held."""
        if self.effective_uid() != 0:
            _fail("non-root qualification is forbidden")
        git_prefix = read_only_git_prefix()
        git_status = _runner_output(
            self.command_runner, [*git_prefix, "status", "--porcelain=v1"]
        )
        head = _runner_output(
            self.command_runner, [*git_prefix, "rev-parse", "HEAD"]
        ).decode("ascii").strip()
        origin_main = _runner_output(
            self.command_runner, [*git_prefix, "rev-parse", "origin/main"]
        ).decode("ascii").strip()
        if git_status or head != origin_main or head != preflight.source_commit:
            _fail("source state changed before locked qualification")
        try:
            config = load_config()
            transition = load_transition_document(required=False)
            service_operation = load_service_operation_intent(required=False)
        except AwgctlError as exc:
            raise QualificationError(safe_error(exc)) from exc
        obfuscation = config.get("obfuscation")
        if (
            not isinstance(obfuscation, dict)
            or obfuscation.get("mode") != "classic"
            or transition is not None
            or service_operation is not None
        ):
            _fail("classic production state changed before locked qualification")
        service = _runner_output(
            self.command_runner,
            ["systemctl", "is-active", "awg-quick@awg0.service"],
        )
        boot = _runner_output(
            self.command_runner,
            ["systemctl", "is-enabled", "awg-quick@awg0.service"],
        )
        if service != b"active\n" or boot != b"enabled\n":
            _fail("production service state changed before locked qualification")
        versions = verify_preflight(
            expected_tools=expected_tools,
            expected_module=expected_module,
            command_runner=self.command_runner,
            loaded_version_reader=lambda: self.protected_reader.read_text(
                pathlib.Path("/sys/module/amneziawg/version")
            ),
        )
        kernel = _runner_output(self.command_runner, ["uname", "-r"]).decode(
            "ascii"
        ).strip()
        if versions != preflight.versions or kernel != preflight.kernel:
            _fail("native version state changed before locked qualification")

    def capture_snapshot(self) -> ProductionSnapshot:
        return capture_production_snapshot(
            self.command_runner, self.protected_reader
        )

    def qualify_namespaces(self) -> dict[str, bool]:
        header_material = secrets.token_bytes(32)
        if len(header_material) != 32:
            _fail("CSPRNG returned invalid isolated header material")
        awg31 = build_russia_ios_obfuscation(
            pathlib.Path("/opt/amneziawg/keys/server/header-protection"),
            mtu=1280,
        )
        qualifier = self.namespace_factory(self.command_runner)
        return qualifier.qualify(_CLASSIC_CANDIDATE, awg31, header_material)

    def now(self) -> str:
        return self.clock()


def execute_qualification(
    *,
    expected_tools: str,
    expected_module: str,
    adapters: LiveAdapters,
    receipt_writer: ReceiptWriter,
) -> pathlib.Path:
    """Execute preflight, isolated traffic, invariant comparison, then receipt."""
    started_at = adapters.now()
    evidence = adapters.verify_preflight(
        expected_tools=expected_tools,
        expected_module=expected_module,
    )
    with adapters.mutation_exclusion():
        adapters.verify_locked_state(
            preflight=evidence,
            expected_tools=expected_tools,
            expected_module=expected_module,
        )
        before = adapters.capture_snapshot()
        qualification_error: BaseException | None = None
        namespace_checks: Mapping[str, bool] | None = None
        try:
            namespace_checks = adapters.qualify_namespaces()
        except BaseException as exc:
            qualification_error = exc
        after = adapters.capture_snapshot()
        if before != after:
            raise QualificationError(
                "production invariants changed; no receipt was written and no repair was attempted"
            ) from qualification_error
        if qualification_error is not None:
            raise qualification_error
        if not isinstance(namespace_checks, Mapping):
            _fail("isolated qualifier returned invalid checks")
        checks = {
            "version_parsing": True,
            **dict(namespace_checks),
            "production_invariants": True,
        }
        completed_at = adapters.now()
        receipt = build_receipt(
            source_commit=evidence.source_commit,
            dirty_worktree=evidence.dirty_worktree,
            os_version=evidence.os_version,
            architecture=evidence.architecture,
            kernel=evidence.kernel,
            versions=evidence.versions,
            checks=checks,
            started_at=started_at,
            completed_at=completed_at,
        )
        return receipt_writer(receipt)


def _default_receipt_writer(receipt: Mapping[str, object]) -> pathlib.Path:
    started = receipt.get("started_at")
    versions = receipt.get("versions")
    if type(started) is not str or not isinstance(versions, Mapping):
        _fail("cannot derive qualification receipt filename")
    tools = versions.get("tools")
    if type(tools) is not str or _VERSION.fullmatch(tools) is None:
        _fail("cannot derive qualification receipt filename")
    stamp = started.replace("-", "").replace(":", "")
    return atomic_write_receipt(
        receipt,
        pathlib.Path("/opt/amneziawg/qualification"),
        f"{stamp}-{tools}.json",
    )


def _version_argument(value: str) -> str:
    if _VERSION.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected N.N.N native version")
    return value


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
) -> int:
    """Run the source-only qualifier and print one secret-free JSON envelope."""
    parser = argparse.ArgumentParser(
        description="Qualify one exact AWG 3.1 pair on this classic production host",
        exit_on_error=False,
    )
    parser.add_argument("--expected-tools", required=True, type=_version_argument)
    parser.add_argument("--expected-module", required=True, type=_version_argument)
    output = stdout if stdout is not None else sys.stdout
    try:
        arguments = parser.parse_args(argv)
    except (argparse.ArgumentError, argparse.ArgumentTypeError) as exc:
        output.write(json.dumps({"ok": False, "error": safe_error(exc)}) + "\n")
        return 2

    def interrupted(signum: int, _frame: Any) -> NoReturn:
        raise QualificationInterrupted(
            f"qualification interrupted by signal {signum}"
        )

    previous_umask = os.umask(0o077)
    previous_handlers: dict[signal.Signals, Any] = {}
    try:
        for selected in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[selected] = signal.signal(selected, interrupted)
        receipt = execute_qualification(
            expected_tools=arguments.expected_tools,
            expected_module=arguments.expected_module,
            adapters=LiveAdapters(),
            receipt_writer=_default_receipt_writer,
        )
        output.write(
            json.dumps(
                {
                    "ok": True,
                    "receipt": str(receipt),
                    "summary": {
                        "scope": "isolated exact-host native qualification",
                        "tools": arguments.expected_tools,
                        "module": arguments.expected_module,
                    },
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 0
    except QualificationError as exc:
        output.write(
            json.dumps({"ok": False, "error": safe_error(exc)}, sort_keys=True)
            + "\n"
        )
        return 1
    except Exception:
        output.write(
            json.dumps(
                {
                    "ok": False,
                    "error": "qualification failed at a protected operational boundary",
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 1
    finally:
        for selected, previous in previous_handlers.items():
            signal.signal(selected, previous)
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
