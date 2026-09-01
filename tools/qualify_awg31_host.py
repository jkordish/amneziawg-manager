#!/usr/bin/env python3
"""Qualify an exact AmneziaWG 3.1 pair without touching production state."""

from __future__ import annotations

import dataclasses
import datetime as dt
import base64
import json
import math
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any, Callable, NoReturn


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from awgctl.core import AWG31_QUALIFICATION_POLICY_VERSION
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
    for link in reversed(resources.host_links):
        try:
            _runner_output(resources.runner, ["ip", "link", "delete", link])
        except Exception as exc:
            cleanup_errors.append(exc)
    for namespace in reversed(resources.namespaces):
        try:
            _runner_output(
                resources.runner, ["ip", "netns", "delete", namespace]
            )
        except Exception as exc:
            cleanup_errors.append(exc)

    try:
        remaining_namespaces = _namespace_names(
            _runner_output(resources.runner, ["ip", "netns", "list"])
        )
        remaining_links = _root_link_names(
            _runner_output(resources.runner, ["ip", "-j", "link", "show"])
        )
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
            self._run(["ip", "netns", "add", namespace])
            self.resources.namespaces.append(namespace)
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
