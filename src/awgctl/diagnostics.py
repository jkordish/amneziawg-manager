"""Creation of secret-safe, integrity-manifested diagnostic directories."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
from collections.abc import Mapping


_KEY_ASSIGNMENT = re.compile(
    r"(\b(?P<name>PrivateKey|PublicKey|PresharedKey|HeaderProtectionKey)\s*=\s*)"
    r"(?P<value>[^\s,;]+)",
)
_CPS_ASSIGNMENT_START = re.compile(r"\bI[1-5][ \t]*=[ \t]*")
_CPS_TAG = re.compile(
    r"<(?:b 0x(?P<bytes>[0-9a-fA-F]+)|(?P<timestamp>t)|"
    r"(?:r|rc|rd) (?P<size>[1-9][0-9]{0,3}))>"
)
_CPS_WRAPPERS = frozenset("'\"`")


class DiagnosticsError(RuntimeError):
    """A diagnostic bundle could not be created safely."""


def _cps_wrapper_at(text: str, position: int) -> tuple[str | None, int]:
    if position < len(text) and text[position] in _CPS_WRAPPERS:
        return text[position], 1
    if (
        position + 1 < len(text)
        and text[position] == "\\"
        and text[position + 1] in _CPS_WRAPPERS
    ):
        return text[position + 1], 2
    return None, 0


def _cps_ambiguous_end(text: str, position: int) -> int:
    """Bound an untrusted assignment at the next line or assignment boundary."""
    following = _CPS_ASSIGNMENT_START.search(text, position)
    boundary = following.start() if following is not None else len(text)
    candidates = [
        index
        for index in (
            text.find("\r", position, boundary),
            text.find("\n", position, boundary),
        )
        if index >= 0
    ]
    return min(candidates, default=boundary)


def _cps_payload_end(text: str, position: int) -> int:
    wrapper, wrapper_width = _cps_wrapper_at(text, position)
    cursor = position + wrapper_width
    tags = 0
    rendered_size = 0
    while cursor < len(text) and text[cursor] == "<":
        tag = _CPS_TAG.match(text, cursor)
        if tag is None:
            return _cps_ambiguous_end(text, position)
        encoded = tag.group("bytes")
        if encoded is not None:
            if len(encoded) % 2:
                return _cps_ambiguous_end(text, position)
            contribution = len(encoded) // 2
        elif tag.group("timestamp") is not None:
            contribution = 4
        else:
            contribution = int(tag.group("size"))
        rendered_size += contribution
        if contribution > 1000 or rendered_size > 1000:
            return _cps_ambiguous_end(text, position)
        tags += 1
        cursor = tag.end()
    if tags == 0:
        return _cps_ambiguous_end(text, position)
    if wrapper is not None:
        closing, closing_width = _cps_wrapper_at(text, cursor)
        if closing == wrapper:
            cursor += closing_width
    return cursor


def sanitize_cps_text(text: str) -> str:
    """Remove CPS assignment payloads from standalone or embedded native text."""
    parts: list[str] = []
    cursor = 0
    while assignment := _CPS_ASSIGNMENT_START.search(text, cursor):
        parts.append(text[cursor:assignment.end()])
        parts.append("[redacted]")
        payload_end = _cps_payload_end(text, assignment.end())
        cursor = max(payload_end, assignment.end())
    parts.append(text[cursor:])
    return "".join(parts)


def redact_awg_config(text: str) -> str:
    """Replace all key values while retaining a correlation-safe fingerprint."""

    def replace(match: re.Match[str]) -> str:
        value = match.group("value").encode("utf-8")
        length = 16
        if match.group("name") == "HeaderProtectionKey":
            length = 12
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, base64.binascii.Error):
                decoded = b""
            if len(decoded) == 32:
                value = decoded
        digest = hashlib.sha256(value).hexdigest()[:length]
        return f"{match.group(1)}[redacted sha256:{digest}]"

    return sanitize_cps_text(_KEY_ASSIGNMENT.sub(replace, text))


def _safe_relative(name: str) -> pathlib.PurePosixPath:
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise DiagnosticsError(f"unsafe diagnostic path: {name}")
    return relative


def _set_private_descriptor(fd: int, mode: int) -> None:
    os.fchown(fd, os.geteuid(), os.getegid())
    os.fchmod(fd, mode)


def _open_private_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(fd)
        raise DiagnosticsError(f"unsafe diagnostic directory: {name}")
    _set_private_descriptor(fd, 0o700)
    return fd


def _write_private(parent_fd: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise DiagnosticsError(f"cannot create diagnostic file: {name}") from exc
    try:
        _set_private_descriptor(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise DiagnosticsError(f"cannot write diagnostic file: {name}")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _same_open_directory(path: pathlib.Path, metadata: os.stat_result) -> bool:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (
        metadata.st_dev,
        metadata.st_ino,
    )


def _remove_open_directory_contents(directory_fd: int) -> None:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    for name in os.listdir(directory_fd):
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            os.unlink(name, dir_fd=directory_fd)
            continue
        child_fd = os.open(name, flags, dir_fd=directory_fd)
        try:
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise DiagnosticsError("diagnostic cleanup directory changed")
            _remove_open_directory_contents(child_fd)
        finally:
            os.close(child_fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise DiagnosticsError("diagnostic cleanup directory changed")
        os.rmdir(name, dir_fd=directory_fd)


def _remove_incomplete_candidate(
    parent_fd: int,
    candidate_name: str,
    candidate_fd: int,
) -> None:
    _remove_open_directory_contents(candidate_fd)
    opened = os.fstat(candidate_fd)
    named = os.stat(candidate_name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISDIR(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise DiagnosticsError("diagnostic candidate changed during cleanup")
    os.rmdir(candidate_name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def create_bundle(
    parent: pathlib.Path,
    *,
    product_version: str,
    created_at: str,
    files: Mapping[str, bytes],
) -> pathlib.Path:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = os.open(parent, flags)
    except OSError as exc:
        raise DiagnosticsError(f"diagnostic parent is not a safe directory: {parent}") from exc
    parent_metadata = os.fstat(parent_fd)
    if parent_metadata.st_uid != os.geteuid():
        os.close(parent_fd)
        raise DiagnosticsError("diagnostic parent is not owned by the effective user")
    if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        os.close(parent_fd)
        raise DiagnosticsError("diagnostic parent is writable by group or other users")
    stem = created_at.replace("-", "").replace(":", "").replace("Z", "Z").replace("T", "T")
    candidate_name = ""
    candidate_fd: int | None = None
    for _ in range(128):
        candidate_name = f"{stem}-{secrets.token_hex(16)}"
        try:
            os.mkdir(candidate_name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        candidate_fd = os.open(
            candidate_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        _set_private_descriptor(candidate_fd, 0o700)
        break
    if candidate_fd is None:
        os.close(parent_fd)
        raise DiagnosticsError("could not allocate a unique diagnostic bundle")
    candidate = parent / candidate_name
    manifest_files: list[dict[str, object]] = []
    directory_fds: dict[tuple[str, ...], int] = {(): candidate_fd}
    try:
        for name, data in sorted(files.items()):
            relative = _safe_relative(name)
            parent_parts = relative.parts[:-1]
            for length in range(1, len(parent_parts) + 1):
                parts = parent_parts[:length]
                if parts not in directory_fds:
                    directory_fds[parts] = _open_private_directory(
                        directory_fds[parts[:-1]],
                        parts[-1],
                    )
            _write_private(directory_fds[parent_parts], relative.name, data)
            manifest_files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
        manifest = {
            "schema_version": 1,
            "created_at": created_at,
            "product_version": product_version,
            "file_count": len(manifest_files),
            "files": manifest_files,
        }
        _write_private(candidate_fd, "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
        for fd in directory_fds.values():
            os.fsync(fd)
        os.fsync(parent_fd)
        if not _same_open_directory(parent, parent_metadata):
            raise DiagnosticsError("diagnostic parent path changed during bundle creation")
    except BaseException as original:
        try:
            _remove_incomplete_candidate(parent_fd, candidate_name, candidate_fd)
        except BaseException as cleanup_error:
            raise DiagnosticsError(
                "diagnostic bundle creation failed and incomplete bundle cleanup failed"
            ) from cleanup_error
        raise original
    finally:
        for _, fd in sorted(directory_fds.items(), key=lambda item: len(item[0]), reverse=True):
            os.close(fd)
        os.close(parent_fd)
    return candidate
