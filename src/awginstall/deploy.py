"""Atomic, versioned product deployment without touching VPN state."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import tempfile
from collections.abc import Mapping


class DeploymentError(RuntimeError):
    """A safe deployment error suitable for operator output."""


def _normalize_release_permissions(release: pathlib.Path) -> None:
    for directory, directories, files in os.walk(release):
        directory_path = pathlib.Path(directory)
        os.chmod(directory_path, 0o755)
        for name in directories:
            os.chmod(directory_path / name, 0o755)
        for name in files:
            os.chmod(directory_path / name, 0o755 if directory_path == release and name == "awgctl" else 0o644)


def _atomic_write(path: pathlib.Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _safe_relative(name: str) -> pathlib.PurePosixPath:
    value = pathlib.PurePosixPath(name)
    if value.is_absolute() or not value.parts or ".." in value.parts:
        raise DeploymentError(f"unsafe release path: {name}")
    return value


def active_release(root: pathlib.Path) -> str | None:
    selector = root / "bin/awgctl"
    if not selector.is_symlink():
        return None
    target = pathlib.PurePosixPath(os.readlink(selector))
    parts = target.parts
    if len(parts) != 4 or parts[:2] != ("..", "releases") or parts[3] != "awgctl":
        return None
    return parts[2]


def activate_release(root: pathlib.Path, version: str) -> None:
    artifact = root / "releases" / version / "awgctl"
    if not artifact.is_file():
        raise DeploymentError(f"release is incomplete: {version}")
    selector = root / "bin/awgctl"
    selector.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(selector.parent, 0o755)
    temporary = selector.parent / f".awgctl.{os.getpid()}"
    temporary.unlink(missing_ok=True)
    os.symlink(f"../releases/{version}/awgctl", temporary)
    os.replace(temporary, selector)


def install_release(
    *,
    root: pathlib.Path,
    artifact: pathlib.Path,
    version: str,
    share_files: Mapping[str, bytes] | None = None,
) -> pathlib.Path:
    """Install an immutable release and atomically make it active."""
    if not version or "/" in version or version in {".", ".."}:
        raise DeploymentError("invalid release version")
    if not artifact.is_file():
        raise DeploymentError(f"release artifact not found: {artifact}")
    share_files = share_files or {}
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o755)
    releases = root / "releases"
    releases.mkdir(mode=0o755, exist_ok=True)
    final = releases / version
    if final.exists():
        installed = final / "awgctl"
        if not installed.is_file() or installed.read_bytes() != artifact.read_bytes():
            raise DeploymentError(f"release already exists with different content: {version}")
        _normalize_release_permissions(final)
        activate_release(root, version)
        return final

    staging = pathlib.Path(tempfile.mkdtemp(prefix=f".{version}.", dir=releases))
    try:
        _atomic_write(staging / "awgctl", artifact.read_bytes(), 0o755)
        files = ["awgctl"]
        hashes = {"awgctl": hashlib.sha256(artifact.read_bytes()).hexdigest()}
        for name, data in sorted(share_files.items()):
            relative = _safe_relative(name)
            target = staging / "share" / pathlib.Path(*relative.parts)
            _atomic_write(target, data, 0o644)
            path_name = f"share/{relative.as_posix()}"
            files.append(path_name)
            hashes[path_name] = hashlib.sha256(data).hexdigest()
        manifest = {
            "schema_version": 1,
            "installation_schema_version": 1,
            "version": version,
            "files": files,
            "sha256": hashes,
        }
        _atomic_write(
            staging / "install-manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            0o644,
        )
        _normalize_release_permissions(staging)
        os.replace(staging, final)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    activate_release(root, version)
    return final


def preserve_legacy_release(root: pathlib.Path) -> str | None:
    """Import a pre-versioned executable exactly once for safe rollback."""
    selector = root / "bin/awgctl"
    if selector.is_symlink() or not selector.is_file():
        return active_release(root)
    version = "legacy-import"
    final = root / "releases" / version
    if final.exists():
        if (final / "awgctl").read_bytes() != selector.read_bytes():
            raise DeploymentError("legacy-import already exists with different content")
        _normalize_release_permissions(final)
        return version
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = pathlib.Path(tempfile.mkdtemp(prefix=".legacy-import.", dir=final.parent))
    try:
        data = selector.read_bytes()
        _atomic_write(staging / "awgctl", data, 0o755)
        manifest = {
            "schema_version": 1,
            "installation_schema_version": 1,
            "version": version,
            "files": ["awgctl"],
            "sha256": {"awgctl": hashlib.sha256(data).hexdigest()},
        }
        _atomic_write(
            staging / "install-manifest.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(),
            0o644,
        )
        _normalize_release_permissions(staging)
        os.replace(staging, final)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return version
