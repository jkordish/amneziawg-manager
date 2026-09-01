"""Secret-safe backup manifests and verification."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
from typing import Any


class BackupError(RuntimeError):
    """Backup integrity or safety validation failed."""


def _relative_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    )


def create_manifest(
    root: pathlib.Path,
    *,
    product_version: str,
    created_at: str,
) -> dict[str, Any]:
    files = []
    for relative in _relative_files(root):
        path = root / relative
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise BackupError(f"unsafe backup entry: {relative.as_posix()}")
        data = path.read_bytes()
        files.append(
            {
                "path": relative.as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
        )
    return {
        "schema_version": 1,
        "created_at": created_at,
        "product_version": product_version,
        "files": files,
    }


def verify_backup(
    root: pathlib.Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise BackupError(f"backup directory not found: {root}")
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("backup manifest is missing or invalid") from exc
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), list):
        raise BackupError("unsupported backup manifest schema")
    expected_entries: dict[str, dict[str, Any]] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise BackupError("invalid backup manifest file entry")
        relative = pathlib.PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise BackupError("unsafe path in backup manifest")
        if entry["path"] in expected_entries:
            raise BackupError(f"duplicate backup manifest path: {entry['path']}")
        expected_entries[entry["path"]] = entry
    actual_entries = {path.as_posix() for path in _relative_files(root)}
    unexpected = sorted(actual_entries - expected_entries.keys())
    missing = sorted(expected_entries.keys() - actual_entries)
    if unexpected:
        raise BackupError(f"unexpected backup file: {unexpected[0]}")
    if missing:
        raise BackupError(f"missing backup file: {missing[0]}")
    for directory in [root, *(path for path in root.rglob("*") if path.is_dir())]:
        metadata = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise BackupError(f"unsafe backup directory: {directory.relative_to(root)}")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise BackupError(f"backup directory mode is not 0700: {directory.relative_to(root)}")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise BackupError(f"backup directory ownership mismatch: {directory.relative_to(root)}")
    for name, entry in expected_entries.items():
        path = root / pathlib.Path(*pathlib.PurePosixPath(name).parts)
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise BackupError(f"unsafe backup file: {name}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
            raise BackupError(f"hash mismatch: {name}")
        if len(data) != entry.get("size"):
            raise BackupError(f"size mismatch: {name}")
        if stat.S_IMODE(metadata.st_mode) != 0o600 or entry.get("mode") != 0o600:
            raise BackupError(f"backup file mode is not 0600: {name}")
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            raise BackupError(f"backup file ownership mismatch: {name}")
        if (entry.get("uid"), entry.get("gid")) != (expected_uid, expected_gid):
            raise BackupError(f"manifest ownership mismatch: {name}")
    manifest_metadata = manifest_path.lstat()
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o600:
        raise BackupError("backup manifest mode is not 0600")
    if (manifest_metadata.st_uid, manifest_metadata.st_gid) != (expected_uid, expected_gid):
        raise BackupError("backup manifest ownership mismatch")
    return {
        "ok": True,
        "path": str(root),
        "created_at": manifest.get("created_at"),
        "product_version": manifest.get("product_version"),
        "file_count": len(expected_entries),
    }
