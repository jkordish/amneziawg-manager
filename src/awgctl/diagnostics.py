"""Creation of secret-safe, integrity-manifested diagnostic directories."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import tempfile
from collections.abc import Mapping


_KEY_LINE = re.compile(r"^(\s*(?:PrivateKey|PublicKey|PresharedKey)\s*=\s*)(\S+)(\s*)$", re.MULTILINE)


class DiagnosticsError(RuntimeError):
    """A diagnostic bundle could not be created safely."""


def redact_awg_config(text: str) -> str:
    """Replace all key values while retaining a correlation-safe fingerprint."""

    def replace(match: re.Match[str]) -> str:
        digest = hashlib.sha256(match.group(2).encode("utf-8")).hexdigest()[:16]
        return f"{match.group(1)}[redacted sha256:{digest}]{match.group(3)}"

    return _KEY_LINE.sub(replace, text)


def _safe_relative(name: str) -> pathlib.PurePosixPath:
    relative = pathlib.PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise DiagnosticsError(f"unsafe diagnostic path: {name}")
    return relative


def _write_private(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = pathlib.Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def create_bundle(
    parent: pathlib.Path,
    *,
    product_version: str,
    created_at: str,
    files: Mapping[str, bytes],
) -> pathlib.Path:
    if parent.exists() and (not parent.is_dir() or parent.is_symlink()):
        raise DiagnosticsError(f"diagnostic parent is not a safe directory: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stem = created_at.replace("-", "").replace(":", "").replace("Z", "Z").replace("T", "T")
    candidate = parent / stem
    counter = 1
    while candidate.exists():
        candidate = parent / f"{stem}-{counter:02d}"
        counter += 1
    candidate.mkdir(mode=0o700)
    manifest_files: list[dict[str, object]] = []
    try:
        for name, data in sorted(files.items()):
            relative = _safe_relative(name)
            target = candidate / pathlib.Path(*relative.parts)
            _write_private(target, data)
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
        _write_private(candidate / "manifest.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    except Exception:
        import shutil

        shutil.rmtree(candidate, ignore_errors=True)
        raise
    return candidate
