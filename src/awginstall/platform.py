"""Strict Ubuntu 24.04 amd64 platform detection."""

from __future__ import annotations

import pathlib
import platform as platform_module


class PlatformError(RuntimeError):
    """The host is outside the deliberately narrow support matrix."""


def read_os_release(path: pathlib.Path = pathlib.Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def validate_platform(os_release: dict[str, str], *, machine: str | None = None) -> dict[str, str]:
    machine = machine or platform_module.machine()
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        raise PlatformError("only Ubuntu 24.04 LTS is supported")
    if os_release.get("VERSION_CODENAME") not in {None, "noble"}:
        raise PlatformError("Ubuntu 24.04 must use the noble package series")
    if machine not in {"x86_64", "amd64"}:
        raise PlatformError("only amd64 is supported in this beta release")
    return {
        "distribution": "ubuntu",
        "version": "24.04",
        "codename": "noble",
        "architecture": "amd64",
    }
