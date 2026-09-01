"""Dependency-free SemVer 2.0 validation and precedence for release versions."""

from __future__ import annotations

import re


_VERSION_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class InvalidVersion(ValueError):
    """A version is outside the repository-supported SemVer grammar."""


def precedence_key(
    value: str,
) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
    if not isinstance(value, str):
        raise InvalidVersion("version must be a string")
    match = _VERSION_RE.fullmatch(value)
    if not match:
        raise InvalidVersion("invalid semantic version")
    major, minor, patch = (int(part) for part in match.groups()[:3])
    prerelease = match.group(4)
    identifiers: list[tuple[int, int | str]] = []
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    raise InvalidVersion("numeric prerelease identifier has a leading zero")
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier))
    return major, minor, patch, 0 if prerelease is not None else 1, tuple(identifiers)
