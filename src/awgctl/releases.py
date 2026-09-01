"""Strict parsing and OpenSSH verification for published awgctl releases."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

from .semver import InvalidVersion, precedence_key


RELEASE_IDENTITY = "releases@amneziawg-manager"
RELEASE_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILyqkGfE04/pFwwS2b+K0trRm6SFVhAGSqrTewfpOhpO releases@amneziawg-manager"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GITHUB_REPOSITORY = "jkordish/amneziawg-manager"


class ReleaseError(RuntimeError):
    """A release failed authenticity or integrity validation."""


def version_key(
    value: str,
) -> tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]:
    try:
        return precedence_key(value)
    except InvalidVersion as exc:
        raise ReleaseError(f"invalid release version: {value}") from exc


def _valid_tag(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("v"):
        return False
    try:
        version_key(value[1:])
    except ReleaseError:
        return False
    return True


def _version_channel(value: str) -> str:
    return "stable" if version_key(value)[3] == 1 else "beta"


def parse_manifest(
    data: bytes,
    *,
    expected_platform: str,
    expected_channel: str | None = None,
) -> dict[str, Any]:
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release manifest is not valid JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "version", "tag", "channel", "platform",
        "installation_schema_version", "artifact"
    }:
        raise ReleaseError("release manifest fields are incomplete or unexpected")
    version = manifest["version"]
    try:
        version_key(version)
    except ReleaseError as exc:
        raise ReleaseError("unsupported release manifest schema or version") from exc
    if manifest["schema_version"] != 1:
        raise ReleaseError("unsupported release manifest schema or version")
    if manifest["tag"] != f"v{version}":
        raise ReleaseError("release tag and version do not match")
    if manifest["channel"] not in {"beta", "stable"}:
        raise ReleaseError("unsupported release channel")
    if manifest["channel"] != _version_channel(version):
        raise ReleaseError("release channel does not match tag prerelease semantics")
    if expected_channel is not None:
        if expected_channel not in {"beta", "stable"}:
            raise ReleaseError("unsupported update channel")
        if manifest["channel"] != expected_channel:
            raise ReleaseError("signed release channel does not match requested channel")
    if manifest["platform"] != expected_platform:
        raise ReleaseError(f"release platform mismatch: expected {expected_platform}")
    if manifest["installation_schema_version"] != 1:
        raise ReleaseError("unsupported installation settings schema")
    artifact = manifest["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "size"}:
        raise ReleaseError("release artifact fields are incomplete or unexpected")
    if artifact["name"] != "awgctl.pyz":
        raise ReleaseError("unexpected release artifact name")
    if not isinstance(artifact["sha256"], str) or not _SHA256_RE.fullmatch(artifact["sha256"]):
        raise ReleaseError("invalid release artifact SHA-256")
    if not isinstance(artifact["size"], int) or isinstance(artifact["size"], bool) or not 1 <= artifact["size"] <= 16 * 1024 * 1024:
        raise ReleaseError("invalid release artifact size")
    return manifest


def verify_artifact(manifest: dict[str, Any], artifact: bytes) -> None:
    expected = manifest["artifact"]
    if len(artifact) != expected["size"]:
        raise ReleaseError("release artifact size mismatch")
    if hashlib.sha256(artifact).hexdigest() != expected["sha256"]:
        raise ReleaseError("release artifact hash mismatch")


def verify_ssh_signature(
    manifest: bytes,
    signature: bytes,
    *,
    public_key: str = RELEASE_PUBLIC_KEY,
) -> None:
    if not public_key.startswith("ssh-ed25519 "):
        raise ReleaseError("release public key is not Ed25519")
    with tempfile.TemporaryDirectory(prefix="awgctl-signature-") as directory:
        root = pathlib.Path(directory)
        allowed = root / "allowed_signers"
        signature_path = root / "release.json.sig"
        allowed.write_text(f"{RELEASE_IDENTITY} {public_key}\n", encoding="utf-8")
        signature_path.write_bytes(signature)
        os.chmod(allowed, 0o600)
        os.chmod(signature_path, 0o600)
        try:
            result = subprocess.run(
                [
                    "ssh-keygen", "-Y", "verify", "-q", "-f", str(allowed),
                    "-I", RELEASE_IDENTITY, "-n", "file", "-s", str(signature_path),
                ],
                input=manifest,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError("could not run OpenSSH release signature verification") from exc
    if result.returncode != 0:
        raise ReleaseError("release signature verification failed")


def fetch_bytes(url: str, *, maximum: int) -> bytes:
    if not url.startswith("https://"):
        raise ReleaseError("release URL must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "awgctl-release-check"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(maximum + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise ReleaseError(f"could not download release metadata from {url}") from exc
    if len(data) > maximum:
        raise ReleaseError("release download exceeds the safety limit")
    return data


def discover_release_tag(*, channel: str = "beta") -> str:
    if channel not in {"beta", "stable"}:
        raise ReleaseError("unsupported update channel")
    data = fetch_bytes(
        f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases?per_page=20",
        maximum=512 * 1024,
    )
    try:
        releases = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("GitHub release discovery returned invalid JSON") from exc
    if not isinstance(releases, list):
        raise ReleaseError("GitHub release discovery returned an unexpected response")
    for release in releases:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        if channel == "stable" and release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if _valid_tag(tag) and _version_channel(tag[1:]) == channel:
            return tag
    raise ReleaseError(f"no published {channel} release was found")


def fetch_verified_release(
    tag: str,
    *,
    expected_platform: str,
    expected_channel: str,
    include_artifact: bool,
) -> tuple[dict[str, Any], bytes | None]:
    if not _valid_tag(tag):
        raise ReleaseError("invalid discovered release tag")
    base = f"https://github.com/{GITHUB_REPOSITORY}/releases/download/{tag}"
    manifest_bytes = fetch_bytes(f"{base}/release.json", maximum=64 * 1024)
    signature = fetch_bytes(f"{base}/release.json.sig", maximum=16 * 1024)
    verify_ssh_signature(manifest_bytes, signature)
    manifest = parse_manifest(
        manifest_bytes,
        expected_platform=expected_platform,
        expected_channel=expected_channel,
    )
    if manifest["tag"] != tag:
        raise ReleaseError("signed manifest does not match the discovered release tag")
    if not include_artifact:
        return manifest, None
    artifact = fetch_bytes(f"{base}/{manifest['artifact']['name']}", maximum=16 * 1024 * 1024)
    verify_artifact(manifest, artifact)
    return manifest, artifact
