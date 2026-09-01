"""Command-line entry point for source checkout installation workflows."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from typing import TextIO

from awgctl.version import VERSION

from .installer import InstallerError, upgrade_product
from .platform import PlatformError, read_os_release, validate_platform


DEFAULT_ROOT = pathlib.Path("/opt/amneziawg")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install, adopt, or upgrade the AmneziaWG manager on Ubuntu 24.04 Lightsail",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="perform read-only host preflight")
    check.add_argument("--json", action="store_true")
    for name in ("install", "adopt", "upgrade"):
        command = commands.add_parser(name)
        command.add_argument("--dry-run", action="store_true")
        command.add_argument("--yes", action="store_true")
        command.add_argument("--json", action="store_true")
    return parser


def _share_files(repo_root: pathlib.Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {"VERSION": (VERSION + "\n").encode()}
    candidates = {
        "README.md": repo_root / "README.md",
        "completions/awgctl.bash": repo_root / "awgctl-completion.bash",
    }
    docs = repo_root / "docs"
    if docs.is_dir():
        for path in sorted(docs.rglob("*.md")):
            candidates[f"docs/{path.relative_to(docs).as_posix()}"] = path
    for name, path in candidates.items():
        if path.is_file():
            result[name] = path.read_bytes()
    return result


def _build_artifact(repo_root: pathlib.Path, output: pathlib.Path) -> None:
    result = subprocess.run(
        [sys.executable, str(repo_root / "tools/build_release.py"), "--output", str(output)],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise InstallerError(f"release build failed: {detail or 'unknown error'}")


def _health_check(executable: pathlib.Path) -> int:
    result = subprocess.run(
        [str(executable), "health"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    return result.returncode


def _emit(output: TextIO, payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True), file=output)
    else:
        print(str(payload["message"]), file=output)


def main(
    argv: Sequence[str] | None = None,
    *,
    root: pathlib.Path = DEFAULT_ROOT,
    repo_root: pathlib.Path | None = None,
    output: TextIO = sys.stdout,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = (repo_root or pathlib.Path(__file__).parents[2]).resolve()
    try:
        if args.command == "check":
            platform_info = validate_platform(read_os_release())
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "platform": platform_info,
                    "message": "Host platform is supported: Ubuntu 24.04 amd64",
                },
                as_json=args.json,
            )
            return 0
        if args.command == "upgrade":
            if args.dry_run:
                _emit(
                    output,
                    {
                        "schema_version": 1,
                        "ok": True,
                        "version": VERSION,
                        "root": str(root),
                        "message": f"Dry run: would install awgctl {VERSION} into {root}",
                    },
                    as_json=args.json,
                )
                return 0
            if root == DEFAULT_ROOT and os.geteuid() != 0:
                raise InstallerError("run installation with sudo")
            with tempfile.TemporaryDirectory(prefix="awgctl-release-") as directory:
                artifact = pathlib.Path(directory) / "awgctl"
                _build_artifact(repo_root, artifact)
                upgrade_product(
                    root=root,
                    artifact=artifact,
                    version=VERSION,
                    share_files=_share_files(repo_root),
                    health_check=_health_check,
                )
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "version": VERSION,
                    "message": f"Installed awgctl {VERSION} into {root}",
                },
                as_json=args.json,
            )
            return 0
        raise InstallerError(f"{args.command} workflow is not implemented yet")
    except (InstallerError, PlatformError) as exc:
        print(f"install.py: {exc}", file=sys.stderr)
        return 1
