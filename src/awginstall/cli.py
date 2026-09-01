"""Command-line entry point for source checkout installation workflows."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import shutil
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
        if name == "install":
            command.add_argument("--endpoint")
            command.add_argument("--subnet", default="10.77.42.0/24")
            command.add_argument("--listen-port", type=int, default=55323)
            command.add_argument("--external-interface")
            command.add_argument("--dns", default="1.1.1.1,1.0.0.1")
            command.add_argument("--mtu", type=int, default=1280)
            command.add_argument("--keepalive", type=int, default=25)
            command.add_argument("--first-client", default="admin-phone")
            command.add_argument("--owner")
            command.add_argument("--device")
        elif name == "adopt":
            command.add_argument("--server-config", type=pathlib.Path, default=pathlib.Path("/etc/amnezia/amneziawg/awg0.conf"))
            command.add_argument("--client-config", type=pathlib.Path)
            command.add_argument("--client-name", default="imported-device")
            command.add_argument("--external-interface")
    return parser


def package_install_plan(kernel: str) -> list[list[str]]:
    if not kernel or "/" in kernel or any(character.isspace() for character in kernel):
        raise InstallerError("invalid running kernel release")
    return [
        ["apt-get", "update"],
        [
            "apt-get", "install", "-y", "software-properties-common", "python3-launchpadlib",
            "gnupg2", f"linux-headers-{kernel}", "linux-headers-generic", "qrencode", "nftables",
        ],
        ["add-apt-repository", "-y", "ppa:amnezia/ppa"],
        ["apt-get", "update"],
        ["apt-get", "install", "-y", "amneziawg", "qrencode", "nftables"],
    ]


def parse_default_interface(route_output: str) -> str:
    devices: list[str] = []
    for line in route_output.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default" or "dev" not in fields:
            continue
        index = fields.index("dev")
        if index + 1 < len(fields) and fields[index + 1] not in devices:
            devices.append(fields[index + 1])
    if len(devices) != 1:
        raise InstallerError("could not determine one unambiguous IPv4 default route interface")
    return devices[0]


def _run(argv: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallerError(f"could not run required command: {argv[0]}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise InstallerError(f"command failed: {argv[0]}{': ' + detail[-1] if detail else ''}")
    return result


def _detect_external_interface() -> str:
    return parse_default_interface(_run(["ip", "-4", "route", "show", "default"], timeout=30).stdout.decode())


def _install_amneziawg_packages() -> None:
    usage = shutil.disk_usage("/")
    if usage.free < 5 * 1024**3:
        raise InstallerError("at least 5 GiB free on / is required before the DKMS/package installation")
    for command in package_install_plan(os.uname().release):
        _run(command)
    _run(["modprobe", "amneziawg"], timeout=60)
    for command in ("awg", "awg-quick", "nft", "ip", "systemctl", "qrencode", "dkms"):
        if shutil.which(command) is None:
            raise InstallerError(f"package installation did not provide required command: {command}")
    dkms = _run(["dkms", "status"], timeout=60).stdout.decode("utf-8", "replace")
    if "amneziawg" not in dkms or os.uname().release not in dkms or "installed" not in dkms:
        raise InstallerError("AmneziaWG DKMS is not installed for the running kernel")


def _install_entrypoints(root: pathlib.Path, repo_root: pathlib.Path) -> None:
    def atomic_public_file(path: pathlib.Path, data: bytes, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = pathlib.Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise

    readme = repo_root / "README.md"
    if readme.is_file():
        atomic_public_file(root / "README.md", readme.read_bytes(), 0o644)
    if root == DEFAULT_ROOT:
        public = pathlib.Path("/usr/local/sbin/awgctl")
        public.parent.mkdir(parents=True, exist_ok=True)
        temporary = public.parent / f".awgctl.{os.getpid()}"
        temporary.unlink(missing_ok=True)
        os.symlink(str(root / "bin/awgctl"), temporary)
        os.replace(temporary, public)
        completion_source = repo_root / "awgctl-completion.bash"
        if completion_source.is_file():
            atomic_public_file(pathlib.Path("/etc/bash_completion.d/awgctl"), completion_source.read_bytes(), 0o644)


def _deploy_source_release(root: pathlib.Path, repo_root: pathlib.Path, *, health: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="awgctl-release-") as directory:
        artifact = pathlib.Path(directory) / "awgctl"
        _build_artifact(repo_root, artifact)
        upgrade_product(
            root=root,
            artifact=artifact,
            version=VERSION,
            share_files=_share_files(repo_root),
            health_check=_health_check if health else None,
        )
    _install_entrypoints(root, repo_root)


def _adoption_backup(root: pathlib.Path, server: pathlib.Path, client: pathlib.Path) -> pathlib.Path:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = root / "adoption-backups" / timestamp
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination.parent, 0o700)
    for source, name in ((server, "server.conf"), (client, "client.conf")):
        target = destination / name
        target.write_bytes(source.read_bytes())
        os.chmod(target, 0o600)
    return destination


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
        platform_info = validate_platform(read_os_release())
        if args.command == "install":
            if not args.endpoint:
                raise InstallerError("fresh install requires --endpoint HOSTNAME")
            external = args.external_interface
            if args.dry_run:
                external = external or "auto-detect-default-route"
                _emit(
                    output,
                    {
                        "schema_version": 1,
                        "ok": True,
                        "dry_run": True,
                        "platform": platform_info,
                        "message": (
                            f"Dry run: would install kernel headers and AmneziaWG from the official Amnezia PPA, "
                            f"deploy awgctl {VERSION}, initialize awg0 on {args.endpoint}:{args.listen_port}, "
                            f"and create {args.first_client}; external interface: {external}"
                        ),
                    },
                    as_json=args.json,
                )
                return 0
            if root == DEFAULT_ROOT and os.geteuid() != 0:
                raise InstallerError("run installation with sudo")
            if not args.yes:
                raise InstallerError("fresh installation is mutating; rerun with --yes after reviewing --dry-run")
            if (root / "config/server.json").exists() or pathlib.Path("/etc/amnezia/amneziawg/awg0.conf").exists():
                raise InstallerError("existing awg0 state detected; use adopt or upgrade, not fresh install")
            _install_amneziawg_packages()
            external = external or _detect_external_interface()
            _deploy_source_release(root, repo_root, health=False)
            command = [
                str(root / "bin/awgctl"), "_initialize-fresh",
                "--endpoint", args.endpoint,
                "--subnet", args.subnet,
                "--listen-port", str(args.listen_port),
                "--external-interface", external,
                "--dns", args.dns,
                "--mtu", str(args.mtu),
                "--keepalive", str(args.keepalive),
                "--first-client", args.first_client,
            ]
            if args.owner:
                command.extend(["--owner", args.owner])
            if args.device:
                command.extend(["--device", args.device])
            initialized = _run(command, timeout=120)
            health = _health_check(root / "bin/awgctl")
            if health != 0:
                raise InstallerError("fresh installation completed but awgctl health failed")
            message = initialized.stdout.decode("utf-8", "replace").strip()
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "version": VERSION,
                    "message": message or f"Installed AmneziaWG and awgctl {VERSION}",
                },
                as_json=args.json,
            )
            return 0
        if args.command == "adopt":
            if args.client_config is None:
                raise InstallerError("adoption requires --client-config PATH for the existing device profile")
            server = args.server_config.resolve()
            client = args.client_config.resolve()
            if not server.is_file() or not client.is_file():
                raise InstallerError("existing server and client configuration files must both exist")
            external = args.external_interface
            if args.dry_run:
                external = external or "auto-detect-default-route"
                _emit(
                    output,
                    {
                        "schema_version": 1,
                        "ok": True,
                        "dry_run": True,
                        "platform": platform_info,
                        "message": (
                            f"Dry run: would back up and adopt {server} with client {args.client_name}, "
                            f"preserving all existing credentials and runtime identity; external interface: {external}"
                        ),
                    },
                    as_json=args.json,
                )
                return 0
            if root == DEFAULT_ROOT and os.geteuid() != 0:
                raise InstallerError("run adoption with sudo")
            if not args.yes:
                raise InstallerError("adoption is mutating; rerun with --yes after reviewing --dry-run")
            if (root / "config/server.json").exists():
                raise InstallerError("manager state already exists; use upgrade")
            for command_name in ("awg", "awg-quick", "nft", "ip", "systemctl", "qrencode", "dkms"):
                if shutil.which(command_name) is None:
                    raise InstallerError(f"working-host adoption requires command: {command_name}")
            external = external or _detect_external_interface()
            backup = _adoption_backup(root, server, client)
            _deploy_source_release(root, repo_root, health=False)
            adopted = _run(
                [
                    str(root / "bin/awgctl"), "_migrate-existing",
                    "--server-config", str(server),
                    "--client-config", str(client),
                    "--client-name", args.client_name,
                    "--interface", "awg0",
                    "--external-interface", external,
                ],
                timeout=120,
            )
            if _health_check(root / "bin/awgctl") != 0:
                raise InstallerError("adoption completed but awgctl health failed")
            message = adopted.stdout.decode("utf-8", "replace").strip()
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "version": VERSION,
                    "adoption_backup": str(backup),
                    "message": message or f"Adopted existing awg0 into awgctl {VERSION}",
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
            _deploy_source_release(root, repo_root, health=True)
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
