"""Command-line entry point for source checkout installation workflows."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import replace
from typing import TextIO

from awgctl.version import VERSION

from .host import (
    HostConfigurationError,
    HostConfigurationReport,
    HostPaths,
    configure_host,
    rollback_host_configuration,
)
from .identity import UserRecord
from .installer import InstallerError, upgrade_product
from .platform import PlatformError, read_os_release, validate_platform
from .settings import InstallationSettings, SettingsError, resolve_installation_settings
from .worker import WorkerError, build_in_confined_worker


DEFAULT_ROOT = pathlib.Path("/opt/amneziawg")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install, adopt, or upgrade the AmneziaWG manager on Ubuntu 24.04 amd64",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    def security_options(command: argparse.ArgumentParser, *, mutating: bool = True) -> None:
        command.add_argument("--settings", type=pathlib.Path, help="installation settings JSON")
        command.add_argument("--staging-user")
        command.add_argument("--staging-group")
        command.add_argument("--staging-uid", type=int)
        command.add_argument("--staging-gid", type=int)
        command.add_argument("--staging-root", type=pathlib.Path)
        command.add_argument("--operator-group")
        command.add_argument("--operator", action="append")
        command.add_argument(
            "--enroll-sudo-invoker", action=argparse.BooleanOptionalAction, default=None
        )
        command.add_argument("--sudo-policy", choices=("scoped-nopasswd", "existing-sudo", "none"))
        command.add_argument("--systemd-hardening", choices=("conservative", "off"))
        command.add_argument("--default-dns")
        command.add_argument(
            "--ingress-boundary",
            choices=("lightsail", "equivalent-external-firewall"),
        )
        if mutating:
            command.add_argument("--adopt-existing-identities", action="store_true")
            command.add_argument("--apply-default-dns", action="store_true")
            command.add_argument("--apply-live", action="store_true")

    check = commands.add_parser("check", help="perform read-only host preflight")
    check.add_argument("--json", action="store_true")
    security_options(check, mutating=False)
    for name in ("install", "adopt", "upgrade", "configure"):
        command = commands.add_parser(name)
        command.add_argument("--dry-run", action="store_true")
        command.add_argument("--yes", action="store_true")
        command.add_argument("--json", action="store_true")
        security_options(command)
        if name == "install":
            command.add_argument("--endpoint")
            command.add_argument("--subnet", default="10.77.42.0/24")
            command.add_argument("--listen-port", type=int, default=55323)
            command.add_argument("--external-interface")
            command.add_argument("--dns")
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


def _persisted_settings(root: pathlib.Path) -> InstallationSettings | None:
    path = root / "config/installation.json"
    try:
        if not path.is_file():
            return None
    except PermissionError:
        return None
    return resolve_installation_settings(settings_path=path, sudo_user=None)


def _resolved_settings(args: argparse.Namespace, *, root: pathlib.Path) -> InstallationSettings:
    names = (
        "staging_user", "staging_group", "staging_uid", "staging_gid", "staging_root",
        "operator_group", "sudo_policy", "systemd_hardening",
        "ingress_boundary",
    )
    overrides = {
        name: getattr(args, name)
        for name in names
        if getattr(args, name, None) is not None
    }
    if getattr(args, "operator", None):
        overrides["operators"] = args.operator
    if getattr(args, "enroll_sudo_invoker", None) is not None:
        overrides["enroll_sudo_invoker"] = args.enroll_sudo_invoker
    if getattr(args, "default_dns", None) is not None:
        overrides["default_dns"] = args.default_dns
    settings_path = getattr(args, "settings", None)
    if settings_path is None and args.command in {"check", "upgrade", "configure"}:
        persisted = root / "config/installation.json"
        try:
            if persisted.is_file():
                settings_path = persisted
        except PermissionError:
            pass
    return resolve_installation_settings(
        settings_path=settings_path,
        sudo_user=os.environ.get("SUDO_USER"),
        overrides=overrides,
    )


def _bootstrap_settings(settings: InstallationSettings) -> InstallationSettings:
    """Provision a builder without granting the pre-upgrade public CLI sudo."""
    return replace(
        settings,
        operators=(),
        enroll_sudo_invoker=False,
        sudo_policy="none",
        systemd_hardening="off",
    )


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
    libexec = root / "libexec"
    libexec.mkdir(parents=True, exist_ok=True)
    os.chmod(libexec, 0o755)
    internal = libexec / "awgctl-internal"
    temporary_internal = libexec / f".awgctl-internal.{os.getpid()}"
    temporary_internal.unlink(missing_ok=True)
    os.symlink("../bin/awgctl", temporary_internal)
    os.replace(temporary_internal, internal)
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


def _deploy_source_release(
    root: pathlib.Path,
    repo_root: pathlib.Path,
    *,
    health: bool,
    settings: InstallationSettings,
) -> None:
    # Health validates both selectors, so establish the stable selector layout
    # before activating and checking a new immutable release.
    _install_entrypoints(root, repo_root)
    with tempfile.TemporaryDirectory(prefix="awgctl-release-") as directory:
        artifact = pathlib.Path(directory) / "awgctl"
        _build_artifact(repo_root, artifact, settings=settings, confined=root == DEFAULT_ROOT)
        upgrade_product(
            root=root,
            artifact=artifact,
            version=VERSION,
            share_files=_share_files(repo_root),
            health_check=_health_check if health else None,
        )


def _rollback_host_reports(reports: Sequence[HostConfigurationReport]) -> None:
    """Roll completed host steps back in reverse transaction order."""
    errors: list[str] = []
    for report in reversed(reports):
        try:
            rollback_host_configuration(report)
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise HostConfigurationError(
            "host rollback was incomplete: " + "; ".join(errors)
        )


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
        "SECURITY.md": repo_root / "SECURITY.md",
        "CHANGELOG.md": repo_root / "CHANGELOG.md",
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


def _build_artifact(
    repo_root: pathlib.Path,
    output: pathlib.Path,
    *,
    settings: InstallationSettings,
    confined: bool,
) -> None:
    if confined:
        try:
            record = pwd.getpwnam(settings.staging_user)
        except KeyError as exc:
            raise InstallerError("staging account is unavailable for the source build") from exc
        build_in_confined_worker(
            settings,
            repo_root=repo_root,
            output=output,
            runner=_run,
            user=UserRecord(
                settings.staging_user,
                record.pw_uid,
                record.pw_gid,
                record.pw_dir,
                record.pw_shell,
            ),
        )
        return
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


def _configure_host_for_command(
    args: argparse.Namespace,
    *,
    root: pathlib.Path,
    settings: InstallationSettings,
) -> object:
    installed_settings = root / "config/installation.json"
    managed_identity_exists = False
    if not args.dry_run:
        try:
            managed_identity_exists = installed_settings.is_file()
        except PermissionError:
            managed_identity_exists = False
    allow_existing = bool(args.adopt_existing_identities or managed_identity_exists)
    return configure_host(
        settings,
        product_root=root,
        paths=HostPaths(),
        allow_existing=allow_existing,
        dry_run=bool(args.dry_run),
    )


def _apply_requested_runtime_settings(
    args: argparse.Namespace,
    *,
    root: pathlib.Path,
    settings: InstallationSettings,
) -> None:
    executable = root / "bin/awgctl"
    if getattr(args, "apply_default_dns", False):
        _run([str(executable), "config", "set", "dns", ",".join(settings.default_dns)], timeout=120)
    if getattr(args, "apply_live", False):
        _run([str(executable), "restart"], timeout=120)


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
        settings = _resolved_settings(args, root=root)
        if args.command == "check":
            platform_info = validate_platform(read_os_release())
            attested = settings.ingress_boundary is not None
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": attested,
                    "platform": platform_info,
                    "settings": settings.to_dict(),
                    "message": (
                        "Host platform is supported: Ubuntu 24.04 amd64; "
                        f"attested ingress boundary: {settings.ingress_boundary}"
                        if attested
                        else "Host platform is supported: Ubuntu 24.04 amd64; ingress boundary is not attested; run configure --ingress-boundary VALUE"
                    ),
                },
                as_json=args.json,
            )
            return 0 if attested else 1
        platform_info = validate_platform(read_os_release())
        if (
            args.command in {"install", "adopt", "upgrade", "configure"}
            and not args.dry_run
            and settings.ingress_boundary is None
        ):
            raise InstallerError(
                "ingress boundary attestation is required; pass --ingress-boundary "
                "lightsail or --ingress-boundary equivalent-external-firewall"
            )
        if args.command == "configure":
            if root == DEFAULT_ROOT and not args.dry_run and os.geteuid() != 0:
                raise InstallerError("run host configuration with sudo")
            if not args.dry_run and not args.yes:
                raise InstallerError("host configuration is mutating; rerun with --yes after reviewing --dry-run")
            report = _configure_host_for_command(args, root=root, settings=settings)
            if args.dry_run:
                payload = {
                    "schema_version": 1,
                    "ok": True,
                    "dry_run": True,
                    "settings": settings.to_dict(),
                    "identity_commands": [list(command) for command in report.identity.commands],
                    "sudoers": "would install scoped policy" if report.sudoers else "disabled",
                    "systemd_hardening": "would install" if report.service_hardening else "disabled",
                    "message": (
                        "Dry run: would configure the staging identity, operator policy, "
                        "confined workers, and native service hardening; "
                        f"attested ingress boundary: {settings.ingress_boundary or 'missing'}"
                    ),
                }
                _emit(output, payload, as_json=args.json)
                return 0
            if not (root / "bin/awgctl").exists() and (args.apply_default_dns or args.apply_live):
                raise InstallerError("runtime settings require an installed manager")
            _apply_requested_runtime_settings(args, root=root, settings=settings)
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "settings": settings.to_dict(),
                    "message": (
                        "Configured AmneziaWG Manager host identities and service policy; "
                        f"attested ingress boundary: {settings.ingress_boundary}"
                    ),
                },
                as_json=args.json,
            )
            return 0
        if args.command == "install":
            if not args.endpoint:
                raise InstallerError("fresh install requires --endpoint HOSTNAME")
            external = args.external_interface
            dns = args.dns or ",".join(settings.default_dns)
            if args.dry_run:
                external = external or "auto-detect-default-route"
                _emit(
                    output,
                    {
                        "schema_version": 1,
                        "ok": True,
                        "dry_run": True,
                        "platform": platform_info,
                        "settings": settings.to_dict(),
                        "message": (
                            f"Dry run: would install kernel headers and AmneziaWG from the official Amnezia PPA, "
                            f"deploy awgctl {VERSION}, initialize awg0 on {args.endpoint}:{args.listen_port}, "
                            f"and create {args.first_client}; external interface: {external}; DNS: {dns}; "
                            f"attested ingress boundary: {settings.ingress_boundary or 'missing (required for mutation)'}"
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
            bootstrap = _bootstrap_settings(settings)
            bootstrap_report = _configure_host_for_command(args, root=root, settings=bootstrap)
            try:
                _deploy_source_release(root, repo_root, health=False, settings=bootstrap)
            except Exception:
                rollback_host_configuration(bootstrap_report)
                raise
            _configure_host_for_command(args, root=root, settings=settings)
            command = [
                str(root / "libexec/awgctl-internal"), "_initialize-fresh",
                "--endpoint", args.endpoint,
                "--subnet", args.subnet,
                "--listen-port", str(args.listen_port),
                "--external-interface", external,
                "--dns", dns,
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
                    "ingress_boundary": settings.ingress_boundary,
                    "message": (
                        (message or f"Installed AmneziaWG and awgctl {VERSION}")
                        + f"; attested ingress boundary: {settings.ingress_boundary}"
                    ),
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
            bootstrap = _bootstrap_settings(settings)
            bootstrap_report = _configure_host_for_command(args, root=root, settings=bootstrap)
            try:
                _deploy_source_release(root, repo_root, health=False, settings=bootstrap)
            except Exception:
                rollback_host_configuration(bootstrap_report)
                raise
            _configure_host_for_command(args, root=root, settings=settings)
            adopted = _run(
                [
                    str(root / "libexec/awgctl-internal"), "_migrate-existing",
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
            _apply_requested_runtime_settings(args, root=root, settings=settings)
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
                        "ingress_boundary": settings.ingress_boundary,
                        "message": (
                            f"Dry run: would install awgctl {VERSION} into {root}; "
                            f"attested ingress boundary: {settings.ingress_boundary or 'missing'}"
                        ),
                    },
                    as_json=args.json,
                )
                return 0
            if root == DEFAULT_ROOT and os.geteuid() != 0:
                raise InstallerError("run installation with sudo")
            if not args.yes:
                raise InstallerError("upgrade is mutating; rerun with --yes after reviewing --dry-run")
            existing_settings = _persisted_settings(root)
            host_reports: list[HostConfigurationReport] = []
            try:
                if existing_settings is None:
                    bootstrap = _bootstrap_settings(settings)
                    host_reports.append(
                        _configure_host_for_command(
                            args,
                            root=root,
                            settings=bootstrap,
                        )
                    )
                host_reports.append(
                    _configure_host_for_command(
                        args,
                        root=root,
                        settings=settings,
                    )
                )
                _deploy_source_release(root, repo_root, health=True, settings=settings)
            except Exception:
                _rollback_host_reports(host_reports)
                raise
            _apply_requested_runtime_settings(args, root=root, settings=settings)
            _emit(
                output,
                {
                    "schema_version": 1,
                    "ok": True,
                    "version": VERSION,
                    "ingress_boundary": settings.ingress_boundary,
                    "message": (
                        f"Installed awgctl {VERSION} into {root}; "
                        f"attested ingress boundary: {settings.ingress_boundary}"
                    ),
                },
                as_json=args.json,
            )
            return 0
        raise InstallerError(f"{args.command} workflow is not implemented yet")
    except (
        HostConfigurationError, InstallerError, PlatformError, SettingsError, WorkerError,
    ) as exc:
        print(f"install.py: {exc}", file=sys.stderr)
        return 1
