"""Transactional host identity, sudo, and systemd configuration."""

from __future__ import annotations

import grp
import json
import os
import pathlib
import pwd
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace

from .identity import (
    GroupRecord,
    IdentityPlan,
    IdentitySnapshot,
    UserRecord,
    build_identity_plan,
    effective_group_members,
    render_sudoers,
)
from .sandbox import render_module_load, render_service_hardening
from .settings import InstallationSettings


class HostConfigurationError(RuntimeError):
    """Host privilege-boundary configuration failed safely."""


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]]


@dataclass(frozen=True)
class HostPaths:
    sudoers: pathlib.Path = pathlib.Path("/etc/sudoers.d/amneziawg-manager")
    service_dropin: pathlib.Path = pathlib.Path(
        "/etc/systemd/system/awg-quick@awg0.service.d/20-awgctl-hardening.conf"
    )
    module_load: pathlib.Path = pathlib.Path("/etc/modules-load.d/amneziawg-manager.conf")
    expiry_service: pathlib.Path = pathlib.Path(
        "/etc/systemd/system/amneziawg-client-expiry.service"
    )
    expiry_timer: pathlib.Path = pathlib.Path(
        "/etc/systemd/system/amneziawg-client-expiry.timer"
    )

    @classmethod
    def under(cls, root: pathlib.Path) -> "HostPaths":
        return cls(
            sudoers=root / "etc/sudoers.d/amneziawg-manager",
            service_dropin=root / "etc/systemd/system/awg-quick@awg0.service.d/20-awgctl-hardening.conf",
            module_load=root / "etc/modules-load.d/amneziawg-manager.conf",
            expiry_service=root / "etc/systemd/system/amneziawg-client-expiry.service",
            expiry_timer=root / "etc/systemd/system/amneziawg-client-expiry.timer",
        )


@dataclass(frozen=True)
class HostConfigurationReport:
    identity: IdentityPlan
    sudoers: str
    service_hardening: str
    module_load: str
    settings: dict[str, object]
    dry_run: bool
    rollback_files: Mapping[pathlib.Path, "_FileSnapshot"] | None = field(
        default=None, repr=False, compare=False
    )
    expiry_timer_state: "ExpiryTimerState | None" = field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True)
class ExpiryTimerState:
    unit_file_state: str
    active_state: str


@dataclass(frozen=True)
class _FileSnapshot:
    exists: bool
    data: bytes = b""
    mode: int = 0


def _file_snapshot(path: pathlib.Path) -> _FileSnapshot:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return _FileSnapshot(False)
    if not stat.S_ISREG(metadata.st_mode):
        raise HostConfigurationError(f"managed host path is not a regular file: {path}")
    return _FileSnapshot(True, path.read_bytes(), stat.S_IMODE(metadata.st_mode))


def _atomic_write(path: pathlib.Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _restore_file(path: pathlib.Path, snapshot: _FileSnapshot) -> None:
    if snapshot.exists:
        _atomic_write(path, snapshot.data, snapshot.mode)
    else:
        path.unlink(missing_ok=True)


def render_expiry_service(product_root: pathlib.Path) -> str:
    """Return the canonical manager-owned expiry service unit."""
    return (
        "# Managed by AmneziaWG Manager\n"
        "[Unit]\n"
        "Description=Expire due AmneziaWG clients\n"
        "After=awg-quick@awg0.service\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={product_root / 'libexec/awgctl-internal'} _expire-clients\n"
        "User=root\n"
        "Group=root\n"
        "UMask=0077\n"
    )


def render_expiry_timer() -> str:
    """Return the canonical manager-owned expiry timer unit."""
    return (
        "# Managed by AmneziaWG Manager\n"
        "[Unit]\n"
        "Description=Run AmneziaWG client expiry daily\n\n"
        "[Timer]\n"
        "OnCalendar=*-*-* 00:00:00 UTC\n"
        "Persistent=true\n"
        "Unit=amneziawg-client-expiry.service\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def _run_local(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostConfigurationError(f"could not run host command: {argv[0]}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise HostConfigurationError(
            f"host command failed: {argv[0]}{': ' + detail[-1] if detail else ''}"
        )
    return result


def _run_local_probe(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostConfigurationError(f"could not query host command: {argv[0]}") from exc


def _probe_expiry_timer_state(
    runner: Runner,
    *,
    allow_loaded_not_found: bool = False,
) -> ExpiryTimerState:
    probe = _run_local_probe if runner is _run_local else runner
    unit = "amneziawg-client-expiry.timer"
    probe_errors: list[str] = []
    enabled_result: subprocess.CompletedProcess[bytes] | None = None
    active_result: subprocess.CompletedProcess[bytes] | None = None
    try:
        enabled_result = probe(("systemctl", "is-enabled", unit))
    except Exception as exc:
        probe_errors.append(f"unit-file state: {exc}")
    try:
        active_result = probe(("systemctl", "is-active", unit))
    except Exception as exc:
        probe_errors.append(f"active state: {exc}")
    if probe_errors:
        raise HostConfigurationError(
            "could not query expiry timer state: " + "; ".join(probe_errors)
        )
    if enabled_result is None or active_result is None:
        raise HostConfigurationError("expiry timer probes returned no result")
    enabled_states = {
        (0, b"enabled\n"): "enabled",
        (0, b"enabled-runtime\n"): "enabled-runtime",
        (1, b"disabled\n"): "disabled",
        (4, b"not-found\n"): "not-found",
    }
    unit_file_state = enabled_states.get(
        (enabled_result.returncode, enabled_result.stdout)
    )
    if unit_file_state is None:
        raise HostConfigurationError(
            "could not determine a supported expiry timer unit-file state "
            f"(exit {enabled_result.returncode})"
        )
    if unit_file_state == "not-found":
        active_states = {(4, b"inactive\n"): "inactive"}
        if allow_loaded_not_found:
            active_states[(0, b"active\n")] = "active"
    else:
        active_states = {
            (0, b"active\n"): "active",
            (3, b"inactive\n"): "inactive",
        }
    active_state = active_states.get((active_result.returncode, active_result.stdout))
    if active_state is None:
        raise HostConfigurationError(
            "could not determine a supported expiry timer active state for "
            f"unit-file state {unit_file_state} "
            f"(exit {active_result.returncode})"
        )
    return ExpiryTimerState(
        unit_file_state=unit_file_state,
        active_state=active_state,
    )


def _snapshot_expiry_timer_state(runner: Runner) -> ExpiryTimerState:
    return _probe_expiry_timer_state(runner)


def _validate_expiry_timer_snapshot(
    timer_file: _FileSnapshot,
    state: ExpiryTimerState,
) -> None:
    if timer_file.exists and state.unit_file_state == "not-found":
        raise HostConfigurationError(
            "present expiry timer file has not-found systemd state before reload"
        )


def _quiesce_expiry_timer(runner: Runner) -> None:
    unit = "amneziawg-client-expiry.timer"
    current = _probe_expiry_timer_state(runner, allow_loaded_not_found=True)
    errors: list[str] = []
    if current.active_state == "active":
        try:
            runner(("systemctl", "stop", unit))
        except Exception as exc:
            errors.append(f"stop: {exc}")
    if current.unit_file_state != "not-found":
        for label, command in (
            ("persistent disable", ("systemctl", "disable", unit)),
            ("runtime disable", ("systemctl", "disable", "--runtime", unit)),
        ):
            try:
                runner(command)
            except Exception as exc:
                errors.append(f"{label}: {exc}")
    if errors:
        raise HostConfigurationError(
            "expiry timer quiesce actions failed: " + "; ".join(errors)
        )


def _restore_expiry_timer_state(state: ExpiryTimerState, runner: Runner) -> None:
    unit = "amneziawg-client-expiry.timer"
    if state.unit_file_state not in {
        "enabled", "enabled-runtime", "disabled", "not-found",
    }:
        raise HostConfigurationError("unsupported expiry timer rollback unit-file state")
    if state.active_state not in {"active", "inactive"}:
        raise HostConfigurationError("unsupported expiry timer rollback active state")
    if state.unit_file_state == "not-found" and state.active_state != "inactive":
        raise HostConfigurationError("a not-found expiry timer cannot be active")

    errors: list[str] = []

    def attempt(label: str, command: tuple[str, ...]) -> None:
        try:
            runner(command)
        except Exception as exc:
            errors.append(f"{label}: {exc}")

    if state.unit_file_state == "enabled":
        attempt("persistent enable", ("systemctl", "enable", unit))
    elif state.unit_file_state == "enabled-runtime":
        attempt(
            "runtime enable",
            ("systemctl", "enable", "--runtime", unit),
        )
    elif state.unit_file_state == "disabled":
        attempt("persistent disable", ("systemctl", "disable", unit))
        attempt(
            "runtime disable",
            ("systemctl", "disable", "--runtime", unit),
        )
    if state.unit_file_state != "not-found":
        action = "start" if state.active_state == "active" else "stop"
        attempt(action, ("systemctl", action, unit))

    try:
        observed = _probe_expiry_timer_state(runner, allow_loaded_not_found=True)
    except Exception as exc:
        errors.append(f"expiry timer rollback postcondition probe failed: {exc}")
    else:
        if observed != state:
            errors.append(
                "expiry timer rollback postcondition failed: "
                f"expected {state.unit_file_state}/{state.active_state}, "
                f"got {observed.unit_file_state}/{observed.active_state}"
            )
    if errors:
        raise HostConfigurationError("; ".join(errors))


def _password_locked(name: str, runner: Runner) -> bool:
    result = runner(("passwd", "--status", name))
    fields = result.stdout.decode("utf-8", "replace").split()
    return len(fields) >= 2 and fields[1] in {"L", "LK"}


def snapshot_identities(
    settings: InstallationSettings,
    *,
    runner: Runner | None = None,
) -> IdentitySnapshot:
    runner = runner or _run_local
    names = {settings.staging_user, *settings.operators}
    users: dict[str, UserRecord | None] = {}
    locked: set[str] = set()
    for name in names:
        try:
            record = pwd.getpwnam(name)
        except KeyError:
            continue
        users[name] = UserRecord(
            name=name,
            uid=record.pw_uid,
            gid=record.pw_gid,
            home=record.pw_dir,
            shell=record.pw_shell,
        )
        if name == settings.staging_user and _password_locked(name, runner):
            locked.add(name)

    all_groups = grp.getgrall()
    all_accounts = tuple((record.pw_name, record.pw_gid) for record in pwd.getpwall())
    wanted_groups = {settings.staging_group, settings.operator_group}
    groups = {
        record.gr_name: GroupRecord(
            record.gr_name,
            record.gr_gid,
            effective_group_members(record.gr_gid, record.gr_mem, all_accounts),
        )
        for record in all_groups
        if record.gr_name in wanted_groups
    }
    supplementary: dict[str, tuple[str, ...]] = {}
    staging = users.get(settings.staging_user)
    if isinstance(staging, UserRecord):
        supplementary[settings.staging_user] = tuple(
            sorted(
                record.gr_name
                for record in all_groups
                if settings.staging_user in record.gr_mem and record.gr_gid != staging.gid
            )
        )
    return IdentitySnapshot(
        users=users,
        groups=groups,
        locked_users=locked,
        supplementary_groups=supplementary,
    )


def _resolve_created_user(name: str) -> UserRecord:
    try:
        record = pwd.getpwnam(name)
    except KeyError as exc:
        raise HostConfigurationError(f"created staging account is unavailable: {name}") from exc
    return UserRecord(name, record.pw_uid, record.pw_gid, record.pw_dir, record.pw_shell)


def _prepare_staging_root(settings: InstallationSettings, user: UserRecord) -> None:
    root = settings.staging_root
    if root.exists() and root.is_symlink():
        raise HostConfigurationError("staging root must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise HostConfigurationError("staging root must be a directory")
    if metadata.st_uid not in {0, user.uid}:
        raise HostConfigurationError("staging root is owned by an unexpected account")
    os.chown(root, user.uid, user.gid)
    os.chmod(root, 0o700)
    jobs = root / "jobs"
    jobs.mkdir(mode=0o700, exist_ok=True)
    os.chown(jobs, user.uid, user.gid)
    os.chmod(jobs, 0o700)


def _install_validated_sudoers(path: pathlib.Path, content: str, runner: Runner) -> None:
    if not content:
        path.unlink(missing_ok=True)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o440)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        runner(("visudo", "-cf", str(temporary)))
        os.replace(temporary, path)
        os.chmod(path, 0o440)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _rollback_identities(plan: IdentityPlan, runner: Runner) -> None:
    for user, group in reversed(plan.added_memberships):
        try:
            runner(("gpasswd", "--delete", user, group))
        except Exception:
            pass
    for user in reversed(plan.created_users):
        try:
            runner(("userdel", "--remove", user))
        except Exception:
            pass
    for group in reversed(plan.created_groups):
        try:
            runner(("groupdel", group))
        except Exception:
            pass


def _restore_managed_host_state(
    rollback_files: Mapping[pathlib.Path, _FileSnapshot],
    expiry_timer_state: ExpiryTimerState,
    runner: Runner,
) -> list[str]:
    """Best-effort exact restoration with a verified timer postcondition."""
    errors: list[str] = []
    try:
        _quiesce_expiry_timer(runner)
    except Exception as exc:
        errors.append(f"quiesce expiry timer: {exc}")
    for path, previous in rollback_files.items():
        try:
            _restore_file(path, previous)
        except Exception as exc:
            errors.append(f"restore {path}: {exc}")
    try:
        runner(("systemctl", "daemon-reload"))
    except Exception as exc:
        errors.append(f"daemon-reload: {exc}")
    try:
        _restore_expiry_timer_state(expiry_timer_state, runner)
    except Exception as exc:
        errors.append(f"restore expiry timer state: {exc}")
    return errors


def rollback_host_configuration(
    report: HostConfigurationReport,
    *,
    runner: Runner | None = None,
) -> None:
    """Compensate a successful host step when a later outer transaction fails."""
    runner = runner or _run_local
    if report.rollback_files is None:
        raise HostConfigurationError("host configuration report has no rollback snapshot")
    if report.expiry_timer_state is None:
        raise HostConfigurationError("host configuration report has no expiry timer snapshot")
    errors = _restore_managed_host_state(
        report.rollback_files,
        report.expiry_timer_state,
        runner,
    )
    _rollback_identities(report.identity, runner)
    if errors:
        raise HostConfigurationError("host rollback was incomplete: " + "; ".join(errors))


def configure_host(
    settings: InstallationSettings,
    *,
    product_root: pathlib.Path,
    paths: HostPaths | None = None,
    allow_existing: bool,
    dry_run: bool,
    snapshot: IdentitySnapshot | None = None,
    runner: Runner | None = None,
) -> HostConfigurationReport:
    """Apply the host privilege boundary and compensate new state on failure."""
    paths = paths or HostPaths()
    runner = runner or _run_local
    initial_snapshot = snapshot or snapshot_identities(settings, runner=runner)
    identity_plan = build_identity_plan(settings, initial_snapshot, allow_existing=allow_existing)
    sudoers = render_sudoers(settings.operator_group, settings.sudo_policy)
    hardening = render_service_hardening(settings.systemd_hardening)
    module_load = render_module_load()
    settings_document = settings.to_dict()
    report = HostConfigurationReport(
        identity=identity_plan,
        sudoers=sudoers,
        service_hardening=hardening,
        module_load=module_load,
        settings=settings_document,
        dry_run=dry_run,
    )
    if dry_run:
        return report

    installation_path = product_root / "config/installation.json"
    managed_paths = (
        paths.sudoers,
        paths.service_dropin,
        paths.module_load,
        paths.expiry_service,
        paths.expiry_timer,
        installation_path,
    )
    file_snapshots = {path: _file_snapshot(path) for path in managed_paths}
    expiry_timer_state = _snapshot_expiry_timer_state(runner)
    _validate_expiry_timer_snapshot(
        file_snapshots[paths.expiry_timer],
        expiry_timer_state,
    )
    report = replace(
        report,
        rollback_files=file_snapshots,
        expiry_timer_state=expiry_timer_state,
    )
    commands_started = False
    try:
        for command in identity_plan.commands:
            commands_started = True
            runner(command)
        staging_user = (
            _resolve_created_user(settings.staging_user)
            if identity_plan.created_users
            else initial_snapshot.users.get(settings.staging_user)
        )
        if not isinstance(staging_user, UserRecord):
            raise HostConfigurationError("staging account validation failed")
        _prepare_staging_root(settings, staging_user)

        _install_validated_sudoers(paths.sudoers, sudoers, runner)
        if hardening:
            _atomic_write(paths.service_dropin, hardening.encode("utf-8"), 0o644)
        else:
            paths.service_dropin.unlink(missing_ok=True)
        _atomic_write(paths.module_load, module_load.encode("utf-8"), 0o644)
        _atomic_write(paths.expiry_service, render_expiry_service(product_root).encode("utf-8"), 0o644)
        _atomic_write(paths.expiry_timer, render_expiry_timer().encode("utf-8"), 0o644)
        _atomic_write(
            installation_path,
            (json.dumps(settings_document, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        runner((
            "systemd-analyze", "verify", "awg-quick@awg0.service",
            "amneziawg-client-expiry.service", "amneziawg-client-expiry.timer",
        ))
        runner(("systemctl", "daemon-reload"))

        if snapshot is None:
            verified = snapshot_identities(settings, runner=runner)
            post_plan = build_identity_plan(settings, verified, allow_existing=True)
            if post_plan.commands:
                raise HostConfigurationError("host identities did not converge to the requested policy")
        runner(("systemctl", "enable", "amneziawg-client-expiry.timer"))
        runner(("systemctl", "start", "amneziawg-client-expiry.timer"))
        return report
    except Exception as exc:
        restoration_errors = _restore_managed_host_state(
            file_snapshots,
            expiry_timer_state,
            runner,
        )
        if commands_started:
            _rollback_identities(identity_plan, runner)
        if restoration_errors:
            raise HostConfigurationError(
                f"{exc}; host compensation was incomplete: "
                + "; ".join(restoration_errors)
            ) from exc
        if isinstance(exc, HostConfigurationError):
            raise
        raise HostConfigurationError(str(exc)) from exc
