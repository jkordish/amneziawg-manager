"""Unix identity planning and confined worker helpers."""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import tempfile
from dataclasses import dataclass
from typing import Mapping, Sequence

from .settings import InstallationSettings


NOLOGIN = "/usr/sbin/nologin"
PUBLIC_ENTRYPOINT = "/usr/local/sbin/awgctl"


class IdentityError(RuntimeError):
    """The requested host identity boundary cannot be established safely."""


@dataclass(frozen=True)
class UserRecord:
    name: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class GroupRecord:
    name: str
    gid: int
    members: tuple[str, ...]


@dataclass(frozen=True)
class IdentitySnapshot:
    users: Mapping[str, UserRecord | None]
    groups: Mapping[str, GroupRecord]
    locked_users: set[str]
    supplementary_groups: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class IdentityPlan:
    commands: tuple[tuple[str, ...], ...]
    created_users: tuple[str, ...]
    created_groups: tuple[str, ...]
    added_memberships: tuple[tuple[str, str], ...]


def _validate_existing_staging(
    settings: InstallationSettings,
    snapshot: IdentitySnapshot,
) -> None:
    user = snapshot.users.get(settings.staging_user)
    group = snapshot.groups.get(settings.staging_group)
    problems: list[str] = []
    if not isinstance(user, UserRecord) or group is None:
        problems.append("user and primary group must both exist")
    else:
        if user.gid != group.gid:
            problems.append("primary GID differs from the staging group")
        if settings.staging_uid is not None and user.uid != settings.staging_uid:
            problems.append("UID differs from requested value")
        if settings.staging_gid is not None and group.gid != settings.staging_gid:
            problems.append("GID differs from requested value")
        if user.home != str(settings.staging_root):
            problems.append("home directory differs from the staging root")
        if user.shell != NOLOGIN:
            problems.append("login shell is not nologin")
    if settings.staging_user not in snapshot.locked_users:
        problems.append("password is not locked")
    extra_groups = snapshot.supplementary_groups.get(settings.staging_user, ())
    if extra_groups:
        problems.append(f"supplementary groups are present: {', '.join(extra_groups)}")
    if problems:
        raise IdentityError("existing staging identity does not match policy: " + "; ".join(problems))


def build_identity_plan(
    settings: InstallationSettings,
    snapshot: IdentitySnapshot,
    *,
    allow_existing: bool,
) -> IdentityPlan:
    commands: list[tuple[str, ...]] = []
    created_users: list[str] = []
    created_groups: list[str] = []
    memberships: list[tuple[str, str]] = []
    staging_user_exists = settings.staging_user in snapshot.users
    staging_group_exists = settings.staging_group in snapshot.groups
    operator_group_exists = settings.operator_group in snapshot.groups

    if (staging_user_exists or staging_group_exists or operator_group_exists) and not allow_existing:
        raise IdentityError("existing manager identities require --adopt-existing-identities")

    if staging_user_exists or staging_group_exists:
        _validate_existing_staging(settings, snapshot)
    else:
        group_command = ["groupadd", "--system"]
        if settings.staging_gid is not None:
            group_command.extend(["--gid", str(settings.staging_gid)])
        group_command.append(settings.staging_group)
        commands.append(tuple(group_command))
        created_groups.append(settings.staging_group)

        user_command = [
            "useradd", "--system", "--gid", settings.staging_group,
            "--home-dir", str(settings.staging_root), "--create-home",
            "--shell", NOLOGIN, "--comment", "AmneziaWG Manager staging account",
        ]
        if settings.staging_uid is not None:
            user_command.extend(["--uid", str(settings.staging_uid)])
        user_command.append(settings.staging_user)
        commands.append(tuple(user_command))
        created_users.append(settings.staging_user)

    if not operator_group_exists:
        commands.append(("groupadd", "--system", settings.operator_group))
        created_groups.append(settings.operator_group)

    existing_members = (
        set(snapshot.groups[settings.operator_group].members)
        if operator_group_exists else set()
    )
    for operator in settings.operators:
        if operator not in snapshot.users:
            raise IdentityError(f"operator account does not exist: {operator}")
        if operator not in existing_members:
            commands.append(("usermod", "--append", "--groups", settings.operator_group, operator))
            memberships.append((operator, settings.operator_group))

    return IdentityPlan(
        commands=tuple(commands),
        created_users=tuple(created_users),
        created_groups=tuple(created_groups),
        added_memberships=tuple(memberships),
    )


def render_sudoers(operator_group: str, policy: str) -> str:
    if policy in {"existing-sudo", "none"}:
        return ""
    if policy != "scoped-nopasswd":
        raise IdentityError(f"unsupported sudo policy: {policy}")
    return (
        "# Managed by AmneziaWG Manager. Local edits will be reported as drift.\n"
        f"%{operator_group} ALL=(root) NOPASSWD: NOSETENV: {PUBLIC_ENTRYPOINT}\n"
    )


def build_worker_command(
    settings: InstallationSettings,
    job_directory: pathlib.Path,
    argv: Sequence[str],
    *,
    network: bool,
) -> list[str]:
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise IdentityError("worker command must contain non-empty argument strings")
    command = [
        "systemd-run", "--quiet", "--wait", "--collect", "--pipe",
        f"--uid={settings.staging_user}", f"--gid={settings.staging_group}",
        f"--working-directory={job_directory}",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=UMask=0077",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=RestrictSUIDSGID=yes",
        f"--property=ReadWritePaths={job_directory}",
        "--property=InaccessiblePaths=/opt/amneziawg/config /opt/amneziawg/keys /opt/amneziawg/clients /opt/amneziawg/backups /opt/amneziawg/revoked /etc/amnezia",
    ]
    if network:
        command.append("--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6")
    else:
        command.append("--property=PrivateNetwork=yes")
    command.extend(["--", *argv])
    return command


def copy_validated_worker_output(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_uid: int,
    max_size: int,
    expected_mode: int = 0o600,
) -> None:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise IdentityError(f"worker output is unavailable: {source}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise IdentityError("worker output must be a regular single-link file")
    if metadata.st_uid != expected_uid:
        raise IdentityError("worker output has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise IdentityError(f"worker output permissions must be {expected_mode:04o}")
    if metadata.st_size > max_size:
        raise IdentityError("worker output exceeds the allowed size")

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
