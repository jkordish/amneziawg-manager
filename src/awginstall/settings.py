"""Validated, non-secret host installation settings."""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


DEFAULT_STAGING_ROOT = pathlib.Path("/var/lib/amneziawg-manager")
DNS_POLICIES = {
    "cloudflare": ("1.1.1.1", "1.0.0.1"),
    "cloudflare-malware": ("1.1.1.2", "1.0.0.2"),
    "cloudflare-family": ("1.1.1.3", "1.0.0.3"),
}
IDENTITY_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
FORBIDDEN_IDENTITIES = {
    "root", "sudo", "wheel", "admin", "adm", "docker", "systemd-journal",
}
INGRESS_BOUNDARIES = {"lightsail", "equivalent-external-firewall"}


class SettingsError(ValueError):
    """Installation settings are unsafe or malformed."""


@dataclass(frozen=True)
class InstallationSettings:
    schema_version: int
    staging_user: str
    staging_group: str
    staging_uid: int | None
    staging_gid: int | None
    staging_root: pathlib.Path
    operator_group: str
    operators: tuple[str, ...]
    enroll_sudo_invoker: bool
    sudo_policy: str
    systemd_hardening: str
    default_dns: tuple[str, ...]
    ingress_boundary: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "staging": {
                "user": self.staging_user,
                "group": self.staging_group,
                "uid": self.staging_uid,
                "gid": self.staging_gid,
                "root": str(self.staging_root),
            },
            "operators": {
                "group": self.operator_group,
                "users": list(self.operators),
                "enroll_sudo_invoker": self.enroll_sudo_invoker,
                "sudo_policy": self.sudo_policy,
            },
            "systemd": {"hardening": self.systemd_hardening},
            "dns": {
                "default": list(self.default_dns),
                "policy": dns_policy_name(self.default_dns),
            },
            "network": {"ingress_boundary": self.ingress_boundary},
        }


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SettingsError(f"unknown {label}: {', '.join(unknown)}")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SettingsError(f"{label} must be a JSON object")
    return value


def validate_identity_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTITY_RE.fullmatch(value):
        raise SettingsError(f"{label} must be a lowercase Unix identity name")
    if value in FORBIDDEN_IDENTITIES:
        raise SettingsError(f"{label} must not reuse privileged identity {value}")
    return value


def validate_staging_root(value: Any) -> pathlib.Path:
    if not isinstance(value, (str, pathlib.Path)):
        raise SettingsError("staging root must be an absolute child of /var/lib")
    path = pathlib.Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise SettingsError("staging root must be an absolute child of /var/lib")
    try:
        relative = path.relative_to("/var/lib")
    except ValueError as exc:
        raise SettingsError("staging root must be an absolute child of /var/lib") from exc
    if not relative.parts:
        raise SettingsError("staging root must be an absolute child of /var/lib")
    return path


def validate_dns_setting(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        candidate = value.strip().lower()
        if candidate in DNS_POLICIES:
            return DNS_POLICIES[candidate]
        values: Sequence[Any] = value.split(",")
    elif isinstance(value, list):
        values = value
    else:
        raise SettingsError("DNS default must be a named policy or IPv4 address list")
    result: list[str] = []
    for item in values:
        try:
            address = ipaddress.ip_address(str(item).strip())
        except ValueError as exc:
            raise SettingsError(f"invalid DNS default address: {item}") from exc
        if address.version != 4:
            raise SettingsError("DNS defaults currently support IPv4 addresses only")
        normalized = str(address)
        if normalized not in result:
            result.append(normalized)
    if not result:
        raise SettingsError("at least one DNS default address is required")
    return tuple(result)


def dns_policy_name(addresses: Sequence[str]) -> str:
    normalized = tuple(addresses)
    for name, values in DNS_POLICIES.items():
        if normalized == values:
            return name
    return "custom"


def _optional_system_id(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 999:
        raise SettingsError(f"{label} must be a system ID from 100 through 999 or null")
    return value


def _load_document(path: pathlib.Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"could not read installation settings: {path}") from exc
    document = _object(value, "installation settings")
    _reject_unknown(
        document,
        {"schema_version", "staging", "operators", "systemd", "dns", "network"},
        "installation settings",
    )
    if document.get("schema_version", 1) != 1:
        raise SettingsError("unsupported installation settings schema")
    return document


def resolve_installation_settings(
    *,
    settings_path: pathlib.Path | None = None,
    sudo_user: str | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> InstallationSettings:
    document = _load_document(settings_path)
    staging = _object(document.get("staging", {}), "staging settings")
    operator = _object(document.get("operators", {}), "operator settings")
    systemd = _object(document.get("systemd", {}), "systemd settings")
    dns = _object(document.get("dns", {}), "DNS settings")
    network = _object(document.get("network", {}), "network settings")
    _reject_unknown(staging, {"user", "group", "uid", "gid", "root"}, "staging settings")
    _reject_unknown(operator, {"group", "users", "enroll_sudo_invoker", "sudo_policy"}, "operator settings")
    _reject_unknown(systemd, {"hardening"}, "systemd settings")
    _reject_unknown(dns, {"default", "policy"}, "DNS settings")
    _reject_unknown(network, {"ingress_boundary"}, "network settings")

    values: dict[str, Any] = {
        "staging_user": staging.get("user", "awgctl"),
        "staging_group": staging.get("group", "awgctl"),
        "staging_uid": staging.get("uid"),
        "staging_gid": staging.get("gid"),
        "staging_root": staging.get("root", DEFAULT_STAGING_ROOT),
        "operator_group": operator.get("group", "awgctl-admin"),
        "operators": list(operator.get("users", [])),
        "enroll_sudo_invoker": operator.get("enroll_sudo_invoker", True),
        "sudo_policy": operator.get("sudo_policy", "scoped-nopasswd"),
        "systemd_hardening": systemd.get("hardening", "conservative"),
        "default_dns": dns.get("default", "cloudflare-malware"),
        "ingress_boundary": network.get("ingress_boundary"),
    }
    explicit = dict(overrides or {})
    extra_operators = explicit.pop("operators", None)
    values.update({key: value for key, value in explicit.items() if value is not None})
    if extra_operators is not None:
        values["operators"] = list(values["operators"]) + list(extra_operators)

    staging_user = validate_identity_name(values["staging_user"], "staging user")
    staging_group = validate_identity_name(values["staging_group"], "staging group")
    operator_group = validate_identity_name(values["operator_group"], "operator group")
    if operator_group in {staging_group, staging_user}:
        raise SettingsError("operator group must be separate from the staging identity")
    if not isinstance(values["enroll_sudo_invoker"], bool):
        raise SettingsError("enroll_sudo_invoker must be boolean")
    if values["sudo_policy"] not in {"scoped-nopasswd", "existing-sudo", "none"}:
        raise SettingsError("unsupported sudo policy")
    if values["systemd_hardening"] not in {"conservative", "off"}:
        raise SettingsError("unsupported systemd hardening policy")
    if values["ingress_boundary"] is not None and (
        not isinstance(values["ingress_boundary"], str)
        or values["ingress_boundary"] not in INGRESS_BOUNDARIES
    ):
        raise SettingsError(
            "network.ingress_boundary must be lightsail or equivalent-external-firewall"
        )

    operators: list[str] = []
    raw_operators = values["operators"]
    if not isinstance(raw_operators, list):
        raise SettingsError("operator users must be a JSON array")
    for name in raw_operators:
        normalized = validate_identity_name(name, "operator user")
        if normalized not in operators:
            operators.append(normalized)
    if values["enroll_sudo_invoker"] and sudo_user and sudo_user != "root":
        normalized = validate_identity_name(sudo_user, "sudo invoking user")
        if normalized not in operators:
            operators.append(normalized)

    return InstallationSettings(
        schema_version=1,
        staging_user=staging_user,
        staging_group=staging_group,
        staging_uid=_optional_system_id(values["staging_uid"], "staging UID"),
        staging_gid=_optional_system_id(values["staging_gid"], "staging GID"),
        staging_root=validate_staging_root(values["staging_root"]),
        operator_group=operator_group,
        operators=tuple(operators),
        enroll_sudo_invoker=values["enroll_sudo_invoker"],
        sudo_policy=values["sudo_policy"],
        systemd_hardening=values["systemd_hardening"],
        default_dns=validate_dns_setting(values["default_dns"]),
        ingress_boundary=values["ingress_boundary"],
    )
