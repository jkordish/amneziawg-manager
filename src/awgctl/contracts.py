"""Stable public output and metadata contracts."""

from __future__ import annotations

import datetime as dt
from typing import Any


class ContractError(ValueError):
    """Input does not satisfy a versioned public contract."""


def json_envelope(
    command: str,
    *,
    data: Any = None,
    warnings: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    error_values = list(errors or [])
    return {
        "schema_version": 1,
        "command": command,
        "ok": not error_values,
        "data": {} if data is None else data,
        "warnings": list(warnings or []),
        "errors": error_values,
    }


def health_envelope(checks: list[tuple[str, str, str]]) -> dict[str, Any]:
    normalized = [
        {"level": level.lower(), "name": name, "detail": detail}
        for level, name, detail in checks
    ]
    warnings = [
        {"name": item["name"], "detail": item["detail"]}
        for item in normalized
        if item["level"] == "warn"
    ]
    errors = [
        {"name": item["name"], "detail": item["detail"]}
        for item in normalized
        if item["level"] == "fail"
    ]
    return json_envelope(
        "health",
        data={
            "checks": normalized,
            "summary": {"failures": len(errors), "warnings": len(warnings)},
        },
        warnings=warnings,
        errors=errors,
    )


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ContractError(f"{field} must be text or null")
    value = value.strip()
    if not value:
        return None
    if len(value) > 64 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ContractError(f"{field} must be 1-64 printable characters")
    return value


def _optional_timestamp(value: Any, field: str) -> str | None:
    value = _optional_text(value, field)
    if value is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{field} must be an ISO 8601 timestamp or null") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{field} must include a timezone")
    return value


def normalize_client_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Read historical client state and return the strict schema 3 representation."""
    if not isinstance(metadata, dict):
        raise ContractError("client metadata must be an object")
    result = dict(metadata)
    schema = result.get("schema_version")
    if schema == 1:
        result.update(
            {
                "management": "managed",
                "owner": None,
                "device": None,
                "expires": None,
            }
        )
    if schema in {1, 2}:
        generated_at = result.get("updated_at") or result.get("created_at")
        result.update(
            {
                "schema_version": 3,
                "profile_revision": 1,
                "profile_generated_at": generated_at,
                "profile_change_reason": "legacy-import",
                "distribution_status": "unknown",
                "distributed_at": None,
            }
        )
    elif schema != 3:
        raise ContractError("unsupported client metadata schema")
    if result.get("management") not in {"managed", "external"}:
        raise ContractError("client management must be managed or external")
    result["owner"] = _optional_text(result.get("owner"), "owner")
    result["device"] = _optional_text(result.get("device"), "device")
    expires = result.get("expires")
    if expires is not None:
        if not isinstance(expires, str):
            raise ContractError("expires must be YYYY-MM-DD or null")
        try:
            parsed = dt.date.fromisoformat(expires)
        except ValueError as exc:
            raise ContractError("expires must be YYYY-MM-DD or null") from exc
        if parsed.isoformat() != expires:
            raise ContractError("expires must be YYYY-MM-DD or null")
    revision = result.get("profile_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise ContractError("profile_revision must be a positive integer")
    result["profile_generated_at"] = _optional_timestamp(
        result.get("profile_generated_at"), "profile_generated_at"
    )
    if result["profile_generated_at"] is None:
        raise ContractError("profile_generated_at must be an ISO 8601 timestamp")
    result["profile_change_reason"] = _optional_text(
        result.get("profile_change_reason"), "profile_change_reason"
    )
    if result["profile_change_reason"] is None:
        raise ContractError("profile_change_reason is required")
    distribution = result.get("distribution_status")
    if distribution not in {"unknown", "pending", "distributed"}:
        raise ContractError("distribution_status must be unknown, pending, or distributed")
    result["distributed_at"] = _optional_timestamp(result.get("distributed_at"), "distributed_at")
    if distribution == "distributed" and result["distributed_at"] is None:
        raise ContractError("distributed_at is required when distribution_status is distributed")
    if distribution != "distributed" and result["distributed_at"] is not None:
        raise ContractError("distributed_at must be null unless distribution_status is distributed")
    return result


def mark_profile_regenerated(
    metadata: dict[str, Any], *, reason: str, timestamp: str
) -> dict[str, Any]:
    """Return metadata for a newly generated, not-yet-distributed profile revision."""
    result = normalize_client_metadata(metadata)
    result.update(
        {
            "schema_version": 3,
            "profile_revision": result["profile_revision"] + 1,
            "profile_generated_at": timestamp,
            "profile_change_reason": reason,
            "distribution_status": "pending",
            "distributed_at": None,
            "updated_at": timestamp,
        }
    )
    return normalize_client_metadata(result)


def mark_profile_rotated(
    previous: dict[str, Any],
    replacement: dict[str, Any],
    *,
    timestamp: str,
) -> dict[str, Any]:
    """Bind a replacement identity to the prior recipient and next revision."""
    old = normalize_client_metadata(previous)
    result = normalize_client_metadata(replacement)
    result.update(
        {
            "owner": old.get("owner"),
            "device": old.get("device"),
            "expires": old.get("expires"),
            "profile_revision": old["profile_revision"] + 1,
            "profile_generated_at": timestamp,
            "profile_change_reason": "rotated",
            "distribution_status": "pending",
            "distributed_at": None,
            "updated_at": timestamp,
        }
    )
    return normalize_client_metadata(result)
