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


def normalize_client_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Read schema 1 state and return the strict schema 2 representation."""
    if not isinstance(metadata, dict):
        raise ContractError("client metadata must be an object")
    result = dict(metadata)
    schema = result.get("schema_version")
    if schema == 1:
        result.update(
            {
                "schema_version": 2,
                "management": "managed",
                "owner": None,
                "device": None,
                "expires": None,
            }
        )
    elif schema != 2:
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
    return result
