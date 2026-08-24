"""Small, explicit migrations for persisted AST JSON payloads."""

from __future__ import annotations

import json
from typing import Any

from surinort_ast.version import __ast_version__


def migrate_ast(data: str | dict[str, Any], from_version: str | None = None) -> dict[str, Any]:
    """Migrate an AST 3.x JSON payload to the current schema.

    AST 4 makes short and headerless forms lossless. Legacy wildcard headers
    are converted back to ``protocol`` or ``None`` according to ``form``.
    """
    payload = json.loads(data) if isinstance(data, str) else data
    if not isinstance(payload, dict):
        raise ValueError("AST payload must be a JSON object")

    source_version = payload.get("ast_version", from_version)
    if source_version is None:
        raise ValueError("AST version is required; pass from_version for bare payloads")
    if not _same_major(source_version, __ast_version__) and not _same_major(
        source_version, "3.0.0"
    ):
        raise ValueError(f"Unsupported AST migration: {source_version} -> {__ast_version__}")

    migrated = dict(payload)
    if isinstance(migrated.get("data"), dict):
        migrated["data"] = _migrate_data(migrated["data"])
        migrated["ast_version"] = __ast_version__
    else:
        migrated = _migrate_data(migrated)
    return migrated


def _migrate_data(data: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(data)
    if isinstance(migrated.get("rules"), list):
        migrated["rules"] = [_migrate_rule(rule) for rule in migrated["rules"]]
    elif "action" in migrated:
        migrated = _migrate_rule(migrated)
    return migrated


def _migrate_rule(rule: Any) -> Any:
    if not isinstance(rule, dict):
        return rule
    migrated = dict(rule)
    form = migrated.setdefault("form", "full")
    header = migrated.get("header")
    if form == "protocol_only":
        if "protocol" not in migrated and isinstance(header, dict):
            migrated["protocol"] = header.get("protocol")
        migrated["header"] = None
    elif form == "headerless":
        migrated["header"] = None
        migrated["protocol"] = None
    return migrated


def _same_major(left: Any, right: str) -> bool:
    try:
        return str(left).split(".", 1)[0] == right.split(".", 1)[0]
    except (AttributeError, IndexError):
        return False


__all__ = ["migrate_ast"]
