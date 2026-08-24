from __future__ import annotations

import pytest

from surinort_ast import migrate_ast, parse_rule
from surinort_ast.version import __ast_version__


def test_migrate_ast_3x_envelope_adds_rule_form() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"legacy"; sid:1;)')
    payload = {
        "ast_version": "3.0.4",
        "timestamp": "2025-01-01T00:00:00Z",
        "count": 1,
        "data": {
            "action": "alert",
            "header": rule.header.model_dump(mode="json"),
            "options": [option.model_dump(mode="json") for option in rule.options],
        },
    }

    migrated = migrate_ast(payload)

    assert migrated["ast_version"] == __ast_version__
    assert migrated["data"]["form"] == "full"
    assert migrate_ast(migrated) == migrated


def test_migrate_ast_bare_payload_requires_source_version() -> None:
    with pytest.raises(ValueError, match="AST version is required"):
        migrate_ast({"action": "alert"})


def test_migrate_ast_rejects_other_major() -> None:
    with pytest.raises(ValueError, match="Unsupported AST migration"):
        migrate_ast({"ast_version": "2.0.0", "data": {"rules": []}})
