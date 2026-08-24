from __future__ import annotations

import pytest

from surinort_ast import migrate_ast, parse_rule
from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import Header
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


def test_migrate_ast_restores_short_and_headerless_forms() -> None:
    short = parse_rule('alert tcp (msg:"short"; sid:2;)', dialect=Dialect.SNORT3)
    headerless = parse_rule("alert (gid:2; sid:3;)", dialect=Dialect.SNORT3)
    payload = {
        "ast_version": "3.1.0",
        "data": {
            "rules": [
                {
                    "action": "alert",
                    "header": Header.wildcard(short.protocol).model_dump(mode="json"),
                    "form": "protocol_only",
                    "options": [option.model_dump(mode="json") for option in short.options],
                },
                {
                    "action": "alert",
                    "header": Header.wildcard().model_dump(mode="json"),
                    "form": "headerless",
                    "options": [option.model_dump(mode="json") for option in headerless.options],
                },
            ]
        },
    }

    migrated = migrate_ast(payload)
    rules = migrated["data"]["rules"]

    assert rules[0]["header"] is None
    assert rules[0]["protocol"] == "tcp"
    assert rules[1]["header"] is None
    assert rules[1]["protocol"] is None


def test_migrate_ast_rejects_other_major() -> None:
    with pytest.raises(ValueError, match="Unsupported AST migration"):
        migrate_ast({"ast_version": "2.0.0", "data": {"rules": []}})
