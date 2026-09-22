import json
from pathlib import Path

import pytest
from tools.snort2_capabilities import registered_keywords, snapshot

from surinort_ast.analysis import CapabilityRegistry
from surinort_ast.api import parse_file, validate_rules
from surinort_ast.core.enums import Dialect


def test_registered_keywords_are_source_backed_and_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "detection-plugins"
    source.mkdir()
    (source / "one.c").write_text(
        'RegisterRuleOption("Content", content_init);\n'
        'RegisterRuleOption("flowbits", flowbits_init);\n',
        encoding="utf-8",
    )
    (source / "two.c").write_text('RegisterRuleOption("content", duplicate);\n', encoding="utf-8")
    (source / "ignored.h").write_text('RegisterRuleOption("ignored", nope);\n', encoding="utf-8")

    keywords, digest, file_count = registered_keywords(source)

    assert keywords == frozenset({"content", "flowbits"})
    assert len(digest) == 64
    assert file_count == 2


def test_snapshot_loads_as_a_complete_snort2_target(tmp_path: Path) -> None:
    source = tmp_path / "detection-plugins"
    source.mkdir()
    (source / "plugin.c").write_text('RegisterRuleOption("byte_test", init);\n', encoding="utf-8")

    payload = snapshot(source, "2.9.20")
    path = tmp_path / "capabilities.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    from surinort_ast.analysis import CapabilityRegistry

    target = CapabilityRegistry.from_json(path).resolve("snort2", "2.9.20")
    assert target is not None
    assert target.keyword_catalog_complete
    assert target.supports("byte_test") is True
    assert target.supports("missing") is False


def test_registered_keywords_rejects_empty_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no C source files"):
        registered_keywords(tmp_path)


def test_checked_in_snort2_snapshot_has_a_complete_keyword_catalog() -> None:
    registry = CapabilityRegistry.from_json(
        Path("conformance/capabilities/4.0.0-snort2-source.json")
    )
    target = registry.resolve("snort2", "2.9.20")

    assert target is not None
    assert target.keyword_catalog_complete
    assert len(target.keywords) == 75
    assert target.supports("msg") is True
    assert target.supports("detection_filter") is True
    assert target.supports("byte_extract") is True


def test_checked_in_snort2_snapshot_validates_community_rules() -> None:
    registry = CapabilityRegistry.from_json(
        Path("conformance/capabilities/4.0.0-snort2-source.json")
    )
    target = registry.resolve("snort2", "2.9.20")
    assert target is not None

    rules = list(
        parse_file(
            Path("rules/snort/snort29-community-rules/community-rules/community.rules"),
            dialect=Dialect.SNORT2,
            stream=True,
        )
    )
    diagnostics = validate_rules(rules, target=target)

    assert len(rules) == 561
    assert not [item for item in diagnostics if item.code == "unsupported_engine_keyword"]
