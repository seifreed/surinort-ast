import pytest

from surinort_ast import parse_rule, validate_rule, validate_rules
from surinort_ast.analysis import EngineTarget


def codes(text: str) -> set[str | None]:
    return {diagnostic.code for diagnostic in validate_rule(parse_rule(text))}


def test_detection_filter_is_singleton() -> None:
    text = (
        'alert tcp any any -> any 80 (msg:"x"; sid:1; rev:1; '
        "detection_filter:track by_src,count 1,seconds 60; "
        "detection_filter:track by_dst,count 1,seconds 60;)"
    )

    assert "duplicate_singleton_option" in codes(text)


def test_content_modifier_requires_preceding_content() -> None:
    text = 'alert tcp any any -> any 80 (msg:"x"; sid:1; rev:1; nocase;)'

    assert "content_modifier_without_content" in codes(text)


def test_content_modifier_after_content_is_valid() -> None:
    text = 'alert tcp any any -> any 80 (content:"x"; nocase; msg:"x"; sid:1; rev:1;)'

    assert "content_modifier_without_content" not in codes(text)


def test_ruleset_validation_reports_duplicate_sids() -> None:
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"a"; sid:1; rev:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"b"; sid:1; rev:1;)'),
    ]

    assert any(d.code == "duplicate_sid" for d in validate_rules(rules))


def test_target_validation_reports_unknown_keyword() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"x"; sid:1;)')
    target = EngineTarget("test-engine", "1.x", frozenset({"sid"}))

    diagnostics = validate_rule(rule, target=target)

    assert any(d.code == "unsupported_engine_keyword" for d in diagnostics)


@pytest.mark.parametrize("keyword", ["sid", "gid", "rev", "priority"])
def test_singleton_rule_options_are_reported(keyword: str) -> None:
    value = "1"
    text = (
        'alert tcp any any -> any 80 (msg:"x"; sid:1; rev:1; '
        f"{keyword}:{value}; {keyword}:{value};)"
    )

    assert "duplicate_singleton_option" in codes(text)
