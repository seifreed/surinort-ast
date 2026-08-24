from surinort_ast import parse_rule, validate_rule, validate_rules


def codes(rule_text: str) -> set[str]:
    return {
        diagnostic.code
        for diagnostic in validate_rule(parse_rule(rule_text))
        if diagnostic.code is not None
    }


def test_fast_pattern_requires_content() -> None:
    assert "fast_pattern_without_content" in codes(
        "alert tcp any any -> any 80 (fast_pattern; sid:1;)"
    )


def test_byte_variable_must_be_defined_first() -> None:
    assert "undefined_byte_variable" in codes(
        'alert tcp any any -> any 80 (content:"x"; depth:missing; sid:1;)'
    )


def test_duplicate_content_modifier_is_reported() -> None:
    assert "duplicate_content_modifier" in codes(
        'alert tcp any any -> any 80 (content:"x",nocase,nocase; sid:1;)'
    )


def test_flowbit_use_without_definition_is_ruleset_warning() -> None:
    diagnostics = validate_rules(
        [parse_rule("alert tcp any any -> any 80 (flowbits:isset,seen; sid:1;)")]
    )
    assert "flowbit_without_definition" in {diagnostic.code for diagnostic in diagnostics}
