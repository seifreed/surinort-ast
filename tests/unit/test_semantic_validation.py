from surinort_ast import parse_rule, validate_rule, validate_rules
from surinort_ast.analysis import EngineTarget


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


def test_sticky_buffer_and_protocol_constraints_are_reported() -> None:
    assert "buffer_protocol_mismatch" in codes(
        'alert udp any any -> any 53 (http_uri; content:"x"; sid:1;)'
    )
    assert "sticky_buffer_without_match" in codes("alert tcp any any -> any 80 (http_uri; sid:1;)")


def test_relative_and_byte_operator_constraints_are_reported() -> None:
    found = codes('alert tcp any any -> any 80 (pcre:"/x/R"; sid:1;)')
    assert "relative_pcre_without_anchor" in found
    assert "relative_modifier_without_content" in codes(
        'alert tcp any any -> any 80 (content:"x",within 5; sid:1;)'
    )


def test_engine_target_checks_actions_and_protocols() -> None:
    rule = parse_rule('drop udp any any -> any 53 (msg:"x"; sid:1;)')
    target = EngineTarget(
        "suricata",
        "8.x",
        keywords=frozenset({"msg", "sid"}),
        actions=frozenset({"alert"}),
        protocols=frozenset({"tcp"}),
        keyword_catalog_complete=True,
    )

    found = {diagnostic.code for diagnostic in validate_rule(rule, target=target)}

    assert "unsupported_engine_action" in found
    assert "unsupported_engine_protocol" in found


def test_engine_target_uses_canonical_multiword_option_names() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (http_uri; content:"x"; sid:1;)')
    target = EngineTarget(
        "suricata",
        "8.x",
        keywords=frozenset({"buffer_select", "content", "sid"}),
        keyword_catalog_complete=True,
    )

    found = {diagnostic.code for diagnostic in validate_rule(rule, target=target)}

    assert "unsupported_engine_keyword" not in found


def test_engine_target_accepts_catalogued_sticky_buffer_name() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (http_uri; content:"x"; sid:1;)')
    target = EngineTarget(
        "suricata",
        "8.x",
        keywords=frozenset({"http_uri", "content", "sid"}),
        keyword_catalog_complete=True,
    )

    found = {diagnostic.code for diagnostic in validate_rule(rule, target=target)}

    assert "unsupported_engine_keyword" not in found
