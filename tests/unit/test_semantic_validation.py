from surinort_ast import apply_safe_fixes, parse_rule, validate_rule, validate_rules
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


def test_safe_fix_removes_only_exact_duplicate_content_modifiers() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"x",nocase,nocase; sid:1;)')

    fixed = apply_safe_fixes(rule)

    content = next(option for option in fixed.options if option.node_type == "ContentOption")
    assert [modifier.name_str for modifier in content.modifiers] == ["nocase"]
    assert fixed != rule


def test_safe_fix_leaves_different_duplicate_values_unchanged() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (content:"x",offset 1,offset 2; sid:1;)')

    assert apply_safe_fixes(rule) == rule


def test_flowbit_use_without_definition_is_ruleset_warning() -> None:
    diagnostics = validate_rules(
        [parse_rule("alert tcp any any -> any 80 (flowbits:isset,seen; sid:1;)")]
    )
    assert "flowbit_without_definition" in {diagnostic.code for diagnostic in diagnostics}


def test_flowbits_require_names_for_mutations_and_checks() -> None:
    assert "missing_flowbit_name" in codes("alert tcp any any -> any 80 (flowbits:set; sid:1;)")
    assert "missing_flowbit_name" in codes("alert tcp any any -> any 80 (flowbits:isset; sid:1;)")
    assert not codes("alert tcp any any -> any 80 (flowbits:noalert; sid:1;)") & {
        "missing_flowbit_name",
        "unexpected_flowbit_name",
    }


def test_flowbits_reject_invalid_mutation_shapes() -> None:
    assert "composite_flowbit_mutation" in codes(
        "alert tcp any any -> any 80 (flowbits:set,a&b; sid:1;)"
    )
    assert "unexpected_flowbit_name" in codes(
        "alert tcp any any -> any 80 (flowbits:noalert,name; sid:1;)"
    )
    assert "invalid_flowbits_action" in codes(
        "alert tcp any any -> any 80 (flowbits:unknown,name; sid:1;)"
    )


def test_sticky_buffer_and_protocol_constraints_are_reported() -> None:
    assert "buffer_protocol_mismatch" in codes(
        'alert udp any any -> any 53 (http_uri; content:"x"; sid:1;)'
    )
    assert "sticky_buffer_without_match" in codes("alert tcp any any -> any 80 (http_uri; sid:1;)")


def test_relative_and_byte_operator_constraints_are_reported() -> None:
    found = codes('alert tcp any any -> any 80 (pcre:"/x/R"; sid:1;)')
    assert "relative_pcre_without_anchor" in found
    assert "relative_byte_operation_without_anchor" in codes(
        "alert tcp any any -> any 80 (byte_test:1,>,1,0,relative; sid:1;)"
    )
    assert "relative_byte_operation_without_anchor" in codes(
        "alert tcp any any -> any 80 (byte_extract:1,0,value,relative; sid:1;)"
    )
    assert "relative_byte_operation_without_anchor" not in codes(
        'alert tcp any any -> any 80 (content:"x"; byte_jump:1,0,relative; sid:1;)'
    )
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


def test_engine_target_rejects_options_with_missing_catalogued_features() -> None:
    target = EngineTarget(
        "snort",
        "2.9.x",
        keywords=frozenset({"buffer_select", "content", "flowbits", "byte_test", "sid"}),
        features=frozenset({"byte-ops", "flowbits", "pcre"}),
        feature_catalog_complete=True,
        keyword_catalog_complete=True,
    )

    sticky = parse_rule('alert tcp any any -> any 80 (http_uri; content:"x"; sid:1;)')
    byte_rule = parse_rule("alert tcp any any -> any 80 (byte_test:1,>,1,0; sid:1;)")
    flowbit_rule = parse_rule("alert tcp any any -> any 80 (flowbits:set,seen; sid:1;)")

    assert "unsupported_engine_feature" in {
        diagnostic.code for diagnostic in validate_rule(sticky, target=target)
    }
    assert "unsupported_engine_feature" not in {
        diagnostic.code for diagnostic in validate_rule(byte_rule, target=target)
    }
    assert "unsupported_engine_feature" not in {
        diagnostic.code for diagnostic in validate_rule(flowbit_rule, target=target)
    }


def test_engine_target_applies_snort_priority_range_only() -> None:
    rule = parse_rule("alert tcp any any -> any 80 (priority:256; sid:1;)")
    snort = EngineTarget("snort", "2.9.x")
    suricata = EngineTarget("suricata", "8.0.0")

    assert "engine_priority_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(rule, target=snort)
    }
    assert "engine_priority_out_of_range" not in {
        diagnostic.code for diagnostic in validate_rule(rule, target=suricata)
    }
