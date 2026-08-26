from surinort_ast import apply_safe_fixes, parse_rule, validate_rule, validate_rules
from surinort_ast.analysis import EngineTarget
from surinort_ast.core.enums import Dialect


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
    assert "undefined_byte_variable" in codes(
        "alert tcp any any -> any 80 (byte_test:1,>,1,missing; sid:1;)"
    )
    assert "undefined_byte_variable" in codes(
        "alert tcp any any -> any 80 (byte_jump:1,missing; sid:1;)"
    )


def test_byte_extract_defines_variables_for_relative_modifiers() -> None:
    found = codes(
        'alert tcp any any -> any 80 (content:"x"; byte_extract:1,0,length; '
        'content:"y"; within:length; sid:1;)'
    )

    assert "undefined_byte_variable" not in found


def test_byte_math_tracks_dependencies_and_relative_anchor() -> None:
    assert "undefined_byte_variable" in codes(
        "alert tcp any any -> any 80 (byte_math:bytes missing,offset 0,oper +,rvalue 1,result total; sid:1;)"
    )
    assert "relative_byte_operation_without_anchor" in codes(
        "alert tcp any any -> any 80 (byte_math:bytes 1,offset 0,oper +,rvalue 1,result total,relative; sid:1;)"
    )
    assert "undefined_byte_variable" not in codes(
        'alert tcp any any -> any 80 (content:"x"; byte_math:bytes 1,offset 0,oper +,rvalue 1,result total,relative; '
        "byte_test:1,>,total,0; sid:1;)"
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


def test_flowbit_definition_is_collected_from_rule_without_sid() -> None:
    diagnostics = validate_rules(
        [
            parse_rule('alert tcp any any -> any 80 (flowbits:set,seen; msg:"setter"; )'),
            parse_rule("alert tcp any any -> any 80 (flowbits:isset,seen; sid:2; )"),
        ]
    )

    assert "flowbit_without_definition" not in {diagnostic.code for diagnostic in diagnostics}


def test_flowbits_require_names_for_mutations_and_checks() -> None:
    assert "missing_flowbit_name" in codes("alert tcp any any -> any 80 (flowbits:set; sid:1;)")
    assert "missing_flowbit_name" in codes("alert tcp any any -> any 80 (flowbits:isset; sid:1;)")
    assert not codes("alert tcp any any -> any 80 (flowbits:noalert; sid:1;)") & {
        "missing_flowbit_name",
        "unexpected_flowbit_name",
    }


def test_flowbits_validate_composite_operators() -> None:
    assert "invalid_flowbit_operator" not in codes(
        "alert tcp any any -> any 80 (flowbits:set,a&b; sid:1;)"
    )
    assert "invalid_flowbit_operator" in codes(
        "alert tcp any any -> any 80 (flowbits:set,a|b; sid:1;)"
    )
    assert "invalid_flowbit_operator" not in codes(
        "alert tcp any any -> any 80 (flowbits:isset,a|b; sid:1;)"
    )
    assert "unexpected_flowbit_name" in codes(
        "alert tcp any any -> any 80 (flowbits:noalert,name; sid:1;)"
    )
    assert "invalid_flowbits_action" in codes(
        "alert tcp any any -> any 80 (flowbits:unknown,name; sid:1;)"
    )


def test_flowbits_expand_composite_names_for_cross_rule_checks() -> None:
    diagnostics = validate_rules(
        [
            parse_rule("alert tcp any any -> any 80 (flowbits:set,a&b; sid:1;)"),
            parse_rule("alert tcp any any -> any 80 (flowbits:isset,b; sid:2;)"),
        ]
    )

    assert "flowbit_without_definition" not in {diagnostic.code for diagnostic in diagnostics}


def test_flowbits_are_versioned_per_engine() -> None:
    rule = parse_rule("alert tcp any any -> any 80 (flowbits:toggle,seen; sid:1;)")

    suricata = {
        diagnostic.code for diagnostic in validate_rule(rule, EngineTarget("suricata", "8.0.6"))
    }
    snort3 = {
        diagnostic.code for diagnostic in validate_rule(rule, EngineTarget("snort", "3.12.2.0"))
    }

    assert "deprecated_engine_flowbit_action" in suricata
    assert "unsupported_engine_flowbit_action" in snort3


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


def test_relative_modifier_ranges_and_combinations_are_reported() -> None:
    assert "invalid_relative_modifier_range" not in codes(
        'alert tcp any any -> any 80 (content:"x"; offset:0; sid:1;)'
    )
    assert "invalid_relative_modifier_range" in codes(
        'alert tcp any any -> any 80 (content:"x"; within:0; sid:1;)'
    )
    assert "invalid_relative_modifier_range" in codes(
        'alert tcp any any -> any 80 (content:"x"; distance:1048577; sid:1;)'
    )
    assert "incompatible_content_modifiers" in codes(
        'alert tcp any any -> any 80 (content:"x",startswith,offset 1; sid:1;)'
    )
    assert "incompatible_content_modifiers" in codes(
        'alert tcp any any -> any 80 (content:"x",endswith,distance 1; sid:1;)'
    )
    assert "incompatible_content_modifiers" in codes(
        'alert tcp any any -> any 80 (content:"x",offset 1,distance 1; sid:1;)'
    )
    assert "incompatible_content_modifiers" in codes(
        'alert tcp any any -> any 80 (content:"x",depth 4,within 1; sid:1;)'
    )
    assert "incompatible_content_modifiers" not in codes(
        'alert tcp any any -> any 80 (content:"x",offset 1,depth 4; sid:1;)'
    )
    assert "incompatible_content_modifiers" not in codes(
        'alert tcp any any -> any 80 (content:"x",distance 1,within 4; sid:1;)'
    )
    assert "invalid_relative_modifier_range" not in codes(
        'alert tcp any any -> any 80 (content:"x"; distance:-1048576; sid:1;)'
    )


def test_relative_variable_references_are_checked() -> None:
    assert "undefined_byte_variable" in codes(
        'alert tcp any any -> any 80 (content:"x"; within:missing; sid:1;)'
    )


def test_singleton_threshold_is_reported() -> None:
    assert "duplicate_singleton_option" in codes(
        "alert tcp any any -> any 80 (threshold:type limit,track by_src,count 1,seconds 1; "
        "threshold:type limit,track by_dst,count 1,seconds 1; sid:1;)"
    )


def test_duplicate_msg_is_reported_but_duplicate_content_is_allowed() -> None:
    assert "duplicate_singleton_option" in codes(
        'alert tcp any any -> any 80 (msg:"a"; msg:"b"; sid:1;)'
    )
    assert "duplicate_singleton_option" not in codes(
        'alert tcp any any -> any 80 (content:"a"; content:"b"; sid:1;)'
    )


def test_detection_filter_and_threshold_are_incompatible() -> None:
    assert "incompatible_threshold_options" in codes(
        "alert tcp any any -> any 80 (detection_filter:track by_src,count 1,seconds 1; "
        "threshold:type limit,track by_src,count 1,seconds 1; sid:1;)"
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


def test_engine_target_accepts_qualified_sticky_buffer_name() -> None:
    rule = parse_rule(
        'alert http any any -> any any (http_header:field user-agent; content:"x"; sid:1;)',
        dialect=Dialect.SNORT3,
    )
    target = EngineTarget(
        "snort",
        "3.12.2.0",
        keywords=frozenset({"http_header", "content", "sid"}),
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


def test_engine_target_applies_versioned_priority_ranges() -> None:
    snort2_rule = parse_rule("alert tcp any any -> any 80 (priority:256; sid:1;)")
    snort3_rule = parse_rule("alert tcp any any -> any 80 (priority:2147483648; sid:1;)")
    suricata_rule = parse_rule("alert tcp any any -> any 80 (priority:256; sid:1;)")
    snort2 = EngineTarget("snort", "2.9.x")
    snort3 = EngineTarget("snort", "3.12.2.0")
    suricata = EngineTarget("suricata", "8.0.6")

    assert "engine_priority_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(snort2_rule, target=snort2)
    }
    assert "engine_priority_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(snort3_rule, target=snort3)
    }
    assert "engine_priority_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(suricata_rule, target=suricata)
    }
    assert "engine_priority_out_of_range" not in {
        diagnostic.code
        for diagnostic in validate_rule(
            parse_rule("alert tcp any any -> any 80 (priority:2147483647; sid:1;)"),
            target=snort3,
        )
    }


def test_snort_byte_operations_use_versioned_ranges() -> None:
    snort2 = EngineTarget("snort", "2.9.20")
    snort3 = EngineTarget("snort", "3.12.2.0")

    zero_jump = parse_rule("alert tcp any any -> any 80 (byte_jump:0,0; sid:1;)")
    assert "invalid_byte_length" in {
        diagnostic.code for diagnostic in validate_rule(zero_jump, target=snort2)
    }
    assert "invalid_byte_length" not in {
        diagnostic.code for diagnostic in validate_rule(zero_jump, target=snort3)
    }

    wide_offset = parse_rule("alert tcp any any -> any 80 (byte_test:1,>,1,65536; sid:1;)")
    assert "engine_byte_offset_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(wide_offset, target=snort3)
    }

    wide_value = parse_rule("alert tcp any any -> any 80 (byte_test:1,>,4294967296,0; sid:1;)")
    assert "engine_byte_value_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(wide_value, target=snort3)
    }

    wide_post_offset = parse_rule(
        "alert tcp any any -> any 80 (byte_jump:1,0,post_offset 65536; sid:1;)"
    )
    assert "engine_byte_post_offset_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(wide_post_offset, target=snort3)
    }

    long_string = parse_rule("alert tcp any any -> any 80 (byte_extract:11,0,value,string; sid:1;)")
    assert "engine_byte_length_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(long_string, target=snort3)
    }

    invalid_math = parse_rule(
        "alert tcp any any -> any 80 "
        "(byte_math:bytes 1,offset 0,oper +,rvalue 0,result value; sid:1;)"
    )
    assert "engine_byte_rvalue_out_of_range" in {
        diagnostic.code for diagnostic in validate_rule(invalid_math, target=snort3)
    }

    invalid_flags = parse_rule("alert tcp any any -> any 80 (byte_test:1,>,1,0,hex; sid:1;)")
    assert "invalid_byte_string_format" in {
        diagnostic.code for diagnostic in validate_rule(invalid_flags, target=snort3)
    }

    invalid_endian = parse_rule(
        "alert tcp any any -> any 80 (byte_test:1,>,1,0,big,little; sid:1;)"
    )
    assert "invalid_byte_endian" in {
        diagnostic.code for diagnostic in validate_rule(invalid_endian, target=snort3)
    }

    invalid_mask = parse_rule(
        "alert tcp any any -> any 80 (byte_test:1,>,1,0,bitmask 0x100000000; sid:1;)"
    )
    assert "invalid_byte_bitmask" in {
        diagnostic.code for diagnostic in validate_rule(invalid_mask, target=snort3)
    }

    incomplete_math = parse_rule(
        "alert tcp any any -> any 80 (byte_math:bytes 1,offset 0,oper +,rvalue 1; sid:1;)"
    )
    assert "invalid_byte_math_syntax" in {
        diagnostic.code for diagnostic in validate_rule(incomplete_math, target=snort3)
    }


def test_snort_content_ranges_allow_negative_offset_but_require_match_length() -> None:
    target = EngineTarget("snort", "3.12.2.0")

    negative_offset = parse_rule(
        'alert tcp any any -> any 80 (content:"x",offset -1; sid:1;)',
        dialect=Dialect.SNORT3,
    )
    assert "invalid_relative_modifier_range" not in {
        diagnostic.code for diagnostic in validate_rule(negative_offset, target=target)
    }

    negative_standalone_offset = parse_rule(
        'alert tcp any any -> any 80 (content:"x"; offset -1; sid:2;)',
        dialect=Dialect.SNORT3,
    )
    assert "invalid_relative_modifier_range" not in {
        diagnostic.code for diagnostic in validate_rule(negative_standalone_offset, target=target)
    }

    short_within = parse_rule('alert tcp any any -> any 80 (content:"abcd",within 3; sid:1;)')
    assert "modifier_shorter_than_content" in {
        diagnostic.code for diagnostic in validate_rule(short_within, target=target)
    }
