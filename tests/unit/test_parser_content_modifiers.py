"""
Regression tests for content-modifier parsing data loss.

These cover bugs where the parser silently corrupted or dropped values:

- Inline content modifiers (Snort3 ``content:"x",depth 16`` form) stored the
  string repr of a Lark ``Tree`` instead of the integer value.
- Negative ``distance`` lost its sign (``distance:-5`` parsed as ``5``).
- ``fast_pattern:<offset>,<length>`` dropped both parameters.
- Negative offsets in ``byte_test`` / ``byte_jump`` / ``byte_extract`` (and
  ``byte_jump`` ``post_offset -N``) dropped the minus sign.
- ``content:!"..."`` negation was dropped (no negated field, '!' filtered).

The shared root cause is that anonymous ``"-"`` / ``"!"`` literals are filtered
out by Lark; the fix promotes them to named ``neg_sign`` / ``neg_bang`` marker
rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule


def _content(rule):
    """The first ContentOption of a rule."""
    return next(o for o in rule.options if o.node_type == "ContentOption")


def _modifier(rule, name):
    """Value of the named inline content modifier on the first content."""
    content = _content(rule)
    return next(m.value for m in content.modifiers if m.name.value == name)


def _option(rule, node_type):
    return next(o for o in rule.options if o.node_type == node_type)


class TestInlineContentModifiers:
    """Snort3 inline modifiers must carry their real integer values."""

    def test_inline_depth_offset_distance_within_are_integers(self):
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x",depth 16,offset 4,distance 2,within 20; sid:1;)'
        )
        assert _modifier(rule, "depth") == 16
        assert _modifier(rule, "offset") == 4
        assert _modifier(rule, "distance") == 2
        assert _modifier(rule, "within") == 20

    def test_inline_modifier_value_is_not_a_stringified_tree(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x",depth 16; sid:1;)')
        value = _modifier(rule, "depth")
        assert isinstance(value, int)
        assert "Tree" not in str(value)

    def test_inline_negative_distance(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x",distance -3; sid:1;)')
        assert _modifier(rule, "distance") == -3

    def test_unknown_inline_modifier_preserves_name_not_nocase(self):
        """An unrecognized inline content modifier must keep its literal name and
        emit a diagnostic, not be silently coerced to ``nocase``."""
        rule = parse_rule('alert tcp any any -> any any (content:"abc",wibble; sid:1;)')
        modifier = _content(rule).modifiers[0]
        assert modifier.name == "wibble"
        assert any("wibble" in d.message for d in rule.diagnostics)


class TestStandaloneDistanceSign:
    """Standalone ``distance:N`` must preserve a negative sign."""

    def test_negative_distance(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x"; distance:-5; sid:1;)')
        assert _option(rule, "DistanceOption").value == -5

    def test_positive_distance_unchanged(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x"; distance:5; sid:1;)')
        assert _option(rule, "DistanceOption").value == 5


class TestFastPatternParameters:
    """``fast_pattern`` parameters must round-trip."""

    def test_offset_and_length(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x"; fast_pattern:10,20; sid:1;)')
        fp = _option(rule, "FastPatternOption")
        assert fp.offset == 10
        assert fp.length == 20

    def test_bare_fast_pattern_has_no_parameters(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x"; fast_pattern; sid:1;)')
        fp = _option(rule, "FastPatternOption")
        assert fp.offset is None
        assert fp.length is None

    def test_only_has_no_parameters(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x"; fast_pattern:only; sid:1;)')
        fp = _option(rule, "FastPatternOption")
        assert fp.offset is None
        assert fp.length is None

    def test_only_flag_preserved_and_roundtrips(self):
        """``fast_pattern:only`` must keep its 'only' flag and re-print as such.

        Regression: 'only' was discarded, so the rule round-tripped to a plain
        'fast_pattern;' which has different matching semantics.
        """
        from surinort_ast.printer.text_printer import print_rule

        rule = parse_rule('alert tcp any any -> any any (content:"x"; fast_pattern:only; sid:1;)')
        fp = _option(rule, "FastPatternOption")
        assert fp.only is True
        printed = print_rule(rule)
        assert "fast_pattern:only;" in printed
        assert _option(parse_rule(printed), "FastPatternOption").only is True


class TestInlineFastPatternModifiers:
    """Snort3 inline ``fast_pattern_offset`` / ``fast_pattern_length`` must
    survive parse and re-print, including when only one of the pair is present.

    Regression: a lone ``fast_pattern_offset N`` (or ``fast_pattern_length M``)
    was collapsed to a bare ``fast_pattern;``, silently dropping the value, because
    the canonical merge only kept a value when BOTH offset and length were given.
    """

    def _fast_pattern_value(self, rule):
        content = _content(rule)
        return next(m.value for m in content.modifiers if m.name.value == "fast_pattern")

    def test_inline_offset_only_preserved_and_roundtrips(self):
        from surinort_ast.printer.text_printer import print_rule

        rule = parse_rule(
            'alert tcp any any -> any any (content:"x",fast_pattern_offset 10; sid:1;)'
        )
        assert self._fast_pattern_value(rule) == "10"
        printed = print_rule(rule)
        assert "fast_pattern_offset 10" in printed
        assert "fast_pattern_length" not in printed
        assert self._fast_pattern_value(parse_rule(printed)) == "10"

    def test_inline_length_only_preserved_and_roundtrips(self):
        from surinort_ast.printer.text_printer import print_rule

        rule = parse_rule(
            'alert tcp any any -> any any (content:"x",fast_pattern_length 20; sid:1;)'
        )
        assert self._fast_pattern_value(rule) == ",20"
        printed = print_rule(rule)
        assert "fast_pattern_length 20" in printed
        assert "fast_pattern_offset" not in printed
        assert self._fast_pattern_value(parse_rule(printed)) == ",20"

    def test_inline_offset_and_length_merge_and_roundtrip(self):
        from surinort_ast.printer.text_printer import print_rule

        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x",fast_pattern_offset 10,fast_pattern_length 20; sid:1;)'
        )
        assert self._fast_pattern_value(rule) == "10,20"
        printed = print_rule(rule)
        assert "fast_pattern_offset 10,fast_pattern_length 20" in printed
        assert self._fast_pattern_value(parse_rule(printed)) == "10,20"


class TestByteOperationOffsetSigns:
    """Negative offsets in byte_test / byte_jump / byte_extract must keep their sign."""

    def _generic(self, rule, keyword):
        return next(
            o.value for o in rule.options if o.node_type == "GenericOption" and o.keyword == keyword
        )

    def test_byte_test_negative_offset(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; byte_test:4,>,1000,-4,relative; sid:1;)'
        )
        assert self._generic(rule, "byte_test") == "4,>,1000,-4,relative"

    def test_byte_test_positive_offset_unchanged(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; byte_test:4,>,1000,4,relative; sid:1;)'
        )
        assert self._generic(rule, "byte_test") == "4,>,1000,4,relative"

    @pytest.mark.parametrize("op", ["!<", "!>", "!^", "!<=", "!>=", "!=", "!&"])
    def test_byte_test_negated_operators(self, op):
        """Any byte_test comparison operator may be negated with a leading '!'."""
        rule = parse_rule(
            f'alert tcp any any -> any any (content:"x"; byte_test:4,{op},1234,0; sid:1;)'
        )
        assert self._generic(rule, "byte_test") == f"4,{op},1234,0"

    def test_byte_jump_negative_offset(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; byte_jump:4,-8,relative; sid:1;)'
        )
        assert self._generic(rule, "byte_jump") == "4,-8,relative"

    def test_byte_jump_post_offset_negative(self):
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x"; byte_jump:4,0,relative,post_offset -10; sid:1;)'
        )
        assert self._generic(rule, "byte_jump") == "4,0,relative,post_offset -10"

    def test_byte_extract_negative_offset(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; byte_extract:4,-2,var,relative; sid:1;)'
        )
        assert self._generic(rule, "byte_extract") == "4,-2,var,relative"

    def test_byte_extract_multiplier_value_flag(self):
        """byte_extract value-flags like 'multiplier 2' / 'align 4' (space-separated
        value) are valid Suricata syntax and must parse and round-trip."""
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x"; byte_extract:4,0,var,multiplier 2,relative; sid:1;)'
        )
        assert self._generic(rule, "byte_extract") == "4,0,var,multiplier 2,relative"

    def test_byte_extract_align_value_flag(self):
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x"; byte_extract:4,0,var,relative,align 4; sid:1;)'
        )
        assert self._generic(rule, "byte_extract") == "4,0,var,relative,align 4"

    def test_byte_jump_hex_values(self):
        """byte_jump must accept hex (0x..) values like byte_test, incl. bitmask."""
        rule = parse_rule(
            "alert tcp any any -> any any (byte_jump:0x2,0x10,bitmask 0x03FF; sid:1;)"
        )
        assert self._generic(rule, "byte_jump") == "0x2,0x10,bitmask 0x03FF"

    def test_byte_extract_hex_values(self):
        """byte_extract must accept hex (0x..) values, including a bitmask flag."""
        rule = parse_rule(
            "alert tcp any any -> any any (byte_extract:0x2,0x10,var,bitmask 0x03FF; sid:1;)"
        )
        assert self._generic(rule, "byte_extract") == "0x2,0x10,var,bitmask 0x03FF"

    def test_byte_test_bitmask_keyword_preserved(self):
        """The 'bitmask' keyword must not be dropped from a byte_test flag.

        Regression: the grammar's anonymous "bitmask" literal was filtered by
        Lark, so byte_test:...,bitmask 0x8000 serialized as '...,0x8000'.
        """
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x"; byte_test:2,&,1,0,relative,bitmask 0x8000; sid:1;)'
        )
        assert self._generic(rule, "byte_test") == "2,&,1,0,relative,bitmask 0x8000"


class TestContentNegation:
    """content:!"..." negation must be captured and round-trip through all formats.

    Regression: the anonymous '!' literal was filtered by Lark and ContentOption
    had no negated field, so negated content (the logical inverse of a positive
    match) was silently parsed as a positive match.
    """

    def _content(self, rule):
        return next(o for o in rule.options if o.node_type == "ContentOption")

    def test_negated_content_parsed(self):
        rule = parse_rule('alert tcp any any -> any any (content:!"evil"; sid:1;)')
        assert self._content(rule).negated is True

    def test_non_negated_content_default(self):
        rule = parse_rule('alert tcp any any -> any any (content:"good"; sid:1;)')
        assert self._content(rule).negated is False

    def test_negated_content_with_inline_modifier(self):
        rule = parse_rule('alert tcp any any -> any any (content:!"x",depth 5; sid:1;)')
        content = self._content(rule)
        assert content.negated is True
        assert next(m.value for m in content.modifiers if m.name.value == "depth") == 5

    def test_negation_round_trips_through_text(self):
        from surinort_ast.api import print_rule

        rule = parse_rule('alert tcp any any -> any any (content:!"evil"; sid:1;)')
        printed = print_rule(rule)
        assert "content:!" in printed
        assert self._content(parse_rule(printed)).negated is True

    def test_negation_round_trips_through_json(self):
        from surinort_ast.serialization import from_json, to_json

        rule = parse_rule('alert tcp any any -> any any (content:!"evil"; sid:1;)')
        assert self._content(from_json(to_json(rule))).negated is True

    def test_negation_round_trips_through_protobuf(self):
        from surinort_ast.serialization.protobuf import from_protobuf, to_protobuf

        rule = parse_rule('alert tcp any any -> any any (content:!"evil"; sid:1;)')
        assert self._content(from_protobuf(to_protobuf(rule))).negated is True


class TestScriptAndIsdataatNegation:
    """lua/luajit/isdataat negation must be captured (shared neg_bang fix).

    Regression: the anonymous '!' literal was filtered by Lark, so lua:!s and
    isdataat:!N silently lost their negation (LuaOption already had a negated
    field; isdataat is a GenericOption).
    """

    def test_lua_negated(self):
        rule = parse_rule("alert tcp any any -> any any (lua:!script.lua; sid:1;)")
        lua = _option(rule, "LuaOption")
        assert lua.negated is True
        assert lua.script_name == "script.lua"

    def test_lua_non_negated(self):
        rule = parse_rule("alert tcp any any -> any any (lua:script.lua; sid:1;)")
        assert _option(rule, "LuaOption").negated is False

    def test_lua_script_name_without_extension(self):
        """A Lua script name is just a filename; an extension is not required."""
        rule = parse_rule("alert tcp any any -> any any (lua:check; sid:1;)")
        lua = _option(rule, "LuaOption")
        assert lua.script_name == "check"
        assert lua.negated is False

    def test_lua_multi_dot_script_name(self):
        rule = parse_rule("alert tcp any any -> any any (lua:my.deep.name.lua; sid:1;)")
        assert _option(rule, "LuaOption").script_name == "my.deep.name.lua"

    def test_luajit_negated(self):
        rule = parse_rule("alert tcp any any -> any any (luajit:!s.lua; sid:1;)")
        assert _option(rule, "LuajitOption").negated is True

    def test_lua_negation_round_trips_through_text(self):
        from surinort_ast.api import print_rule

        rule = parse_rule("alert tcp any any -> any any (lua:!script.lua; sid:1;)")
        printed = print_rule(rule)
        assert "lua:!" in printed
        assert _option(parse_rule(printed), "LuaOption").negated is True

    def test_isdataat_negated_value_keeps_bang(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; isdataat:!10,relative; sid:1;)'
        )
        isdataat = next(
            o for o in rule.options if o.node_type == "GenericOption" and o.keyword == "isdataat"
        )
        assert isdataat.value == "!10,relative"

    def test_isdataat_non_negated(self):
        rule = parse_rule(
            'alert tcp any any -> any any (content:"x"; isdataat:10,relative; sid:1;)'
        )
        isdataat = next(
            o for o in rule.options if o.node_type == "GenericOption" and o.keyword == "isdataat"
        )
        assert isdataat.value == "10,relative"


class TestContentEscapeUnescaping:
    r"""Quoted content must unescape \;, \" and \\ to their literal bytes."""

    def test_escaped_semicolon_becomes_literal(self):
        rule = parse_rule(r'alert tcp any any -> any any (content:"a\;b"; sid:1;)')
        assert _content(rule).pattern == b"a;b"

    def test_escaped_quote_and_backslash(self):
        rule = parse_rule(r'alert tcp any any -> any any (content:"a\"b\\c"; sid:1;)')
        assert _content(rule).pattern == b'a"b\\c'

    def test_escapes_round_trip(self):
        from surinort_ast.printer import print_rule

        text = r'alert tcp any any -> any any (content:"a\;b"; sid:1;)'
        printed = print_rule(parse_rule(text))
        assert print_rule(parse_rule(printed)) == printed
        assert _content(parse_rule(printed)).pattern == b"a;b"


class TestPcreNewlineRoundTrip:
    r"""A pcre body containing a literal newline must split body/flags correctly."""

    def test_literal_newline_in_pcre_body_round_trips(self):
        from surinort_ast.printer import print_rule

        text = 'alert tcp any any -> any any (pcre:"/a[^\n]*b/i"; sid:1;)'
        rule = parse_rule(text)
        pcre = _option(rule, "PcreOption")
        # Delimiters must not leak into the stored body, and flags are extracted.
        assert pcre.pattern == "a[^\n]*b"
        assert pcre.flags == "i"
        printed = print_rule(rule)
        assert print_rule(parse_rule(printed)) == printed

    def test_pcre_with_newline_and_leading_slash_is_stable(self):
        from surinort_ast.printer import print_rule

        text = 'alert tcp any any -> any any (pcre:"//x=[^\n]*y/i/"; sid:1;)'
        first = print_rule(parse_rule(text))
        second = print_rule(parse_rule(first))
        assert first == second

    def test_pcre_escape_sequences_are_preserved_verbatim(self):
        r"""Regex escapes (\n, \r, \t, \xNN) inside a pcre are part of the regex
        and must not be interpreted by the rule parser. Interpreting \n into a
        real newline used to split the rule across physical lines, silently
        dropping rules on the next parse."""
        from surinort_ast.printer import print_rule

        text = r'alert tcp any any -> any any (pcre:"/filename=[^\r\n]*\x2eemf/i"; sid:1;)'
        rule = parse_rule(text)
        pcre = _option(rule, "PcreOption")
        assert pcre.pattern == r"filename=[^\r\n]*\x2eemf"
        assert pcre.flags == "i"

        printed = print_rule(rule)
        # No control characters leaked into the serialized rule.
        assert "\n" not in printed
        assert "\r" not in printed
        assert "\t" not in printed
        # Stable fixed point: re-parsing the output yields the same text.
        assert print_rule(parse_rule(printed)) == printed


class TestInlineFastPatternOffsetLength:
    """Snort3 inline fast_pattern offset/length must serialize to valid syntax."""

    def test_inline_fast_pattern_offset_length_merged(self):
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(content:"x",fast_pattern,fast_pattern_offset 0,fast_pattern_length 10; sid:1;)'
        )
        content = _content(rule)
        fps = [m for m in content.modifiers if m.name.value == "fast_pattern"]
        assert len(fps) == 1
        assert fps[0].value == "0,10"

    def test_inline_fast_pattern_offset_length_round_trips(self):
        from surinort_ast.printer import print_rule

        text = (
            "alert tcp any any -> any any "
            '(content:"x",fast_pattern,fast_pattern_offset 0,fast_pattern_length 10; sid:1;)'
        )
        rule = parse_rule(text)
        printed = print_rule(rule)
        # Emitted as the inline offset/length keywords so the modifier stays
        # attached to its content on re-parse (a standalone fast_pattern:0,10
        # would detach into a separate option).
        assert "fast_pattern_offset 0,fast_pattern_length 10" in printed
        reparsed = parse_rule(printed)
        assert not reparsed.diagnostics
        assert print_rule(reparsed) == printed
        # The fast_pattern modifier survives round-trip on the content itself.
        fps = [m for m in _content(reparsed).modifiers if m.name.value == "fast_pattern"]
        assert len(fps) == 1
        assert fps[0].value == "0,10"

    def test_bare_inline_fast_pattern_unchanged(self):
        rule = parse_rule('alert tcp any any -> any any (content:"x",fast_pattern; sid:1;)')
        fps = [m for m in _content(rule).modifiers if m.name.value == "fast_pattern"]
        assert len(fps) == 1
        assert fps[0].value is None

    def test_content_modifiers_stay_attached_on_round_trip(self):
        """Inline modifiers must re-attach to their content, not detach into
        standalone options, when printed and re-parsed."""
        from surinort_ast.printer import print_rule

        rule = parse_rule(
            'alert tcp any any -> any any (content:"WHATISIT",depth 9,nocase; sid:1;)'
        )
        reparsed = parse_rule(print_rule(rule))
        # Same number of top-level options (content stays a single option).
        assert len(reparsed.options) == len(rule.options)
        mods = _content(reparsed).modifiers
        assert [(m.name.value, m.value) for m in mods] == [("depth", 9), ("nocase", None)]


class TestFlagsAndHexGrouping:
    """flags-spec modifiers and canonical hex-block grouping in the printer."""

    @staticmethod
    def _flags(rule):
        from surinort_ast.core.nodes import GenericOption

        return next(
            o.value for o in rule.options if isinstance(o, GenericOption) and o.keyword == "flags"
        )

    @pytest.mark.parametrize("spec", ["A+", "12FS", "FRS*", "S,12", "!S", "SA", "U+"])
    def test_flags_specs_with_modifiers_parse(self, spec):
        """TCP flag specs with +/*/! modifiers and reserved-bit digits are valid
        Suricata/Snort and must parse and round-trip."""
        from surinort_ast.printer import print_rule

        rule = parse_rule(f"alert tcp any any -> any any (flags:{spec}; sid:1;)")
        assert self._flags(rule) == spec
        assert self._flags(parse_rule(print_rule(rule))) == spec

    def test_flag_letter_words_not_stolen_elsewhere(self):
        """The flags terminal must not steal flag-letter words in other contexts."""
        rule = parse_rule(
            'alert tcp any any -> any any (flowbits:set,SAFE; content:"FACE"; sid:1;)'
        )
        from surinort_ast.core.nodes import ContentOption, FlowbitsOption

        flowbits = next(o for o in rule.options if isinstance(o, FlowbitsOption))
        content = next(o for o in rule.options if isinstance(o, ContentOption))
        assert flowbits.name == "SAFE"
        assert content.pattern == b"FACE"

    @pytest.mark.parametrize(
        ("rule_text", "expected_block"),
        [
            ('content:"|00 01 ff|"', "|00 01 FF|"),
            ('content:"a|0d 0a|b"', "a|0D 0A|b"),
            ('content:"|de ad be ef|"', "|DE AD BE EF|"),
        ],
    )
    def test_consecutive_hex_bytes_print_as_one_block(self, rule_text, expected_block):
        """Consecutive non-printable bytes print as one space-separated hex block
        (|00 01 FF|), the canonical form, not one |XX| block per byte."""
        from surinort_ast.printer import print_rule

        rule = parse_rule(f"alert tcp any any -> any any ({rule_text}; sid:1;)")
        printed = print_rule(rule)
        assert f'content:"{expected_block}"' in printed
        # Bytes survive the round-trip.
        assert _content(parse_rule(printed)).pattern == _content(rule).pattern
