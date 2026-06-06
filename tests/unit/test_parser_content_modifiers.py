"""
Regression tests for content-modifier parsing data loss.

These cover bugs where the parser silently corrupted or dropped values:

- Inline content modifiers (Snort3 ``content:"x",depth 16`` form) stored the
  string repr of a Lark ``Tree`` instead of the integer value.
- Negative ``distance`` lost its sign (``distance:-5`` parsed as ``5``).
- ``fast_pattern:<offset>,<length>`` dropped both parameters.
- Negative offsets in ``byte_test`` / ``byte_jump`` / ``byte_extract`` (and
  ``byte_jump`` ``post_offset -N``) dropped the minus sign.

The shared root cause is that anonymous ``"-"`` literals are filtered out by
Lark; the fix promotes them to a named ``neg_sign`` marker rule.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

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
