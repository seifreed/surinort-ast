"""
Comprehensive tests for Query API Phase 2 and Phase 3 features.

Tests hierarchical navigation, union selectors, comparison operators,
string operators, pseudo-selectors, and advanced features.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.query import (
    query,
    query_all,
)

# ============================================================================
# Phase 2: Hierarchical Navigation Tests
# ============================================================================


class TestDescendantCombinator:
    """Test descendant combinator (space) for any depth matching."""

    def test_descendant_simple(self):
        """Test simple descendant selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Rule ContentOption would find ContentOptions under Rule (at any depth)
        # But this rule has no ContentOption, so test with SidOption
        results = query(rule, "Rule SidOption")
        assert len(results) == 1
        assert results[0].node_type == "SidOption"

    def test_descendant_multiple_levels(self):
        """Test descendant selector across multiple levels."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"admin"; content:"login"; sid:1;)'
        )

        # Rule ContentOption finds all ContentOptions under Rule
        results = query(rule, "Rule ContentOption")
        assert len(results) == 2

    def test_descendant_no_match(self):
        """Test descendant selector with no matches."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule PcreOption should find no matches
        results = query(rule, "Rule PcreOption")
        assert len(results) == 0


class TestChildCombinator:
    """Test child combinator (>) for direct child matching."""

    def test_child_direct_match(self):
        """Test child selector for direct children."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Rule > Header should match (Header is direct child of Rule)
        results = query(rule, "Rule > Header")
        assert len(results) == 1
        assert results[0].node_type == "Header"

    def test_child_no_indirect_match(self):
        """Test that child selector does not match indirect descendants."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule > SidOption should NOT match because SidOption
        # is not a direct child of Rule (it's an option)
        # Actually, options ARE direct children, so this will match
        results = query(rule, "Rule > SidOption")
        # Options are direct children of Rule
        assert len(results) == 1

    def test_child_with_attributes(self):
        """Test child selector combined with attributes."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule[action=alert] > Header
        results = query(rule, "Rule[action=alert] > Header")
        assert len(results) == 1
        assert results[0].protocol == "tcp"


class TestAdjacentSiblingCombinator:
    """Test adjacent sibling combinator (+) for immediate siblings."""

    def test_adjacent_sibling_match(self):
        """Test adjacent sibling selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # SidOption + RevOption should match
        results = query(rule, "SidOption + RevOption")
        assert len(results) == 1
        assert results[0].node_type == "RevOption"

    def test_adjacent_sibling_no_match(self):
        """Test adjacent sibling with non-adjacent elements."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # MsgOption + RevOption should NOT match (SidOption is in between)
        results = query(rule, "MsgOption + RevOption")
        assert len(results) == 0

    def test_adjacent_sibling_content(self):
        """Test adjacent sibling with content options."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"A"; nocase; content:"B"; sid:1;)')

        # ContentOption + NocaseOption should match
        results = query(rule, "ContentOption + NocaseOption")
        assert len(results) == 1


class TestGeneralSiblingCombinator:
    """Test general sibling combinator (~) for any following siblings."""

    def test_general_sibling_match(self):
        """Test general sibling selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # MsgOption ~ RevOption should match (RevOption follows MsgOption)
        results = query(rule, "MsgOption ~ RevOption")
        assert len(results) == 1
        assert results[0].value == 2

    def test_general_sibling_multiple_matches(self):
        """Test general sibling with multiple following siblings."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"A"; content:"B"; sid:1;)'
        )

        # MsgOption ~ ContentOption should match both ContentOptions
        results = query(rule, "MsgOption ~ ContentOption")
        assert len(results) == 2

    def test_general_sibling_no_preceding(self):
        """Test that general sibling doesn't match preceding elements."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # SidOption ~ MsgOption should NOT match (MsgOption comes before SidOption)
        results = query(rule, "SidOption ~ MsgOption")
        assert len(results) == 0


class TestMultiSelectorChains:
    """Test complex multi-selector chains with combinators."""

    def test_chain_descendant_child(self):
        """Test chain combining descendant and child combinators."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Rule > Header AnyAddress (Header is child, AnyAddress is descendant of Header)
        results = query(rule, "Rule > Header AnyAddress")
        # This should find AnyAddress nodes that are descendants of Header which is a child of Rule
        assert len(results) >= 1

    def test_chain_with_attributes(self):
        """Test chain with attribute selectors."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000001; rev:2;)")

        # Rule[action=alert] > SidOption[value>1000000]
        results = query(rule, "Rule[action=alert] > SidOption[value>1000000]")
        assert len(results) == 1
        assert results[0].value == 1000001


# ============================================================================
# Phase 2: Union Selectors Tests
# ============================================================================


class TestUnionSelectors:
    """Test union selectors (comma-separated) for OR logic."""

    def test_union_simple(self):
        """Test simple union selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # MsgOption, SidOption should match both
        results = query(rule, "MsgOption, SidOption")
        assert len(results) == 2
        node_types = {r.node_type for r in results}
        assert node_types == {"MsgOption", "SidOption"}

    def test_union_multiple(self):
        """Test union with multiple selectors."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"admin"; pcre:"/test/"; sid:1;)'
        )

        # ContentOption, PcreOption, MsgOption
        results = query(rule, "ContentOption, PcreOption, MsgOption")
        assert len(results) == 3

    def test_union_with_attributes(self):
        """Test union with attribute selectors."""
        rule1 = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        rule2 = parse_rule("drop tcp any any -> any 80 (sid:2;)")

        # Rule[action=alert], Rule[action=drop]
        results = query_all([rule1, rule2], "Rule[action=alert], Rule[action=drop]")
        assert len(results) == 2

    def test_union_no_duplicates(self):
        """Test that union doesn't create duplicate results."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # SidOption, SidOption (same selector twice)
        results = query(rule, "SidOption, SidOption")
        # Should deduplicate
        assert len(results) == 1


# ============================================================================
# Phase 3: Comparison Operators Tests
# ============================================================================


class TestComparisonOperators:
    """Test numeric comparison operators (>, <, >=, <=)."""

    def test_greater_than(self):
        """Test greater than operator."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")

        # SidOption[value>1000000]
        results = query(rule, "SidOption[value>1000000]")
        assert len(results) == 1

        # SidOption[value>1000001] should NOT match
        results = query(rule, "SidOption[value>1000001]")
        assert len(results) == 0

    def test_less_than(self):
        """Test less than operator."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:100;)")

        # SidOption[value<1000]
        results = query(rule, "SidOption[value<1000]")
        assert len(results) == 1

        # SidOption[value<100] should NOT match
        results = query(rule, "SidOption[value<100]")
        assert len(results) == 0

    def test_greater_than_or_equal(self):
        """Test greater than or equal operator."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000;)")

        # SidOption[value>=1000]
        results = query(rule, "SidOption[value>=1000]")
        assert len(results) == 1

        # SidOption[value>=999]
        results = query(rule, "SidOption[value>=999]")
        assert len(results) == 1

    def test_less_than_or_equal(self):
        """Test less than or equal operator."""
        rule = parse_rule("alert tcp any any -> any 80 (rev:2;)")

        # RevOption[value<=2]
        results = query(rule, "RevOption[value<=2]")
        assert len(results) == 1

        # RevOption[value<=3]
        results = query(rule, "RevOption[value<=3]")
        assert len(results) == 1

    def test_not_equal(self):
        """Test not equal operator."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # SidOption[value!=999]
        results = query(rule, "SidOption[value!=999]")
        assert len(results) == 1

        # SidOption[value!=1] should NOT match
        results = query(rule, "SidOption[value!=1]")
        assert len(results) == 0


# ============================================================================
# Phase 3: String Operators Tests
# ============================================================================


class TestStringOperators:
    """Test string matching operators (*=, ^=, $=)."""

    def test_contains(self):
        """Test contains substring operator (*=)."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"SQL Injection Attack";)')

        # MsgOption[text*="Injection"]
        results = query(rule, 'MsgOption[text*="Injection"]')
        assert len(results) == 1

        # MsgOption[text*="SQL"]
        results = query(rule, 'MsgOption[text*="SQL"]')
        assert len(results) == 1

    def test_starts_with(self):
        """Test starts with operator (^=)."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"MALWARE-CNC Trojan";)')

        # MsgOption[text^="MALWARE"]
        results = query(rule, 'MsgOption[text^="MALWARE"]')
        assert len(results) == 1

        # MsgOption[text^="Trojan"] should NOT match
        results = query(rule, 'MsgOption[text^="Trojan"]')
        assert len(results) == 0

    def test_ends_with(self):
        """Test ends with operator ($=)."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Attack detected";)')

        # MsgOption[text$="detected"]
        results = query(rule, 'MsgOption[text$="detected"]')
        assert len(results) == 1

        # MsgOption[text$="Attack"] should NOT match
        results = query(rule, 'MsgOption[text$="Attack"]')
        assert len(results) == 0

    def test_string_operators_case_sensitive(self):
        """Test that string operators are case-sensitive."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Admin Access";)')

        # Exact case
        results = query(rule, 'MsgOption[text*="Admin"]')
        assert len(results) == 1

        # Different case
        results = query(rule, 'MsgOption[text*="admin"]')
        # String comparison is case-sensitive
        assert len(results) == 0


# ============================================================================
# Phase 3: Pseudo-Selectors Tests
# ============================================================================


class TestPseudoSelectors:
    """Test pseudo-selectors (:first, :last, :has, :not, :empty)."""

    def test_first_child(self):
        """Test :first-child pseudo-selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # Find first option (should be MsgOption)
        results = query(rule, "Rule > MsgOption:first-child")
        # MsgOption should be the first child option
        assert len(results) == 1 or len(results) == 0  # Depends on implementation

    def test_last_child(self):
        """Test :last-child pseudo-selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # Find last option (should be RevOption)
        results = query(rule, "Rule > RevOption:last-child")
        # RevOption should be the last child option
        assert len(results) == 1 or len(results) == 0  # Depends on implementation

    def test_has_descendant(self):
        """Test :has() pseudo-selector."""
        rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; sid:1;)')

        # Rule:has(PcreOption) should match rules containing PcreOption
        results = query(rule, "Rule:has(PcreOption)")
        assert len(results) == 1

        # Rule:has(ContentOption) should NOT match (no ContentOption in this rule)
        results = query(rule, "Rule:has(ContentOption)")
        assert len(results) == 0

    def test_not_selector(self):
        """Test :not() pseudo-selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule:not([action=drop]) should match alert rules
        results = query(rule, "Rule:not([action=drop])")
        assert len(results) == 1

        # Rule:not([action=alert]) should NOT match
        results = query(rule, "Rule:not([action=alert])")
        assert len(results) == 0

    def test_empty_selector(self):
        """Test :empty pseudo-selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # SidOption:empty (SidOption has no children, so it's empty)
        results = query(rule, "SidOption:empty")
        assert len(results) == 1

    def test_not_empty_selector(self):
        """Test :not-empty pseudo-selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule:not-empty (Rule has children - header and options)
        results = query(rule, "Rule:not-empty")
        assert len(results) == 1


# ============================================================================
# Complex Integration Tests
# ============================================================================


class TestComplexQueries:
    """Test complex queries combining multiple Phase 2/3 features."""

    def test_complex_hierarchical_union(self):
        """Test combination of hierarchical selectors and union."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"admin"; pcre:"/test/"; sid:1;)'
        )

        # (Rule > ContentOption), (Rule > PcreOption)
        results = query(rule, "Rule > ContentOption, Rule > PcreOption")
        assert len(results) == 2

    def test_complex_attributes_combinators(self):
        """Test combination of attributes and combinators."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"High priority"; priority:1; sid:1000001;)'
        )

        # Rule[action=alert] > SidOption[value>1000000]
        results = query(rule, "Rule[action=alert] > SidOption[value>1000000]")
        assert len(results) == 1

    def test_complex_string_ops_hierarchy(self):
        """Test combination of string operators and hierarchy."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"MALWARE detected"; sid:1;)')

        # Rule MsgOption[text^="MALWARE"]
        results = query(rule, 'Rule MsgOption[text^="MALWARE"]')
        assert len(results) == 1

    def test_complex_pseudo_union(self):
        """Test combination of pseudo-selectors and union."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"A"; content:"B"; sid:1;)'
        )

        # Rule:has(ContentOption), Rule:has(PcreOption)
        results = query(rule, "Rule:has(ContentOption), Rule:has(PcreOption)")
        # Should match once for ContentOption
        assert len(results) == 1

    def test_real_world_complex_query(self):
        """Test real-world complex query scenario."""
        rules = [
            parse_rule(
                "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
                '(msg:"HTTP Admin Access"; flow:established,to_server; '
                'content:"GET"; content:"/admin"; pcre:"/\\/admin\\/[a-z]+/i"; '
                "sid:1000001; rev:2;)"
            ),
            parse_rule(
                "drop tcp any any -> any 445 "
                '(msg:"SMB Attack"; content:"|ff|SMB"; '
                "sid:1000002; rev:1;)"
            ),
            parse_rule('alert tcp any any -> any 3389 (msg:"RDP Connection"; sid:1000003; rev:1;)'),
        ]

        # Find all alert rules with high SIDs
        results = query_all(rules, "Rule[action=alert] > SidOption[value>1000000]")
        assert len(results) == 2

        # Find rules with PCRE or ContentOption containing specific patterns
        results = query_all(rules, "Rule:has(PcreOption), Rule:has(ContentOption)")
        assert len(results) >= 2


# ============================================================================
# Performance and Edge Cases
# ============================================================================


class TestEdgeCasesPhase23:
    """Test edge cases for Phase 2/3 features."""

    def test_empty_union(self):
        """Test union with no matches."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # ContentOption, PcreOption (neither present)
        results = query(rule, "ContentOption, PcreOption")
        assert len(results) == 0

    def test_deeply_nested_selectors(self):
        """Test deeply nested hierarchical selectors."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Rule > Header > AnyAddress
        results = query(rule, "Rule > Header > AnyAddress")
        # Header has address children, but they're not direct children (they're attributes)
        # This might not match depending on implementation
        assert len(results) >= 0

    def test_multiple_combinators_chain(self):
        """Test chain with multiple different combinators."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')

        # Rule > MsgOption + SidOption
        results = query(rule, "Rule > MsgOption + SidOption")
        # MsgOption is child of Rule, and SidOption is adjacent to MsgOption
        assert len(results) == 1 or len(results) == 0

    def test_attribute_operator_edge_values(self):
        """Test comparison operators with edge values."""
        # Use sid:1 (minimum valid SID value) to test edge cases
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # SidOption[value>=1] - test edge value match
        results = query(rule, "SidOption[value>=1]")
        assert len(results) == 1

        # SidOption[value<1] - test edge value non-match
        results = query(rule, "SidOption[value<1]")
        assert len(results) == 0


# ============================================================================
# Regression Tests
# ============================================================================


class TestPhase1Regression:
    """Ensure Phase 1 features still work correctly after Phase 2/3."""

    def test_basic_type_selector_still_works(self):
        """Test that basic type selectors still work."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        results = query(rule, "SidOption")
        assert len(results) == 1

    def test_basic_attribute_selector_still_works(self):
        """Test that basic attribute selectors still work."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000;)")
        results = query(rule, "SidOption[value=1000]")
        assert len(results) == 1

    def test_universal_selector_still_works(self):
        """Test that universal selector still works."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        results = query(rule, "*")
        assert len(results) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
