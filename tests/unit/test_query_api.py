"""
Unit tests for Query API (Phase 1 MVP).

Tests CSS-style AST selectors for Snort/Suricata rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.query import (
    QuerySyntaxError,
    query,
    query_exists,
    query_first,
)


class TestBasicTypeSelectors:
    """Test basic type selectors (Phase 1)."""

    def test_type_selector_single_match(self):
        """Test type selector with single match."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Find SidOption node
        results = query(rule, "SidOption")
        assert len(results) == 1
        assert results[0].node_type == "SidOption"
        assert results[0].value == 1

    def test_type_selector_multiple_matches(self):
        """Test type selector with multiple matches."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; content:"A"; content:"B"; sid:1;)'
        )

        # Find all ContentOption nodes
        results = query(rule, "ContentOption")
        assert len(results) == 2
        assert all(r.node_type == "ContentOption" for r in results)

    def test_type_selector_no_matches(self):
        """Test type selector with no matches."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Try to find PcreOption (not present)
        results = query(rule, "PcreOption")
        assert len(results) == 0
        assert results == []

    def test_type_selector_case_sensitive(self):
        """Test that type selectors are case-sensitive."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Exact case should work
        results = query(rule, "SidOption")
        assert len(results) == 1

        # Wrong case should not match
        results = query(rule, "sidoption")
        assert len(results) == 0

    def test_universal_selector(self):
        """Test universal selector matches all nodes."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Universal selector should match many nodes
        results = query(rule, "*")
        assert len(results) > 0
        # Should match various address/port nodes, SidOption, etc.
        # Note: Rule and Header nodes are handled by specialized visitors,
        # so they appear as the root but descendants are matched
        assert any(r.node_type == "SidOption" for r in results)
        assert any(r.node_type == "AnyAddress" for r in results)


class TestAttributeSelectors:
    """Test attribute equality selectors (Phase 1)."""

    def test_attribute_equality_int(self):
        """Test attribute selector with integer value."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")

        # Find SidOption with value=1000001
        results = query(rule, "SidOption[value=1000001]")
        assert len(results) == 1
        assert results[0].value == 1000001

        # Try non-matching value
        results = query(rule, "SidOption[value=9999999]")
        assert len(results) == 0

    def test_attribute_equality_string(self):
        """Test attribute selector with string value."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test message"; sid:1;)')

        # Find MsgOption with specific text (use quotes for strings with spaces)
        results = query(rule, 'MsgOption[text="Test message"]')
        assert len(results) == 1
        assert results[0].text == "Test message"

    def test_attribute_equality_action(self):
        """Test attribute selector on Rule action."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Find Rule with action=alert
        results = query(rule, "Rule[action=alert]")
        assert len(results) == 1
        assert results[0].action == "alert"

        # Try different action
        rule2 = parse_rule("drop tcp any any -> any 80 (sid:1;)")
        results = query(rule2, "Rule[action=drop]")
        assert len(results) == 1
        assert results[0].action == "drop"

    def test_attribute_selector_nonexistent_attribute(self):
        """Test attribute selector on non-existent attribute."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Try to match non-existent attribute
        results = query(rule, "SidOption[nonexistent=value]")
        assert len(results) == 0

    def test_attribute_selector_protocol(self):
        """Test attribute selector on Header protocol."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Find Header with protocol=tcp
        results = query(rule, "Header[protocol=tcp]")
        assert len(results) == 1
        assert results[0].protocol == "tcp"


class TestCombinedSelectors:
    """Test type + attribute combined selectors (Phase 1)."""

    def test_type_and_attribute(self):
        """Test combined type and attribute selector."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1000001;)')

        # Type + attribute
        results = query(rule, "SidOption[value=1000001]")
        assert len(results) == 1
        assert results[0].node_type == "SidOption"
        assert results[0].value == 1000001

    def test_multiple_options_same_type(self):
        """Test selecting specific option when multiple of same type exist."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"A"; content:"B"; sid:1;)')

        # Should find both content options
        results = query(rule, "ContentOption")
        assert len(results) == 2

        # Note: Phase 1 doesn't support content-specific filtering
        # This would require Phase 3 string operators


class TestQueryFirst:
    """Test query_first function (Phase 1)."""

    def test_query_first_single_match(self):
        """Test query_first returns first match."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        result = query_first(rule, "SidOption")
        assert result is not None
        assert result.node_type == "SidOption"
        assert result.value == 1

    def test_query_first_multiple_matches(self):
        """Test query_first returns first of multiple matches."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"A"; content:"B"; sid:1;)')

        # Should return first ContentOption
        result = query_first(rule, "ContentOption")
        assert result is not None
        assert result.node_type == "ContentOption"
        # Should be the first one (content:"A")
        assert result.pattern == b"A"

    def test_query_first_no_match(self):
        """Test query_first returns None when no match."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        result = query_first(rule, "PcreOption")
        assert result is None


class TestQueryExists:
    """Test query_exists function (Phase 1)."""

    def test_query_exists_true(self):
        """Test query_exists returns True when match exists."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        assert query_exists(rule, "SidOption") is True
        assert query_exists(rule, "Rule") is True
        assert query_exists(rule, "Header") is True

    def test_query_exists_false(self):
        """Test query_exists returns False when no match."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        assert query_exists(rule, "PcreOption") is False
        assert query_exists(rule, "ContentOption") is False

    def test_query_exists_with_attribute(self):
        """Test query_exists with attribute selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")

        assert query_exists(rule, "SidOption[value=1000001]") is True
        assert query_exists(rule, "SidOption[value=9999999]") is False


class TestErrorHandling:
    """Test error handling and validation (Phase 1)."""

    def test_invalid_syntax_empty_selector(self):
        """Test error on empty selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        with pytest.raises(QuerySyntaxError):
            query(rule, "")

    def test_invalid_syntax_unclosed_bracket(self):
        """Test error on unclosed attribute bracket."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        with pytest.raises(QuerySyntaxError):
            query(rule, "SidOption[value=1")

    def test_invalid_syntax_malformed_attribute(self):
        """Test error on malformed attribute selector."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        with pytest.raises(QuerySyntaxError):
            query(rule, "SidOption[=1]")


class TestRealWorldUseCases:
    """Test real-world use cases (Phase 1)."""

    def test_find_all_content_options(self):
        """Test finding all content options in a rule."""
        rule = parse_rule(
            "alert tcp any any -> any 80 "
            '(msg:"Multiple contents"; '
            'content:"admin"; nocase; '
            'content:"login"; nocase; '
            "sid:1;)"
        )

        contents = query(rule, "ContentOption")
        assert len(contents) == 2
        assert contents[0].pattern == b"admin"
        assert contents[1].pattern == b"login"

    def test_check_rule_has_sid(self):
        """Test checking if rule has SID option."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        assert query_exists(rule, "SidOption") is True

        # Get the SID value
        sid = query_first(rule, "SidOption")
        assert sid is not None
        assert sid.value == 1

    def test_find_tcp_rules(self):
        """Test finding TCP protocol rules."""
        tcp_rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        udp_rule = parse_rule("alert udp any any -> any 53 (sid:2;)")

        # Check TCP
        assert query_exists(tcp_rule, "Header[protocol=tcp]") is True
        assert query_exists(tcp_rule, "Header[protocol=udp]") is False

        # Check UDP
        assert query_exists(udp_rule, "Header[protocol=udp]") is True
        assert query_exists(udp_rule, "Header[protocol=tcp]") is False

    def test_find_alert_vs_drop_rules(self):
        """Test distinguishing alert vs drop rules."""
        alert_rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        drop_rule = parse_rule("drop tcp any any -> any 80 (sid:2;)")

        # Check alert
        assert query_exists(alert_rule, "Rule[action=alert]") is True
        assert query_exists(alert_rule, "Rule[action=drop]") is False

        # Check drop
        assert query_exists(drop_rule, "Rule[action=drop]") is True
        assert query_exists(drop_rule, "Rule[action=alert]") is False

    def test_complex_rule_analysis(self):
        """Test analyzing a complex rule with many options."""
        rule = parse_rule(
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
            '(msg:"HTTP Admin Access"; '
            "flow:established,to_server; "
            'content:"GET"; http_method; '
            'content:"/admin"; http_uri; '
            'pcre:"/\\/admin\\/[a-z]+/i"; '
            "classtype:web-application-attack; "
            "sid:1000001; rev:2;)"
        )

        # Check various components
        assert query_exists(rule, "Rule[action=alert]") is True
        assert query_exists(rule, "Header[protocol=tcp]") is True
        assert query_exists(rule, "MsgOption") is True
        assert query_exists(rule, "ContentOption") is True
        assert query_exists(rule, "PcreOption") is True
        assert query_exists(rule, "SidOption") is True
        assert query_exists(rule, "RevOption") is True

        # Count content options
        contents = query(rule, "ContentOption")
        assert len(contents) == 2

        # Get SID and Rev values
        sid = query_first(rule, "SidOption")
        assert sid is not None
        assert sid.value == 1000001

        rev = query_first(rule, "RevOption")
        assert rev is not None
        assert rev.value == 2


class TestEdgeCases:
    """Test edge cases and boundary conditions (Phase 1)."""

    def test_query_on_single_option_node(self):
        """Test querying starting from an option node."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Get an option first
        sid_option = query_first(rule, "SidOption")
        assert sid_option is not None

        # Query on the option itself (should match if selector matches)
        results = query(sid_option, "SidOption")
        assert len(results) == 1
        assert results[0] == sid_option

    def test_universal_selector_comprehensive(self):
        """Test universal selector matches all node types."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"A"; sid:1;)')

        # Get all nodes
        all_nodes = query(rule, "*")

        # Should include various node types
        # Note: Rule and Header have specialized visitors, so descendants are matched
        node_types = {n.node_type for n in all_nodes}
        assert "MsgOption" in node_types
        assert "ContentOption" in node_types
        assert "SidOption" in node_types
        assert len(node_types) >= 3

    def test_attribute_with_special_characters(self):
        """Test attribute matching with special characters in values."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test: Special-Chars_123"; sid:1;)')

        # Should match message with special chars
        results = query(rule, "MsgOption")
        assert len(results) == 1
        assert results[0].text == "Test: Special-Chars_123"


class TestPerformance:
    """Basic performance validation tests (Phase 1)."""

    def test_query_large_option_list(self):
        """Test querying rule with many options."""
        # Create rule with many content options
        options = " ".join(f'content:"{i}";' for i in range(50))
        rule = parse_rule(f"alert tcp any any -> any 80 ({options} sid:1;)")

        # Should find all content options
        results = query(rule, "ContentOption")
        assert len(results) == 50

    def test_query_first_early_exit(self):
        """Test that query_first stops at first match."""
        # Create rule with many content options
        options = " ".join(f'content:"{i}";' for i in range(100))
        rule = parse_rule(f"alert tcp any any -> any 80 ({options} sid:1;)")

        # query_first should return quickly (first match only)
        result = query_first(rule, "ContentOption")
        assert result is not None
        assert result.node_type == "ContentOption"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
