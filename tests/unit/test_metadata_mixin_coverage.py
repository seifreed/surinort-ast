# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for MetadataOptionsMixin to achieve maximum achievable code coverage.

This test suite targets lines in metadata_mixin.py with the following notes:

UNREACHABLE LINES (Dead Code):
- Line 112: if sid < 1 - Pydantic Field(ge=1) validates before this code executes
- Line 144: if rev < 1 - Pydantic Field(ge=1) validates before this code executes
- Line 230: if priority < 1 or priority > 4 - Pydantic Field(ge=1, le=4) validates first

These defensive validations are unreachable in normal execution because Pydantic's
validator raises ValidationError before the transformer's add_diagnostic code runs.
They exist as defensive programming but cannot be tested without modifying Pydantic models.

REACHABLE LINES COVERED BY THIS SUITE:
- Line 290: return "" when reference_id items list is empty
- Lines 318, 341, 360: metadata edge cases (empty lists, invalid items)
- Lines 350-357: Tree node handling in metadata_entry

All tests use real parser execution without mocks or test doubles.
"""

import pytest
from lark import Lark, Token

from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.transformer import RuleTransformer


def create_token(token_type: str, value: str) -> Token:
    """
    Create a Token with all required position attributes for testing.

    Args:
        token_type: Token type (e.g., "INT", "WORD")
        value: Token value

    Returns:
        Token with position attributes set

    Note:
        Lark tokens need position attributes (line, column, start_pos, etc.)
        for location tracking. This helper creates tokens suitable for direct
        transformer method testing.
    """
    # Create base token
    token = Token(token_type, value)
    # Set required position attributes
    token.line = 1
    token.column = 1
    token.start_pos = 0
    token.end_line = 1
    token.end_column = len(value)
    token.end_pos = len(value)
    return token


class TestGidOption:
    """Test gid_option coverage (lines 170-171)."""

    def test_gid_option_basic(self):
        """
        Test gid_option with valid value.

        Coverage: Lines 170-171 (gid_option return statement)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        gid_token = create_token("INT", "1")

        result = transformer.gid_option(gid_token)

        assert result.value == 1
        assert result.location is not None


class TestClasstypeOption:
    """Test classtype_option coverage (lines 198-199)."""

    def test_classtype_option_basic(self):
        """
        Test classtype_option with valid value.

        Coverage: Lines 198-199 (classtype_option return statement)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        classtype_token = create_token("WORD", "trojan-activity")

        result = transformer.classtype_option(classtype_token)

        assert result.value == "trojan-activity"
        assert result.location is not None


class TestReferenceOption:
    """Test reference_option coverage (lines 266-269)."""

    def test_reference_option_with_token_id(self):
        """
        Test reference_option with Token as ref_id.

        Coverage: Lines 266-269 (reference_option with Token ref_id)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        ref_type_token = create_token("WORD", "cve")
        ref_id_token = create_token("WORD", "2021-12345")

        result = transformer.reference_option(ref_type_token, ref_id_token)

        assert result.ref_type == "cve"
        assert result.ref_id == "2021-12345"
        assert result.location is not None

    def test_reference_option_with_string_id(self):
        """
        Test reference_option with string as ref_id.

        Coverage: Lines 266-269 (reference_option with string ref_id)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        ref_type_token = create_token("WORD", "url")

        # Test with string ref_id (already processed)
        result = transformer.reference_option(ref_type_token, "example.com/advisory")

        assert result.ref_type == "url"
        assert result.ref_id == "example.com/advisory"


class TestReferenceEdgeCases:
    """Test reference_id edge cases (line 290)."""

    def test_reference_id_empty_items(self):
        """
        Test reference_id with empty items list.

        Coverage: Line 290 (return "" when items is empty)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Directly test the reference_id method with empty list
        result = transformer.reference_id([])

        assert result == "", "Expected empty string for empty items"

    def test_reference_id_single_token(self):
        """
        Test reference_id with single token.

        This verifies the normal path (line 289) works correctly.
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create a real Token
        token = create_token("WORD", "CVE-2021-12345")
        result = transformer.reference_id([token])

        assert result == "CVE-2021-12345", "Expected token value as string"


class TestMetadataEntryEdgeCases:
    """Test metadata_entry edge cases (lines 341, 350-357, 360)."""

    def test_metadata_entry_empty_items(self):
        """
        Test metadata_entry with empty items list.

        Coverage: Line 341 (return ("", "") when items is empty)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Directly test metadata_entry method with empty list
        result = transformer.metadata_entry([])

        assert result == ("", ""), "Expected empty tuple for empty items"

    def test_metadata_entry_only_key(self):
        """
        Test metadata_entry with only key (no value).

        Coverage: Line 364 (value = "" when len(values) == 1)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create Token with only key
        key_token = create_token("WORD", "author")
        result = transformer.metadata_entry([key_token])

        assert result == ("author", ""), "Expected key with empty value"

    def test_metadata_entry_key_value(self):
        """
        Test metadata_entry with key and single value.

        Coverage: Line 364 (value joining with single value)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create Tokens for key and value
        key_token = create_token("WORD", "author")
        value_token = create_token("WORD", "seifreed")
        result = transformer.metadata_entry([key_token, value_token])

        assert result == ("author", "seifreed"), "Expected key-value pair"

    def test_metadata_entry_key_multiple_values(self):
        """
        Test metadata_entry with key and multiple values (space-joined).

        Coverage: Line 364 (value joining with multiple values)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create Tokens for key and multiple values
        key_token = create_token("WORD", "created_at")
        value1_token = create_token("WORD", "2021")
        value2_token = create_token("WORD", "01")
        value3_token = create_token("WORD", "15")

        result = transformer.metadata_entry([key_token, value1_token, value2_token, value3_token])

        assert result == ("created_at", "2021 01 15"), "Expected space-joined values"

    def test_metadata_entry_with_tree_nodes(self, lark_parser: Lark, transformer: RuleTransformer):
        """
        Test metadata_entry with Tree nodes (lines 350-357).

        Coverage: Lines 350-357 (Tree node handling in metadata_entry)

        This tests real parsing where metadata values come as Tree nodes.
        """
        # Rule with metadata containing multiple words
        rule_text = (
            'alert tcp any any -> any any (msg:"Test"; metadata:created_at 2021 01 15; sid:1;)'
        )
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)

        rule = result[0]
        assert isinstance(rule, Rule)

        # Find metadata option
        metadata_options = [opt for opt in rule.options if hasattr(opt, "entries")]
        assert len(metadata_options) > 0, "Expected metadata option"

        metadata_option = metadata_options[0]
        assert len(metadata_option.entries) > 0, "Expected metadata entries"

        # Verify the entry was parsed correctly
        key, value = metadata_option.entries[0]
        assert key == "created_at", "Expected 'created_at' key"
        assert value == "2021 01 15", "Expected space-joined date values"

    def test_metadata_entry_string_items(self):
        """
        Test metadata_entry with string items (line 357).

        Coverage: Line 357 (string item handling)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Test with string items instead of Tokens
        result = transformer.metadata_entry(["key", "value1", "value2"])

        assert result == ("key", "value1 value2"), "Expected string handling"

    def test_metadata_entry_no_valid_values(self):
        """
        Test metadata_entry when no valid values are extracted.

        Coverage: Line 360 (return ("", "") when values is empty)

        This tests edge case where items contain objects that don't match
        Token, Tree, or str types.
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Test with items that won't produce valid values
        # Using None or other non-extractable objects
        result = transformer.metadata_entry([None])

        assert result == ("", ""), "Expected empty tuple when no valid values"

    def test_metadata_entry_with_tree_containing_token(self):
        """
        Test metadata_entry with Tree containing Token child.

        Coverage: Lines 352-355 (Tree with children containing Token)

        This directly tests the Tree node extraction logic.
        """
        from lark import Tree

        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create Tree with Token child (simulating metadata_word production)
        key_token = create_token("WORD", "author")
        value_token = create_token("WORD", "seifreed")
        tree_with_token = Tree("metadata_word", [value_token])

        result = transformer.metadata_entry([key_token, tree_with_token])

        assert result == ("author", "seifreed"), "Expected key-value from Tree node"

    def test_metadata_entry_with_empty_tree(self):
        """
        Test metadata_entry with empty Tree (no children).

        Coverage: Line 352 (if item.children branch when children is empty)
        """
        from lark import Tree

        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Create empty Tree
        key_token = create_token("WORD", "author")
        empty_tree = Tree("metadata_word", [])

        result = transformer.metadata_entry([key_token, empty_tree])

        # Empty tree contributes no value
        assert result == ("author", ""), "Expected key with no value from empty Tree"


class TestMetadataOptionEdgeCases:
    """Test metadata_option edge cases (line 318)."""

    def test_metadata_option_with_tuple_entries(self):
        """
        Test metadata_option with tuple entries (line 318).

        Coverage: Line 318 (tuple entry handling)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Test with tuple entries (simulating metadata_entry output)
        items = [
            ("author", "seifreed"),
            ("created_at", "2021 01 15"),
        ]

        result = transformer.metadata_option(items)

        assert len(result.entries) == 2, "Expected 2 metadata entries"
        assert result.entries[0] == ("author", "seifreed")
        assert result.entries[1] == ("created_at", "2021 01 15")

    def test_metadata_option_with_list_entries(self):
        """
        Test metadata_option with list entries (line 318).

        Coverage: Line 318 (list entry handling)
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Test with list entries instead of tuples
        items = [
            ["key1", "value1"],
            ["key2", "value2"],
        ]

        result = transformer.metadata_option(items)

        assert len(result.entries) == 2, "Expected 2 metadata entries"
        assert result.entries[0] == ("key1", "value1")
        assert result.entries[1] == ("key2", "value2")

    def test_metadata_option_invalid_entries_skipped(self):
        """
        Test that metadata_option skips invalid entries.

        This verifies that only valid (list/tuple with len==2) entries are processed.
        """
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        # Mix of valid and invalid entries
        items = [
            ("valid1", "value1"),
            "invalid_string",
            ("only_one",),  # tuple with len != 2
            ("valid2", "value2"),
            ["valid3", "value3"],
            None,
        ]

        result = transformer.metadata_option(items)

        # Only valid entries should be included
        assert len(result.entries) == 3, "Expected only 3 valid entries"
        assert result.entries[0] == ("valid1", "value1")
        assert result.entries[1] == ("valid2", "value2")
        assert result.entries[2] == ("valid3", "value3")


class TestIntegrationMetadataEdgeCases:
    """Integration tests for complex metadata scenarios."""

    def test_complex_metadata_with_multiple_entries(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """
        Test complex rule with multiple metadata entries.

        This integration test ensures all metadata parsing works together.
        """
        rule_text = (
            "alert tcp any any -> any any ("
            'msg:"Complex Metadata Test"; '
            "metadata:author seifreed, created_at 2021 01 15, attack_target Client_Endpoint; "
            "sid:1;)"
        )
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)

        rule = result[0]
        assert isinstance(rule, Rule)

        # Find metadata option
        metadata_options = [opt for opt in rule.options if hasattr(opt, "entries")]
        assert len(metadata_options) > 0, "Expected metadata option"

        metadata_option = metadata_options[0]
        assert len(metadata_option.entries) == 3, "Expected 3 metadata entries"

        # Verify entries
        entries_dict = dict(metadata_option.entries)
        assert entries_dict["author"] == "seifreed"
        assert entries_dict["created_at"] == "2021 01 15"
        assert entries_dict["attack_target"] == "Client_Endpoint"

    def test_all_metadata_options_in_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """
        Test rule with all metadata-related options.

        This comprehensive test covers msg, sid, rev, gid, classtype, priority, reference, metadata.
        """
        rule_text = (
            "alert tcp any any -> any any ("
            'msg:"All Options"; '
            "sid:1000001; "
            "rev:2; "
            "gid:1; "
            "classtype:trojan-activity; "
            "priority:1; "
            "reference:cve,2021-12345; "
            "metadata:author seifreed; "
            ")"
        )
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)

        rule = result[0]
        assert isinstance(rule, Rule)
        assert len(rule.options) >= 7, "Expected at least 7 options"

        # Verify each option type is present
        option_types = {type(opt).__name__ for opt in rule.options}
        assert "MsgOption" in option_types
        assert "SidOption" in option_types
        assert "RevOption" in option_types
        assert "GidOption" in option_types
        assert "ClasstypeOption" in option_types
        assert "PriorityOption" in option_types
        assert "ReferenceOption" in option_types
        assert "MetadataOption" in option_types


class TestPydanticValidationBehavior:
    """
    Document Pydantic validation behavior that makes lines 112, 144, 230 unreachable.

    These tests demonstrate WHY certain defensive validation lines cannot be covered.
    """

    def test_sid_pydantic_validation_prevents_zero(self):
        """
        Demonstrate that Pydantic Field(ge=1) prevents SID=0 from reaching transformer logic.

        This test shows that line 112 in metadata_mixin.py is UNREACHABLE because
        Pydantic's validation raises ValidationError before add_diagnostic is called.
        """
        from pydantic_core import ValidationError

        from surinort_ast.core.nodes import SidOption

        # Attempt to create SidOption with value < 1
        with pytest.raises(ValidationError) as exc_info:
            SidOption(value=0)

        # Verify Pydantic caught the error
        assert "greater_than_equal" in str(exc_info.value)

    def test_rev_pydantic_validation_prevents_zero(self):
        """
        Demonstrate that Pydantic Field(ge=1) prevents Rev=0 from reaching transformer logic.

        This test shows that line 144 in metadata_mixin.py is UNREACHABLE.
        """
        from pydantic_core import ValidationError

        from surinort_ast.core.nodes import RevOption

        with pytest.raises(ValidationError) as exc_info:
            RevOption(value=0)

        assert "greater_than_equal" in str(exc_info.value)

    def test_priority_pydantic_validation_prevents_out_of_range(self):
        """
        Demonstrate that Pydantic Field(ge=1, le=4) prevents Priority out of range.

        This test shows that line 230 in metadata_mixin.py is UNREACHABLE.
        """
        from pydantic_core import ValidationError

        from surinort_ast.core.nodes import PriorityOption

        # Test value < 1
        with pytest.raises(ValidationError) as exc_info:
            PriorityOption(value=0)
        assert "greater_than_equal" in str(exc_info.value)

        # Test value > 4
        with pytest.raises(ValidationError) as exc_info:
            PriorityOption(value=5)
        assert "less_than_equal" in str(exc_info.value)
