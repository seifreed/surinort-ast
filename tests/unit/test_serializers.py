# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for JSON serializers.

Tests JSON serialization/deserialization with real data.
NO MOCKS - all tests use actual JSON encoding/decoding.
"""

import json

from lark import Lark

from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.transformer import RuleTransformer
from surinort_ast.serialization.json_serializer import (
    JSONSerializer,
    from_dict,
    from_json,
    to_dict,
    to_json,
)


class TestJSONSerialization:
    """Test JSON serialization."""

    def test_serialize_simple_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Serialize simple rule to JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        serializer = JSONSerializer()
        json_str = serializer.to_json(rule)

        # Should be valid JSON
        data = json.loads(json_str)

        # Should have metadata envelope
        assert "ast_version" in data
        assert "data" in data

        # Data should contain rule fields
        rule_data = data["data"]
        assert rule_data["action"] == "alert"

    def test_serialize_without_metadata(self, lark_parser: Lark, transformer: RuleTransformer):
        """Serialize without metadata envelope."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        serializer = JSONSerializer(include_metadata=False)
        json_str = serializer.to_json(rule)

        data = json.loads(json_str)

        # Should not have metadata envelope
        assert "ast_version" not in data
        assert "action" in data  # Direct rule fields

    def test_serialize_with_custom_indent(self, lark_parser: Lark, transformer: RuleTransformer):
        """Serialize with custom indentation."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Compact (no indent)
        serializer_compact = JSONSerializer(indent=None)
        json_compact = serializer_compact.to_json(rule)

        # Pretty-printed
        serializer_pretty = JSONSerializer(indent=4)
        json_pretty = serializer_pretty.to_json(rule)

        # Compact should be shorter
        assert len(json_compact) < len(json_pretty)

        # Both should parse to same data (excluding timestamps which may differ)
        data_compact = json.loads(json_compact)
        data_pretty = json.loads(json_pretty)

        # Remove timestamps before comparison as they may differ by microseconds
        data_compact.pop("timestamp", None)
        data_pretty.pop("timestamp", None)
        assert data_compact == data_pretty


class TestJSONDeserialization:
    """Test JSON deserialization."""

    def test_deserialize_simple_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Deserialize simple rule from JSON."""
        # Create and serialize rule
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1000001; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        serializer = JSONSerializer()
        json_str = serializer.to_json(original_rule)

        # Deserialize
        restored_rule = serializer.from_json(json_str)

        # Should be a Rule instance
        assert isinstance(restored_rule, Rule)

        # Key fields should match
        assert restored_rule.action == original_rule.action
        assert restored_rule.header.protocol == original_rule.header.protocol

    def test_deserialize_from_dict(self, lark_parser: Lark, transformer: RuleTransformer):
        """Deserialize rule from dictionary."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        serializer = JSONSerializer()

        # Serialize to dict
        rule_dict = serializer.to_dict(original_rule)

        # Deserialize from dict
        restored_rule = serializer.from_dict(rule_dict)

        assert isinstance(restored_rule, Rule)
        assert restored_rule.action == original_rule.action


class TestJSONRoundtrip:
    """Test JSON roundtrip: rule -> JSON -> rule."""

    def test_roundtrip_simple_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Roundtrip simple rule through JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Message"; sid:1000001; rev:2; classtype:misc-attack;)'

        # Parse original
        parse_tree1 = lark_parser.parse(rule_text)
        rule1 = transformer.transform(parse_tree1)[0]

        # Serialize to JSON
        serializer = JSONSerializer()
        json_str = serializer.to_json(rule1)

        # Deserialize
        rule2 = serializer.from_json(json_str)

        # Compare key fields
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert rule1.header.direction == rule2.header.direction
        assert len(rule1.options) == len(rule2.options)

    def test_roundtrip_complex_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Roundtrip complex rule with content."""
        rule_text = 'alert http any any -> any any (msg:"HTTP POST"; flow:established,to_server; http.method; content:"POST"; sid:2000001; rev:1;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        rule1 = transformer.transform(parse_tree)[0]

        # Roundtrip
        serializer = JSONSerializer()
        json_str = serializer.to_json(rule1)
        rule2 = serializer.from_json(json_str)

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert len(rule1.options) == len(rule2.options)


class TestMultipleRulesJSON:
    """Test serialization of multiple rules."""

    def test_serialize_multiple_rules(self, lark_parser: Lark, transformer: RuleTransformer):
        """Serialize multiple rules to JSON."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        rules = []
        for rule_text in rules_text:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        serializer = JSONSerializer()
        json_str = serializer.to_json(rules)

        # Should be valid JSON
        data = json.loads(json_str)

        # Should have metadata
        assert "count" in data
        assert data["count"] == 2

        # Should have rules array
        assert "data" in data
        assert "rules" in data["data"]
        assert len(data["data"]["rules"]) == 2

    def test_deserialize_multiple_rules(self, lark_parser: Lark, transformer: RuleTransformer):
        """Deserialize multiple rules from JSON."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        original_rules = []
        for rule_text in rules_text:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            original_rules.append(rule)

        # Serialize
        serializer = JSONSerializer()
        json_str = serializer.to_json(original_rules)

        # Deserialize
        restored_rules = serializer.from_json(json_str)

        # Should be a sequence
        assert hasattr(restored_rules, "__iter__")
        restored_list = list(restored_rules)
        assert len(restored_list) == 2

        # Compare
        for original, restored in zip(original_rules, restored_list, strict=False):
            assert original.action == restored.action
            assert original.header.protocol == restored.header.protocol


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_to_json_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test to_json convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Use convenience function
        json_str = to_json(rule)

        # Should be valid JSON
        data = json.loads(json_str)
        assert "data" in data or "action" in data

    def test_from_json_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test from_json convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Serialize
        json_str = to_json(rule)

        # Deserialize with convenience function
        restored_rule = from_json(json_str)

        assert isinstance(restored_rule, Rule)

    def test_to_dict_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test to_dict convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Use convenience function
        rule_dict = to_dict(rule)

        assert isinstance(rule_dict, dict)

    def test_from_dict_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test from_dict convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Convert to dict
        rule_dict = to_dict(rule, include_metadata=False)

        # Deserialize with convenience function
        restored_rule = from_dict(rule_dict)

        assert isinstance(restored_rule, Rule)


class TestDeterministicJSON:
    """Test that JSON output is deterministic."""

    def test_json_stable_output(self, lark_parser: Lark, transformer: RuleTransformer):
        """JSON output should be stable (same input -> same output) when timestamps disabled."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Disable timestamps for deterministic output
        serializer = JSONSerializer(sort_keys=True, include_metadata=False)

        # Serialize multiple times
        json_outputs = [serializer.to_json(rule) for _ in range(5)]

        # All outputs should be identical
        assert all(output == json_outputs[0] for output in json_outputs)
