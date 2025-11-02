# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Complete JSON serializer tests to achieve 100% coverage.

Tests all serialization paths using real rules and data.
NO MOCKS - all tests use actual serialization/deserialization.
"""

import pytest
from lark import Lark

from surinort_ast.parsing.transformer import RuleTransformer
from surinort_ast.serialization.json_serializer import JSONSerializer


class TestJSONSerializerMultipleRules:
    """Test serialization of multiple rules (line 137)."""

    def test_to_dict_multiple_rules(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test to_dict with a list of rules (line 137)."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        rules = []
        for rule_text in rule_texts:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        serializer = JSONSerializer()
        data = serializer.to_dict(rules)

        # With metadata (default), should have nested structure
        assert "data" in data
        assert "rules" in data["data"]
        assert len(data["data"]["rules"]) == 2
        assert data["count"] == 2


class TestJSONSerializerMetadataEnvelope:
    """Test serialization with metadata (line 192)."""

    def test_serialize_without_metadata(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test serialization without metadata envelope (line 192)."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        rules = []
        for rule_text in rule_texts:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Serialize without metadata
        serializer = JSONSerializer(include_metadata=False)
        data = serializer.to_dict(rules)

        # Should only have rules, no metadata
        assert "rules" in data
        assert "ast_version" not in data
        assert "timestamp" not in data
        assert "count" not in data


class TestJSONSerializerValidation:
    """Test metadata validation (lines 205, 209)."""

    def test_validate_metadata_missing_version(self):
        """Test validation fails when ast_version is missing (line 205)."""
        serializer = JSONSerializer()

        # Data without ast_version
        invalid_data = {"data": {"rules": []}}

        with pytest.raises(ValueError, match="Missing ast_version"):
            serializer._validate_metadata(invalid_data)

    def test_validate_metadata_incompatible_version(self):
        """Test validation fails with incompatible version (line 209)."""
        serializer = JSONSerializer()

        # Data with incompatible version
        invalid_data = {"ast_version": "99.99.99", "data": {"rules": []}}

        with pytest.raises(ValueError, match="Incompatible AST version"):
            serializer._validate_metadata(invalid_data)


class TestJSONSerializerRoundtrip:
    """Test full roundtrip with various configurations."""

    def test_roundtrip_multiple_rules_with_metadata(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test complete roundtrip with multiple rules and metadata."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1; rev:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2; rev:1;)',
            'alert udp any any -> any 53 (msg:"Rule 3"; sid:3; rev:1;)',
        ]

        rules = []
        for rule_text in rule_texts:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Serialize with metadata
        serializer = JSONSerializer(include_metadata=True)
        json_str = serializer.to_json(rules)

        # Deserialize
        deserialized_rules = serializer.from_json(json_str)

        # Verify count
        assert len(deserialized_rules) == 3

        # Verify each rule
        for original, deserialized in zip(rules, deserialized_rules, strict=False):
            assert original.action == deserialized.action
            assert original.header.protocol == deserialized.header.protocol

    def test_roundtrip_multiple_rules_without_metadata(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test roundtrip with multiple rules without metadata."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        rules = []
        for rule_text in rule_texts:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Serialize without metadata
        serializer = JSONSerializer(include_metadata=False)
        json_str = serializer.to_json(rules)

        # Deserialize
        deserialized_rules = serializer.from_json(json_str)

        # Verify count
        assert len(deserialized_rules) == 2
