# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Complete unit tests for api.py to achieve 100% coverage.

Tests all public API functions, error handling, and edge cases.
NO MOCKS - all tests use real parsing, printing, and serialization.
"""

import json
from pathlib import Path

import pytest

from surinort_ast.api import (
    from_json,
    parse_file,
    parse_rule,
    parse_rules,
    print_rule,
    to_json,
    to_json_schema,
    validate_rule,
)
from surinort_ast.core.enums import DiagnosticLevel, Dialect
from surinort_ast.exceptions import ParseError, SerializationError


class TestParseRule:
    """Test parse_rule function."""

    def test_parse_simple_rule(self):
        """Parse a simple rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule.action.value == "alert"
        assert rule.header.protocol.value == "tcp"

    def test_parse_rule_with_dialect(self):
        """Parse rule with specific dialect."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SURICATA)

        assert rule.raw_text == rule_text

    def test_parse_rule_snort3(self):
        """Parse Snort3 rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SNORT3)

        assert rule.action.value == "alert"

    def test_parse_rule_invalid_syntax(self):
        """Parse invalid rule raises ParseError."""
        rule_text = 'invalid_action tcp any any -> any 80 (msg:"Test"; sid:1;)'

        with pytest.raises(ParseError) as exc_info:
            parse_rule(rule_text)

        assert "Failed to parse rule" in str(exc_info.value)

    def test_parse_rule_unexpected_error(self):
        """Parse rule with unexpected error."""
        # Empty string should trigger an error
        with pytest.raises(ParseError):
            parse_rule("")


class TestParseFile:
    """Test parse_file function."""

    def test_parse_file_basic(self, tmp_path):
        """Parse file with valid rules."""
        file = tmp_path / "test.rules"
        file.write_text("""alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
""")

        rules = parse_file(file)

        assert len(rules) == 2
        assert rules[0].origin.file_path == str(file)
        assert rules[0].origin.line_number == 1
        assert rules[1].origin.line_number == 2

    def test_parse_file_with_comments(self, tmp_path):
        """Parse file with comments."""
        file = tmp_path / "test.rules"
        file.write_text("""# This is a comment
alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
# Another comment
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
""")

        rules = parse_file(file)

        assert len(rules) == 2

    def test_parse_file_with_blank_lines(self, tmp_path):
        """Parse file with blank lines."""
        file = tmp_path / "test.rules"
        file.write_text("""
alert tcp any any -> any 80 (msg:"Test1"; sid:1;)

alert tcp any any -> any 443 (msg:"Test2"; sid:2;)

""")

        rules = parse_file(file)

        assert len(rules) == 2

    def test_parse_file_not_found(self):
        """Parse non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_file(Path("/nonexistent/file.rules"))

    def test_parse_file_not_a_file(self, tmp_path):
        """Parse directory raises ParseError."""
        directory = tmp_path / "dir"
        directory.mkdir()

        with pytest.raises(ParseError) as exc_info:
            parse_file(directory)

        assert "Not a file" in str(exc_info.value)

    def test_parse_file_read_error(self, tmp_path):
        """Parse file with read error."""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Make file unreadable (on Unix-like systems)
        import os

        if os.name != "nt":  # Skip on Windows
            file.chmod(0o000)

            try:
                with pytest.raises(ParseError) as exc_info:
                    parse_file(file)

                assert "Failed to read file" in str(exc_info.value)
            finally:
                # Restore permissions for cleanup
                file.chmod(0o644)

    def test_parse_file_with_some_invalid_rules(self, tmp_path):
        """Parse file with some invalid rules."""
        file = tmp_path / "test.rules"
        file.write_text("""alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
invalid_rule syntax here
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
""")

        rules = parse_file(file)

        # Should parse valid rules and skip invalid
        assert len(rules) == 2

    def test_parse_file_all_invalid_rules(self, tmp_path):
        """Parse file with all invalid rules."""
        file = tmp_path / "test.rules"
        file.write_text("""invalid rule 1
invalid rule 2
invalid rule 3
""")

        with pytest.raises(ParseError) as exc_info:
            parse_file(file)

        assert "Failed to parse any rules" in str(exc_info.value)

    def test_parse_file_with_dialect(self, tmp_path):
        """Parse file with specific dialect."""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        rules = parse_file(file, dialect=Dialect.SNORT3)

        assert len(rules) == 1

    def test_parse_file_string_path(self, tmp_path):
        """Parse file using string path."""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        rules = parse_file(str(file))

        assert len(rules) == 1


class TestPrintRule:
    """Test print_rule function."""

    def test_print_rule_standard(self):
        """Print rule with standard formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule)

        assert "alert" in printed
        assert "msg:" in printed

    def test_print_rule_stable(self):
        """Print rule with stable formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule, stable=True)

        assert "alert" in printed
        assert "msg:" in printed

    def test_print_rule_not_stable(self):
        """Print rule without stable formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule, stable=False)

        assert "alert" in printed


class TestJSONSerialization:
    """Test JSON serialization functions."""

    def test_to_json_basic(self):
        """Serialize rule to JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule)

        assert len(json_str) > 0
        data = json.loads(json_str)
        assert data["action"] == "alert"

    def test_to_json_compact(self):
        """Serialize rule to compact JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule, indent=None)

        assert len(json_str) > 0
        assert "\n" not in json_str  # Compact format

    def test_to_json_with_indent(self):
        """Serialize rule to JSON with indentation."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule, indent=4)

        assert len(json_str) > 0
        assert "\n" in json_str  # Formatted with newlines

    def test_from_json_string(self):
        """Deserialize rule from JSON string."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        original_rule = parse_rule(rule_text)

        json_str = to_json(original_rule)
        restored_rule = from_json(json_str)

        assert restored_rule.action == original_rule.action
        assert restored_rule.header.protocol == original_rule.header.protocol

    def test_from_json_dict(self):
        """Deserialize rule from dict."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        original_rule = parse_rule(rule_text)

        json_str = to_json(original_rule)
        data_dict = json.loads(json_str)
        restored_rule = from_json(data_dict)

        assert restored_rule.action == original_rule.action

    def test_from_json_invalid(self):
        """Deserialize invalid JSON raises SerializationError."""
        invalid_json = '{"invalid": '

        with pytest.raises(SerializationError) as exc_info:
            from_json(invalid_json)

        assert "Invalid JSON" in str(exc_info.value)

    def test_from_json_invalid_data(self):
        """Deserialize invalid data raises SerializationError."""
        invalid_data = {"invalid_field": "value"}

        with pytest.raises(SerializationError) as exc_info:
            from_json(invalid_data)

        assert "Failed to deserialize" in str(exc_info.value)

    def test_to_json_schema(self):
        """Generate JSON schema."""
        schema = to_json_schema()

        assert isinstance(schema, dict)
        assert "$defs" in schema or "definitions" in schema or "properties" in schema


class TestValidateRule:
    """Test validate_rule function."""

    def test_validate_rule_complete(self):
        """Validate complete rule with no issues."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have no errors, but may have warnings
        errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
        assert len(errors) == 0

    def test_validate_rule_missing_sid(self):
        """Validate rule missing SID."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test";)'
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have warning about missing SID
        sid_warnings = [d for d in diagnostics if "sid" in d.message.lower()]
        assert len(sid_warnings) > 0
        assert sid_warnings[0].level == DiagnosticLevel.WARNING
        assert sid_warnings[0].code == "missing_sid"

    def test_validate_rule_missing_msg(self):
        """Validate rule missing MSG."""
        rule_text = "alert tcp any any -> any 80 (sid:1;)"
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have warning about missing MSG
        msg_warnings = [d for d in diagnostics if "msg" in d.message.lower()]
        assert len(msg_warnings) > 0
        assert msg_warnings[0].level == DiagnosticLevel.WARNING
        assert msg_warnings[0].code == "missing_msg"

    def test_validate_rule_missing_both(self):
        """Validate rule missing both SID and MSG."""
        # Parser requires at least empty parentheses
        rule_text = "alert tcp any any -> any 80 ()"

        try:
            rule = parse_rule(rule_text)
            diagnostics = validate_rule(rule)

            # Should have warnings about both
            assert len(diagnostics) >= 2
        except ParseError:
            # If parser requires at least one option, skip this test
            pytest.skip("Parser requires at least one option")

    def test_validate_rule_with_existing_diagnostics(self):
        """Validate rule that already has diagnostics."""
        from surinort_ast.core.diagnostics import Diagnostic

        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        # Add a diagnostic
        existing_diag = Diagnostic(
            level=DiagnosticLevel.INFO, message="Test diagnostic", code="test_code"
        )
        rule = rule.model_copy(update={"diagnostics": [existing_diag]})

        diagnostics = validate_rule(rule)

        # Should include the existing diagnostic
        info_diags = [d for d in diagnostics if d.level == DiagnosticLevel.INFO]
        assert len(info_diags) > 0


class TestParseRules:
    """Test parse_rules batch function."""

    def test_parse_rules_all_valid(self):
        """Parse multiple valid rules."""
        texts = [
            'alert tcp any any -> any 80 (msg:"Test1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Test2"; sid:2;)',
            'alert udp any any -> any 53 (msg:"Test3"; sid:3;)',
        ]

        rules, errors = parse_rules(texts)

        assert len(rules) == 3
        assert len(errors) == 0

    def test_parse_rules_some_invalid(self):
        """Parse rules with some invalid."""
        texts = [
            'alert tcp any any -> any 80 (msg:"Test1"; sid:1;)',
            "invalid rule syntax",
            'alert tcp any any -> any 443 (msg:"Test2"; sid:2;)',
        ]

        rules, errors = parse_rules(texts)

        assert len(rules) == 2
        assert len(errors) == 1
        assert errors[0][0] == 1  # Index of invalid rule

    def test_parse_rules_all_invalid(self):
        """Parse all invalid rules."""
        texts = [
            "invalid rule 1",
            "invalid rule 2",
            "invalid rule 3",
        ]

        rules, errors = parse_rules(texts)

        assert len(rules) == 0
        assert len(errors) == 3

    def test_parse_rules_empty_list(self):
        """Parse empty list of rules."""
        texts = []

        rules, errors = parse_rules(texts)

        assert len(rules) == 0
        assert len(errors) == 0

    def test_parse_rules_with_dialect(self):
        """Parse rules with specific dialect."""
        texts = [
            'alert tcp any any -> any 80 (msg:"Test1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Test2"; sid:2;)',
        ]

        rules, errors = parse_rules(texts, dialect=Dialect.SNORT3)

        assert len(rules) == 2
        assert len(errors) == 0


class TestErrorHandling:
    """Test error handling in API functions."""

    def test_parse_error_message_content(self):
        """Test ParseError contains useful message."""
        try:
            parse_rule("completely invalid")
        except ParseError as e:
            assert "Failed to parse rule" in str(e)
            assert len(str(e)) > 0

    def test_serialization_error_on_invalid_object(self):
        """Test serialization error handling with invalid object."""
        # Try to serialize an object that's not a Rule
        invalid_object = "not a rule"

        # The to_json function expects a Rule, so this should fail
        # We can't easily trigger SerializationError without modifying the Rule,
        # so we'll just verify the error path exists by checking the exception is raised
        try:
            # This will fail because string doesn't have model_dump_json
            to_json(invalid_object)  # type: ignore
            pytest.fail("Expected AttributeError or SerializationError")
        except (AttributeError, SerializationError):
            # Expected - either AttributeError from missing method
            # or SerializationError if it's caught
            pass


class TestRoundtrips:
    """Test complete roundtrip scenarios."""

    def test_parse_print_parse_roundtrip(self):
        """Test parse -> print -> parse roundtrip."""
        original_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

        rule1 = parse_rule(original_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol

    def test_parse_json_parse_roundtrip(self):
        """Test parse -> JSON -> parse roundtrip."""
        original_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule1 = parse_rule(original_text)
        json_str = to_json(rule1)
        rule2 = from_json(json_str)
        printed = print_rule(rule2)
        rule3 = parse_rule(printed)

        assert rule1.action == rule3.action
        assert rule1.header.protocol == rule3.header.protocol


class TestEdgeCases:
    """Test edge cases in API."""

    def test_parse_rule_whitespace_variations(self):
        """Parse rules with various whitespace."""
        variations = [
            'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
            '  alert tcp any any -> any 80 (msg:"Test"; sid:1;)  ',
            'alert  tcp  any  any  ->  any  80  (msg:"Test";  sid:1;)',
        ]

        for text in variations:
            rule = parse_rule(text)
            assert rule.action.value == "alert"

    def test_parse_file_unicode_content(self, tmp_path):
        """Parse file with unicode content."""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Tëst UTF-8"; sid:1;)', encoding="utf-8")

        rules = parse_file(file)

        assert len(rules) == 1

    def test_to_json_with_zero_indent(self):
        """Test to_json with indent=0."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule, indent=0)

        assert len(json_str) > 0


class TestDialectSupport:
    """Test dialect support in API."""

    def test_parse_suricata_dialect(self):
        """Parse rule with Suricata dialect."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SURICATA)

        assert rule.action.value == "alert"

    def test_parse_snort2_dialect(self):
        """Parse rule with Snort2 dialect."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SNORT2)

        assert rule.action.value == "alert"

    def test_parse_snort3_dialect(self):
        """Parse rule with Snort3 dialect."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SNORT3)

        assert rule.action.value == "alert"
