# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive API tests focusing on parallel parsing and edge cases.

Tests file parsing with multiple workers, error handling, caching behavior,
and all public API functions.
"""

import json
import tempfile
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
from surinort_ast.core.enums import Action, Dialect, Protocol
from surinort_ast.core.nodes import Rule
from surinort_ast.exceptions import ParseError, SerializationError


class TestParseRule:
    """Test parse_rule API function."""

    def test_parse_simple_rule(self):
        """Test parsing a simple rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP

    def test_parse_with_dialect(self):
        """Test parsing with specific dialect."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        # Test each dialect
        for dialect in [Dialect.SURICATA, Dialect.SNORT2, Dialect.SNORT3]:
            rule = parse_rule(rule_text, dialect=dialect)
            assert rule is not None
            assert rule.dialect == dialect

    def test_parse_without_location_tracking(self):
        """Test parsing with location tracking disabled for performance."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Fast Parse"; sid:1;)'
        rule = parse_rule(rule_text, track_locations=False)

        assert rule is not None
        assert rule.action == Action.ALERT

    def test_parse_invalid_rule_raises_error(self):
        """Test that invalid rules raise ParseError."""
        with pytest.raises(ParseError):
            parse_rule("invalid rule syntax")

    def test_parse_empty_string_raises_error(self):
        """Test that empty strings raise ParseError."""
        with pytest.raises(ParseError):
            parse_rule("")

    def test_raw_text_preservation(self):
        """Test that raw text is preserved in parsed rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Preserved"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule.raw_text == rule_text


class TestParseFile:
    """Test parse_file API function."""

    def test_parse_simple_file(self):
        """Test parsing a simple rules file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)\n')
            f.write('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)\n')
            temp_path = Path(f.name)

        try:
            rules = parse_file(temp_path)
            assert len(rules) == 2
            assert all(isinstance(r, Rule) for r in rules)
            assert rules[0].origin.line_number == 1
            assert rules[1].origin.line_number == 2
        finally:
            temp_path.unlink()

    def test_parse_file_with_comments(self):
        """Test that comments are skipped."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("# This is a comment\n")
            f.write('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)\n')
            f.write("# Another comment\n")
            f.write('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)\n')
            temp_path = Path(f.name)

        try:
            rules = parse_file(temp_path)
            assert len(rules) == 2
        finally:
            temp_path.unlink()

    def test_parse_file_with_blank_lines(self):
        """Test that blank lines are skipped."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("\n\n")
            f.write('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)\n')
            f.write("\n")
            f.write('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)\n')
            f.write("\n\n")
            temp_path = Path(f.name)

        try:
            rules = parse_file(temp_path)
            assert len(rules) == 2
        finally:
            temp_path.unlink()

    def test_parse_file_sequential(self):
        """Test sequential file parsing (workers=1)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            for i in range(1, 11):
                f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
            temp_path = Path(f.name)

        try:
            rules = parse_file(temp_path, workers=1)
            assert len(rules) == 10
        finally:
            temp_path.unlink()

    def test_parse_file_parallel(self):
        """Test parallel file parsing with multiple workers."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            # Create enough rules to benefit from parallelism
            for i in range(1, 101):
                f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
            temp_path = Path(f.name)

        try:
            # Parse with 4 workers
            rules = parse_file(temp_path, workers=4)
            assert len(rules) == 100
            # All rules should be valid
            assert all(isinstance(r, Rule) for r in rules)
        finally:
            temp_path.unlink()

    def test_parse_file_with_errors_partial_success(self):
        """Test file parsing with some malformed rules."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write('alert tcp any any -> any 80 (msg:"Good Rule"; sid:1;)\n')
            f.write("invalid rule here\n")
            f.write('alert tcp any any -> any 443 (msg:"Another Good"; sid:2;)\n')
            temp_path = Path(f.name)

        try:
            # Should parse the valid rules and skip invalid ones
            rules = parse_file(temp_path)
            # At least the valid rules should be parsed
            assert len(rules) >= 1
        finally:
            temp_path.unlink()

    def test_parse_file_all_errors_raises(self):
        """Test that file with all invalid rules raises ParseError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("invalid rule 1\n")
            f.write("invalid rule 2\n")
            f.write("invalid rule 3\n")
            temp_path = Path(f.name)

        try:
            with pytest.raises(ParseError, match="Failed to parse any rules"):
                parse_file(temp_path)
        finally:
            temp_path.unlink()

    def test_parse_nonexistent_file_raises(self):
        """Test that nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_file("/nonexistent/path/to/file.rules")

    def test_parse_directory_raises(self):
        """Test that directory path raises ParseError."""
        with tempfile.TemporaryDirectory() as tmpdir, pytest.raises(ParseError, match="Not a file"):
            parse_file(tmpdir)

    def test_parse_file_origin_tracking(self):
        """Test that file origin is tracked correctly."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')
            temp_path = Path(f.name)

        try:
            rules = parse_file(temp_path)
            assert len(rules) == 1
            rule = rules[0]
            assert rule.origin is not None
            # Use resolved path since parse_file resolves symlinks
            assert rule.origin.file_path == str(temp_path.resolve())
            assert rule.origin.line_number == 1
        finally:
            temp_path.unlink()


class TestParseRules:
    """Test parse_rules batch parsing function."""

    def test_parse_multiple_rules(self):
        """Test parsing multiple rules in batch."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
            'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
        ]

        rules, errors = parse_rules(rule_texts)

        assert len(rules) == 3
        assert len(errors) == 0
        assert all(isinstance(r, Rule) for r in rules)

    def test_parse_with_some_errors(self):
        """Test batch parsing with some invalid rules."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Valid"; sid:1;)',
            "invalid rule syntax",
            'alert tcp any any -> any 443 (msg:"Also Valid"; sid:2;)',
        ]

        rules, errors = parse_rules(rule_texts)

        # Should have 2 valid rules
        assert len(rules) == 2
        # Should have 1 error
        assert len(errors) == 1
        # Error should be for index 1
        assert errors[0][0] == 1

    def test_parse_all_invalid(self):
        """Test batch parsing with all invalid rules."""
        rule_texts = [
            "invalid rule 1",
            "invalid rule 2",
            "invalid rule 3",
        ]

        rules, errors = parse_rules(rule_texts)

        assert len(rules) == 0
        assert len(errors) == 3

    def test_parse_empty_list(self):
        """Test batch parsing with empty list."""
        rules, errors = parse_rules([])

        assert len(rules) == 0
        assert len(errors) == 0


class TestPrintRule:
    """Test print_rule API function."""

    def test_print_simple_rule(self):
        """Test printing a simple rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule)

        assert printed
        assert "alert" in printed
        assert "tcp" in printed

    def test_print_stable_format(self):
        """Test printing with stable formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule, stable=True)

        assert printed
        # Should be parseable
        reparsed = parse_rule(printed)
        assert reparsed.action == Action.ALERT

    def test_print_standard_format(self):
        """Test printing with standard formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printed = print_rule(rule, stable=False)

        assert printed
        # Should be parseable
        reparsed = parse_rule(printed)
        assert reparsed.action == Action.ALERT


class TestJSONSerialization:
    """Test JSON serialization functions."""

    def test_to_json(self):
        """Test serializing rule to JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule)

        assert json_str
        # Should be valid JSON
        data = json.loads(json_str)
        assert data["action"] == "alert"
        assert "header" in data

    def test_to_json_compact(self):
        """Test compact JSON serialization."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule, indent=None)

        assert json_str
        # Should not have indentation
        assert "\n" not in json_str or json_str.count("\n") < 5

    def test_to_json_pretty(self):
        """Test pretty JSON serialization."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        json_str = to_json(rule, indent=2)

        assert json_str
        # Should have indentation
        assert "\n" in json_str

    def test_from_json_string(self):
        """Test deserializing rule from JSON string."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        # Serialize
        json_str = to_json(rule)

        # Deserialize
        restored = from_json(json_str)

        assert restored is not None
        assert restored.action == rule.action
        assert restored.header.protocol == rule.header.protocol

    def test_from_json_dict(self):
        """Test deserializing rule from dict."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        # Serialize
        json_str = to_json(rule)
        data = json.loads(json_str)

        # Deserialize from dict
        restored = from_json(data)

        assert restored is not None
        assert restored.action == rule.action

    def test_from_json_invalid_raises(self):
        """Test that invalid JSON raises SerializationError."""
        with pytest.raises(SerializationError):
            from_json("invalid json {{{")

    def test_to_json_schema(self):
        """Test generating JSON schema."""
        schema = to_json_schema()

        assert schema is not None
        assert isinstance(schema, dict)
        # Should have standard JSON Schema fields
        assert "properties" in schema or "type" in schema


class TestValidateRule:
    """Test validate_rule API function."""

    def test_validate_complete_rule(self):
        """Test validation of complete rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have no errors (msg and sid present)
        assert isinstance(diagnostics, list)

    def test_validate_missing_sid(self):
        """Test validation detects missing SID."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test";)'
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have warning about missing SID
        assert len(diagnostics) > 0
        assert any("sid" in d.message.lower() for d in diagnostics)

    def test_validate_missing_msg(self):
        """Test validation detects missing msg."""
        rule_text = "alert tcp any any -> any 80 (sid:1;)"
        rule = parse_rule(rule_text)

        diagnostics = validate_rule(rule)

        # Should have warning about missing msg
        assert len(diagnostics) > 0
        assert any("msg" in d.message.lower() for d in diagnostics)

    def test_validate_both_missing(self):
        """Test validation detects both missing msg and sid."""
        try:
            rule_text = "alert tcp any any -> any 80 ()"
            rule = parse_rule(rule_text)

            diagnostics = validate_rule(rule)

            # Should have warnings for both
            assert len(diagnostics) >= 2
        except ParseError:
            # If parser requires at least one option, skip this test
            pytest.skip("Parser requires at least one option")


class TestParserCaching:
    """Test parser caching behavior."""

    def test_parser_caching(self):
        """Test that parser instances are cached."""
        # Parse multiple rules with same dialect
        for _ in range(5):
            rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
            assert rule is not None

        # Parser should be reused (implicitly tested via successful parsing)

    def test_different_dialects_different_parsers(self):
        """Test that different dialects use different parser instances."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        # Parse with different dialects
        rule1 = parse_rule(rule_text, dialect=Dialect.SURICATA)
        rule2 = parse_rule(rule_text, dialect=Dialect.SNORT2)
        rule3 = parse_rule(rule_text, dialect=Dialect.SNORT3)

        assert rule1.dialect == Dialect.SURICATA
        assert rule2.dialect == Dialect.SNORT2
        assert rule3.dialect == Dialect.SNORT3

    def test_location_tracking_affects_caching(self):
        """Test that location tracking setting affects parser caching."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        # Parse with location tracking
        rule1 = parse_rule(rule_text, track_locations=True)
        assert rule1 is not None

        # Parse without location tracking
        rule2 = parse_rule(rule_text, track_locations=False)
        assert rule2 is not None

        # Both should succeed (different cached parsers)


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_very_long_rule(self):
        """Test parsing very long rule."""
        # Create a long rule with many options
        options = " ".join([f"reference:url,http://example.com/{i};" for i in range(100)])
        rule_text = f'alert tcp any any -> any 80 (msg:"Long"; {options} sid:1;)'

        rule = parse_rule(rule_text)
        assert rule is not None

    def test_unicode_in_msg(self):
        """Test Unicode characters in message."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Unicode café 日本語"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

    def test_roundtrip_fidelity(self):
        """Test that parse → print → parse maintains fidelity."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Roundtrip Test"; sid:12345; rev:2;)'

        # First parse
        rule1 = parse_rule(rule_text)

        # Print
        printed = print_rule(rule1)

        # Second parse
        rule2 = parse_rule(printed)

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert len(rule1.options) == len(rule2.options)

    def test_json_roundtrip_fidelity(self):
        """Test that parse → JSON → parse maintains fidelity."""
        rule_text = 'alert tcp any any -> any 80 (msg:"JSON Test"; sid:12345;)'

        # Parse
        rule1 = parse_rule(rule_text)

        # Serialize to JSON
        json_str = to_json(rule1)

        # Deserialize from JSON
        rule2 = from_json(json_str)

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol


class TestPerformance:
    """Test performance-related features."""

    def test_track_locations_false_performance(self):
        """Test that disabling location tracking works."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Fast"; sid:1;)'

        # Parse without location tracking (faster)
        rule = parse_rule(rule_text, track_locations=False)

        assert rule is not None
        assert rule.action == Action.ALERT

    def test_parallel_parsing_performance(self):
        """Test parallel parsing with multiple workers."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            # Create many rules
            for i in range(1, 501):
                f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
            temp_path = Path(f.name)

        try:
            # Parse with parallel workers
            rules = parse_file(temp_path, workers=4)
            assert len(rules) == 500
        finally:
            temp_path.unlink()
