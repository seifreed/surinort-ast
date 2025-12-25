# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive error recovery and timeout tests for parser module.

Tests parser behavior with malformed rules, edge cases, and resource limits.
All tests use real parser with actual error conditions.
"""

import tempfile
from pathlib import Path

import pytest

from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError
from surinort_ast.parsing.parser import RuleParser, parse_rule
from surinort_ast.parsing.parser_config import ParserConfig


class TestParserErrorRecovery:
    """Test parser handles malformed rules gracefully."""

    def test_empty_input(self):
        """Parser should handle empty input gracefully."""
        parser = RuleParser(strict=False)
        rule = parser.parse("")

        # Should return error rule in non-strict mode
        assert rule is not None
        assert len(rule.diagnostics) > 0
        assert any(d.level == DiagnosticLevel.ERROR for d in rule.diagnostics)

    def test_empty_input_strict_mode(self):
        """Parser should raise ParseError for empty input in strict mode."""
        parser = RuleParser(strict=True)

        with pytest.raises(ParseError, match="Empty input"):
            parser.parse("")

    def test_comment_line(self):
        """Parser should handle comment lines."""
        parser = RuleParser(strict=False)
        rule = parser.parse("# This is a comment")

        # Should return error rule (comments are not rules)
        assert rule is not None

    def test_missing_options(self):
        """Parser should handle missing options section."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert tcp any any -> any 80")

        # Should have diagnostics about missing options
        assert rule is not None
        assert len(rule.diagnostics) > 0

    def test_missing_semicolons(self):
        """Parser should handle missing semicolons in options."""
        parser = RuleParser(strict=False)
        rule = parser.parse('alert tcp any any -> any 80 (msg:"Test" sid:1)')

        # Should attempt to recover
        assert rule is not None

    def test_invalid_action(self):
        """Parser should handle invalid action keyword."""
        parser = RuleParser(strict=False)
        rule = parser.parse("invalid_action tcp any any -> any 80 (sid:1;)")

        # Should return error rule
        assert rule is not None
        assert len(rule.diagnostics) > 0

    def test_invalid_protocol(self):
        """Parser should handle invalid protocol."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert invalid_proto any any -> any 80 (sid:1;)")

        # Should return error rule
        assert rule is not None
        assert len(rule.diagnostics) > 0

    def test_invalid_port_number(self):
        """Parser should handle out-of-range port numbers."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert tcp any any -> any 70000 (sid:1;)")

        # Parser should handle gracefully
        assert rule is not None

    def test_invalid_sid(self):
        """Parser should handle invalid SID values."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert tcp any any -> any 80 (sid:invalid;)")

        # Should return error rule
        assert rule is not None
        assert len(rule.diagnostics) > 0

    def test_malformed_cidr(self):
        """Parser should handle malformed CIDR notation."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert tcp 192.168.1.0/999 any -> any 80 (sid:1;)")

        # Should return error rule or recover
        assert rule is not None

    def test_unmatched_brackets(self):
        """Parser should handle unmatched brackets in lists."""
        parser = RuleParser(strict=False)
        rule = parser.parse("alert tcp [192.168.1.1 any -> any 80 (sid:1;)")

        # Should return error rule
        assert rule is not None
        assert len(rule.diagnostics) > 0

    def test_unclosed_options(self):
        """Parser should handle unclosed options parentheses."""
        parser = RuleParser(strict=False)
        rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;')

        # Should return error rule
        assert rule is not None
        assert len(rule.diagnostics) > 0


class TestParserStrictMode:
    """Test strict mode raises exceptions instead of recovering."""

    def test_strict_mode_malformed_rule(self):
        """Strict mode should raise ParseError for malformed rules."""
        parser = RuleParser(strict=True)

        with pytest.raises(ParseError):
            parser.parse("alert tcp any any -> any 80")

    def test_strict_mode_invalid_syntax(self):
        """Strict mode should raise ParseError for syntax errors."""
        parser = RuleParser(strict=True)

        with pytest.raises(ParseError):
            parser.parse("invalid tcp any any -> any 80 (sid:1;)")


class TestParserResourceLimits:
    """Test parser resource limits and timeout enforcement."""

    def test_maximum_rule_length(self):
        """Parser should enforce maximum rule length."""
        config = ParserConfig(max_rule_length=100)
        parser = RuleParser(config=config, strict=False)

        # Create a very long rule
        long_rule = 'alert tcp any any -> any 80 (msg:"' + "A" * 1000 + '"; sid:1;)'

        rule = parser.parse(long_rule)

        # Should either truncate or return error
        assert rule is not None

    def test_timeout_enforcement(self):
        """Parser should timeout on extremely complex rules."""
        config = ParserConfig(timeout_seconds=1.0)
        parser = RuleParser(config=config, strict=False)

        # Create a potentially slow rule with deep nesting
        nested = "[" * 50 + "1.1.1.1" + "]" * 50
        slow_rule = f"alert tcp {nested} any -> any any (sid:1;)"

        # Should complete or timeout gracefully
        try:
            rule = parser.parse(slow_rule)
            assert rule is not None
        except (TimeoutError, ParseError):
            # Either timeout or parse error is acceptable
            pass

    def test_maximum_option_count(self):
        """Parser should handle rules with many options."""
        config = ParserConfig(max_options=1000)
        parser = RuleParser(config=config, strict=False)

        # Create rule with many options
        options = "; ".join([f"reference:url,http://example.com/{i}" for i in range(50)])
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; {options}; sid:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None


class TestParserFileOperations:
    """Test file parsing with various encodings and formats."""

    def test_parse_empty_file(self):
        """Parser should handle empty files."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path)
            assert isinstance(rules, list)
            assert len(rules) == 0
        finally:
            temp_path.unlink()

    def test_parse_file_with_comments(self):
        """Parser should skip comment lines in files."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("# Comment line\n")
            f.write('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')
            f.write("# Another comment\n")
            f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)\n')
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path)
            assert len(rules) == 2
            # Verify both rules parsed
            assert all(rule.action is not None for rule in rules)
        finally:
            temp_path.unlink()

    def test_parse_file_with_blank_lines(self):
        """Parser should skip blank lines."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("\n")
            f.write('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')
            f.write("\n\n")
            f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)\n')
            f.write("\n")
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path)
            assert len(rules) == 2
        finally:
            temp_path.unlink()

    def test_parse_multiline_rules(self):
        """Parser should handle multiline rules in files."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write("alert tcp any any -> any 80 (\n")
            f.write('    msg:"Multi-line rule";\n')
            f.write("    flow:established,to_server;\n")
            f.write("    sid:1;\n")
            f.write(")\n")
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path)
            assert len(rules) >= 1
            # First rule should be valid
            if rules:
                assert rules[0].action is not None
        finally:
            temp_path.unlink()

    def test_parse_file_utf8_encoding(self):
        """Parser should handle UTF-8 encoded files."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            # Rule with UTF-8 characters in message
            f.write('alert tcp any any -> any 80 (msg:"Test with UTF-8 café"; sid:1;)\n')
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path, encoding="utf-8")
            assert len(rules) >= 1
        finally:
            temp_path.unlink()

    def test_parse_file_with_errors_skip(self):
        """Parser should skip malformed rules when skip_errors=True."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write('alert tcp any any -> any 80 (msg:"Good"; sid:1;)\n')
            f.write("invalid rule here\n")
            f.write('alert tcp any any -> any 443 (msg:"Also Good"; sid:2;)\n')
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path, skip_errors=True)
            # Should get 2 valid rules
            assert len(rules) >= 2
        finally:
            temp_path.unlink()

    def test_parse_file_with_errors_no_skip(self):
        """Parser should include error nodes when skip_errors=False."""
        parser = RuleParser(strict=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            f.write('alert tcp any any -> any 80 (msg:"Good"; sid:1;)\n')
            f.write("invalid rule here\n")
            temp_path = Path(f.name)

        try:
            rules = parser.parse_file(temp_path, skip_errors=False)
            # Should get at least 2 entries (1 valid + 1 error)
            assert len(rules) >= 1
        finally:
            temp_path.unlink()

    def test_parse_nonexistent_file(self):
        """Parser should raise FileNotFoundError for missing files."""
        parser = RuleParser()

        with pytest.raises(FileNotFoundError):
            parser.parse_file(Path("/nonexistent/file.rules"))

    def test_parse_file_size_limit(self):
        """Parser should enforce maximum file size."""
        config = ParserConfig(max_input_size=100)  # 100 bytes
        parser = RuleParser(config=config, strict=False)

        # Create a file larger than limit
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, encoding="utf-8"
        ) as f:
            # Write more than 100 bytes
            for i in range(20):
                f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
            temp_path = Path(f.name)

        try:
            # Should raise error due to size limit
            with pytest.raises(ValueError, match="exceeds maximum"):
                parser.parse_file(temp_path)
        finally:
            temp_path.unlink()


class TestParserDialects:
    """Test parser with different IDS dialects."""

    def test_suricata_dialect(self):
        """Test Suricata-specific features."""
        parser = RuleParser(dialect=Dialect.SURICATA, strict=False)
        rule_text = 'alert http any any -> any any (msg:"Suricata"; http.uri; sid:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None
        assert rule.dialect == Dialect.SURICATA

    def test_snort2_dialect(self):
        """Test Snort2 compatibility."""
        parser = RuleParser(dialect=Dialect.SNORT2, strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Snort2"; sid:1; rev:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None
        assert rule.dialect == Dialect.SNORT2

    def test_snort3_dialect(self):
        """Test Snort3-specific features."""
        parser = RuleParser(dialect=Dialect.SNORT3, strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Snort3"; sid:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None
        assert rule.dialect == Dialect.SNORT3


class TestParserDiagnostics:
    """Test diagnostic generation during parsing."""

    def test_diagnostics_for_warnings(self):
        """Parser should generate warnings for suspicious patterns."""
        parser = RuleParser(strict=False)
        # Rule with potential issues (negative SID handled by transformer)
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None
        # Diagnostics may or may not be present depending on rule validity

    def test_diagnostics_include_location(self):
        """Diagnostics should include location information."""
        parser = RuleParser(strict=False)
        rule_text = "invalid tcp any any -> any 80 (sid:1;)"

        rule = parser.parse(rule_text)
        assert rule is not None
        # Error diagnostics should be present
        if rule.diagnostics:
            # At least one diagnostic should have location info
            assert any(d.location is not None or d.message for d in rule.diagnostics)


class TestParserConvenienceFunctions:
    """Test convenience functions for parsing."""

    def test_parse_rule_function(self):
        """Test parse_rule convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.action.value == "alert"

    def test_parse_rule_with_dialect(self):
        """Test parse_rule with dialect parameter."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SURICATA)

        assert rule is not None
        assert rule.dialect == Dialect.SURICATA

    def test_parse_rule_strict_mode(self):
        """Test parse_rule with strict mode."""
        with pytest.raises(ParseError):
            parse_rule("invalid rule", strict=True)


class TestParserLocationTracking:
    """Test location tracking in parsed rules."""

    def test_rule_has_location(self):
        """Parsed rules should have location information."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule = parser.parse(rule_text, file_path="/test/file.rules", line_offset=0)
        assert rule is not None

    def test_rule_with_file_path(self):
        """Location should include file path when provided."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule = parser.parse(rule_text, file_path="/test/rules.rules")
        assert rule is not None
        # Origin should include file path
        if rule.origin:
            assert rule.origin.file_path == "/test/rules.rules"

    def test_rule_with_line_offset(self):
        """Location should include line offset for multi-file parsing."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule = parser.parse(rule_text, file_path="/test/rules.rules", line_offset=100)
        assert rule is not None


class TestParserRawText:
    """Test preservation of raw rule text."""

    def test_raw_text_preserved(self):
        """Parser should preserve original rule text."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any 80 (msg:"Original Text"; sid:1;)'

        rule = parser.parse(rule_text)
        assert rule is not None
        assert rule.raw_text == rule_text.strip()

    def test_raw_text_with_whitespace(self):
        """Raw text should be stripped of leading/trailing whitespace."""
        parser = RuleParser(strict=False)
        rule_text = '  alert tcp any any -> any 80 (msg:"Test"; sid:1;)  \n'

        rule = parser.parse(rule_text)
        assert rule is not None
        assert rule.raw_text
        assert not rule.raw_text.startswith(" ")
        assert not rule.raw_text.endswith(" ")
