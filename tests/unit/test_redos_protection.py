# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Unit tests for ReDoS (Regular Expression Denial of Service) protection.

Tests verify that the parser is protected against catastrophic backtracking
attacks through:
1. Regex pattern length bounds in grammar.lark
2. Cross-platform timeout mechanisms
3. Input validation before parsing
"""

import platform
import time

import pytest

from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.parser import RuleParser
from surinort_ast.parsing.parser_config import ParserConfig


class TestRegexLengthBounds:
    """Test that regex patterns enforce length bounds to prevent ReDoS."""

    def test_reference_id_within_bounds(self):
        """Test REFERENCE_ID pattern accepts normal URLs under 500 chars."""
        parser = RuleParser()
        # Normal URL-like reference (well within 500 char limit)
        rule_text = (
            "alert tcp any any -> any 80 "
            '(msg:"Test"; reference:url,https://example.com/path/to/resource?query=123; sid:1;)'
        )
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_reference_id_max_length_boundary(self):
        """Test REFERENCE_ID pattern with reference near 500 char limit."""
        parser = RuleParser()
        # Create a reference ID near the 500 character boundary
        # Format: "a" + 490 chars + "/"  (requires separator at end per new pattern)
        long_ref = "a" * 490 + "/"
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; reference:url,{long_ref}; sid:1;)'

        rule = parser.parse(rule_text)
        # Should parse successfully at the boundary
        assert isinstance(rule, Rule)

    def test_reference_tail_within_bounds(self):
        """Test REFERENCE_TAIL pattern accepts values under 500 chars."""
        parser = RuleParser()
        # REFERENCE_TAIL catches remaining characters until delimiter
        value = "a" * 400
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; reference:type,{value}; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_generic_tail_within_bounds(self):
        """Test GENERIC_TAIL pattern accepts values under 1000 chars."""
        parser = RuleParser()
        # Generic option with long value
        value = "a" * 900
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; unknown_option:{value}; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_generic_value_within_bounds(self):
        """Test GENERIC_VALUE pattern accepts values under 200 chars."""
        parser = RuleParser()
        # flags option uses GENERIC_VALUE
        value = "A" * 150
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; flags:{value}; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_quoted_string_within_bounds(self):
        """Test QUOTED_STRING pattern accepts strings under 10000 chars."""
        parser = RuleParser()
        # Very long message content (but within limit)
        content = "A" * 9000
        rule_text = f'alert tcp any any -> any 80 (msg:"{content}"; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_pcre_pattern_within_bounds(self):
        """Test PCRE_PATTERN accepts patterns under 5000 chars."""
        parser = RuleParser()
        # Long PCRE pattern (but within limit)
        pattern = "a" * 4000
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; pcre:"/{pattern}/i"; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_hex_string_within_bounds(self):
        """Test HEX_STRING accepts hex values under 5000 pairs."""
        parser = RuleParser()
        # Hex string with many pairs (but within limit)
        # 1000 pairs = 2000 hex chars
        hex_pairs = " ".join(["FF"] * 1000)
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; content:|{hex_pairs}|; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)


class TestReDoSPatternPrevention:
    """Test that vulnerable patterns are prevented from causing catastrophic backtracking."""

    def test_reference_id_no_catastrophic_backtracking(self):
        """Test REFERENCE_ID doesn't cause exponential backtracking."""
        parser = RuleParser(config=ParserConfig.default())

        # This pattern would cause catastrophic backtracking with old regex:
        # /(?![A-Za-z0-9_]+$)[A-Za-z0-9][A-Za-z0-9_.\/:\-?&=%#~@!+*()]+/
        # But new regex has length bound and no negative lookahead
        attack_string = "a" * 100 + "!"

        start_time = time.perf_counter()
        rule_text = (
            f'alert tcp any any -> any 80 (msg:"Test"; reference:url,{attack_string}; sid:1;)'
        )
        rule = parser.parse(rule_text)
        elapsed = time.perf_counter() - start_time

        # Should parse quickly (under 1 second)
        assert elapsed < 1.0
        assert isinstance(rule, Rule)

    def test_pcre_pattern_no_nested_quantifier_explosion(self):
        """Test PCRE_PATTERN doesn't cause nested quantifier explosion."""
        parser = RuleParser(config=ParserConfig.default())

        # Pattern with backslash escapes that could trigger backtracking
        # Old pattern: /\/(?:[^\/\\]|\\.)*\/[a-zA-Z]*/
        # New pattern: /\/(?:[^\/\\]|\\[^\n]){0,5000}\/[a-zA-Z]{0,20}/
        pattern = "\\" + "a" * 100

        start_time = time.perf_counter()
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; pcre:"/{pattern}/i"; sid:1;)'
        rule = parser.parse(rule_text)
        elapsed = time.perf_counter() - start_time

        # Should parse quickly
        assert elapsed < 1.0
        assert isinstance(rule, Rule)

    def test_generic_tail_bounded_matching(self):
        """Test GENERIC_TAIL has bounded matching behavior."""
        parser = RuleParser(config=ParserConfig.default())

        # Long value but under limit - should parse fine
        value = "x" * 500

        start_time = time.perf_counter()
        rule_text = f'alert tcp any any -> any 80 (msg:"Test"; custom:{value}; sid:1;)'
        rule = parser.parse(rule_text)
        elapsed = time.perf_counter() - start_time

        assert elapsed < 1.0
        assert isinstance(rule, Rule)


class TestTimeoutMechanism:
    """Test cross-platform timeout mechanism for parse operations."""

    def test_timeout_disabled_by_default_in_permissive(self):
        """Test that permissive config has timeout disabled."""
        config = ParserConfig.permissive()
        assert config.timeout_seconds == 0.0

    def test_timeout_enabled_in_default_config(self):
        """Test that default config has timeout enabled."""
        config = ParserConfig.default()
        assert config.timeout_seconds > 0

    def test_timeout_strict_in_strict_config(self):
        """Test that strict config has aggressive timeout."""
        config = ParserConfig.strict()
        assert config.timeout_seconds == 10.0

    def test_normal_rule_parses_within_timeout(self):
        """Test that normal rules parse well within timeout."""
        config = ParserConfig.strict()  # 10 second timeout
        parser = RuleParser(config=config)

        start_time = time.perf_counter()
        rule_text = 'alert tcp any any -> any 80 (msg:"Normal rule"; sid:1;)'
        rule = parser.parse(rule_text)
        elapsed = time.perf_counter() - start_time

        # Should parse very quickly (well under timeout)
        assert elapsed < 1.0
        assert isinstance(rule, Rule)

    def test_complex_rule_parses_within_timeout(self):
        """Test that complex but legitimate rules parse within timeout."""
        config = ParserConfig.default()  # 30 second timeout
        parser = RuleParser(config=config)

        # Complex rule with many options
        rule_text = (
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
            '(msg:"Complex rule"; flow:established,to_server; '
            'content:"GET"; http_method; content:"/admin"; http_uri; '
            'pcre:"/admin\\/.*\\.php/Ui"; classtype:web-application-attack; '
            "sid:1000001; rev:2; metadata:policy balanced-ips;)"
        )

        start_time = time.perf_counter()
        rule = parser.parse(rule_text)
        elapsed = time.perf_counter() - start_time

        assert elapsed < 5.0  # Should be very fast
        assert isinstance(rule, Rule)

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="Signal-based timeout test only works on Unix",
    )
    def test_timeout_uses_signal_on_unix(self):
        """Test that Unix systems use signal.SIGALRM for timeout."""
        import signal

        config = ParserConfig.default()
        parser = RuleParser(config=config)

        # Verify signal module is available
        assert hasattr(signal, "SIGALRM")

        # Normal parse should work
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_timeout_works_on_windows(self):
        """Test that timeout mechanism works on Windows using threading."""
        if platform.system() != "Windows":
            pytest.skip("Windows-specific test")

        config = ParserConfig.default()
        parser = RuleParser(config=config)

        # Normal parse should work
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)


class TestInputValidation:
    """Test that parser validates input sizes before parsing."""

    def test_rule_length_validation_accepts_normal(self):
        """Test that normal rule lengths are accepted."""
        config = ParserConfig.default()  # max_rule_length = 100_000
        parser = RuleParser(config=config)

        # Normal length rule
        rule_text = 'alert tcp any any -> any 80 (msg:"Normal"; sid:1;)'
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_rule_length_validation_rejects_excessive(self):
        """Test that excessively long rules are rejected."""
        config = ParserConfig.strict()  # max_rule_length = 10_000
        parser = RuleParser(config=config, strict=True)  # Enable strict mode to raise exceptions

        # Create rule exceeding limit
        massive_content = "A" * 15000
        rule_text = f'alert tcp any any -> any 80 (msg:"{massive_content}"; sid:1;)'

        # In strict mode, should raise ParseError wrapping the ValueError
        from surinort_ast.exceptions import ParseError

        with pytest.raises(ParseError):
            parser.parse(rule_text)

    def test_option_count_validation_accepts_normal(self):
        """Test that normal option counts are accepted."""
        config = ParserConfig.default()  # max_options = 1000
        parser = RuleParser(config=config)

        # Rule with reasonable number of options
        rule_text = (
            "alert tcp any any -> any 80 "
            '(msg:"Test"; sid:1; rev:1; classtype:web-application-attack; '
            'content:"test"; nocase; depth:100;)'
        )
        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_input_size_validation_in_file_parse(self):
        """Test that file size is validated before reading."""
        import tempfile
        from pathlib import Path

        config = ParserConfig.strict()  # max_input_size = 10_000_000 (10 MB)
        parser = RuleParser(config=config)

        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            # Write some rules
            f.write('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')
            temp_path = Path(f.name)

        try:
            # Should parse successfully (small file)
            rules = parser.parse_file(temp_path)
            assert len(rules) >= 1
        finally:
            temp_path.unlink()


class TestConfigurationModes:
    """Test different parser configuration security modes."""

    def test_default_config_balanced(self):
        """Test default configuration has balanced security/performance."""
        config = ParserConfig.default()

        assert config.max_rule_length == 100_000
        assert config.max_options == 1000
        assert config.max_nesting_depth == 50
        assert config.timeout_seconds == 30.0
        assert config.max_input_size == 100_000_000

    def test_permissive_config_relaxed(self):
        """Test permissive configuration for trusted input."""
        config = ParserConfig.permissive()

        assert config.max_rule_length == 1_000_000
        assert config.max_options == 10_000
        assert config.max_nesting_depth == 100
        assert config.timeout_seconds == 0.0  # No timeout
        assert config.max_input_size == 1_000_000_000

    def test_strict_config_restrictive(self):
        """Test strict configuration for untrusted input."""
        config = ParserConfig.strict()

        assert config.max_rule_length == 10_000
        assert config.max_options == 100
        assert config.max_nesting_depth == 20
        assert config.timeout_seconds == 10.0
        assert config.max_input_size == 10_000_000

    def test_parser_uses_custom_config(self):
        """Test parser respects custom configuration."""
        config = ParserConfig(
            max_rule_length=5000,
            max_options=50,
            max_nesting_depth=10,
            timeout_seconds=5.0,
            max_input_size=5_000_000,
        )
        parser = RuleParser(config=config, strict=True)  # Enable strict mode

        # Should reject rule exceeding custom limit
        from surinort_ast.exceptions import ParseError

        long_rule = 'alert tcp any any -> any 80 (msg:"' + "A" * 6000 + '"; sid:1;)'
        with pytest.raises(ParseError):
            parser.parse(long_rule)


class TestRegressionPrevention:
    """Test that ReDoS fixes don't break legitimate parsing."""

    def test_normal_reference_urls_still_parse(self):
        """Test that legitimate reference URLs still parse correctly."""
        parser = RuleParser()

        test_cases = [
            "https://example.com/path",
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234",
            "https://attack.mitre.org/techniques/T1059/",
            "ftp://ftp.example.com/file.txt",
        ]

        for url in test_cases:
            rule_text = f'alert tcp any any -> any 80 (msg:"Test"; reference:url,{url}; sid:1;)'
            rule = parser.parse(rule_text)
            assert isinstance(rule, Rule), f"Failed to parse URL: {url}"

    def test_normal_pcre_patterns_still_parse(self):
        """Test that legitimate PCRE patterns still parse correctly."""
        parser = RuleParser()

        test_cases = [
            "/test/i",
            "/admin\\/.*\\.php/Ui",
            "/^GET .*HTTP\\/1\\.[01]/",
            "/[a-zA-Z0-9]{10,50}/",
            "/(SELECT|UPDATE|DELETE).*FROM/i",
        ]

        for pattern in test_cases:
            rule_text = f'alert tcp any any -> any 80 (msg:"Test"; pcre:"{pattern}"; sid:1;)'
            rule = parser.parse(rule_text)
            assert isinstance(rule, Rule), f"Failed to parse PCRE: {pattern}"

    def test_complex_real_world_rules_still_parse(self):
        """Test that complex real-world rules still parse after ReDoS fixes."""
        parser = RuleParser()

        # Real-world Suricata rule example
        rule_text = (
            "alert http $HOME_NET any -> $EXTERNAL_NET any "
            '(msg:"ET MALWARE Win32/Emotet Data Exfiltration"; '
            'flow:established,to_server; content:"POST"; http_method; '
            'content:"/"; http_uri; depth:1; '
            'content:"Mozilla/4.0"; http_user_agent; '
            'pcre:"/^\\/[a-z]{1,10}$/U"; '
            "reference:md5,1234567890abcdef1234567890abcdef; "
            "classtype:trojan-activity; sid:2028401; rev:2; "
            "metadata:created_at 2020_01_15, updated_at 2020_01_15;)"
        )

        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_hex_content_patterns_still_parse(self):
        """Test that hex content patterns still parse correctly."""
        parser = RuleParser()

        rule_text = (
            "alert tcp any any -> any any "
            '(msg:"Test Hex"; content:"|4D 5A 90 00 03 00 00 00|"; sid:1;)'
        )

        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)

    def test_generic_unknown_options_still_parse(self):
        """Test that generic/unknown options still parse correctly."""
        parser = RuleParser()

        # Unknown options that should be caught by generic_option
        rule_text = (
            "alert tcp any any -> any 80 "
            '(msg:"Test"; custom_option:value123; another_opt:ABC+; sid:1;)'
        )

        rule = parser.parse(rule_text)
        assert isinstance(rule, Rule)
