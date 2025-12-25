#!/usr/bin/env python3
"""
Custom Parser Implementation Example

This example demonstrates how to implement custom parsers for surinort-ast
using dependency injection patterns. Custom parsers enable:

- Strict validation beyond syntax checking
- Custom preprocessing and normalization
- Performance optimizations (caching, batching)
- Testing with mock parsers
- Middleware patterns

This demonstrates the recommended approach for v1.1.0+ after RuleParser deprecation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from collections.abc import Callable
from functools import lru_cache

from surinort_ast.api.parsing import parse_rule as api_parse_rule
from surinort_ast.core.nodes import Rule
from surinort_ast.exceptions import ParseError
from surinort_ast.parsing.lark_parser import LarkRuleParser

# ==============================================================================
# Example 1: Strict Validation Parser
# ==============================================================================


class StrictValidationParser:
    """
    Parser with strict validation requirements.

    This parser enforces that rules have all required options and follow
    specific conventions (e.g., SID ranges, required metadata).

    Features:
    - Validates required options presence
    - Enforces SID ranges
    - Checks option constraints
    - Provides clear error messages
    """

    def __init__(
        self,
        required_options: list[str] | None = None,
        min_sid: int = 1000000,
        max_sid: int = 9999999,
        **kwargs,
    ):
        """
        Initialize strict parser.

        Args:
            required_options: List of required option names (default: sid, msg, rev)
            min_sid: Minimum allowed SID value
            max_sid: Maximum allowed SID value
            **kwargs: Additional LarkRuleParser arguments
        """
        self._lark_parser = LarkRuleParser(**kwargs)
        self.required_options = required_options or ["sid", "msg", "rev"]
        self.min_sid = min_sid
        self.max_sid = max_sid

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        """
        Parse rule with strict validation.

        Args:
            text: Rule text to parse
            file_path: Optional source file path
            line_offset: Line number offset

        Returns:
            Validated Rule AST

        Raises:
            ParseError: If validation fails
        """
        # Parse with LarkRuleParser
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Validate required options
        self._validate_required_options(rule, text)

        # Validate SID range
        self._validate_sid_range(rule, text)

        # Validate option consistency
        self._validate_option_consistency(rule, text)

        return rule

    def _validate_required_options(self, rule: Rule, text: str) -> None:
        """Validate that all required options are present."""
        option_types = {opt.node_type for opt in rule.options}

        for required in self.required_options:
            required_type = f"{required.capitalize()}Option"
            if required_type not in option_types:
                raise ParseError(f"Rule missing required option: {required}\nRule text: {text}")

    def _validate_sid_range(self, rule: Rule, text: str) -> None:
        """Validate SID is within allowed range."""
        sid_option = next((opt for opt in rule.options if opt.node_type == "SidOption"), None)

        if sid_option:
            if sid_option.value < self.min_sid:
                raise ParseError(
                    f"SID {sid_option.value} is below minimum threshold of {self.min_sid}\n"
                    f"Rule text: {text}"
                )
            if sid_option.value > self.max_sid:
                raise ParseError(
                    f"SID {sid_option.value} exceeds maximum threshold of {self.max_sid}\n"
                    f"Rule text: {text}"
                )

    def _validate_option_consistency(self, rule: Rule, text: str) -> None:
        """Validate option combinations are consistent."""
        # Example: Ensure rules with PCRE also have content for fast pattern
        has_pcre = any(opt.node_type == "PcreOption" for opt in rule.options)
        has_content = any(opt.node_type == "ContentOption" for opt in rule.options)

        if has_pcre and not has_content:
            # This is a warning, not an error - just log it
            print(
                f"Warning: Rule has PCRE but no content option for fast pattern matching\n"
                f"Rule text: {text}"
            )


# ==============================================================================
# Example 2: Caching Parser
# ==============================================================================


class CachingParser:
    """
    Parser that caches parsed rules for repeated parse operations.

    This is useful when parsing the same rules multiple times (e.g., in tests,
    or when processing large rule files with duplicates).

    Features:
    - LRU cache for parsed results
    - Configurable cache size
    - Cache statistics
    - Cache clearing
    """

    def __init__(self, cache_size: int = 1000, **kwargs):
        """
        Initialize caching parser.

        Args:
            cache_size: Maximum number of cached parse results
            **kwargs: Additional LarkRuleParser arguments
        """
        self._lark_parser = LarkRuleParser(**kwargs)
        self._cache_size = cache_size

        # Create cached parse method with lru_cache
        self._cached_parse = lru_cache(maxsize=cache_size)(self._parse_impl)

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        """
        Parse rule with caching.

        Identical text will return cached result without re-parsing.

        Args:
            text: Rule text to parse
            file_path: Optional source file path (not cached)
            line_offset: Line number offset (not cached)

        Returns:
            Parsed Rule AST
        """
        # Cache based on text only (file_path and line_offset don't affect parsing)
        return self._cached_parse(text, file_path, line_offset)

    def _parse_impl(self, text: str, file_path: str | None, line_offset: int) -> Rule:
        """Internal parse implementation (cached)."""
        return self._lark_parser.parse(text, file_path, line_offset)

    def cache_info(self) -> tuple[int, int, int, int]:
        """
        Get cache statistics.

        Returns:
            Tuple of (hits, misses, maxsize, currsize)
        """
        return self._cached_parse.cache_info()

    def clear_cache(self) -> None:
        """Clear the parse cache."""
        self._cached_parse.cache_clear()


# ==============================================================================
# Example 3: Parser Middleware Pattern
# ==============================================================================


class ParserMiddleware:
    """
    Parser that applies middleware functions before and after parsing.

    This enables composable transformations without subclassing.

    Features:
    - Composable preprocessors
    - Composable postprocessors
    - Easy to test and maintain
    - Flexible transformation pipeline
    """

    def __init__(self, **kwargs):
        """
        Initialize parser middleware.

        Args:
            **kwargs: Additional LarkRuleParser arguments
        """
        self._lark_parser = LarkRuleParser(**kwargs)
        self._preprocessors: list[Callable[[str], str]] = []
        self._postprocessors: list[Callable[[Rule], Rule]] = []

    def add_preprocessor(self, func: Callable[[str], str]) -> None:
        """
        Add a text preprocessing function.

        Args:
            func: Function that takes rule text and returns modified text
        """
        self._preprocessors.append(func)

    def add_postprocessor(self, func: Callable[[Rule], Rule]) -> None:
        """
        Add a rule post-processing function.

        Args:
            func: Function that takes Rule and returns modified Rule
        """
        self._postprocessors.append(func)

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        """
        Parse with middleware pipeline.

        Args:
            text: Rule text to parse
            file_path: Optional source file path
            line_offset: Line number offset

        Returns:
            Processed Rule AST
        """
        # Apply preprocessors
        for preprocessor in self._preprocessors:
            text = preprocessor(text)

        # Parse
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Apply postprocessors
        for postprocessor in self._postprocessors:
            rule = postprocessor(rule)

        return rule


# ==============================================================================
# Example Middleware Functions
# ==============================================================================


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace in rule text."""
    return " ".join(text.split())


def uppercase_action(text: str) -> str:
    """Ensure rule action is uppercase."""
    parts = text.split(maxsplit=1)
    if parts:
        parts[0] = parts[0].upper()
    return " ".join(parts)


def add_processing_metadata(rule: Rule) -> Rule:
    """Add processing timestamp to rule metadata (example)."""
    # In a real implementation, you would create a new MetadataOption
    # and append it to rule.options using model_copy
    return rule


# ==============================================================================
# Example 4: Mock Parser for Testing
# ==============================================================================


class MockParser:
    """
    Mock parser for testing without actual parsing.

    Useful for unit tests where you want to verify code behavior
    without depending on real parser implementation.
    """

    def __init__(self, mock_rule: Rule | None = None):
        """
        Initialize mock parser.

        Args:
            mock_rule: Rule to return from parse() calls
        """
        self.mock_rule = mock_rule
        self.parse_calls: list[tuple[str, str | None, int]] = []

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        """
        Mock parse that returns predetermined result.

        Args:
            text: Rule text (recorded but not parsed)
            file_path: Optional source file path (recorded)
            line_offset: Line number offset (recorded)

        Returns:
            Mock rule
        """
        # Record the call for verification
        self.parse_calls.append((text, file_path, line_offset))

        # Return mock rule
        if self.mock_rule is None:
            raise ValueError("No mock rule configured")

        return self.mock_rule


# ==============================================================================
# Main: Demonstration
# ==============================================================================


def main():
    """Demonstrate custom parser implementations."""
    print("=" * 70)
    print("Custom Parser Implementation Examples")
    print("=" * 70)

    # Sample rules
    valid_rule = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'
    invalid_sid = 'alert tcp any any -> any 80 (msg:"HTTP"; sid:100; rev:1;)'
    missing_option = 'alert tcp any any -> any 80 (msg:"HTTP"; rev:1;)'

    # Example 1: Strict Validation Parser
    print("\n1. Strict Validation Parser")
    print("-" * 70)

    strict_parser = StrictValidationParser(required_options=["sid", "msg", "rev"], min_sid=1000000)

    try:
        rule = api_parse_rule(valid_rule, parser=strict_parser)
        print(f"✓ Valid rule parsed successfully: SID {rule.options[1].value}")
    except ParseError as e:
        print(f"✗ Parse failed: {e}")

    try:
        rule = api_parse_rule(invalid_sid, parser=strict_parser)
        print(f"✓ Parsed: {rule}")
    except ParseError as e:
        print(f"✗ Expected validation failure: {str(e)[:80]}...")

    try:
        rule = api_parse_rule(missing_option, parser=strict_parser)
        print(f"✓ Parsed: {rule}")
    except ParseError as e:
        print(f"✗ Expected validation failure: {str(e)[:80]}...")

    # Example 2: Caching Parser
    print("\n2. Caching Parser")
    print("-" * 70)

    caching_parser = CachingParser(cache_size=100)

    # Parse the same rule multiple times
    for i in range(3):
        rule = api_parse_rule(valid_rule, parser=caching_parser)

    hits, misses, maxsize, currsize = caching_parser.cache_info()
    print("Cache statistics:")
    print(f"  Hits: {hits}, Misses: {misses}")
    print(f"  Size: {currsize}/{maxsize}")

    # Example 3: Parser Middleware
    print("\n3. Parser Middleware")
    print("-" * 70)

    middleware_parser = ParserMiddleware()
    middleware_parser.add_preprocessor(normalize_whitespace)
    middleware_parser.add_preprocessor(uppercase_action)

    messy_rule = 'alert   tcp  any any  ->  any 80  (msg:"Test";  sid:1000001; rev:1;)'
    rule = api_parse_rule(messy_rule, parser=middleware_parser)
    print(f"✓ Parsed messy rule: {rule.action}")

    # Example 4: Using with api.parsing functions
    print("\n4. Integration with api.parsing Functions")
    print("-" * 70)

    # Any custom parser works with api_parse_rule via dependency injection
    custom_parser = StrictValidationParser()
    rule = api_parse_rule(valid_rule, parser=custom_parser)
    print(f"✓ Dependency injection works: {rule.header.protocol}")

    print("\n" + "=" * 70)
    print("All examples completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()
