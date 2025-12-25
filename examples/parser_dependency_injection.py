"""
Example: Using Parser Dependency Injection in surinort-ast

This example demonstrates how to use the IParser interface for dependency
injection, enabling parser library swapping and custom parser implementations.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from pathlib import Path

from surinort_ast.core.enums import Action, Dialect, Protocol
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing import (
    IParser,
    LarkRuleParser,
    ParserConfig,
    ParserFactory,
    RuleParser,
)


def example_1_using_lark_parser_directly():
    """Example 1: Using LarkRuleParser directly (recommended for new code)."""
    print("Example 1: Using LarkRuleParser directly")
    print("=" * 60)

    # Create parser with default configuration
    parser = LarkRuleParser()

    # Parse a simple rule
    rule = parser.parse('alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1;)')

    print(f"Action: {rule.action}")
    print(f"Protocol: {rule.header.protocol}")
    print(f"Rule: {rule.raw_text}")
    print()


def example_2_using_parser_factory():
    """Example 2: Using ParserFactory for centralized parser creation."""
    print("Example 2: Using ParserFactory")
    print("=" * 60)

    # Create parser with default settings
    parser = ParserFactory.create()
    rule = parser.parse('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)')

    print(f"Factory created parser: {type(parser).__name__}")
    print(f"Rule SID: {[opt for opt in rule.options if opt.node_type == 'SidOption'][0].value}")

    # Create parser with custom configuration
    strict_config = ParserConfig.strict()
    strict_parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True, config=strict_config)

    print(f"Strict parser dialect: {strict_parser.dialect}")
    print()


def example_3_custom_parser_implementation():
    """Example 3: Creating a custom parser implementation."""
    print("Example 3: Custom Parser Implementation")
    print("=" * 60)

    class LoggingParser:
        """Custom parser that logs all parse operations."""

        def __init__(
            self,
            dialect: Dialect = Dialect.SURICATA,
            strict: bool = False,
            error_recovery: bool = True,
            config: ParserConfig | None = None,
        ):
            self.dialect = dialect
            self.strict = strict
            self.config = config or ParserConfig.default()
            # Delegate to LarkRuleParser
            self._inner_parser = LarkRuleParser(dialect, strict, error_recovery, config)
            self.parse_count = 0

        def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
            """Parse with logging."""
            self.parse_count += 1
            print(f"  [LoggingParser] Parse #{self.parse_count}: {text[:50]}...")
            return self._inner_parser.parse(text, file_path, line_offset)

        def parse_file(
            self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True
        ) -> list[Rule]:
            """Parse file with logging."""
            print(f"  [LoggingParser] Parsing file: {path}")
            return self._inner_parser.parse_file(path, encoding, skip_errors)

    # Use custom parser
    logging_parser: IParser = LoggingParser()
    rule1 = logging_parser.parse("alert tcp any any -> any 80 (sid:1;)")
    rule2 = logging_parser.parse("alert tcp any any -> any 443 (sid:2;)")

    print(f"Total parses: {logging_parser.parse_count}")
    print()


def example_4_registering_default_parser():
    """Example 4: Registering a custom default parser with ParserFactory."""
    print("Example 4: Registering Custom Default Parser")
    print("=" * 60)

    class FastParser:
        """Example fast parser (delegates to LarkRuleParser)."""

        def __init__(self, **kwargs):
            self._parser = LarkRuleParser(**kwargs)

        def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
            return self._parser.parse(text, file_path, line_offset)

        def parse_file(self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True):
            return self._parser.parse_file(path, encoding, skip_errors)

    # Register custom parser as default
    ParserFactory.register_default(FastParser)

    # Now all factory.create() calls use FastParser
    parser = ParserFactory.create()
    print(f"Factory now creates: {type(parser).__name__}")

    # Reset to default
    ParserFactory.reset_default()
    parser = ParserFactory.create()
    print(f"After reset, factory creates: {type(parser).__name__}")
    print()


def example_5_dependency_injection_in_api():
    """Example 5: Using parser dependency injection in the parse_rule API."""
    print("Example 5: Dependency Injection in API")
    print("=" * 60)

    from surinort_ast.api.parsing import parse_rule

    # Parse with default parser
    rule1 = parse_rule('alert tcp any any -> any 80 (msg:"Default"; sid:1;)')
    print(f"Parsed with default parser: {rule1.action}")

    # Parse with custom parser injected
    custom_parser = LarkRuleParser(dialect=Dialect.SNORT3, strict=True)
    rule2 = parse_rule('alert tcp any any -> any 443 (msg:"Custom"; sid:2;)', parser=custom_parser)
    print(f"Parsed with custom parser (dialect={custom_parser.dialect}): {rule2.action}")
    print()


def example_6_type_safe_dependency_injection():
    """Example 6: Type-safe dependency injection with IParser protocol."""
    print("Example 6: Type-Safe Dependency Injection")
    print("=" * 60)

    def analyze_rules(parser: IParser, rules: list[str]) -> dict[str, int]:
        """
        Analyze rules using any parser implementation.

        This function accepts any parser that implements IParser protocol.
        Python's type system verifies protocol compliance.
        """
        statistics = {"total": 0, "tcp": 0, "udp": 0, "alert": 0}

        for rule_text in rules:
            rule = parser.parse(rule_text)
            statistics["total"] += 1

            if rule.header.protocol == Protocol.TCP:
                statistics["tcp"] += 1
            elif rule.header.protocol == Protocol.UDP:
                statistics["udp"] += 1

            if rule.action == Action.ALERT:
                statistics["alert"] += 1

        return statistics

    # Use with LarkRuleParser
    parser = LarkRuleParser()
    rules = [
        "alert tcp any any -> any 80 (sid:1;)",
        "alert udp any any -> any 53 (sid:2;)",
        "alert tcp any any -> any 443 (sid:3;)",
    ]

    stats = analyze_rules(parser, rules)
    print(f"Statistics: {stats}")
    print()


def example_7_backward_compatibility():
    """Example 7: Backward compatibility with existing RuleParser."""
    print("Example 7: Backward Compatibility")
    print("=" * 60)

    # Old code still works (RuleParser now wraps LarkRuleParser)
    old_parser = RuleParser()
    rule = old_parser.parse('alert tcp any any -> any 80 (msg:"Old API"; sid:1;)')

    print(f"RuleParser still works: {rule.action}")
    print(f"RuleParser delegates to: {type(old_parser._parser).__name__}")

    # Convenience functions still work
    from surinort_ast.parsing import parse_rule as parse_rule_old

    rule2 = parse_rule_old("alert tcp any any -> any 443 (sid:2;)")
    print(f"Convenience function works: {rule2.header.protocol}")
    print()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Parser Dependency Injection Examples")
    print("surinort-ast with IParser Interface")
    print("=" * 60 + "\n")

    example_1_using_lark_parser_directly()
    example_2_using_parser_factory()
    example_3_custom_parser_implementation()
    example_4_registering_default_parser()
    example_5_dependency_injection_in_api()
    example_6_type_safe_dependency_injection()
    example_7_backward_compatibility()

    print("=" * 60)
    print("All examples completed successfully!")
    print("=" * 60)
