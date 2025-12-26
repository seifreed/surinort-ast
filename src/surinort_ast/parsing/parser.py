"""
Parser for Suricata and Snort IDS rules.

This module provides the main parser interface for parsing IDS rules into AST nodes.
It uses Lark parser with LALR(1) parsing strategy and includes robust error recovery
mechanisms.

BACKWARD COMPATIBILITY WRAPPER:
This module now wraps LarkRuleParser for backward compatibility. New code should
use LarkRuleParser directly or use the ParserFactory for dependency injection.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.enums import Dialect
from ..core.nodes import Rule
from .lark_parser import LarkRuleParser
from .parser_config import ParserConfig

if TYPE_CHECKING:
    from lark import Lark

    from ..core.nodes import ErrorNode

logger = logging.getLogger(__name__)


# ============================================================================
# Parser Class (Backward Compatibility Wrapper)
# ============================================================================


class RuleParser:
    """
    Parser for Suricata and Snort IDS rules.

    .. deprecated:: 1.1.0
       Use :class:`LarkRuleParser` instead. This class is maintained for backward
       compatibility only and will be removed in version 2.0.0.

    DEPRECATED: This class is now a backward compatibility wrapper around LarkRuleParser.
    New code should use LarkRuleParser directly or ParserFactory for dependency injection.

    This parser converts text rules into strongly-typed AST nodes. It supports:
    - Multiple dialects (Suricata, Snort2, Snort3)
    - Error recovery with ErrorNode generation
    - Location tracking for all nodes
    - Diagnostic messages for warnings and errors

    Examples:
        >>> # Old way (deprecated)
        >>> parser = RuleParser()
        >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

        >>> # New way (recommended)
        >>> from surinort_ast.parsing.lark_parser import LarkRuleParser
        >>> parser = LarkRuleParser()
        >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

        >>> # Or use api functions (simplest)
        >>> from surinort_ast.api.parsing import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

        >>> # For custom parsers with dependency injection
        >>> from surinort_ast.api.parsing import parse_rule
        >>> custom_parser = LarkRuleParser(dialect=Dialect.SNORT3, strict=True)
        >>> rule = parse_rule(text, parser=custom_parser)

    See Also:
        - :class:`LarkRuleParser`: Recommended replacement
        - :mod:`surinort_ast.api.parsing`: High-level parsing functions
        - Migration guide: docs/MIGRATION_GUIDE.md
    """

    def __init__(
        self,
        dialect: Dialect = Dialect.SURICATA,
        strict: bool = False,
        error_recovery: bool = True,
        config: ParserConfig | None = None,
    ):
        """
        Initialize parser.

        .. deprecated:: 1.1.0
           Use :class:`LarkRuleParser` instead. This constructor will be removed in 2.0.0.

        Args:
            dialect: Target IDS dialect (Suricata, Snort2, Snort3)
            strict: If True, raise ParseError on any error; if False, return ErrorNode
            error_recovery: Enable error recovery during parsing
            config: Parser configuration with resource limits (default: ParserConfig.default())

        Raises:
            DeprecationWarning: Always emitted to warn about deprecated usage

        Examples:
            >>> # Deprecated
            >>> parser = RuleParser()

            >>> # Recommended
            >>> from surinort_ast.parsing.lark_parser import LarkRuleParser
            >>> parser = LarkRuleParser()
        """
        # Emit deprecation warning
        warnings.warn(
            "RuleParser is deprecated and will be removed in version 2.0.0. "
            "Use LarkRuleParser directly or the parse_rule() function from surinort_ast.api.parsing instead. "
            "See docs/MIGRATION_GUIDE.md for migration instructions.",
            DeprecationWarning,
            stacklevel=2,
        )

        # Delegate to LarkRuleParser for all functionality
        self._parser = LarkRuleParser(
            dialect=dialect,
            strict=strict,
            error_recovery=error_recovery,
            config=config,
        )

        # Expose properties for backward compatibility
        self.dialect = self._parser.dialect
        self.strict = self._parser.strict
        self.error_recovery = self._parser.error_recovery
        self.config = self._parser.config

    # Expose internal methods for backward compatibility with existing tests
    def _get_parser(self) -> Lark:  # type: ignore
        """Get Lark parser (backward compatibility)."""
        return self._parser._get_parser()

    def _get_grammar(self) -> str:
        """Get grammar (backward compatibility)."""
        return self._parser._get_grammar()

    def _handle_parse_error(self, error: Exception, text: str, file_path: str | None) -> Rule:
        """Handle parse error (backward compatibility)."""
        return self._parser._handle_parse_error(error, text, file_path)

    def _create_error_rule(
        self, error_node: ErrorNode, raw_text: str, file_path: str | None
    ) -> Rule:  # type: ignore
        """Create error rule (backward compatibility)."""
        return self._parser._create_error_rule(error_node, raw_text, file_path)

    def _attach_source_metadata(
        self, rule: Rule, raw_text: str, file_path: str | None, line_offset: int
    ) -> Rule:
        """Attach source metadata (backward compatibility)."""
        return self._parser._attach_source_metadata(rule, raw_text, file_path, line_offset)

    def _extract_sid(self, rule: Rule) -> int | None:
        """Extract SID (backward compatibility)."""
        return self._parser._extract_sid(rule)

    def _parse_multiline_rule(
        self, lines: Sequence[tuple[int, str]], file_path: str, skip_errors: bool
    ) -> Rule | None:  # type: ignore
        """Parse multiline rule (backward compatibility)."""
        return self._parser._parse_multiline_rule(lines, file_path, skip_errors)

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> Rule:
        """
        Parse a single IDS rule from text.

        .. deprecated:: 1.1.0
           Use :meth:`LarkRuleParser.parse` or :func:`surinort_ast.api.parsing.parse_rule` instead.

        Args:
            text: Rule text to parse
            file_path: Optional source file path for location tracking
            line_offset: Line number offset for multi-line files

        Returns:
            Parsed Rule AST node, or ErrorNode if parsing fails

        Raises:
            ParseError: If strict mode enabled and parsing fails

        Examples:
            >>> # Deprecated
            >>> parser = RuleParser()
            >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

            >>> # Recommended
            >>> from surinort_ast.api.parsing import parse_rule
            >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        """
        return self._parser.parse(text, file_path, line_offset)

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        skip_errors: bool = True,
    ) -> list[Rule]:
        """
        Parse IDS rules from a file.

        .. deprecated:: 1.1.0
           Use :meth:`LarkRuleParser.parse_file` or :func:`surinort_ast.api.parsing.parse_file` instead.

        This method handles multi-line rules, comments, and blank lines.

        Args:
            path: Path to rules file
            encoding: File encoding (default: utf-8)
            skip_errors: If True, skip lines that fail to parse; if False, include ErrorNode

        Returns:
            List of parsed Rule nodes

        Raises:
            FileNotFoundError: If file does not exist
            ParseError: If strict mode enabled and parsing fails

        Examples:
            >>> # Deprecated
            >>> parser = RuleParser()
            >>> rules = parser.parse_file("rules/emerging-threats.rules")

            >>> # Recommended
            >>> from surinort_ast.api.parsing import parse_file
            >>> rules = parse_file("rules/emerging-threats.rules")
        """
        return self._parser.parse_file(path, encoding, skip_errors)


# ============================================================================
# Convenience Functions
# ============================================================================


def parse_rule(
    text: str,
    dialect: Dialect = Dialect.SURICATA,
    strict: bool = False,
) -> Rule:
    """
    Parse a single IDS rule from text (convenience function).

    .. deprecated:: 1.1.0
       Use :func:`surinort_ast.api.parsing.parse_rule` instead. This function will be removed in 2.0.0.

    Args:
        text: Rule text
        dialect: Target dialect
        strict: Strict mode (raise on error)

    Returns:
        Parsed Rule

    Examples:
        >>> # Deprecated
        >>> from surinort_ast.parsing.parser import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        >>> # Recommended
        >>> from surinort_ast.api.parsing import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
    """
    warnings.warn(
        "surinort_ast.parsing.parser.parse_rule() is deprecated. "
        "Use surinort_ast.api.parsing.parse_rule() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    parser = RuleParser(dialect=dialect, strict=strict)
    return parser.parse(text)


def parse_rules_file(
    path: str | Path,
    dialect: Dialect = Dialect.SURICATA,
    skip_errors: bool = True,
) -> list[Rule]:
    """
    Parse IDS rules from file (convenience function).

    .. deprecated:: 1.1.0
       Use :func:`surinort_ast.api.parsing.parse_file` instead. This function will be removed in 2.0.0.

    Args:
        path: File path
        dialect: Target dialect
        skip_errors: Skip unparseable rules

    Returns:
        List of parsed Rules

    Examples:
        >>> # Deprecated
        >>> from surinort_ast.parsing.parser import parse_rules_file
        >>> rules = parse_rules_file("rules.rules")

        >>> # Recommended
        >>> from surinort_ast.api.parsing import parse_file
        >>> rules = parse_file("rules.rules")
    """
    warnings.warn(
        "surinort_ast.parsing.parser.parse_rules_file() is deprecated. "
        "Use surinort_ast.api.parsing.parse_file() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    parser = RuleParser(dialect=dialect, strict=False)
    return parser.parse_file(path, skip_errors=skip_errors)
