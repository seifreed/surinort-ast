"""
Public API for surinort-ast.

This module provides the main public interface for parsing, printing,
and serializing Suricata/Snort IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from lark import Lark
from lark.exceptions import LarkError

from .core.diagnostics import Diagnostic, DiagnosticLevel
from .core.enums import Dialect
from .core.nodes import Rule, SourceOrigin
from .exceptions import ParseError, SerializationError
from .parsing.transformer import RuleTransformer
from .printer.formatter import FormatterOptions
from .printer.text_printer import TextPrinter

# ============================================================================
# Parser Management
# ============================================================================

_PARSERS: dict[Dialect, Lark] = {}


def _get_parser(dialect: Dialect = Dialect.SURICATA) -> Lark:
    """
    Get or create a Lark parser for the specified dialect.

    Args:
        dialect: IDS rule dialect

    Returns:
        Lark parser instance
    """
    if dialect not in _PARSERS:
        grammar_path = Path(__file__).parent / "parsing" / "grammar.lark"
        with grammar_path.open(encoding="utf-8") as f:
            grammar = f.read()

        _PARSERS[dialect] = Lark(
            grammar,
            start="rule",
            parser="lalr",
            propagate_positions=True,
            maybe_placeholders=False,
        )

    return _PARSERS[dialect]


# ============================================================================
# Parsing Functions
# ============================================================================


def parse_rule(text: str, dialect: Dialect = Dialect.SURICATA) -> Rule:
    """
    Parse a single IDS rule from text.

    Args:
        text: Rule text to parse
        dialect: Rule dialect (Suricata, Snort2, Snort3)

    Returns:
        Parsed Rule AST

    Raises:
        ParseError: If parsing fails

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> print(rule.header.protocol)
        Protocol.TCP
    """
    try:
        parser = _get_parser(dialect)
        tree = parser.parse(text.strip())
        transformer = RuleTransformer(dialect=dialect)
        rule = transformer.transform(tree)

        # Add raw text
        return rule.model_copy(update={"raw_text": text})

    except LarkError as e:
        raise ParseError(f"Failed to parse rule: {e}") from e
    except Exception as e:
        raise ParseError(f"Unexpected error during parsing: {e}") from e


def parse_file(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
) -> list[Rule]:
    """
    Parse all rules from a file.

    Args:
        path: Path to file containing rules
        dialect: Rule dialect

    Returns:
        List of parsed Rule ASTs

    Raises:
        ParseError: If file cannot be read or parsed
        FileNotFoundError: If file doesn't exist

    Example:
        >>> rules = parse_file("/etc/suricata/rules/local.rules")
        >>> print(f"Parsed {len(rules)} rules")
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ParseError(f"Not a file: {file_path}")

    try:
        with file_path.open(encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise ParseError(f"Failed to read file {file_path}: {e}") from e

    rules: list[Rule] = []
    errors: list[str] = []

    # Parse line by line, skipping comments and blank lines
    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        try:
            rule = parse_rule(line, dialect=dialect)
            # Add origin metadata
            rule = rule.model_copy(
                update={
                    "origin": SourceOrigin(
                        file_path=str(file_path),
                        line_number=line_num,
                    )
                }
            )
            rules.append(rule)
        except ParseError as e:
            errors.append(f"Line {line_num}: {e}")
            continue

    if errors and not rules:
        # All rules failed to parse
        raise ParseError("Failed to parse any rules:\n" + "\n".join(errors[:10]))

    return rules


# ============================================================================
# Printing Functions
# ============================================================================


def print_rule(rule: Rule, stable: bool = False) -> str:
    """
    Convert a Rule AST back to text format.

    Args:
        rule: Rule AST to print
        stable: Use stable/canonical formatting

    Returns:
        Formatted rule text

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> text = print_rule(rule)
        >>> print(text)
        alert tcp any any -> any 80 (msg:"Test"; sid:1;)
    """
    if stable:
        options = FormatterOptions.stable()
    else:
        options = FormatterOptions.standard()

    printer = TextPrinter(options=options)
    return printer.print_rule(rule)


# ============================================================================
# JSON Serialization
# ============================================================================


def to_json(rule: Rule, indent: int | None = 2) -> str:
    """
    Serialize Rule AST to JSON string.

    Args:
        rule: Rule to serialize
        indent: JSON indentation (None for compact)

    Returns:
        JSON string representation

    Raises:
        SerializationError: If serialization fails

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> json_str = to_json(rule)
        >>> print(json_str)
    """
    try:
        # Pydantic v2 model_dump_json
        return rule.model_dump_json(indent=indent, exclude_none=True)
    except Exception as e:
        raise SerializationError(f"Failed to serialize to JSON: {e}") from e


def from_json(data: str | dict) -> Rule:
    """
    Deserialize Rule AST from JSON.

    Args:
        data: JSON string or dict

    Returns:
        Deserialized Rule AST

    Raises:
        SerializationError: If deserialization fails

    Example:
        >>> json_str = '{"action": "alert", "header": {...}, ...}'
        >>> rule = from_json(json_str)
    """
    try:
        if isinstance(data, str):
            # Parse JSON string
            data_dict = json.loads(data)
        else:
            data_dict = data

        # Pydantic v2 model_validate
        return Rule.model_validate(data_dict)
    except json.JSONDecodeError as e:
        raise SerializationError(f"Invalid JSON: {e}") from e
    except Exception as e:
        raise SerializationError(f"Failed to deserialize from JSON: {e}") from e


def to_json_schema() -> dict[str, Any]:
    """
    Generate JSON Schema for Rule AST.

    Returns:
        JSON Schema dict

    Example:
        >>> schema = to_json_schema()
        >>> print(schema["$schema"])
        https://json-schema.org/draft/2020-12/schema
    """
    # Pydantic v2 model_json_schema
    return Rule.model_json_schema()


# ============================================================================
# Validation Functions
# ============================================================================


def validate_rule(rule: Rule) -> list[Diagnostic]:
    """
    Validate a Rule AST and return diagnostics.

    Args:
        rule: Rule to validate

    Returns:
        List of diagnostics (errors, warnings, info)

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test";)')
        >>> diagnostics = validate_rule(rule)
        >>> for diag in diagnostics:
        ...     print(f"{diag.level}: {diag.message}")
        WARNING: Missing required option 'sid'
    """
    diagnostics: list[Diagnostic] = []

    # Check for required options
    has_sid = any(opt.node_type == "SidOption" for opt in rule.options)
    has_msg = any(opt.node_type == "MsgOption" for opt in rule.options)

    if not has_sid:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message="Missing required option 'sid'",
                code="missing_sid",
            )
        )

    if not has_msg:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message="Missing required option 'msg'",
                code="missing_msg",
            )
        )

    # Check for duplicate SIDs (would need multiple rules context)
    # Check for deprecated options based on dialect
    # Check for conflicting options
    # etc.

    # Include any diagnostics from parsing
    if rule.diagnostics:
        diagnostics.extend(rule.diagnostics)

    return diagnostics


# ============================================================================
# Batch Processing
# ============================================================================


def parse_rules(
    texts: Sequence[str],
    dialect: Dialect = Dialect.SURICATA,
) -> tuple[list[Rule], list[tuple[int, str]]]:
    """
    Parse multiple rules, collecting errors.

    Args:
        texts: List of rule texts
        dialect: Rule dialect

    Returns:
        Tuple of (successful rules, errors as (index, error_message))

    Example:
        >>> rules, errors = parse_rules([
        ...     'alert tcp any any -> any 80 (msg:"Test1"; sid:1;)',
        ...     'invalid rule',
        ...     'alert tcp any any -> any 443 (msg:"Test2"; sid:2;)',
        ... ])
        >>> print(f"Parsed {len(rules)}, failed {len(errors)}")
    """
    rules: list[Rule] = []
    errors: list[tuple[int, str]] = []

    for idx, text in enumerate(texts):
        try:
            rule = parse_rule(text, dialect=dialect)
            rules.append(rule)
        except ParseError as e:
            errors.append((idx, str(e)))

    return rules, errors


# ============================================================================
# Public API Exports
# ============================================================================

__all__ = [
    # JSON serialization
    "from_json",
    # Parsing
    "parse_file",
    "parse_rule",
    "parse_rules",
    # Printing
    "print_rule",
    "to_json",
    "to_json_schema",
    # Validation
    "validate_rule",
]
