"""Source-preserving and canonical rule printers."""

from __future__ import annotations

from collections.abc import Sequence

from ..core.nodes import Rule
from .formatter import FormatterOptions
from .text_printer import TextPrinter


class CanonicalPrinter(TextPrinter):
    """Print rules from AST fields using the canonical formatter."""

    def __init__(self, options: FormatterOptions | None = None) -> None:
        super().__init__(options or FormatterOptions.standard())


class SourcePrinter:
    """Return the parsed source block when the AST retained it.

    ASTs created programmatically fall back to canonical printing because they
    have no source text to preserve.
    """

    def __init__(self, fallback: CanonicalPrinter | None = None) -> None:
        self.fallback = fallback or CanonicalPrinter()

    def print_rule(self, rule: Rule) -> str:
        """Print one rule without discarding retained source formatting."""
        if rule.raw_text is None:
            return self.fallback.print_rule(rule)
        if not rule.comments:
            return rule.raw_text
        prefix = "\n".join(
            comment if comment.lstrip().startswith("#") else f"# {comment}"
            for comment in rule.comments
        )
        return f"{prefix}\n{rule.raw_text}"

    def print_rules(self, rules: Sequence[Rule]) -> str:
        """Print multiple source blocks separated by newlines."""
        return "\n".join(self.print_rule(rule) for rule in rules)


__all__ = ["CanonicalPrinter", "SourcePrinter"]
