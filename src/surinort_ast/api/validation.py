"""
Validation functions for surinort-ast.

This module provides functions for validating Rule ASTs and generating
diagnostics for errors, warnings, and informational messages.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.nodes import Rule


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


__all__ = [
    "validate_rule",
]
