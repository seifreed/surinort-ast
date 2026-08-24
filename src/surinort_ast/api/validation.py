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

_SINGLETON_OPTIONS = {
    "SidOption": "sid",
    "GidOption": "gid",
    "RevOption": "rev",
    "PriorityOption": "priority",
    "DetectionFilterOption": "detection_filter",
}
_CONTENT_MODIFIERS = {
    "DepthOption",
    "OffsetOption",
    "DistanceOption",
    "WithinOption",
    "NocaseOption",
    "RawbytesOption",
    "StartswithOption",
    "EndswithOption",
    "FastPatternOption",
}


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

    # Check for recommended options
    has_sid = any(opt.node_type == "SidOption" for opt in rule.options)
    has_msg = any(opt.node_type == "MsgOption" for opt in rule.options)
    has_rev = any(opt.node_type == "RevOption" for opt in rule.options)

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

    if has_sid and not has_rev:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.INFO,
                message="Missing recommended option 'rev'",
                code="missing_rev",
            )
        )

    # These options are singleton or positional in the engine rule language;
    # accepting them silently produces a rule whose meaning depends on engine
    # version and option order.
    counts: dict[str, int] = {}
    previous_content = False
    for option in rule.options:
        option_type = option.node_type
        if option_type in _SINGLETON_OPTIONS:
            counts[option_type] = counts.get(option_type, 0) + 1
        if option_type == "ContentOption":
            previous_content = True
            continue
        if option_type in _CONTENT_MODIFIERS:
            if not previous_content:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Option '{option_type.removesuffix('Option').lower()}' requires a preceding content option",
                        location=option.location,
                        code="content_modifier_without_content",
                        hint="Place the modifier immediately after content or use an inline modifier.",
                    )
                )
            continue
        previous_content = False

    for option_type, count in counts.items():
        if count > 1:
            keyword = _SINGLETON_OPTIONS[option_type]
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Option '{keyword}' may appear only once",
                    code="duplicate_singleton_option",
                    hint=f"Keep one {keyword} option in the rule.",
                )
            )

    # Cross-rule checks (duplicate SIDs, shadowing, conflicting actions) require a
    # whole rule set and live in surinort_ast.analysis.conflicts and the streaming
    # ValidateProcessor, not in this single-rule validator.

    # Include any diagnostics from parsing
    if rule.diagnostics:
        diagnostics.extend(rule.diagnostics)

    return diagnostics


__all__ = [
    "validate_rule",
]
