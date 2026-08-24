"""
Serialization functions for surinort-ast.

This module provides functions for serializing and deserializing Rule ASTs
to/from JSON format, including schema generation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ..analysis.coverage import CoverageReport
from ..analysis.findings import (
    Finding,
    coverage_report_to_findings,
    diagnostics_to_findings,
    optimization_results_to_findings,
)
from ..analysis.optimizer import OptimizationResult
from ..core.diagnostics import Diagnostic
from ..core.nodes import Rule
from ..exceptions import SerializationError
from ..serialization.json_serializer import JSONSerializer
from ..serialization.migration import migrate_ast
from ..serialization.sarif import to_sarif_json


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


def from_json(data: str | dict[str, Any]) -> Rule | Sequence[Rule]:
    """
    Deserialize Rule AST from JSON.

    Accepts both bare rule dicts (as produced by ``to_json``) and the
    metadata envelope format used by ``JSONSerializer`` (single-rule envelope
    with a top-level ``data`` key, multi-rule envelope with a ``data.rules``
    list, or a bare ``{"rules": [...]}`` payload).

    Args:
        data: JSON string or dict

    Returns:
        Deserialized Rule, or a sequence of Rules for multi-rule payloads

    Raises:
        SerializationError: If deserialization fails

    Example:
        >>> json_str = '{"action": "alert", "header": {...}, ...}'
        >>> rule = from_json(json_str)
    """
    # Delegate to the canonical deserializer so the envelope-stripping and
    # single-vs-multiple dispatch live in one place. ``JSONSerializer`` raises
    # bare ``ValueError``/JSON errors; wrap them in ``SerializationError`` to
    # preserve this façade's documented contract.
    try:
        return JSONSerializer().from_json(data)
    except SerializationError:
        raise
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


def to_sarif(findings: Sequence[Finding], indent: int | None = 2) -> str:
    """
    Serialize normalized findings to SARIF 2.1.0 JSON.

    Args:
        findings: Normalized findings collection
        indent: JSON indentation (None for compact)

    Returns:
        SARIF JSON string
    """
    try:
        return to_sarif_json(list(findings), indent=indent)
    except Exception as e:
        raise SerializationError(f"Failed to serialize to SARIF: {e}") from e


def diagnostics_to_sarif(
    diagnostics: Sequence[Diagnostic],
    default_file_path: str | None = None,
    indent: int | None = 2,
) -> str:
    """Convert diagnostics directly to SARIF 2.1.0 JSON."""
    findings = diagnostics_to_findings(list(diagnostics), default_file_path=default_file_path)
    return to_sarif(findings, indent=indent)


def optimization_results_to_sarif(
    results: Sequence[OptimizationResult], indent: int | None = 2
) -> str:
    """Convert optimization results directly to SARIF 2.1.0 JSON."""
    findings = optimization_results_to_findings(list(results))
    return to_sarif(findings, indent=indent)


def coverage_report_to_sarif(report: CoverageReport, indent: int | None = 2) -> str:
    """Convert a coverage report to SARIF 2.1.0 JSON."""
    findings = coverage_report_to_findings(report)
    return to_sarif(findings, indent=indent)


__all__ = [
    "coverage_report_to_sarif",
    "diagnostics_to_sarif",
    "from_json",
    "migrate_ast",
    "optimization_results_to_sarif",
    "to_json",
    "to_json_schema",
    "to_sarif",
]
