"""
Normalized findings for diagnostics and analysis outputs.

This module defines a stable finding model to decouple diagnostics/analysis
from output formats such as SARIF.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ..core.diagnostics import Diagnostic
from ..core.enums import DiagnosticLevel
from .coverage import CoverageReport
from .optimizer import OptimizationResult


class FindingLevel(str, Enum):
    """Normalized finding severity."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


@dataclass(frozen=True)
class FindingLocation:
    """Normalized source location."""

    file_path: str | None = None
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


@dataclass(frozen=True)
class Finding:
    """Normalized finding independent from presentation format."""

    rule_id: str
    level: FindingLevel
    message: str
    category: str
    location: FindingLocation | None = None
    description: str | None = None
    help_text: str | None = None
    properties: dict[str, str | int | float | bool] = field(default_factory=dict)


def _normalize_rule_id(raw: str) -> str:
    # SARIF 2.1.0 requires rule IDs to be ASCII; using str.isalnum() depends on
    # the current locale (e.g. Turkish 'İ' is alnum), so we explicitly restrict
    # to ASCII alphanumerics here.
    normalized = "".join(ch if (ch.isascii() and ch.isalnum()) else "_" for ch in raw.upper())
    normalized = "_".join(part for part in normalized.split("_") if part)
    return normalized or "SURINORT_GENERIC"


def _diagnostic_level_to_finding(level: DiagnosticLevel) -> FindingLevel:
    if level == DiagnosticLevel.ERROR:
        return FindingLevel.ERROR
    if level == DiagnosticLevel.WARNING:
        return FindingLevel.WARNING
    return FindingLevel.NOTE


def diagnostic_to_finding(diag: Diagnostic, default_file_path: str | None = None) -> Finding:
    """Convert a parser/validator Diagnostic to normalized Finding."""
    code = diag.code or "DIAGNOSTIC"
    rule_id = _normalize_rule_id(f"SURINORT_{code}")

    location = None
    if diag.location is not None:
        span = diag.location.span
        location = FindingLocation(
            file_path=diag.location.file_path or default_file_path,
            start_line=span.start.line,
            start_column=span.start.column,
            end_line=span.end.line,
            end_column=span.end.column,
        )
    elif default_file_path is not None:
        location = FindingLocation(file_path=default_file_path)

    return Finding(
        rule_id=rule_id,
        level=_diagnostic_level_to_finding(diag.level),
        message=diag.message,
        category="diagnostic",
        location=location,
        description=diag.message,
        help_text=diag.hint,
        properties={"source": "diagnostic"},
    )


def diagnostics_to_findings(
    diagnostics: list[Diagnostic], default_file_path: str | None = None
) -> list[Finding]:
    """Convert diagnostics list to normalized findings."""
    return [
        diagnostic_to_finding(diag, default_file_path=default_file_path) for diag in diagnostics
    ]


def _coverage_severity_to_level(severity: str) -> FindingLevel:
    sev = severity.lower()
    if sev == "high":
        return FindingLevel.ERROR
    if sev == "medium":
        return FindingLevel.WARNING
    return FindingLevel.NOTE


def coverage_report_to_findings(report: CoverageReport) -> list[Finding]:
    """Convert coverage analysis report to findings."""
    findings: list[Finding] = []

    for gap in report.gaps:
        findings.append(
            Finding(
                rule_id=_normalize_rule_id(f"SURINORT_COVERAGE_{gap.gap_type}"),
                level=_coverage_severity_to_level(gap.severity),
                message=gap.description,
                category="coverage",
                description=gap.description,
                help_text=gap.recommendation,
                properties={
                    "severity": gap.severity,
                    "gap_type": gap.gap_type,
                    "experimental": report.experimental,
                    "confidence": report.confidence,
                    "engine_verified": report.engine_verified,
                },
            )
        )

    if not findings:
        findings.append(
            Finding(
                rule_id="SURINORT_COVERAGE_OK",
                level=FindingLevel.NOTE,
                message="No coverage gaps detected",
                category="coverage",
                description="Coverage analyzer did not detect actionable gaps.",
                properties={
                    "total_rules": report.total_rules,
                    "experimental": report.experimental,
                    "confidence": report.confidence,
                    "engine_verified": report.engine_verified,
                },
            )
        )

    return findings


def optimization_results_to_findings(results: list[OptimizationResult]) -> list[Finding]:
    """Convert optimizer results to findings."""
    findings: list[Finding] = []

    for result in results:
        for opt in result.optimizations:
            findings.append(
                Finding(
                    rule_id=_normalize_rule_id(f"SURINORT_OPTIMIZER_{opt.strategy}"),
                    level=FindingLevel.NOTE,
                    message=opt.description,
                    category="optimizer",
                    description=opt.description,
                    help_text=(
                        f"Heuristic cost delta: {opt.estimated_gain:+.1f}%; "
                        "engine verification is required"
                    ),
                    properties={
                        "strategy": opt.strategy,
                        "estimated_gain": round(opt.estimated_gain, 3),
                        "experimental": result.experimental,
                        "confidence": result.confidence,
                        "engine_verified": result.engine_verified,
                        "behavior_verified": result.behavior_verified,
                    },
                )
            )

    if not findings:
        findings.append(
            Finding(
                rule_id="SURINORT_OPTIMIZER_NO_CHANGES",
                level=FindingLevel.NOTE,
                message="Optimizer produced no changes",
                category="optimizer",
                description="No optimization opportunities were identified.",
            )
        )

    return findings


__all__ = [
    "Finding",
    "FindingLevel",
    "FindingLocation",
    "coverage_report_to_findings",
    "diagnostic_to_finding",
    "diagnostics_to_findings",
    "optimization_results_to_findings",
]
