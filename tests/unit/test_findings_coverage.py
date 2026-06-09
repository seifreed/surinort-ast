# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for analysis/findings.py.

Covers the NOTE fall-throughs of the level mappers, the no-gaps coverage-OK
finding, the optimizer finding produced per optimization, and the
no-optimizations fallback finding.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.analysis.coverage import CoverageReport
from surinort_ast.analysis.findings import (
    FindingLevel,
    _coverage_severity_to_level,
    _diagnostic_level_to_finding,
    coverage_report_to_findings,
    optimization_results_to_findings,
)
from surinort_ast.analysis.optimizer import OptimizationResult
from surinort_ast.analysis.strategies import Optimization
from surinort_ast.core.diagnostics import DiagnosticLevel


def _empty_coverage_report() -> CoverageReport:
    return CoverageReport(
        total_rules=3,
        protocol_distribution={},
        port_coverage={},
        common_ports_uncovered=[],
        direction_distribution={},
        action_distribution={},
        content_types={},
    )


class TestLevelMappers:
    def test_info_diagnostic_maps_to_note(self):
        assert _diagnostic_level_to_finding(DiagnosticLevel.INFO) == FindingLevel.NOTE

    def test_low_coverage_severity_maps_to_note(self):
        assert _coverage_severity_to_level("low") == FindingLevel.NOTE


class TestCoverageFindings:
    def test_no_gaps_produces_ok_finding(self):
        findings = coverage_report_to_findings(_empty_coverage_report())

        assert len(findings) == 1
        assert findings[0].rule_id == "SURINORT_COVERAGE_OK"


class TestOptimizationFindings:
    def test_optimization_produces_finding(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
        result = OptimizationResult(
            original=rule,
            optimized=rule,
            optimizations=[
                Optimization(
                    strategy="FastPattern",
                    description="add fast_pattern",
                    estimated_gain=12.5,
                    before="before",
                    after="after",
                )
            ],
            total_improvement=12.5,
            was_modified=True,
        )

        findings = optimization_results_to_findings([result])

        assert len(findings) == 1
        assert findings[0].rule_id.startswith("SURINORT_OPTIMIZER_")
        assert findings[0].level == FindingLevel.NOTE

    def test_no_optimizations_produces_no_changes_finding(self):
        findings = optimization_results_to_findings([])

        assert len(findings) == 1
        assert findings[0].rule_id == "SURINORT_OPTIMIZER_NO_CHANGES"
