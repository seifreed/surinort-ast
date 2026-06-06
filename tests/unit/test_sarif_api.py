"""
Tests for SARIF API serialization.

This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

import json

from surinort_ast import parse_rule, validate_rule
from surinort_ast.analysis import CoverageAnalyzer, RuleOptimizer
from surinort_ast.api import (
    coverage_report_to_sarif,
    diagnostics_to_sarif,
    optimization_results_to_sarif,
    to_sarif,
)
from surinort_ast.core.diagnostics import Diagnostic
from surinort_ast.core.enums import DiagnosticLevel
from surinort_ast.core.location import Location, Position, Span


def _extract_json(text: str) -> dict[str, object]:
    start = text.find("{")
    end = text.rfind("}")
    return json.loads(text[start : end + 1])


def test_diagnostics_to_sarif_has_required_fields() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP";)')
    diagnostics = validate_rule(rule)

    sarif_text = diagnostics_to_sarif(diagnostics)
    payload = _extract_json(sarif_text)

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "surinort-ast"
    assert len(run["results"]) >= 1

    first = run["results"][0]
    assert first["ruleId"].startswith("SURINORT_")
    assert first["level"] in {"error", "warning", "note"}
    assert "text" in first["message"]


def test_to_sarif_includes_locations_and_stable_fingerprints() -> None:
    diag = Diagnostic(
        level=DiagnosticLevel.ERROR,
        message="Parse failure",
        code="parse_error",
        location=Location(
            file_path="rules/test.rules",
            span=Span(
                start=Position(line=3, column=4, offset=42),
                end=Position(line=3, column=12, offset=50),
            ),
        ),
    )

    sarif_1 = _extract_json(to_sarif([]))
    assert sarif_1["runs"][0]["results"] == []

    payload_a = _extract_json(diagnostics_to_sarif([diag]))
    payload_b = _extract_json(diagnostics_to_sarif([diag]))

    result_a = payload_a["runs"][0]["results"][0]
    result_b = payload_b["runs"][0]["results"][0]
    assert (
        result_a["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "rules/test.rules"
    )
    assert result_a["partialFingerprints"] == result_b["partialFingerprints"]


def test_coverage_report_to_sarif_contract() -> None:
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"A"; sid:1;)'),
        parse_rule('alert udp any any -> any 53 (msg:"B"; sid:2;)'),
    ]
    report = CoverageAnalyzer().analyze(rules)

    payload = _extract_json(coverage_report_to_sarif(report))
    run = payload["runs"][0]
    assert run["tool"]["driver"]["version"]
    assert len(run["results"]) >= 1


def test_optimizer_results_to_sarif_contract() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"X"; sid:10; rev:1;)')
    result = RuleOptimizer().optimize(rule)

    payload = _extract_json(optimization_results_to_sarif([result]))
    run = payload["runs"][0]
    assert len(run["results"]) >= 1
    assert run["results"][0]["level"] in {"error", "warning", "note"}


def test_finding_with_empty_location_omits_physical_location() -> None:
    """A location with neither file nor line must not emit an empty object."""
    from surinort_ast.analysis.findings import Finding, FindingLevel, FindingLocation
    from surinort_ast.serialization.sarif import to_sarif_log

    finding = Finding(
        rule_id="R1",
        level=FindingLevel.ERROR,
        message="m",
        category="c",
        location=FindingLocation(),
    )
    result = to_sarif_log([finding])["runs"][0]["results"][0]
    # No usable physical location -> the locations array is omitted entirely,
    # never "[{'physicalLocation': {}}]" (invalid per SARIF 2.1.0).
    assert "locations" not in result or result["locations"] == []


def test_finding_with_line_only_keeps_region() -> None:
    from surinort_ast.analysis.findings import Finding, FindingLevel, FindingLocation
    from surinort_ast.serialization.sarif import to_sarif_log

    finding = Finding(
        rule_id="R2",
        level=FindingLevel.ERROR,
        message="m",
        category="c",
        location=FindingLocation(start_line=5),
    )
    result = to_sarif_log([finding])["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["region"]["startLine"] == 5
