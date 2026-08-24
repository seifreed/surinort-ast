from surinort_ast import parse_rule
from surinort_ast.analysis import CoverageAnalyzer, RuleOptimizer
from surinort_ast.analysis.findings import (
    coverage_report_to_findings,
    optimization_results_to_findings,
)


def test_coverage_report_marks_heuristic_evidence() -> None:
    report = CoverageAnalyzer().analyze(
        [parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')]
    )

    assert report.experimental is True
    assert report.confidence == "low"
    assert report.engine_verified is False
    assert report.to_dict()["experimental"] is True
    assert coverage_report_to_findings(report)[0].properties["confidence"] == "low"


def test_optimizer_findings_disclose_unverified_estimates() -> None:
    rule = parse_rule('alert tcp any any -> any 80 (pcre:"/x/"; content:"x"; msg:"x"; sid:1;)')
    result = RuleOptimizer().optimize(rule)

    findings = optimization_results_to_findings([result])
    if result.optimizations:
        assert "engine verification is required" in (findings[0].help_text or "")
        assert findings[0].properties["experimental"] is True
        assert result.estimated_cost_class in {"A", "B", "C", "D"}
        assert result.evidence
