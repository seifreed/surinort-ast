from pathlib import Path

from surinort_ast import parse_rule
from surinort_ast.analysis import CoverageAnalyzer, RulesetContext


def test_suricata_variables_resolve_port_groups(tmp_path: Path) -> None:
    config = tmp_path / "suricata.yaml"
    config.write_text(
        'vars:\n  port-groups:\n    HTTP_PORTS: "80,443"\n',
        encoding="utf-8",
    )

    context = RulesetContext.from_suricata_yaml(config)
    report = CoverageAnalyzer(context).analyze(
        [parse_rule('alert tcp any any -> any $HTTP_PORTS (msg:"http"; sid:1;)')]
    )

    assert context.resolve("HTTP_PORTS") == "80,443"
    assert 80 in report.port_coverage
    assert 443 in report.port_coverage
    assert report.confidence == "medium"


def test_snort_variables_support_ranges(tmp_path: Path) -> None:
    config = tmp_path / "snort.conf"
    config.write_text("portvar WEB_PORTS [80:443]\n", encoding="utf-8")

    context = RulesetContext.from_snort_config(config)

    assert context.resolve_port_intervals("WEB_PORTS") == [(80, 443)]


def test_unresolved_port_variable_is_reported_as_indeterminate() -> None:
    report = CoverageAnalyzer().analyze(
        [parse_rule('alert tcp any any -> any $UNKNOWN (msg:"x"; sid:1;)')]
    )

    assert "$UNKNOWN" in report.indeterminate_ports
    assert "$UNKNOWN" in report.to_dict()["indeterminate_ports"]
