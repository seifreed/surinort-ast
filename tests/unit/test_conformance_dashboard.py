import json

from tools.conformance_dashboard import render


def test_dashboard_renders_single_and_engine_reports(tmp_path) -> None:
    history = tmp_path / "history"
    history.mkdir()
    (history / "bundled.json").write_text(
        json.dumps(
            {
                "total_rules": 2,
                "package_version": "4.0.0",
                "dialect_metrics": {
                    "suricata": {
                        "total_rules": 2,
                        "parsed": 2,
                        "round_trip_passed": 2,
                        "unexpected_failures": 0,
                    }
                },
                "parse_rate": 1.0,
                "round_trip_rate": 1.0,
                "unexpected_failures": 0,
                "parse_exceptions": 1,
                "errors_by_keyword": {"content": 1},
                "rules_per_second": 10,
                "peak_memory_mb": 2,
                "dialects": ["suricata"],
            }
        ),
        encoding="utf-8",
    )
    current = tmp_path / "matrix.json"
    current.write_text(
        json.dumps(
            {
                "engines": [
                    {
                        "id": "suricata-test",
                        "version": "8.0.1",
                        "report": {
                            "total_rules": 1,
                            "parse_rate": 1.0,
                            "round_trip_rate": 1.0,
                            "unexpected_failures": 0,
                            "rules_per_second": 5,
                            "peak_memory_mb": 1,
                            "dialects": ["suricata"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (history / "optimizer.json").write_text(
        json.dumps({"kind": "optimizer-behavior-conformance", "pcap_count": 2}),
        encoding="utf-8",
    )
    output = tmp_path / "dashboard.md"

    rendered = render(history, output, current)

    assert rendered.count("| bundled.json |") == 1
    assert rendered.count("| 4.0.0 |") == 1
    assert rendered.count("| suricata |") == 2
    assert rendered.count("| 8.0.1 |") == 1
    assert rendered.count("| matrix.json:suricata-test |") == 1
    assert "optimizer.json" not in rendered
    assert "| 1 | content:1 |" in rendered
    assert output.read_text(encoding="utf-8") == rendered
