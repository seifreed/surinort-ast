import json

from tools.conformance_dashboard import render


def test_dashboard_renders_single_and_engine_reports(tmp_path) -> None:
    history = tmp_path / "history"
    history.mkdir()
    (history / "bundled.json").write_text(
        json.dumps(
            {
                "total_rules": 2,
                "parse_rate": 1.0,
                "round_trip_rate": 1.0,
                "unexpected_failures": 0,
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
    output = tmp_path / "dashboard.md"

    rendered = render(history, output, current)

    assert rendered.count("| bundled.json |") == 1
    assert rendered.count("| matrix.json:suricata-test |") == 1
    assert output.read_text(encoding="utf-8") == rendered
