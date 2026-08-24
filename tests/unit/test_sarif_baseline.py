import json
from pathlib import Path

from tools.sarif_baseline import findings


def _write(path: Path, message: str, uri: str = "rules.rules") -> None:
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "missing_msg",
                                "message": {"text": message},
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def test_baseline_key_ignores_line_location(tmp_path: Path) -> None:
    current = tmp_path / "current.sarif"
    baseline = tmp_path / "baseline.sarif"
    _write(current, "Missing msg", "rules.rules")
    _write(baseline, "Missing msg", "rules.rules")

    assert findings(current) == findings(baseline)
