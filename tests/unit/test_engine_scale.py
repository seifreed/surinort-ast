import json
import sys
from pathlib import Path

from tools.engine_scale import run


def test_engine_scale_validates_one_combined_ruleset(tmp_path: Path) -> None:
    rules = tmp_path / "rules.rules"
    rules.write_text('alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"files": [{"path": "rules.rules", "dialect": "suricata"}]}),
        encoding="utf-8",
    )

    report = run(manifest, f"{sys.executable} -c pass {{file}}")

    assert report["total_rules"] == 1
    assert report["parse_rate"] == 1.0
    assert report["engine_validation_passed"] == 1
    assert report["engine_validation_after_print_passed"] == 1
    assert report["unexpected_failures"] == 0


def test_engine_scale_marks_parse_failures_unexpected(tmp_path: Path) -> None:
    rules = tmp_path / "rules.rules"
    rules.write_text("not a rule\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"files": [{"path": "rules.rules", "dialect": "suricata"}]}),
        encoding="utf-8",
    )

    report = run(manifest, f"{sys.executable} -c pass {{file}}")

    assert report["parse_exceptions"] == 1
    assert report["unexpected_failures"] == 1
