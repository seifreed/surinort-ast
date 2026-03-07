"""CLI SARIF output tests without mocks."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from surinort_ast.cli.main import app

runner = CliRunner()


def _extract_json(text: str) -> dict[str, object]:
    start = text.find("{")
    end = text.rfind("}")
    return json.loads(text[start : end + 1])


def test_parse_format_sarif(tmp_path) -> None:
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n', encoding="utf-8")

    result = runner.invoke(app, ["parse", str(rules_file), "--format", "sarif"])

    assert result.exit_code == 0
    payload = _extract_json(result.output)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "surinort-ast"


def test_parse_sarif_out_keeps_text_mode(tmp_path) -> None:
    rules_file = tmp_path / "rules.rules"
    sarif_file = tmp_path / "results.sarif"
    rules_file.write_text('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n', encoding="utf-8")

    result = runner.invoke(app, ["parse", str(rules_file), "--sarif-out", str(sarif_file)])

    assert result.exit_code == 0
    assert "Successfully parsed" in result.output
    payload = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert payload["runs"][0]["results"]


def test_validate_format_sarif_contains_warning(tmp_path) -> None:
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text('alert tcp any any -> any 80 (msg:"HTTP";)\n', encoding="utf-8")

    result = runner.invoke(app, ["validate", str(rules_file), "--format", "sarif"])

    assert result.exit_code == 0
    payload = _extract_json(result.output)
    results = payload["runs"][0]["results"]
    assert any(item["ruleId"] == "SURINORT_MISSING_SID" for item in results)


def test_stats_format_sarif(tmp_path) -> None:
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text(
        'alert tcp any any -> any 80 (msg:"A"; sid:1;)\n'
        'alert tcp any any -> any 443 (msg:"B"; sid:2;)\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["stats", str(rules_file), "--format", "sarif"])

    assert result.exit_code == 0
    payload = _extract_json(result.output)
    assert payload["runs"][0]["tool"]["driver"]["name"] == "surinort-ast"
