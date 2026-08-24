import json

from typer.testing import CliRunner

from surinort_ast.cli.main import app


def test_diff_command_reports_semantic_changes(tmp_path) -> None:
    before = tmp_path / "before.rules"
    after = tmp_path / "after.rules"
    before.write_text('alert tcp any any -> any 80 (content:"GET"; sid:1;)\n', encoding="utf-8")
    after.write_text('alert tcp any any -> any 443 (content:"POST"; sid:1;)\n', encoding="utf-8")

    result = CliRunner().invoke(app, ["diff", str(before), str(after), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["sid"] == 1
    assert data["changed"] is True
    assert "dst_port: changed" in data["header_changes"]
