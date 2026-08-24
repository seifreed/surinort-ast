from typer.testing import CliRunner

from surinort_ast.cli.main import app


def test_validate_accepts_multiple_rule_files(tmp_path) -> None:
    first = tmp_path / "first.rules"
    second = tmp_path / "second.rules"
    first.write_text('alert tcp any any -> any 80 (msg:"one"; sid:1; rev:1;)\n')
    second.write_text('alert tcp any any -> any 443 (msg:"two"; sid:2; rev:1;)\n')

    result = CliRunner().invoke(app, ["validate", str(first), str(second)])

    assert result.exit_code == 0
    assert "Total rules: 2" in result.output
