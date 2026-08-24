import json
import sys

from typer.testing import CliRunner

from surinort_ast.cli.main import app

RULE = 'alert tcp any any -> any 80 (pcre:"/test/"; content:"test"; sid:1;)\n'


def test_optimize_defaults_to_suggestions(tmp_path) -> None:
    source = tmp_path / "rules.rules"
    source.write_text(RULE, encoding="utf-8")

    result = CliRunner().invoke(app, ["optimize", str(source), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)[0]["experimental"] is True
    assert source.read_text(encoding="utf-8") == RULE


def test_optimize_apply_requires_engine_and_verifies_before_write(tmp_path) -> None:
    source = tmp_path / "rules.rules"
    target = tmp_path / "optimized.rules"
    source.write_text(RULE, encoding="utf-8")
    command = f'{sys.executable} -c "import sys; sys.exit(0)" {{file}}'

    result = CliRunner().invoke(
        app,
        [
            "optimize",
            str(source),
            "--apply",
            "--output",
            str(target),
            "--engine-command",
            command,
        ],
    )

    assert result.exit_code == 0
    assert target.exists()
    assert "engine_verified" not in result.stdout


def test_optimize_apply_rejects_missing_verification(tmp_path) -> None:
    source = tmp_path / "rules.rules"
    target = tmp_path / "optimized.rules"
    source.write_text(RULE, encoding="utf-8")

    result = CliRunner().invoke(app, ["optimize", str(source), "--apply", "--output", str(target)])

    assert result.exit_code == 1
    assert not target.exists()
