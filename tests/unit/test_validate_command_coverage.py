# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for the ``validate`` CLI command.

Targets the Lua-script-existence checks, the SARIF finding paths (lua warning
and the no-diagnostics note), and the SARIF-out-plus-text fallback. The
path-traversal branch in _check_lua_scripts is exercised directly because the
grammar forbids separators in Lua script names, so it cannot be reached by
parsing a real rule.
"""

from pathlib import Path

from typer.testing import CliRunner

from surinort_ast import parse_rule
from surinort_ast.cli.commands.validate import _check_lua_scripts
from surinort_ast.cli.main import app
from surinort_ast.core.nodes import LuaOption

runner = CliRunner()

_LUA_RULE = 'alert tcp any any -> any 80 (msg:"lua"; lua:check.lua; sid:1; rev:1;)\n'
_CLEAN_RULE = 'alert tcp any any -> any 80 (msg:"ok"; sid:1; rev:1;)\n'


def _write(tmp_path: Path, text: str) -> Path:
    rules_file = tmp_path / "rules.rules"
    rules_file.write_text(text, encoding="utf-8")
    return rules_file


class TestLuaScriptChecks:
    def test_missing_lua_script_reported(self, tmp_path):
        """A referenced Lua script absent from --lua-dir surfaces as a warning."""
        rules_file = _write(tmp_path, _LUA_RULE)
        lua_dir = tmp_path / "lua"
        lua_dir.mkdir()

        result = runner.invoke(app, ["validate", str(rules_file), "--lua-dir", str(lua_dir)])

        assert "Lua Script Checks" in result.output
        assert "check.lua" in result.output

    def test_present_lua_script_not_reported(self, tmp_path):
        """When the script exists under --lua-dir no warning is produced."""
        rules_file = _write(tmp_path, _LUA_RULE)
        lua_dir = tmp_path / "lua"
        lua_dir.mkdir()
        (lua_dir / "check.lua").write_text("-- noop\n", encoding="utf-8")

        result = runner.invoke(app, ["validate", str(rules_file), "--lua-dir", str(lua_dir)])

        assert "Lua script not found" not in result.output

    def test_traversal_script_name_rejected(self, tmp_path):
        """A Lua script name escaping the base directory is flagged, not read."""
        lua_dir = tmp_path / "lua"
        lua_dir.mkdir()
        base = parse_rule(_CLEAN_RULE.strip())
        rule = base.model_copy(update={"options": [LuaOption(script_name="../../../etc/passwd")]})

        warnings = _check_lua_scripts([rule], lua_dir)

        assert len(warnings) == 1
        assert "Invalid Lua script path" in warnings[0][1]

    def test_no_lua_dir_skips_checks(self, tmp_path):
        """Without --lua-dir, no Lua checks run."""
        base = parse_rule(_CLEAN_RULE.strip())
        rule = base.model_copy(update={"options": [LuaOption(script_name="x.lua")]})

        assert _check_lua_scripts([rule], None) == []


class TestSarifOutput:
    def test_clean_rule_emits_validation_ok_note(self, tmp_path):
        """A clean rule in SARIF format yields the no-diagnostics note."""
        rules_file = _write(tmp_path, _CLEAN_RULE)

        result = runner.invoke(app, ["validate", str(rules_file), "--format", "sarif"])

        assert result.exit_code == 0
        assert "SURINORT_VALIDATION_OK" in result.output

    def test_lua_warning_appears_in_sarif(self, tmp_path):
        """A missing Lua script becomes a SARIF finding."""
        rules_file = _write(tmp_path, _LUA_RULE)
        lua_dir = tmp_path / "lua"
        lua_dir.mkdir()

        result = runner.invoke(
            app,
            ["validate", str(rules_file), "--lua-dir", str(lua_dir), "--format", "sarif"],
        )

        assert "SURINORT_LUA_SCRIPT_NOT_FOUND" in result.output

    def test_sarif_out_with_text_format_writes_file_and_text(self, tmp_path):
        """--sarif-out with default text format writes SARIF and prints the summary."""
        rules_file = _write(tmp_path, _CLEAN_RULE)
        sarif_file = tmp_path / "report.sarif"

        result = runner.invoke(app, ["validate", str(rules_file), "--sarif-out", str(sarif_file)])

        assert result.exit_code == 0
        assert sarif_file.exists()
        assert "Total rules:" in result.output
        assert "SARIF report written" in result.output
