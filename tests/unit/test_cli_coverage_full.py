# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for the five CLI command modules that had incomplete branch/line
coverage.  This single file is intended to achieve 100 % line+branch coverage
on its own when run with the ``--cov`` flags pointing at those five modules.

Modules targeted:
    cli/commands/conflicts.py
    cli/commands/schema.py
    cli/commands/from_json.py
    cli/commands/parse.py
    cli/commands/format.py

Structurally unreachable arcs (cannot be covered without mocking or refactoring):
    format.py 130->exit  — the False arm of ``if not check:`` at line 130 is only
                           reachable when ``check=True`` at that point, but
                           ``_handle_check_mode`` always raises ``typer.Exit``
                           before execution reaches line 130 when check=True.
    schema.py line 45    — the ``raise`` inside ``except typer.Exit: raise`` is
                           only reached when something in the try-block raises
                           ``typer.Exit``, but neither ``to_json_schema()``,
                           ``json.dumps()``, nor ``write_output()`` can raise it.

Every test uses real production code through the Typer CliRunner or by calling
module-level helpers directly.  No mocks, stubs, or patch decorators are used.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from surinort_ast import parse_rule
from surinort_ast import to_json as api_to_json
from surinort_ast.cli.commands.format import _handle_check_mode, _handle_in_place_mode
from surinort_ast.cli.commands.from_json import _flatten_loaded
from surinort_ast.cli.commands.parse import (
    _build_parse_findings,
    _emit_parse_sarif,
    _format_output,
    _parse_stdin_rules,
    _resolve_output_format,
)
from surinort_ast.cli.main import app
from surinort_ast.core.diagnostics import Diagnostic
from surinort_ast.core.enums import Action, DiagnosticLevel, Dialect, Direction, Protocol
from surinort_ast.core.nodes import AnyAddress, AnyPort, Header, Rule

_VALID_RULE = 'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'
_VALID_RULE_2 = 'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)'


def _rule_dict():  # return type omitted: json.loads returns Any
    """Return a well-formed rule dict suitable for from-json input."""
    rule = parse_rule(_VALID_RULE)
    return json.loads(api_to_json(rule))


def _make_rule_with_diagnostic() -> Rule:
    """Return a Rule carrying one WARNING diagnostic."""
    return Rule(
        action=Action.ALERT,
        header=Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        ),
        options=(),
        diagnostics=(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message="missing rev option",
                code="W001",
            ),
        ),
        dialect=Dialect.SURICATA,
    )


# ---------------------------------------------------------------------------
# conflicts.py
# ---------------------------------------------------------------------------


class TestConflictsCommand:
    """Full branch coverage for cli/commands/conflicts.py."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_default_text_format(self, tmp_path: Path) -> None:
        """Default output renders the text conflict report (line 61)."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n" + _VALID_RULE_2 + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["conflicts", str(rules_file)])

        assert result.exit_code == 0
        # to_text always emits "Rules analyzed"
        assert "Rules analyzed" in result.output or "Conflict" in result.output

    def test_json_format(self, tmp_path: Path) -> None:
        """--format json renders ``report.to_json()`` (line 57)."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n" + _VALID_RULE_2 + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["conflicts", str(rules_file), "--format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "conflicts" in data or "rules_analyzed" in data

    def test_markdown_format(self, tmp_path: Path) -> None:
        """--format markdown renders ``report.to_markdown()`` (line 59)."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n" + _VALID_RULE_2 + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["conflicts", str(rules_file), "--format", "markdown"])

        assert result.exit_code == 0
        assert "# Conflict Report" in result.output

    def test_parse_error_branch(self, tmp_path: Path) -> None:
        """Malformed file → ParseError → lines 65-67."""
        bad = tmp_path / "bad.rules"
        bad.write_text("not a valid rule\n", encoding="utf-8")

        result = self.runner.invoke(app, ["conflicts", str(bad)])

        assert result.exit_code == 1
        assert "Parse error" in result.output

    def test_generic_exception_branch(self) -> None:
        """Non-existent file → FileNotFoundError → lines 68-70."""
        result = self.runner.invoke(app, ["conflicts", "/no/such/file.rules"])

        assert result.exit_code == 1
        assert "Unexpected error" in result.output


# ---------------------------------------------------------------------------
# schema.py
# ---------------------------------------------------------------------------


class TestSchemaCommand:
    """Full branch coverage for cli/commands/schema.py."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_stdout_success(self) -> None:
        """schema command prints JSON schema to stdout and a success status (line 42)."""
        result = self.runner.invoke(app, ["schema"])

        assert result.exit_code == 0
        assert "Generated JSON Schema" in result.output
        # stdout must contain valid JSON schema
        assert '"$defs"' in result.output or '"definitions"' in result.output

    def test_output_file_success(self, tmp_path: Path) -> None:
        """schema --output writes schema to file and prints success (line 42)."""
        out = tmp_path / "schema.json"

        result = self.runner.invoke(app, ["schema", "--output", str(out)])

        assert result.exit_code == 0
        assert out.exists()
        schema = json.loads(out.read_text(encoding="utf-8"))
        assert "$defs" in schema or "definitions" in schema

    def test_exception_handler_on_bad_output_path(self) -> None:
        """Bad output directory → FileNotFoundError → lines 46-48."""
        result = self.runner.invoke(
            app, ["schema", "--output", "/no_such_dir_schema_test/out.json"]
        )

        assert result.exit_code == 1
        assert "Error:" in result.output


# ---------------------------------------------------------------------------
# from_json.py
# ---------------------------------------------------------------------------


class TestFromJsonHelpers:
    """Direct tests for _flatten_loaded to cover branch at line 26."""

    def test_non_list_items_yield_directly(self) -> None:
        """Non-list items take the ``else: yield item`` path (line 28)."""
        items = [object(), object()]
        result = list(_flatten_loaded(iter(items)))
        assert result == items

    def test_list_items_are_flattened(self) -> None:
        """List items take the ``yield from item`` path (line 26)."""
        inner = [1, 2, 3]
        result = list(_flatten_loaded(iter([inner])))
        assert result == [1, 2, 3]

    def test_mixed_items(self) -> None:
        """A mix of list and non-list items exercises both branches."""
        sentinel = object()
        result = list(_flatten_loaded(iter([[1, 2], sentinel])))
        assert result == [1, 2, sentinel]


class TestFromJsonCommand:
    """Full branch coverage for cli/commands/from_json.py."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_rules_envelope_format(self, tmp_path: Path) -> None:
        """``{"rules": [...]}`` envelope is split before calling from_json (line 65)."""
        json_file = tmp_path / "rules.json"
        json_file.write_text(json.dumps({"rules": [_rule_dict()]}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        assert result.exit_code == 0
        assert "Converted 1 rule(s) from JSON" in result.output

    def test_list_format(self, tmp_path: Path) -> None:
        """Top-level JSON array is used as rules_data directly (line 67)."""
        json_file = tmp_path / "rules.json"
        json_file.write_text(json.dumps([_rule_dict()]), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        assert result.exit_code == 0
        assert "Converted 1 rule(s) from JSON" in result.output

    def test_single_rule_dict_format(self, tmp_path: Path) -> None:
        """A bare rule dict is wrapped in a list (line 70)."""
        json_file = tmp_path / "rule.json"
        json_file.write_text(json.dumps(_rule_dict()), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        assert result.exit_code == 0

    def test_stdin_dash_argument(self) -> None:
        """Passing ``-`` as file argument reads from stdin (line 57)."""
        result = self.runner.invoke(app, ["from-json", "-"], input=json.dumps(_rule_dict()))

        assert result.exit_code == 0
        assert "Converted 1 rule(s) from JSON" in result.output

    def test_stable_flag(self, tmp_path: Path) -> None:
        """--stable flag passes through to print_rule."""
        json_file = tmp_path / "r.json"
        json_file.write_text(json.dumps({"rules": [_rule_dict()]}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file), "--stable"])

        assert result.exit_code == 0

    def test_output_file(self, tmp_path: Path) -> None:
        """--output writes converted rules to a file."""
        json_file = tmp_path / "r.json"
        out_file = tmp_path / "out.rules"
        json_file.write_text(json.dumps({"rules": [_rule_dict()]}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file), "--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()

    def test_empty_rules_error(self, tmp_path: Path) -> None:
        """Empty rules list → lines 76-77 (no valid rules error exit)."""
        json_file = tmp_path / "empty.json"
        json_file.write_text(json.dumps({"rules": []}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        assert result.exit_code == 1
        assert "No valid rules found" in result.output

    def test_json_decode_error(self, tmp_path: Path) -> None:
        """Invalid JSON → lines 90-91."""
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json}", encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(bad)])

        assert result.exit_code == 1
        assert "JSON decode error" in result.output

    def test_serialization_error(self, tmp_path: Path) -> None:
        """Structurally invalid rule dict → lines 93-94."""
        bad = tmp_path / "bad_rule.json"
        bad.write_text(json.dumps({"rules": [{"action": "alert"}]}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(bad)])

        assert result.exit_code == 1

    def test_typer_exit_re_raised(self, tmp_path: Path) -> None:
        """Empty rules raises typer.Exit → caught by lines 95-96 and re-raised."""
        json_file = tmp_path / "empty.json"
        json_file.write_text(json.dumps({"rules": []}), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        # typer.Exit(1) propagates without being wrapped in an Unexpected error
        assert result.exit_code == 1
        assert "Unexpected error" not in result.output

    def test_flatten_loaded_list_item_via_cli(self, tmp_path: Path) -> None:
        """
        Top-level list containing a ``{"rules": [...]}`` envelope causes
        ``from_json`` to return a Sequence[Rule] (list), exercising the
        ``yield from item`` path (line 26) in ``_flatten_loaded``.
        """
        json_input = [{"rules": [_rule_dict(), _rule_dict()]}]
        json_file = tmp_path / "nested.json"
        json_file.write_text(json.dumps(json_input), encoding="utf-8")

        result = self.runner.invoke(app, ["from-json", str(json_file)])

        assert result.exit_code == 0
        assert "Converted 2 rule(s) from JSON" in result.output

    def test_generic_exception_branch(self, tmp_path: Path) -> None:
        """Bad output path → FileNotFoundError → lines 97-99."""
        json_file = tmp_path / "r.json"
        json_file.write_text(json.dumps({"rules": [_rule_dict()]}), encoding="utf-8")

        result = self.runner.invoke(
            app, ["from-json", str(json_file), "--output", "/no_dir_fj/out.rules"]
        )

        assert result.exit_code == 1
        assert "Unexpected error" in result.output


# ---------------------------------------------------------------------------
# parse.py — helper functions
# ---------------------------------------------------------------------------


class TestParseHelpers:
    """Direct tests for parse.py module-level helpers."""

    def test_parse_stdin_rules_valid(self) -> None:
        """_parse_stdin_rules parses valid rules from content string."""
        rules = _parse_stdin_rules(_VALID_RULE + "\n", Dialect.SURICATA, verbose=False)

        assert len(rules) == 1

    def test_parse_stdin_rules_invalid_line_skipped(self) -> None:
        """Invalid lines are skipped (no on_error callback, verbose=False)."""
        rules = _parse_stdin_rules("not a rule\n", Dialect.SURICATA, verbose=False)

        assert rules == []

    def test_parse_stdin_rules_verbose_long_line_via_cli(self) -> None:
        """Lines 40-41 are covered when --verbose is used with >50-char bad stdin."""
        runner = CliRunner()
        long_bad = "x" * 51
        result = runner.invoke(app, ["parse", "-", "--verbose"], input=long_bad + "\n")

        assert result.exit_code == 1
        assert "Warning:" in result.output
        # Truncated output marker
        warning_text = result.output.split("Warning:")[1].split("\n")[0]
        assert "..." in warning_text

    def test_parse_stdin_rules_verbose_short_line_via_cli(self) -> None:
        """_warn with short line (<=50 chars) takes the non-truncation branch."""
        runner = CliRunner()
        short_bad = "bad rule"  # 8 chars < 50
        result = runner.invoke(app, ["parse", "-", "--verbose"], input=short_bad + "\n")

        assert result.exit_code == 1
        assert "Warning:" in result.output

    def test_format_output_text_no_verbose(self) -> None:
        """_format_output returns a summary string without rule bodies."""
        rule = parse_rule(_VALID_RULE)
        output = _format_output([rule], json_output=False, dialect=Dialect.SURICATA, verbose=False)

        assert "1 rule(s)" in output
        # No rule body (verbose=False)
        assert "[Rule 1]" not in output

    def test_format_output_text_verbose(self) -> None:
        """_format_output includes rule bodies when verbose=True."""
        rule = parse_rule(_VALID_RULE)
        output = _format_output([rule], json_output=False, dialect=Dialect.SURICATA, verbose=True)

        assert "[Rule 1]" in output

    def test_format_output_json(self) -> None:
        """_format_output returns valid JSON when json_output=True."""
        rule = parse_rule(_VALID_RULE)
        output = _format_output([rule], json_output=True, dialect=Dialect.SURICATA, verbose=False)

        data = json.loads(output)
        assert data["count"] == 1
        assert data["dialect"] == "suricata"

    def test_build_parse_findings_no_diagnostics(self) -> None:
        """When no diagnostics exist the fallback SURINORT_PARSE_SUCCESS is appended."""
        rule = parse_rule(_VALID_RULE)
        findings = _build_parse_findings([rule], file_path=None)

        assert len(findings) == 1
        assert findings[0].rule_id == "SURINORT_PARSE_SUCCESS"

    def test_build_parse_findings_with_diagnostics(self) -> None:
        """When diagnostics exist the fallback block is skipped (73->83 arc)."""
        rule = _make_rule_with_diagnostic()
        findings = _build_parse_findings([rule], file_path="/test.rules")

        assert len(findings) == 1
        assert findings[0].rule_id == "SURINORT_W001"
        assert not any(f.rule_id == "SURINORT_PARSE_SUCCESS" for f in findings)

    def test_resolve_output_format_json_flag_overrides(self) -> None:
        """When json_output=True, fmt is forced to 'json' regardless of --format."""
        fmt = _resolve_output_format("text", json_output=True)
        assert fmt == "json"

    def test_resolve_output_format_text(self) -> None:
        """When json_output=False, the --format value passes through."""
        fmt = _resolve_output_format("text", json_output=False)
        assert fmt == "text"

    def test_resolve_output_format_sarif(self) -> None:
        """--format sarif returns 'sarif'."""
        fmt = _resolve_output_format("sarif", json_output=False)
        assert fmt == "sarif"

    def test_emit_parse_sarif_no_sarif(self) -> None:
        """_emit_parse_sarif returns False when neither --format sarif nor --sarif-out."""
        rule = parse_rule(_VALID_RULE)
        emitted = _emit_parse_sarif([rule], file=None, output=None, fmt="text", sarif_out=None)

        assert emitted is False

    def test_emit_parse_sarif_sarif_format(self, tmp_path: Path) -> None:
        """_emit_parse_sarif returns True and writes output when fmt='sarif'."""
        rule = parse_rule(_VALID_RULE)
        out_file = tmp_path / "out.sarif"

        emitted = _emit_parse_sarif([rule], file=None, output=out_file, fmt="sarif", sarif_out=None)

        assert emitted is True
        assert out_file.exists()
        sarif = json.loads(out_file.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"

    def test_emit_parse_sarif_sarif_out_file(self, tmp_path: Path) -> None:
        """_emit_parse_sarif writes to sarif_out when provided even if fmt != 'sarif'."""
        rule = parse_rule(_VALID_RULE)
        sarif_file = tmp_path / "report.sarif"

        emitted = _emit_parse_sarif(
            [rule], file=None, output=None, fmt="text", sarif_out=sarif_file
        )

        assert emitted is False  # fmt is "text", so SARIF is not primary output
        assert sarif_file.exists()


# ---------------------------------------------------------------------------
# parse.py — full command paths
# ---------------------------------------------------------------------------


class TestParseCommand:
    """Full branch coverage for the parse_command entry point."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_file_text_output(self, tmp_path: Path) -> None:
        """Parsing a file with default text output (line 162 + 172-180)."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["parse", str(rules_file)])

        assert result.exit_code == 0
        assert "Parsed 1 rule(s)" in result.output

    def test_file_json_output(self, tmp_path: Path) -> None:
        """--json flag switches to JSON output format."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["parse", str(rules_file), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["count"] == 1

    def test_file_verbose_output(self, tmp_path: Path) -> None:
        """--verbose includes rule bodies in text output."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["parse", str(rules_file), "--verbose"])

        assert result.exit_code == 0
        assert "[Rule 1]" in result.output

    def test_stdin_dash_argument(self) -> None:
        """``-`` as file arg switches to stdin mode (line 154->157)."""
        result = self.runner.invoke(app, ["parse", "-"], input=_VALID_RULE + "\n")

        assert result.exit_code == 0
        assert "Parsed 1 rule(s)" in result.output

    def test_stdin_verbose_short_bad_line(self) -> None:
        """Stdin with verbose + short bad line covers lines 40-41 (_warn short)."""
        bad = "bad rule"
        result = self.runner.invoke(app, ["parse", "-", "--verbose"], input=bad + "\n")

        assert result.exit_code == 1

    def test_stdin_verbose_long_bad_line(self) -> None:
        """Stdin with verbose + long bad line covers the truncation branch (line 40 else)."""
        long_bad = "b" * 51
        result = self.runner.invoke(app, ["parse", "-", "--verbose"], input=long_bad + "\n")

        assert result.exit_code == 1
        assert "..." in result.output

    def test_sarif_format_output(self, tmp_path: Path) -> None:
        """--format sarif produces a SARIF report as primary output."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")
        out = tmp_path / "out.sarif"

        result = self.runner.invoke(
            app, ["parse", str(rules_file), "--format", "sarif", "--output", str(out)]
        )

        assert result.exit_code == 0
        sarif = json.loads(out.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"

    def test_sarif_out_file(self, tmp_path: Path) -> None:
        """--sarif-out writes SARIF alongside the normal text output."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")
        sarif_file = tmp_path / "report.sarif"

        result = self.runner.invoke(app, ["parse", str(rules_file), "--sarif-out", str(sarif_file)])

        assert result.exit_code == 0
        assert sarif_file.exists()

    def test_no_valid_rules_error(self, tmp_path: Path) -> None:
        """Empty/comment-only file exits with code 1."""
        rules_file = tmp_path / "empty.rules"
        rules_file.write_text("# comment\n", encoding="utf-8")

        result = self.runner.invoke(app, ["parse", str(rules_file)])

        assert result.exit_code == 1
        assert "No valid rules found" in result.output

    def test_output_file(self, tmp_path: Path) -> None:
        """--output writes results to a file."""
        rules_file = tmp_path / "r.rules"
        out_file = tmp_path / "out.txt"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["parse", str(rules_file), "--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()


# ---------------------------------------------------------------------------
# format.py — helper functions
# ---------------------------------------------------------------------------


class TestFormatHelpers:
    """Direct tests for format.py helper functions (lines unreachable via CLI)."""

    def test_handle_check_mode_already_formatted(self, tmp_path: Path) -> None:
        """Identical content → raises typer.Exit(0) and prints 'already formatted'."""
        content = _VALID_RULE + "\n"
        with pytest.raises(typer.Exit) as exc_info:
            _handle_check_mode(content, content)
        assert exc_info.value.exit_code == 0

    def test_handle_check_mode_needs_formatting(self) -> None:
        """Different content → raises typer.Exit(1) and prints 'would be reformatted'."""
        with pytest.raises(typer.Exit) as exc_info:
            _handle_check_mode("original content", "different formatted content")
        assert exc_info.value.exit_code == 1

    def test_handle_in_place_mode_returns_none_when_disabled(self) -> None:
        """in_place=False → returns None (line 47)."""
        assert _handle_in_place_mode(None, False) is None
        assert _handle_in_place_mode(Path("/some/file.rules"), False) is None

    def test_handle_in_place_mode_returns_file_when_enabled(self, tmp_path: Path) -> None:
        """in_place=True with a valid file path → returns the path."""
        target = tmp_path / "r.rules"
        target.write_text(_VALID_RULE + "\n", encoding="utf-8")

        returned = _handle_in_place_mode(target, True)

        assert returned == target

    def test_handle_in_place_mode_stdin_error(self) -> None:
        """in_place=True with file=None → raises typer.Exit(1)."""
        with pytest.raises(typer.Exit) as exc_info:
            _handle_in_place_mode(None, True)
        assert exc_info.value.exit_code == 1


# ---------------------------------------------------------------------------
# format.py — full command paths
# ---------------------------------------------------------------------------


class TestFormatCommand:
    """Full branch coverage for fmt_command."""

    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_file_text_output(self, tmp_path: Path) -> None:
        """Basic formatting of a rules file (lines 87-131)."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file)])

        assert result.exit_code == 0
        assert "Formatted 1 rule(s)" in result.output

    def test_stable_flag(self, tmp_path: Path) -> None:
        """--stable passes stable=True to print_rule."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file), "--stable"])

        assert result.exit_code == 0

    def test_output_file(self, tmp_path: Path) -> None:
        """--output writes formatted rules to a file."""
        rules_file = tmp_path / "r.rules"
        out_file = tmp_path / "out.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file), "--output", str(out_file)])

        assert result.exit_code == 0
        assert out_file.exists()

    def test_stdin_mode(self) -> None:
        """``-`` reads from stdin."""
        result = self.runner.invoke(app, ["fmt", "-"], input=_VALID_RULE + "\n")

        assert result.exit_code == 0
        assert "Formatted 1 rule(s)" in result.output

    def test_in_place_mode(self, tmp_path: Path) -> None:
        """--in-place rewrites the source file."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file), "--in-place"])

        assert result.exit_code == 0

    def test_in_place_stdin_error(self) -> None:
        """--in-place with stdin → error (line 44-45 of _handle_in_place_mode)."""
        result = self.runner.invoke(app, ["fmt", "-", "--in-place"], input=_VALID_RULE + "\n")

        assert result.exit_code == 1
        assert "Cannot use --in-place with stdin" in result.output

    def test_in_place_and_output_are_mutually_exclusive(self, tmp_path: Path) -> None:
        """--in-place and --output together → error."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(_VALID_RULE + "\n", encoding="utf-8")
        out_file = tmp_path / "out.rules"

        result = self.runner.invoke(
            app,
            ["fmt", str(rules_file), "--in-place", "--output", str(out_file)],
        )

        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_check_mode_already_formatted(self, tmp_path: Path) -> None:
        """--check exits 0 when file is already formatted."""
        rule = parse_rule(_VALID_RULE)
        from surinort_ast import print_rule

        formatted = print_rule(rule) + "\n"
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(formatted, encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file), "--check"])

        assert result.exit_code == 0
        assert "already formatted" in result.output

    def test_check_mode_needs_formatting(self, tmp_path: Path) -> None:
        """--check exits 1 when file needs reformatting."""
        rules_file = tmp_path / "r.rules"
        rules_file.write_text(
            'alert  tcp  any  any  ->  any  80  (msg:"HTTP";  sid:1;)\n',
            encoding="utf-8",
        )

        result = self.runner.invoke(app, ["fmt", str(rules_file), "--check"])

        assert result.exit_code == 1
        assert "would be reformatted" in result.output

    def test_no_valid_rules_error(self, tmp_path: Path) -> None:
        """Comment-only file → exit 1 with error."""
        rules_file = tmp_path / "empty.rules"
        rules_file.write_text("# only a comment\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file)])

        assert result.exit_code == 1
        assert "No valid rules found" in result.output

    def test_parse_error(self, tmp_path: Path) -> None:
        """Completely invalid syntax → parse error exit."""
        rules_file = tmp_path / "bad.rules"
        rules_file.write_text("not a rule\n", encoding="utf-8")

        result = self.runner.invoke(app, ["fmt", str(rules_file)])

        assert result.exit_code == 1
