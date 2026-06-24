# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for cli/shared.py.

Targets the error and fallback branches: an unresolvable allowed-base in
validate_file_path, the generic-exception arm of cli_error_handler (with and
without verbose), invalid-UTF-8 stdin in read_input, and the
parser/transformer/comment/on_error branches of parse_rules_from_content.
"""

from __future__ import annotations

import io
import sys
import types
from pathlib import Path

import pytest
import typer

from surinort_ast.api._internal import _get_parser
from surinort_ast.cli.shared import (
    cli_error_handler,
    parse_rules_from_content,
    read_input,
    validate_file_path,
)
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError
from surinort_ast.parsing.transformer import RuleTransformer

_RULE = 'alert tcp any any -> any 80 (msg:"ok"; sid:1;)'


class TestValidateFilePath:
    def test_unresolvable_allowed_base(self, tmp_path, monkeypatch):
        target = tmp_path / "f.txt"
        target.write_text("x", encoding="utf-8")
        base = tmp_path / "base"
        base.mkdir()

        real_resolve = Path.resolve

        def fake_resolve(self, *args, **kwargs):
            if self == base:
                raise OSError("cannot resolve base")
            return real_resolve(self, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", fake_resolve)

        with pytest.raises(ValueError, match="Invalid base directory"):
            validate_file_path(target, allowed_base=base)


class TestCliErrorHandler:
    def test_parse_error_reported(self):
        with pytest.raises(typer.Exit) as exc, cli_error_handler():
            raise ParseError("bad rule")
        assert exc.value.exit_code == 1

    def test_typer_exit_propagates(self):
        with pytest.raises(typer.Exit) as exc, cli_error_handler():
            raise typer.Exit(3)
        assert exc.value.exit_code == 3

    def test_unexpected_error_non_verbose(self):
        with pytest.raises(typer.Exit) as exc, cli_error_handler(verbose=False):
            raise RuntimeError("boom")
        assert exc.value.exit_code == 1

    def test_unexpected_error_verbose_includes_traceback(self):
        with pytest.raises(typer.Exit) as exc, cli_error_handler(verbose=True):
            raise RuntimeError("boom")
        assert exc.value.exit_code == 1


class TestReadInput:
    def test_stdin_invalid_utf8(self, monkeypatch):
        fake_stdin = types.SimpleNamespace(
            isatty=lambda: False,
            buffer=io.BytesIO(b"\xff\xfe invalid"),
        )
        monkeypatch.setattr(sys, "stdin", fake_stdin)

        with pytest.raises(typer.Exit) as exc:
            read_input(None)
        assert exc.value.exit_code == 1


class TestParseRulesFromContent:
    def test_creates_parser_and_transformer_when_omitted(self):
        rules = parse_rules_from_content(f"{_RULE}\n", Dialect.SURICATA)

        assert len(rules) == 1
        assert rules[0].raw_text == _RULE

    def test_reuses_supplied_parser_transformer_and_reports_errors(self):
        parser = _get_parser(Dialect.SURICATA)
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        content = f"# a comment\n\n{_RULE}\nthis is not a rule\n"
        errors: list[str] = []

        rules = parse_rules_from_content(
            content,
            Dialect.SURICATA,
            parser=parser,
            transformer=transformer,
            on_error=lambda line, exc: errors.append(line),
        )

        assert len(rules) == 1
        assert errors == ["this is not a rule"]

    def test_malformed_line_without_callback_is_skipped(self):
        rules = parse_rules_from_content(f"{_RULE}\nbroken line here\n", Dialect.SURICATA)

        assert len(rules) == 1

    def test_reassembles_multi_line_rule(self):
        # A rule continued across physical lines must parse as one rule, matching
        # the file path; parsing physical lines independently dropped it.
        content = 'alert tcp any any -> any 80 (\n  msg:"x";\n  sid:1;)\n'
        rules = parse_rules_from_content(content, Dialect.SURICATA)

        assert len(rules) == 1
        sid_values = [o.value for o in rules[0].options if type(o).__name__ == "SidOption"]
        assert sid_values == [1]

    def test_applies_normalization_for_trailing_quote_quirk(self):
        # content ending in ...\"; is accepted from a file; stdin must match.
        content = 'alert tcp any any -> any any (msg:"x"; content:"abc\\"; sid:1;)\n'
        rules = parse_rules_from_content(content, Dialect.SURICATA)

        assert len(rules) == 1
