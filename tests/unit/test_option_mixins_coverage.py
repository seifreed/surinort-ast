# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for the parsing option mixins and their helpers.

Covers the generic-option transformer fallbacks (None filtering, valueless and
non-token values, terminal ignores), the urilen value helper, the quote/PCRE
helper edge cases, the fileops atom-text fallback, and the flowbits
unknown-action / single-token branches.
"""

from __future__ import annotations

from lark import Token

from surinort_ast import parse_rule
from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import GenericOption
from surinort_ast.parsing.mixins.options._helpers import (
    parse_pcre_pattern,
    parse_quoted_string,
    strip_outer_quotes,
)
from surinort_ast.parsing.mixins.options.fileops_mixin import _atom_text
from surinort_ast.parsing.transformer import RuleTransformer


def _token(token_type: str, value: str) -> Token:
    token = Token(token_type, value)
    token.line = 1
    token.column = 1
    token.start_pos = 0
    token.end_line = 1
    token.end_column = len(value)
    token.end_pos = len(value)
    return token


def _transformer() -> RuleTransformer:
    return RuleTransformer(dialect=Dialect.SURICATA)


class TestHelperEdgeCases:
    def test_strip_outer_quotes_short_string(self):
        assert strip_outer_quotes("a") == "a"

    def test_strip_outer_quotes_single_quoted(self):
        assert strip_outer_quotes("'abc'") == "abc"

    def test_parse_quoted_string_short(self):
        assert parse_quoted_string("a") == "a"

    def test_parse_pcre_pattern_without_delimiters(self):
        assert parse_pcre_pattern("plainpattern") == ("plainpattern", "")

    def test_atom_text_non_token_fallback(self):
        assert _atom_text(123) == "123"

    def test_atom_text_tree_recursion(self):
        from lark import Tree

        tree = Tree("atom", [_token("WORD", "val")])
        assert _atom_text(tree) == "val"


class TestGenericOptionTransformer:
    def test_options_filters_none(self):
        result = _transformer().options([GenericOption(keyword="a", raw="a"), None])
        assert None not in result

    def test_generic_option_empty(self):
        result = _transformer().generic_option([])
        assert isinstance(result, GenericOption)
        assert result.keyword == ""

    def test_generic_option_non_token_value(self):
        result = _transformer().generic_option([_token("WORD", "kw"), "rawvalue"])
        assert result.value == "rawvalue"

    def test_option_value_with_and_without_items(self):
        transformer = _transformer()
        assert transformer.option_value([_token("STRING", '"hello"')]) == "hello"
        assert transformer.option_value([]) == ""

    def test_terminal_ignores_return_none(self):
        transformer = _transformer()
        assert transformer.comment([]) is None
        assert transformer.NEWLINE(_token("NEWLINE", "\n")) is None


class TestUrilenValue:
    def test_empty_and_populated(self):
        transformer = _transformer()
        assert transformer.urilen_value([]) == ""
        assert transformer.urilen_value([_token("URILEN_OP", "<"), _token("INT", "100")]) == "<100"


class TestFlowbits:
    def test_unknown_action_warns(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; flowbits:bogus,name; sid:1;)')
        assert any(d.level == DiagnosticLevel.WARNING for d in rule.diagnostics)

    def test_single_token_action_without_name(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; flowbits:noalert; sid:1;)')
        # noalert is valid and has no name; no unknown-action warning.
        assert not any("Unknown flowbits" in d.message for d in rule.diagnostics)


class TestFilestore:
    def test_filestore_single_param(self):
        result = _transformer().filestore_option([[_token("WORD", "request")]])
        assert result.direction == "request"
        assert result.scope is None


class TestFlowbitsSingleToken:
    def test_flowbits_action_without_name(self):
        result = _transformer().flowbits_option([[_token("WORD", "noalert")]])
        assert result is not None
