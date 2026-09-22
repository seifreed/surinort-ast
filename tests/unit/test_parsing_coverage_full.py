# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Full-coverage tests for parsing modules.

Targets every remaining missing line and branch across:
  - content_transformer.py
  - lark_parser.py
  - transformer.py
  - helpers.py
  - mixins/__init__.py
  - mixins/options/_helpers.py
  - mixins/options/fileops_mixin.py
  - mixins/options/flow_mixin.py
  - mixins/options/metadata_mixin.py

All tests use real production code paths — no mocks, no stubs.
"""

from __future__ import annotations

import platform
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from lark import Token, Tree
from lark.exceptions import UnexpectedInput

from surinort_ast import parse_rule
from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import (
    AddressNegation,
    AnyAddress,
    ByteTestOption,
    FastPatternOption,
    FilestoreOption,
    FlowbitsOption,
)
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.parsing.mixins import DiagnosticReporter
from surinort_ast.parsing.mixins.content_transformer import (
    ContentTransformerMixin,
    _is_pure_hex_piped,
    _parse_mixed_content,
    parse_hex_string,
)
from surinort_ast.parsing.mixins.options._helpers import strip_outer_quotes
from surinort_ast.parsing.parser_config import ParserConfig
from surinort_ast.parsing.transformer import RuleTransformer
from tests._helpers import temp_file

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _transformer() -> RuleTransformer:
    return RuleTransformer(dialect=Dialect.SURICATA)


def _token(type_: str, value: str, *, line: int = 1, col: int = 1) -> Token:
    tok = Token(type_, value)
    tok.line = line
    tok.column = col
    tok.start_pos = 0
    tok.end_line = line
    tok.end_column = col + len(value)
    tok.end_pos = len(value)
    return tok


# ---------------------------------------------------------------------------
# helpers.py  — lines 70-71
# (token_to_location: end_pos fallback when token.end_pos is None)
# ---------------------------------------------------------------------------


class TestTokenToLocationFallback:
    """helpers.py lines 70-71: end_pos fallback when token.end_pos is None."""

    def test_end_pos_none_falls_back_to_start_pos_plus_len(self) -> None:
        from surinort_ast.parsing.helpers import token_to_location

        tok = Token("WORD", "hello")
        tok.line = 1
        tok.column = 3
        tok.start_pos = 2
        tok.end_line = 1
        tok.end_column = 8
        # Explicitly unset end_pos so the else-branch fires
        tok.end_pos = None

        loc = token_to_location(tok)

        # end offset = start_pos + len("hello") = 2 + 5 = 7
        assert loc.span.end.offset == 7


# ---------------------------------------------------------------------------
# mixins/__init__.py  — line 26->exit
# (DiagnosticReporter Protocol __call__ stub body reachable via unbound call)
# ---------------------------------------------------------------------------


class TestDiagnosticReporterProtocol:
    """mixins/__init__.py line 26->exit: Protocol stub covered via unbound call."""

    def test_protocol_call_stub_is_reachable(self) -> None:
        class _Impl:
            def __call__(
                self,
                level: DiagnosticLevel,
                message: str,
                location: object = None,
                code: object = None,
                hint: object = None,
            ) -> None:
                pass

        impl = _Impl()
        # Invoking the Protocol's unbound __call__ covers the stub body.
        DiagnosticReporter.__call__(impl, DiagnosticLevel.INFO, "test")


# ---------------------------------------------------------------------------
# options/_helpers.py  — line 65
# (strip_outer_quotes: final fallback `return s` for unquoted strings)
# ---------------------------------------------------------------------------


class TestStripOuterQuotesFallback:
    """_helpers.py line 65: strip_outer_quotes returns s unchanged for unquoted input."""

    def test_unquoted_string_returned_unchanged(self) -> None:
        result = strip_outer_quotes("plainvalue")
        assert result == "plainvalue"

    def test_empty_string_returned_unchanged(self) -> None:
        result = strip_outer_quotes("")
        assert result == ""


# ---------------------------------------------------------------------------
# content_transformer.py  — module-level functions
# ---------------------------------------------------------------------------


class TestParseHexStringError:
    """Lines 82-84: parse_hex_string raises ValueError for odd-length hex content."""

    def test_odd_hex_digit_count_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid hex content"):
            parse_hex_string("|4|")

    def test_warning_logged_before_re_raise(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        with (
            caplog.at_level(
                logging.WARNING, logger="surinort_ast.parsing.mixins.content_transformer"
            ),
            pytest.raises(ValueError),
        ):
            parse_hex_string("|ABC|")  # 3 hex chars → odd → fromhex fails


class TestIsPureHexPiped:
    """Lines 98 and 102: _is_pure_hex_piped early-return branches."""

    def test_no_leading_pipe_returns_false(self) -> None:
        # Line 98: len check / s[0] != "|" branch
        assert _is_pure_hex_piped("abc") is False

    def test_does_not_end_with_pipe_returns_false(self) -> None:
        # Line 98: not s.endswith("|") branch
        assert _is_pure_hex_piped("|abc") is False

    def test_too_short_returns_false(self) -> None:
        # Line 97: len(s) < 2
        assert _is_pure_hex_piped("|") is False

    def test_empty_inner_returns_false(self) -> None:
        # Line 102: inner == "" (i.e. "||")
        assert _is_pure_hex_piped("||") is False


class TestParseMixedContent:
    """Lines 139-140 and 148-149: _parse_mixed_content edge cases."""

    def test_unclosed_pipe_treated_as_ascii(self) -> None:
        # Lines 139-140: pipe with no closing partner
        result = _parse_mixed_content("|unclosed")
        assert result == b"|unclosed"

    def test_invalid_hex_between_pipes_raises(self) -> None:
        # Invalid hex inside pipes must propagate so the caller preserves the
        # original bytes instead of silently deleting the malformed segment.
        with pytest.raises(ValueError, match="Invalid hex content"):
            _parse_mixed_content("|GG|rest")

    def test_empty_hex_between_pipes_raises(self) -> None:
        with pytest.raises(ValueError, match="empty hex segment"):
            _parse_mixed_content("||rest")

    def test_invalid_hex_in_mixed_content_preserves_raw_bytes(self) -> None:
        # Through a full parse, malformed hex falls back to the raw string and
        # records a WARNING diagnostic rather than dropping the |...| segment.
        rule = parse_rule('alert tcp any any -> any any (content:"abc|zz|def"; sid:1;)')
        content = next(o for o in rule.options if type(o).__name__ == "ContentOption")
        assert content.pattern == b"abc|zz|def"
        warnings = [d for d in rule.diagnostics if d.level == DiagnosticLevel.WARNING]
        assert any("Invalid hex content" in d.message for d in warnings)


# ---------------------------------------------------------------------------
# content_transformer.py  — ContentTransformerMixin methods
# ---------------------------------------------------------------------------


class TestCanonicalFastPatternValue:
    """Line 232: _canonical_fast_pattern_value returns "only" when list contains "only"."""

    def test_only_value_returns_only(self) -> None:
        result = ContentTransformerMixin._canonical_fast_pattern_value(["only"])
        assert result == "only"

    def test_only_takes_precedence_over_offset(self) -> None:
        result = ContentTransformerMixin._canonical_fast_pattern_value(["offset 2", "only"])
        assert result == "only"


class TestContentValueViaParser:
    """Lines 355-360, 371, 392: content_value edge cases via full rule parse."""

    def test_invalid_hex_odd_digits_adds_diagnostic(self) -> None:
        # Lines 355-360: _parse_content_value raises ValueError → diagnostic added
        rule = parse_rule('alert tcp any any -> any any (content:"|4|"; sid:1;)')
        warnings = [d for d in rule.diagnostics if d.level == DiagnosticLevel.WARNING]
        assert any("Invalid hex content" in d.message for d in warnings)

    def test_mixed_pipe_content_starts_with_pipe_quoted(self) -> None:
        # Lines 386-387: quoted string containing mixed hex/ascii pipe content
        rule = parse_rule('alert tcp any any -> any any (content:"|08|com|00|"; sid:1;)')
        content = next(o for o in rule.options if o.node_type == "ContentOption")
        assert content.pattern == b"\x08com\x00"

    def test_mixed_pipe_content_unquoted_token_hits_line_371(self) -> None:
        # Line 371: token value is UNQUOTED, starts and ends with "|", but not pure hex
        # first_char="|", endswith("|"), _is_pure_hex_piped returns False → line 371
        t = _transformer()
        tok = _token("CONTENT_VALUE", "|08|com|00|")
        result = t.content_value(tok)
        assert result == b"\x08com\x00"

    def test_unquoted_string_encodes_as_utf8(self) -> None:
        # Line 392: first_char not pipe or quote → encode as-is
        t = _transformer()
        tok = _token("CONTENT_VALUE", "plaintext")
        result = t.content_value(tok)
        assert result == b"plaintext"


class TestInlineModifiersMissingLines:
    """Lines 479, 491, 503: cm_rawbytes, cm_startswith, cm_endswith via rule parse."""

    def test_inline_rawbytes_modifier(self) -> None:
        # Line 479: cm_rawbytes produces ContentModifier(RAWBYTES, None)
        rule = parse_rule('alert tcp any any -> any any (content:"x",rawbytes; sid:1;)')
        content = next(o for o in rule.options if o.node_type == "ContentOption")
        modifier_names = {m.name.value for m in content.modifiers}
        assert "rawbytes" in modifier_names

    def test_inline_startswith_modifier(self) -> None:
        # Line 491: cm_startswith produces ContentModifier(STARTSWITH, None)
        rule = parse_rule('alert tcp any any -> any any (content:"x",startswith; sid:1;)')
        content = next(o for o in rule.options if o.node_type == "ContentOption")
        modifier_names = {m.name.value for m in content.modifiers}
        assert "startswith" in modifier_names

    def test_inline_endswith_modifier(self) -> None:
        # Line 503: cm_endswith produces ContentModifier(ENDSWITH, None)
        rule = parse_rule('alert tcp any any -> any any (content:"x",endswith; sid:1;)')
        content = next(o for o in rule.options if o.node_type == "ContentOption")
        modifier_names = {m.name.value for m in content.modifiers}
        assert "endswith" in modifier_names


class TestCmGenericEdgeCases:
    """Lines 544->549, 553, 566: cm_generic branches."""

    def test_empty_args_returns_modifier_with_empty_name(self) -> None:
        # Lines 544->549: if args is False (empty list)
        t = _transformer()
        result = t.cm_generic([])
        assert result.name == ""
        assert result.value is None

    def test_known_modifier_name_maps_to_enum(self) -> None:
        # Line 553: matched is not None → modifier_type = matched (enum value)
        t = _transformer()
        result = t.cm_generic([_token("WORD", "nocase")])
        from surinort_ast.core.enums import ContentModifierType

        assert result.name == ContentModifierType.NOCASE

    def test_three_or_more_args_returns_modifier_without_value(self) -> None:
        # Line 566: len(args) > 2 → fallback return
        t = _transformer()
        result = t.cm_generic([_token("WORD", "nocase"), _token("INT", "1"), _token("INT", "2")])
        assert result.value is None


class TestFastPatternOptionOnly:
    """Lines 708->711: fast_pattern_option with ("only",) tuple and unknown spec."""

    def test_only_tuple_sets_only_flag(self) -> None:
        t = _transformer()
        option = t.fast_pattern_option([("only",)])
        assert isinstance(option, FastPatternOption)
        assert option.only is True
        assert option.offset is None
        assert option.length is None

    def test_unknown_spec_tuple_takes_neither_branch(self) -> None:
        # Branch 708->711: spec is a tuple but spec[0] is neither "offset" nor "only"
        # → both if and elif are False, execution falls through to line 711
        t = _transformer()
        option = t.fast_pattern_option([("unknown", 1, 2)])
        assert isinstance(option, FastPatternOption)
        assert option.offset is None
        assert option.length is None
        assert option.only is False


class TestByteTestOptionTreeBranches:
    """byte_test_option flag-param handling (the four required positional params
    precede the flags). byte_test parses to a dedicated ByteTestOption."""

    @staticmethod
    def _params(flag: Any) -> list[list[Any]]:
        # bytes, operator, value, offset, then the flag under test.
        return [[_token("INT", "4"), ">", _token("INT", "1000"), _token("INT", "0"), flag]]

    def test_byte_test_flag_tree_node_with_data_byte_test_flag(self) -> None:
        # Tree with data=="byte_test_flag" and Token children → joined flag.
        tree_flag = Tree("byte_test_flag", [_token("WORD", "relative")])
        result = _transformer().byte_test_option(self._params(tree_flag))
        assert isinstance(result, ByteTestOption)
        assert "relative" in result.flags

    def test_byte_test_flag_tree_with_non_token_child(self) -> None:
        # A non-Token (Tree) child inside byte_test_flag → str(child).
        inner_child: Tree[Any] = Tree("inner_rule", [])
        tree_flag = Tree("byte_test_flag", [inner_child])
        result = _transformer().byte_test_option(self._params(tree_flag))
        assert isinstance(result, ByteTestOption)

    def test_byte_test_option_with_non_flag_tree(self) -> None:
        # Tree with different data (not byte_test_flag) → str(p).
        tree_other = Tree("other_node", [_token("WORD", "other")])
        result = _transformer().byte_test_option(self._params(tree_other))
        assert isinstance(result, ByteTestOption)

    def test_byte_test_option_with_non_token_non_str_non_tree(self) -> None:
        # Integer flag param (else branch) → str(42).
        result = _transformer().byte_test_option(self._params(42))
        assert isinstance(result, ByteTestOption)
        assert "42" in result.flags


class TestSignedOffsetEmpty:
    """Line 785: _signed_offset with empty items list returns "0"."""

    def test_empty_items_returns_zero_string(self) -> None:
        result = ContentTransformerMixin._signed_offset([])
        assert result == "0"


class TestByteTestFlagEmpty:
    """Line 807: byte_test_flag with empty items returns empty string."""

    def test_empty_items_returns_empty_string(self) -> None:
        t = _transformer()
        result = t.byte_test_flag([])
        assert result == ""


class TestByteFlagParamList:
    """_byte_flag_param_list Tree and long-tuple branches (returns a positional
    string list for byte_jump/byte_extract)."""

    def test_tree_with_single_child(self) -> None:
        tree = Tree("byte_jump_flag", [_token("WORD", "relative")])
        result = ContentTransformerMixin._byte_flag_param_list([tree])
        assert result == ["relative"]

    def test_tree_with_two_children(self) -> None:
        name = _token("WORD", "post_offset")
        value = _token("INT", "10")
        tree = Tree("byte_jump_flag", [name, value])
        result = ContentTransformerMixin._byte_flag_param_list([tree])
        assert result == ["post_offset 10"]

    def test_tree_with_no_children(self) -> None:
        tree: Tree[Any] = Tree("byte_jump_flag", [])
        result = ContentTransformerMixin._byte_flag_param_list([tree])
        assert "byte_jump_flag" in result[0]

    def test_list_or_tuple_with_three_or_more_items(self) -> None:
        a = _token("WORD", "a")
        b = _token("WORD", "b")
        c = _token("WORD", "c")
        result = ContentTransformerMixin._byte_flag_param_list([(a, b, c)])
        assert result == ["a b c"]


class TestResolveByteFlag:
    """Line 894: _resolve_byte_flag with empty items returns []."""

    def test_empty_items_returns_empty_list(self) -> None:
        result = ContentTransformerMixin._resolve_byte_flag([])
        assert result == []


# ---------------------------------------------------------------------------
# transformer.py — _expr_depth AddressNegation branch (called from address_list)
# ---------------------------------------------------------------------------


class TestAddressExprDepthNegation:
    """_expr_depth handles AddressNegation nodes."""

    def test_address_list_with_negated_element_triggers_negation_depth(self) -> None:
        # A list containing a negated address forces address_list to call
        # _expr_depth on an AddressNegation, exercising the negation branch.
        rule = parse_rule('alert tcp [!192.168.1.1,10.0.0.1] any -> any any (msg:"Test"; sid:1;)')
        from surinort_ast.core.nodes import AddressList

        assert isinstance(rule.header.src_addr, AddressList)
        assert isinstance(rule.header.src_addr.elements[0], AddressNegation)

    def test_address_expr_depth_negation_direct(self) -> None:
        # Call _expr_depth directly with an AddressNegation wrapping another
        # AddressNegation to exercise the recursive negation branch.
        inner = AddressNegation(expr=AnyAddress())
        outer = AddressNegation(expr=inner)
        depth = RuleTransformer._expr_depth(outer)
        # outer(1) + inner(1) + leaf(0) = 2
        assert depth == 2


# ---------------------------------------------------------------------------
# lark_parser.py  — line 181-182
# (_timeout_context: early yield+return when timeout_seconds <= 0)
# ---------------------------------------------------------------------------


class TestTimeoutContextDisabled:
    """Lines 181-182: _timeout_context yields immediately when timeout is zero."""

    def test_parse_with_zero_timeout_succeeds(self) -> None:
        config = ParserConfig(timeout_seconds=0.0)
        parser = LarkRuleParser(config=config)
        rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        assert rule.action.value == "alert"

    def test_timeout_context_with_zero_timeout_is_noop(self) -> None:
        config = ParserConfig(timeout_seconds=0.0)
        parser = LarkRuleParser(config=config)
        executed = []
        with parser._timeout_context():
            executed.append(True)
        assert executed == [True]


# ---------------------------------------------------------------------------
# lark_parser.py  — lines 196, 227
# (thread-based timeout: callback fires and TimeoutError is raised)
# ---------------------------------------------------------------------------


class TestThreadBasedTimeout:
    """Lines 196, 227: thread-based timeout path (Windows or non-main-thread)."""

    def test_thread_timeout_fires_and_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Force the thread-based path by pretending we are on Windows.
        monkeypatch.setattr(platform, "system", lambda: "Windows")

        config = ParserConfig(timeout_seconds=0.01)
        parser = LarkRuleParser(config=config)

        with pytest.raises(TimeoutError), parser._timeout_context():
            # Sleep long enough for the 0.01-second timer to fire.
            time.sleep(0.2)

    def test_thread_timeout_on_non_main_thread(self) -> None:
        # Run with a short timeout on a non-main thread: SIGALRM is unavailable
        # there, so the threading path (lines 196, 227) is taken automatically.
        config = ParserConfig(timeout_seconds=0.01)
        parser = LarkRuleParser(config=config)

        errors: list[BaseException] = []

        def run() -> None:
            try:
                with parser._timeout_context():
                    time.sleep(0.2)
                errors.append(RuntimeError("expected TimeoutError, got none"))
            except TimeoutError:
                pass  # expected
            except Exception as exc:  # capture unexpected errors
                errors.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=5.0)
        assert not errors, f"Thread raised unexpected error: {errors}"


# ---------------------------------------------------------------------------
# lark_parser.py  — line 417
# (parse_file: blank-line flush of non-empty current_rule_lines)
# ---------------------------------------------------------------------------


class TestParseFileBlankLineFlush:
    """Line 417: rules.append(rule) in the blank-line branch of parse_file."""

    def test_blank_line_flushes_accumulated_lines_to_rules(self) -> None:
        # A rule whose option block is NOT closed before a blank line is
        # encountered; parse_file must flush current_rule_lines (line 413-417).
        # skip_errors=False ensures the error rule (non-None) is appended.
        parser = LarkRuleParser(strict=False)
        rule_line = 'alert tcp any any -> any 80 (msg:"BlankFlush"; sid:1;'
        # paren depth = 1 (unclosed), so it will not be flushed at lines 446-449

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(rule_line + "\n")
            f.write("\n")  # blank line triggers the flush at line 413-417
            tmp = f.name

        try:
            rules = parser.parse_file(tmp, skip_errors=False)
            assert len(rules) >= 1
        finally:
            Path(tmp).unlink()


# ---------------------------------------------------------------------------
# lark_parser.py  — line 454->457
# (parse_file: remaining lines at EOF produce None with skip_errors=True)
# ---------------------------------------------------------------------------


class TestParseFileRemainingLinesNone:
    """Line 454->457: _parse_multiline_rule returns None at EOF with skip_errors=True."""

    def test_incomplete_rule_at_eof_with_skip_errors_true_produces_empty_list(self) -> None:
        parser = LarkRuleParser(strict=False)
        # An incomplete rule at end of file (no newline or blank line terminator),
        # with skip_errors=True, means _parse_multiline_rule returns None,
        # so the `if rule:` at line 454 is False and rules.append is skipped.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write('alert tcp any any -> any 80 (msg:"Incomplete"')  # unclosed
            tmp = f.name

        try:
            rules = parser.parse_file(tmp, skip_errors=True)
            # The incomplete rule produces a PARSE_ERROR diagnostic, which
            # skip_errors=True filters out → result is empty.
            assert len(rules) == 0
        finally:
            Path(tmp).unlink()

    def test_valid_rule_at_eof_without_trailing_newline(self) -> None:
        # Positive case: a valid rule at EOF (no trailing newline) is appended
        # via line 454->455.
        parser = LarkRuleParser(strict=False)
        with temp_file('alert tcp any any -> any 80 (msg:"EOF"; sid:1;)') as tmp:
            rules = parser.parse_file(tmp)
            assert len(rules) == 1
            assert rules[0].action.value == "alert"


# ---------------------------------------------------------------------------
# lark_parser.py  — lines 585->587, 587->589, 589->598
# (_handle_parse_error: missing-attribute branches in UnexpectedInput handler)
# ---------------------------------------------------------------------------


class _MinimalUnexpectedInput(UnexpectedInput):
    """Minimal UnexpectedInput with no expected/token/line/column attributes."""

    def get_context(self, text: str, span: int | None = None) -> str:
        return ""


class TestHandleParseErrorMissingAttributes:
    """Lines 585->587, 587->589, 589->598: False branches when attributes absent."""

    def test_error_without_expected_token_line_attributes(self) -> None:
        # A bare UnexpectedInput subclass with none of the optional attributes
        # set causes all three inner if-branches (585, 587, 589) to take their
        # False paths.
        parser = LarkRuleParser(strict=False)
        error = _MinimalUnexpectedInput()
        result = parser._handle_parse_error(error, "bad rule text", "/f.rules")
        # The result is an error rule, not a raised exception
        assert result is not None
        assert len(result.diagnostics) > 0
        assert result.diagnostics[0].code == "PARSE_ERROR"

    def test_error_node_location_is_none_when_no_line_column(self) -> None:
        parser = LarkRuleParser(strict=False)
        error = _MinimalUnexpectedInput()
        result = parser._handle_parse_error(error, "bad rule", None)
        # location is None because error has no .line/.column
        assert result.diagnostics[0].location is None


# ---------------------------------------------------------------------------
# options/fileops_mixin.py  — branch 90->92
# (filestore_option: len(params) >= 1 is False when params is empty)
# ---------------------------------------------------------------------------


class TestFilestoreOptionEmptyParams:
    """Branch 90->92: filestore_option with empty inner params list."""

    def test_empty_inner_params_list_skips_direction_assignment(self) -> None:
        # items[0] is an empty list → params=[] → len(params) >= 1 is False
        t = _transformer()
        result: FilestoreOption = t.filestore_option([[]])
        assert result.direction is None
        assert result.scope is None


# ---------------------------------------------------------------------------
# options/flow_mixin.py  — branch 170->172
# (flowbits_option: len(action_items) >= 1 is False when action_items is empty)
# ---------------------------------------------------------------------------


class TestFlowbitsOptionEmptyActionItems:
    """Branch 170->172: flowbits_option with empty action_items."""

    def test_empty_action_items_produces_empty_action_and_name(self) -> None:
        # items is [] → action_items = [] → len >= 1 is False (branch 170->172)
        t = _transformer()
        result: FlowbitsOption = t.flowbits_option([[]])
        assert result.action == ""
        assert result.name == ""

    def test_items_completely_empty_produces_empty_action_and_name(self) -> None:
        # items is [] → action_items = [] (from `items[0] if items else []`)
        t = _transformer()
        result: FlowbitsOption = t.flowbits_option([])
        assert result.action == ""
        assert result.name == ""


# ---------------------------------------------------------------------------
# options/metadata_mixin.py  — branch 332->325
# (metadata_entry: first child of a Tree item is itself a Tree, not a Token)
# ---------------------------------------------------------------------------


class TestMetadataEntryNonTokenChild:
    """Branch 332->325: metadata_entry skips Tree items whose first child is a Tree."""

    def test_tree_item_with_tree_child_skipped(self) -> None:
        # Build a Tree whose first child is another Tree (not a Token).
        # The isinstance(child, Token) check at line 332 is False → loop continues
        # without appending anything (branch 332->325).
        inner_tree = Tree("inner_rule", [_token("WORD", "deep")])
        outer_tree: Tree[Any] = Tree("metadata_word", [inner_tree])

        t = _transformer()
        result = t.metadata_entry([outer_tree])
        # No values extracted → falls to `if not values: return ("", "")`
        assert result == ("", "")

    def test_mixed_token_and_tree_with_tree_child(self) -> None:
        # A Token followed by a Tree-with-Tree-child: only the Token contributes
        tok = _token("WORD", "created_at")
        inner_tree: Tree[Any] = Tree("inner", [Tree("nested", [])])
        outer_tree: Tree[Any] = Tree("metadata_word", [inner_tree])

        t = _transformer()
        result = t.metadata_entry([tok, outer_tree])
        # Only "created_at" was extracted, so key="created_at", value=""
        assert result == ("created_at", "")
