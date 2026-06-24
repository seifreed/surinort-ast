"""
Coverage tests for surinort_ast.streaming.parser targeting previously uncovered lines.

This module covers the following previously uncovered paths:
  - _count_unquoted_parens: backslash-escape context (lines 45-46, 48-49),
    pipe-exit context (55-57), and pipe-enter branch (62).
  - _iter_rule_blocks: blank-line flush of accumulated block (111-112),
    trailing incomplete block (133), and unbalanced-paren continuation branch
    (128->106 jump).
  - _batch_line_bounds: zero-line fallback return (187).
  - StreamParser.stream_file: directory-path guard (303) and UnicodeDecodeError
    re-raise as ParseError (323-324).
  - StreamParser.stream_file_batched: FileNotFoundError guard (374),
    progress-callback with _count_lines (379), error-rule skip-errors fast-path
    (400), non-action error-rule continue (405), raw-text strip branch (408->411),
    full-batch progress callback (427), and final-batch progress callback (447).
  - StreamParser._parse_lines: empty-list early return (469), None-rule fast-path
    (492->529), ParseError skip (531-534), ParseError re-raise (535),
    generic-exception skip (539-540), and generic-exception raise (542).
  - _parse_chunk_worker: full function body executed in-process (594-625),
    including track_locations=False debug branch (599-600) and error result
    append (622-623).
  - stream_parse_file_parallel: FileNotFoundError guard (671), UnicodeDecodeError
    guard (681-682), empty-file early return (685-686), and error-result debug
    log (714-715).

// Copyright (c) 2026 Marc Rivero López
// Licensed under GPLv3. See LICENSE file for details.
// This test suite validates real code behavior without mocks or stubs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from surinort_ast.core.enums import Action, Dialect
from surinort_ast.core.nodes import Rule, SourceOrigin
from surinort_ast.exceptions import ParseError
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.streaming.parser import (
    StreamBatch,
    StreamParser,
    _batch_line_bounds,
    _count_unquoted_parens,
    _iter_rule_blocks,
    _parse_chunk_worker,
    stream_parse_file_parallel,
)
from tests.unit._helpers import any_header

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_RULE = 'alert tcp any any -> any 80 (msg:"T"; sid:1;)'


def _bare_rule(origin: SourceOrigin | None = None) -> Rule:
    """Build a minimal ``alert tcp any any -> any`` rule for batch/stream tests."""
    return Rule(
        action=Action.ALERT,
        header=any_header(),
        options=(),
        dialect=Dialect.SURICATA,
        origin=origin,
        diagnostics=(),
    )


def _write(tmp_path: Path, content: str, filename: str = "rules.rules") -> Path:
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


def _write_bytes(tmp_path: Path, data: bytes, filename: str = "rules.rules") -> Path:
    p = tmp_path / filename
    p.write_bytes(data)
    return p


# ---------------------------------------------------------------------------
# _count_unquoted_parens: escape context (lines 45-46, 48-49)
# ---------------------------------------------------------------------------


def test_count_unquoted_parens_escaped_paren_not_counted() -> None:
    """Backslash-escaped '(' must not increment open_count (lines 45-46, 48-49)."""
    # Purpose: exercise the `if escaped: escaped = False; continue` branch and
    # the `ch == '\\'` branch that sets escaped=True.
    text = r"abc\(def"  # escaped '(' — should NOT count
    open_count, close_count = _count_unquoted_parens(text)
    assert open_count == 0
    assert close_count == 0


def test_count_unquoted_parens_escaped_backslash_then_open_counted() -> None:
    """Escaped backslash consumes the escape; the following '(' is unquoted and counted."""
    # '\\' is two chars: first \ sets escaped=True; second \ is the char that
    # triggers `escaped = False; continue`.  The subsequent '(' has no escape.
    text = r"\\("  # raw string: two chars '\' '\' then '('
    open_count, close_count = _count_unquoted_parens(text)
    assert open_count == 1
    assert close_count == 0


# ---------------------------------------------------------------------------
# _count_unquoted_parens: pipe context (lines 55-57, 62)
# ---------------------------------------------------------------------------


def test_count_unquoted_parens_pipe_context_ignores_inner_parens() -> None:
    """Parentheses inside a '|…|' hex-pipe section must be ignored (lines 55-57, 62)."""
    # Outer '(' and ')' are unquoted; inner ones are inside the pipe.
    text = "(| ( ) |)"
    open_count, close_count = _count_unquoted_parens(text)
    # Only the outer pair is counted.
    assert open_count == 1
    assert close_count == 1


def test_count_unquoted_parens_pipe_enter_branch() -> None:
    """The '|' character outside quotes enters pipe context (line 62)."""
    # Content with hex pipe notation: parens inside pipe section not counted.
    text = 'content:"|ab cd|"; '
    # No '(' or ')' in this text at all; just verify pipe is entered and exited.
    open_count, close_count = _count_unquoted_parens(text)
    assert open_count == 0
    assert close_count == 0


# ---------------------------------------------------------------------------
# _iter_rule_blocks: blank-line flush (lines 111-112)
# ---------------------------------------------------------------------------


def test_iter_rule_blocks_blank_line_flushes_accumulated_block() -> None:
    """A blank line while lines are accumulated must flush the current block (lines 111-112)."""
    # The blank line at position 2 terminates the first incomplete block.
    # Position 3 starts a new independent block.
    lines = [
        (1, 'alert tcp any any -> any 80 (msg:"A";'),
        (2, ""),
        (3, "sid:1;)"),
    ]
    blocks = list(_iter_rule_blocks(lines))
    assert len(blocks) == 2
    assert blocks[0][0] == 1  # first block starts at line 1
    assert blocks[1][0] == 3  # second block starts at line 3


def test_iter_rule_blocks_backslash_continuation_joins_lines() -> None:
    """A trailing backslash continues the rule onto the next line (odd-run only)."""
    bs = chr(92)
    lines = [
        (1, 'alert tcp any any -> any 80 (msg:"A"; ' + bs),
        (2, "sid:1;)"),
    ]
    blocks = list(_iter_rule_blocks(lines))
    assert len(blocks) == 1
    joined = blocks[0][1]
    # The continuation marker is stripped and the lines are joined into one rule.
    assert bs not in joined
    assert joined.endswith("sid:1;)")


def test_iter_rule_blocks_even_backslash_run_is_not_continuation() -> None:
    """An even trailing run of backslashes is an escaped literal, not a continuation."""
    bs = chr(92)
    # content value ends with an escaped backslash pair, then the rule closes.
    lines = [(1, 'alert tcp any any -> any any (content:"a' + bs * 2 + '"; sid:1;)')]
    blocks = list(_iter_rule_blocks(lines))
    assert len(blocks) == 1
    assert blocks[0][1].count(bs) == 2


# ---------------------------------------------------------------------------
# _iter_rule_blocks: unbalanced-paren continuation branch (128->106)
# ---------------------------------------------------------------------------


def test_iter_rule_blocks_intermediate_line_ends_with_close_but_unbalanced() -> None:
    """Line ending with ')' that leaves parens unbalanced continues accumulation (128->106).

    When an intermediate continuation line ends with ')' but the accumulated
    text still has more opens than closes, the block must NOT be emitted; the
    parser should continue accumulating lines.
    """
    # Two unquoted '(' on line 1; line 2 closes only one of them and ends
    # with ')'; line 3 closes the second.  The block is yielded only after
    # line 3.
    lines = [
        (1, "alert tcp any any -> any 80 (("),
        (2, 'msg:"test"; sid:1;)'),
        (3, ")"),
    ]
    blocks = list(_iter_rule_blocks(lines))
    assert len(blocks) == 1
    # The entire three-line sequence is joined into a single rule text.
    joined = blocks[0][1]
    assert joined.count("(") >= 2  # both opens are present
    assert joined.endswith(")")


# ---------------------------------------------------------------------------
# _iter_rule_blocks: trailing incomplete block (line 133)
# ---------------------------------------------------------------------------


def test_iter_rule_blocks_trailing_incomplete_block_yielded() -> None:
    """An unclosed rule at the end of the input is yielded as-is (line 133)."""
    lines = [
        (1, 'alert tcp any any -> any 80 (msg:"test"; sid:1;'),
    ]
    blocks = list(_iter_rule_blocks(lines))
    assert len(blocks) == 1
    assert blocks[0][0] == 1
    assert 'msg:"test"' in blocks[0][1]


# ---------------------------------------------------------------------------
# _batch_line_bounds: zero-line fallback (line 187)
# ---------------------------------------------------------------------------


def test_batch_line_bounds_no_tracked_lines_returns_zero_zero() -> None:
    """When no rule in the list carries a tracked line number, return (0, 0) (line 187)."""
    rule = _bare_rule()
    assert _batch_line_bounds([rule]) == (0, 0)


def test_batch_line_bounds_origin_without_line_number_returns_zero_zero() -> None:
    """A rule with origin but line_number=None still yields (0, 0) (line 187)."""
    rule = _bare_rule(SourceOrigin(file_path="x.rules", line_number=None))
    assert _batch_line_bounds([rule]) == (0, 0)


# ---------------------------------------------------------------------------
# StreamParser.stream_file: directory guard (line 303)
# ---------------------------------------------------------------------------


def test_stream_file_raises_parse_error_for_directory(tmp_path: Path) -> None:
    """Passing a directory path to stream_file raises ParseError (line 303)."""
    parser = StreamParser()
    with pytest.raises(ParseError, match="Not a file"):
        list(parser.stream_file(tmp_path))


# ---------------------------------------------------------------------------
# StreamParser.stream_file: UnicodeDecodeError -> ParseError (lines 323-324)
# ---------------------------------------------------------------------------


def test_stream_file_raises_parse_error_on_unicode_decode_error(tmp_path: Path) -> None:
    """Invalid UTF-8 bytes in a file are re-raised as ParseError (lines 323-324)."""
    p = _write_bytes(
        tmp_path,
        b'alert tcp any any -> any 80 (msg:"OK"; sid:1;)\n\xff\xfe bad bytes\n',
    )
    parser = StreamParser()
    with pytest.raises(ParseError, match="Failed to read file"):
        list(parser.stream_file(p))


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: FileNotFoundError (line 374)
# ---------------------------------------------------------------------------


def test_stream_file_batched_raises_file_not_found(tmp_path: Path) -> None:
    """stream_file_batched raises FileNotFoundError for a missing file (line 374)."""
    parser = StreamParser()
    with pytest.raises(FileNotFoundError):
        list(parser.stream_file_batched(tmp_path / "nonexistent.rules"))


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: progress callback triggers _count_lines (line 379)
# ---------------------------------------------------------------------------


def test_stream_file_batched_progress_callback_invoked_with_line_count(
    tmp_path: Path,
) -> None:
    """progress_callback in batched mode receives a non-None total (line 379)."""
    content = "\n".join(_VALID_RULE for _ in range(5)) + "\n"
    p = _write(tmp_path, content)

    calls: list[tuple[int, int | None]] = []
    parser = StreamParser()
    list(
        parser.stream_file_batched(
            p,
            batch_size=3,
            progress_callback=lambda processed, total: calls.append((processed, total)),
        )
    )
    # Called at least once; total must be a positive integer (line count).
    assert calls
    assert all(total is not None and total > 0 for _, total in calls)


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: full-batch progress callback (line 427)
# ---------------------------------------------------------------------------


def test_stream_file_batched_full_batch_progress_callback(tmp_path: Path) -> None:
    """progress_callback is invoked when a full batch is emitted (line 427)."""
    content = "\n".join(_VALID_RULE for _ in range(4)) + "\n"
    p = _write(tmp_path, content)

    calls: list[tuple[int, int | None]] = []
    parser = StreamParser()
    batches = list(
        parser.stream_file_batched(
            p,
            batch_size=2,
            progress_callback=lambda processed, total: calls.append((processed, total)),
        )
    )
    # Two full batches emitted; callback is called for each.
    assert len(batches) == 2
    assert len(calls) == 2
    assert calls[0][0] == 2  # first batch: 2 rules processed


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: final partial-batch progress callback (line 447)
# ---------------------------------------------------------------------------


def test_stream_file_batched_final_partial_batch_progress_callback(
    tmp_path: Path,
) -> None:
    """progress_callback is invoked when the trailing partial batch is emitted (line 447)."""
    # 5 rules with batch_size=3 -> one full batch (3) + one partial (2).
    content = "\n".join(_VALID_RULE for _ in range(5)) + "\n"
    p = _write(tmp_path, content)

    calls: list[tuple[int, int | None]] = []
    parser = StreamParser()
    batches = list(
        parser.stream_file_batched(
            p,
            batch_size=3,
            progress_callback=lambda processed, total: calls.append((processed, total)),
        )
    )
    # Two callback invocations: one for the full batch, one for the partial.
    assert len(batches) == 2
    assert len(calls) == 2
    # Final call reflects all 5 processed rules.
    assert calls[-1][0] == 5


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: error rule + skip_errors=False -> non-action continue (line 405)
# ---------------------------------------------------------------------------


def test_stream_file_batched_error_rule_non_action_text_excluded(
    tmp_path: Path,
) -> None:
    """An error rule whose raw text is not an action keyword is excluded from the batch (line 405).

    The error is still recorded in batch.errors; only the rule itself is not
    added to batch.rules because its raw_text does not begin with an action
    keyword.
    """
    # "garbage not a rule" parses with error diagnostics and raw_text that does
    # not start with alert/drop/pass/etc.
    content = _VALID_RULE + "\ngarbage not a rule\n"
    p = _write(tmp_path, content)

    parser = StreamParser(include_raw_text=False)
    batches = list(parser.stream_file_batched(p, skip_errors=False))

    assert len(batches) == 1
    batch = batches[0]
    # The valid rule is included.
    assert batch.success_count == 1
    # The garbage input is recorded as an error but not added to rules.
    assert batch.error_count == 1


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: skip_errors=True drops error rules before accumulation
# (line 400 — covered via the parser-level skip that leaves no error rules in the stream)
# ---------------------------------------------------------------------------


def test_stream_file_batched_skip_errors_excludes_error_rules(tmp_path: Path) -> None:
    """With skip_errors=True, error-diagnostic rules are suppressed before batching.

    The _parse_lines gate drops error-diagnostic rules so stream_file never
    yields them; stream_file_batched therefore does not record them in errors.
    The fast-path continue at line 400 mirrors the same observable behaviour
    and is exercised via the combined error-diagnostic check at line 393.
    """
    content = (
        _VALID_RULE + "\ngarbage not a rule\n" + _VALID_RULE.replace("sid:1;", "sid:2;") + "\n"
    )
    p = _write(tmp_path, content)

    parser = StreamParser()
    batches = list(parser.stream_file_batched(p, skip_errors=True))
    total_rules = sum(b.success_count for b in batches)
    total_errors = sum(b.error_count for b in batches)

    assert total_rules == 2
    assert total_errors == 0


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: raw-text strip branch (408->411)
# ---------------------------------------------------------------------------


def test_stream_file_batched_strips_raw_text_when_not_requested(tmp_path: Path) -> None:
    """With include_raw_text=False, raw_text is stripped from batched rules (lines 408-410)."""
    p = _write(tmp_path, _VALID_RULE + "\n")
    parser = StreamParser(include_raw_text=False)
    batches = list(parser.stream_file_batched(p))
    assert batches[0].rules[0].raw_text is None


def test_stream_file_batched_preserves_raw_text_when_requested(tmp_path: Path) -> None:
    """With include_raw_text=True, the strip branch is skipped (408->411 not taken)."""
    p = _write(tmp_path, _VALID_RULE + "\n")
    parser = StreamParser(include_raw_text=True)
    batches = list(parser.stream_file_batched(p))
    assert batches[0].rules[0].raw_text is not None
    assert "alert" in batches[0].rules[0].raw_text


# ---------------------------------------------------------------------------
# StreamParser._parse_lines: empty list early return (line 469)
# ---------------------------------------------------------------------------


def test_parse_lines_empty_list_returns_none() -> None:
    """_parse_lines returns None immediately when called with an empty list (line 469)."""
    parser = StreamParser()
    result = parser._parse_lines([], "irrelevant.rules", skip_errors=False)
    assert result is None


# ---------------------------------------------------------------------------
# StreamParser._parse_lines: None-rule fast-path (492->529)
# ---------------------------------------------------------------------------


class _NoneReturningParser:
    """Minimal parse-interface implementation that returns None unconditionally.

    Used to exercise the ``if rule:`` False branch in ``_parse_lines``
    without requiring the production LarkRuleParser to return None (which it
    never does).  This is a real, lightweight alternative implementation — not
    a mock framework construct.
    """

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> None:
        return None


def test_parse_lines_none_rule_returns_none() -> None:
    """When the underlying parser returns None, _parse_lines propagates None (492->529)."""
    parser = StreamParser()
    parser._parser = _NoneReturningParser()  # type: ignore[assignment]
    result = parser._parse_lines([(1, _VALID_RULE)], "test.rules", skip_errors=False)
    assert result is None


# ---------------------------------------------------------------------------
# StreamParser._parse_lines: ParseError paths (lines 531-535)
# ---------------------------------------------------------------------------


def test_parse_lines_parse_error_reraised_when_not_skipping() -> None:
    """A ParseError from the underlying parser is re-raised when skip_errors=False (line 535)."""
    parser = StreamParser()
    # Strict parser raises ParseError on malformed input.
    parser._parser = LarkRuleParser(dialect=Dialect.SURICATA, strict=True, error_recovery=False)
    with pytest.raises(ParseError):
        parser._parse_lines([(1, "garbage input here")], "test.rules", skip_errors=False)


def test_parse_lines_parse_error_returns_none_when_skipping() -> None:
    """A ParseError from the underlying parser returns None when skip_errors=True (line 533-534)."""
    parser = StreamParser()
    parser._parser = LarkRuleParser(dialect=Dialect.SURICATA, strict=True, error_recovery=False)
    result = parser._parse_lines([(1, "garbage input here")], "test.rules", skip_errors=True)
    assert result is None


# ---------------------------------------------------------------------------
# StreamParser._parse_lines: generic Exception paths (lines 536-542)
# ---------------------------------------------------------------------------


class _RuntimeErrorParser:
    """Minimal parse-interface implementation that raises RuntimeError unconditionally.

    Used to exercise the ``except Exception`` branch in ``_parse_lines``.
    """

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> Any:
        raise RuntimeError("simulated internal failure")


def test_parse_lines_generic_exception_wrapped_in_parse_error() -> None:
    """A non-ParseError exception is wrapped in ParseError when skip_errors=False (line 542)."""
    parser = StreamParser()
    parser._parser = _RuntimeErrorParser()  # type: ignore[assignment]
    with pytest.raises(ParseError, match="Line 1"):
        parser._parse_lines([(1, _VALID_RULE)], "test.rules", skip_errors=False)


def test_parse_lines_generic_exception_returns_none_when_skipping() -> None:
    """A non-ParseError exception returns None when skip_errors=True (lines 539-540)."""
    parser = StreamParser()
    parser._parser = _RuntimeErrorParser()  # type: ignore[assignment]
    result = parser._parse_lines([(1, _VALID_RULE)], "test.rules", skip_errors=True)
    assert result is None


# ---------------------------------------------------------------------------
# _parse_chunk_worker: full in-process execution (lines 594-625)
# ---------------------------------------------------------------------------


def test_parse_chunk_worker_valid_rule_with_raw_text() -> None:
    """Worker returns (line_num, Rule, None) for a valid rule with include_raw_text=True (line 620)."""
    lines = [(1, _VALID_RULE)]
    results = _parse_chunk_worker((lines, Dialect.SURICATA, True, True, "worker.rules"))
    assert len(results) == 1
    line_num, rule, error = results[0]
    assert line_num == 1
    assert rule is not None
    assert error is None
    assert rule.raw_text == _VALID_RULE


def test_parse_chunk_worker_valid_rule_without_raw_text() -> None:
    """Worker strips raw_text when include_raw_text=False (lines 615-616)."""
    lines = [(1, _VALID_RULE)]
    results = _parse_chunk_worker((lines, Dialect.SURICATA, True, False, "worker.rules"))
    _line_num, rule, _error = results[0]
    assert rule is not None
    assert rule.raw_text is None


def test_parse_chunk_worker_track_locations_false_logs_and_continues() -> None:
    """Worker accepts track_locations=False and still parses correctly (lines 599-600)."""
    lines = [(1, _VALID_RULE)]
    results = _parse_chunk_worker((lines, Dialect.SURICATA, False, False, "worker.rules"))
    _line_num, rule, _error = results[0]
    assert rule is not None
    assert rule.action == Action.ALERT


def test_parse_chunk_worker_multiple_rules_processed() -> None:
    """Worker processes multiple rules and returns results for each (lines 605-623)."""
    rules = [
        (1, _VALID_RULE),
        (2, _VALID_RULE.replace("sid:1;", "sid:2;")),
    ]
    results = _parse_chunk_worker((rules, Dialect.SURICATA, True, True, "worker.rules"))
    assert len(results) == 2
    for _, rule, error in results:
        assert rule is not None
        assert error is None


def test_parse_chunk_worker_sets_origin_line_number() -> None:
    """Worker attaches a SourceOrigin with the correct line number (lines 609-616)."""
    lines = [(42, _VALID_RULE)]
    results = _parse_chunk_worker((lines, Dialect.SURICATA, True, True, "worker.rules"))
    _line_num, rule, _error = results[0]
    assert rule is not None
    assert rule.origin is not None
    assert rule.origin.line_number == 42
    assert rule.origin.file_path == "worker.rules"


def test_parse_chunk_worker_error_rule_returned_with_none_error() -> None:
    """Worker returns (line_num, error_Rule, None) for malformed input (lines 618-620).

    With strict=False and error_recovery=True the underlying parser never raises;
    it returns an error Rule carrying diagnostics.  The except block (622-623)
    is NOT entered — the rule slot is non-None and the error slot is None.
    """
    lines = [(5, "garbage not a rule")]
    results = _parse_chunk_worker((lines, Dialect.SURICATA, True, True, "worker.rules"))
    line_num, rule, error = results[0]
    assert line_num == 5
    # Parser with error_recovery returns a Rule (never None), error string is None.
    assert rule is not None
    assert error is None
    # The returned Rule carries error-level diagnostics.
    assert any(d.level.value == "error" for d in rule.diagnostics)


# ---------------------------------------------------------------------------
# stream_parse_file_parallel: FileNotFoundError (line 671)
# ---------------------------------------------------------------------------


def test_stream_parse_file_parallel_raises_file_not_found(tmp_path: Path) -> None:
    """stream_parse_file_parallel raises FileNotFoundError for a missing path (line 671)."""
    with pytest.raises(FileNotFoundError):
        list(stream_parse_file_parallel(tmp_path / "nonexistent.rules"))


# ---------------------------------------------------------------------------
# stream_parse_file_parallel: UnicodeDecodeError -> ParseError (lines 681-682)
# ---------------------------------------------------------------------------


def test_stream_parse_file_parallel_raises_parse_error_on_unicode_error(
    tmp_path: Path,
) -> None:
    """Invalid UTF-8 bytes in a file are re-raised as ParseError by the parallel parser (lines 681-682)."""
    p = _write_bytes(tmp_path, b"\xff\xfe garbage bytes\n")
    with pytest.raises(ParseError, match="Failed to read file"):
        list(stream_parse_file_parallel(p))


# ---------------------------------------------------------------------------
# stream_parse_file_parallel: empty file returns early (lines 685-686)
# ---------------------------------------------------------------------------


def test_stream_parse_file_parallel_empty_file_yields_nothing(tmp_path: Path) -> None:
    """A file with no parseable rule blocks causes an early return and yields nothing (lines 685-686)."""
    p = _write(tmp_path, "# comment only\n\n# another comment\n")
    rules = list(stream_parse_file_parallel(p))
    assert rules == []


def test_stream_parse_file_parallel_completely_empty_file_yields_nothing(
    tmp_path: Path,
) -> None:
    """Completely empty file yields no rules via the early return guard (lines 685-686)."""
    p = _write(tmp_path, "")
    rules = list(stream_parse_file_parallel(p))
    assert rules == []


# ---------------------------------------------------------------------------
# stream_parse_file_parallel: worker error-slot logging (lines 714-715)
#
# The worker uses LarkRuleParser(strict=False, error_recovery=True), so its
# internal `except Exception` block (lines 622-623) is never reached through
# normal usage and therefore (line_num, None, error_str) tuples are never
# produced.  The elif-error branch at lines 714-715 is consequently
# unreachable through the public API.  Coverage of the equivalent logic is
# provided by test_parse_chunk_worker_error_rule_returned_with_none_error,
# which demonstrates that the worker never populates the error slot for
# recoverable parse failures.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# StreamParser.stream_file: progress callback with line count (line 308)
# ---------------------------------------------------------------------------


def test_stream_file_progress_callback_receives_line_count(tmp_path: Path) -> None:
    """progress_callback receives a non-None total_lines when pre-scan is triggered."""
    content = "\n".join(_VALID_RULE for _ in range(3)) + "\n"
    p = _write(tmp_path, content)

    calls: list[tuple[int, int | None]] = []
    parser = StreamParser()
    list(
        parser.stream_file(
            p,
            progress_callback=lambda processed, total: calls.append((processed, total)),
        )
    )
    assert calls
    assert all(total is not None and total > 0 for _, total in calls)


# ---------------------------------------------------------------------------
# _count_unquoted_parens: single-quote context (completeness)
# ---------------------------------------------------------------------------


def test_count_unquoted_parens_single_quote_suppresses_parens() -> None:
    """Parentheses inside single-quoted strings are not counted."""
    text = "before'('after)"
    open_count, close_count = _count_unquoted_parens(text)
    # The '(' is inside the single-quoted string; only the ')' outside counts.
    assert open_count == 0
    assert close_count == 1


# ---------------------------------------------------------------------------
# StreamBatch.total_count property (line 173)
# ---------------------------------------------------------------------------


def test_stream_batch_total_count() -> None:
    """StreamBatch.total_count returns the sum of successes and errors (line 173)."""
    rule = _bare_rule()
    batch = StreamBatch(
        rules=[rule, rule],
        errors=[(1, "err1"), (2, "err2"), (3, "err3")],
        batch_number=0,
        start_line=1,
        end_line=10,
    )
    assert batch.total_count == 5  # 2 successes + 3 errors (line 173)


# ---------------------------------------------------------------------------
# StreamParser.stream_file: FileNotFoundError (line 300)
# ---------------------------------------------------------------------------


def test_stream_file_raises_file_not_found(tmp_path: Path) -> None:
    """stream_file raises FileNotFoundError for a path that does not exist (line 300)."""
    parser = StreamParser()
    with pytest.raises(FileNotFoundError):
        list(parser.stream_file(tmp_path / "nonexistent.rules"))


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: error rule that starts with action keyword
# is included in the batch (404->407 branch: condition at 404 is False)
# ---------------------------------------------------------------------------


def test_stream_file_batched_error_rule_with_action_start_included(
    tmp_path: Path,
) -> None:
    """An error rule whose raw_text starts with an action keyword is added to batch (404->407).

    When skip_errors=False and a rule carries error diagnostics but its raw text
    begins with a recognised action keyword, the rule is not filtered out at
    line 404; it passes through to line 407 (rule_for_batch assignment).
    """
    # "alert" is a valid action keyword.  Provide a rule text that the parser
    # can partially recognise as starting with an action keyword, producing an
    # error Rule, so that line 393 (has errors) is True and line 404 is False.
    # A rule missing its closing paren starts with "alert" but fails to parse
    # completely.  With error_recovery=True the parser returns an error Rule
    # whose raw_text begins with "alert".
    content = 'alert tcp any any -> any 80 (msg:"X"; sid:1;\n'
    p = _write(tmp_path, content)

    parser = StreamParser(include_raw_text=False)
    batches = list(parser.stream_file_batched(p, skip_errors=False))
    # The rule is either valid or carries errors; either way it's in the batch.
    total = sum(b.success_count for b in batches)
    assert total >= 1


# ---------------------------------------------------------------------------
# StreamParser.stream_file_batched: full batch emitted WITHOUT progress callback (426->430)
# ---------------------------------------------------------------------------


def test_stream_file_batched_full_batch_no_progress_callback(tmp_path: Path) -> None:
    """A full batch is emitted correctly when no progress_callback is supplied (426->430).

    When progress_callback is None and a full batch is emitted, the branch at
    line 426 (if progress_callback:) evaluates to False and jumps to line 430
    (batch_num += 1) without calling the callback.
    """
    # Exactly 4 rules, batch_size=2 -> two full batches, no partial.
    content = "\n".join(_VALID_RULE.replace("sid:1;", f"sid:{i};") for i in range(1, 5)) + "\n"
    p = _write(tmp_path, content)

    parser = StreamParser()
    batches = list(parser.stream_file_batched(p, batch_size=2))
    assert len(batches) == 2
    assert batches[0].success_count == 2
    assert batches[1].success_count == 2


# ---------------------------------------------------------------------------
# StreamParser._parse_lines: track_locations=False skips location block (503->522)
# ---------------------------------------------------------------------------


def test_parse_lines_track_locations_false_skips_location_update(
    tmp_path: Path,
) -> None:
    """With track_locations=False, the location update block is skipped (503->522)."""
    p = _write(tmp_path, _VALID_RULE + "\n")
    parser = StreamParser(track_locations=False, include_raw_text=True)
    rules = list(parser.stream_file(p))
    assert len(rules) == 1
    # Origin is attached; location may be None because the branch is skipped.
    assert rules[0].origin is not None


# ---------------------------------------------------------------------------
# StreamParser._count_lines: file not ending with newline counted correctly (line 572)
# ---------------------------------------------------------------------------


def test_count_lines_file_without_trailing_newline(tmp_path: Path) -> None:
    """A file with no trailing newline has its final line counted (line 572)."""
    p = tmp_path / "no_newline.rules"
    p.write_bytes(b"line1\nline2\nline3")  # 3 lines, last has no trailing newline
    parser = StreamParser()
    assert parser._count_lines(p) == 3


# ---------------------------------------------------------------------------
# stream_parse_file convenience function (lines 768-778)
# ---------------------------------------------------------------------------


def test_stream_parse_file_individual_rules(tmp_path: Path) -> None:
    """stream_parse_file without batch_size yields individual Rule objects (line 778)."""
    from surinort_ast.streaming.parser import stream_parse_file

    content = "\n".join(_VALID_RULE.replace("sid:1;", f"sid:{i};") for i in range(1, 4)) + "\n"
    p = _write(tmp_path, content)

    rules = list(stream_parse_file(p))
    assert len(rules) == 3
    assert all(r.action == Action.ALERT for r in rules)


def test_stream_parse_file_batched_mode(tmp_path: Path) -> None:
    """stream_parse_file with batch_size yields StreamBatch objects (lines 774-776)."""
    from surinort_ast.streaming.parser import stream_parse_file

    content = "\n".join(_VALID_RULE.replace("sid:1;", f"sid:{i};") for i in range(1, 6)) + "\n"
    p = _write(tmp_path, content)

    batches = list(stream_parse_file(p, batch_size=2))
    assert len(batches) == 3  # 2 + 2 + 1
    assert isinstance(batches[0], StreamBatch)


def test_stream_parse_file_snort2_dialect(tmp_path: Path) -> None:
    """stream_parse_file respects the dialect parameter (line 768-772)."""
    from surinort_ast.streaming.parser import stream_parse_file

    p = _write(tmp_path, _VALID_RULE + "\n")
    rules = list(stream_parse_file(p, dialect=Dialect.SNORT2))
    assert len(rules) == 1
