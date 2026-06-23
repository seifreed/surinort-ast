"""
Tests for streaming parser functionality.

This module tests the streaming parser API for memory-efficient processing
of large rule files.

Licensed under GNU General Public License v3.0
"""

from pathlib import Path

import pytest

from surinort_ast.core.enums import Action, Dialect, Protocol
from surinort_ast.streaming import (
    StreamBatch,
    StreamParser,
    stream_parse_file,
    stream_parse_file_parallel,
)
from tests._helpers import temp_file, temp_rules_file

# ============================================================================
# Basic Streaming Tests
# ============================================================================


def test_stream_parser_initialization():
    """Test StreamParser initialization with various options."""
    # Default initialization
    parser = StreamParser()
    assert parser.dialect == Dialect.SURICATA
    assert parser.track_locations is True
    assert parser.include_raw_text is False

    # Custom initialization
    parser = StreamParser(
        dialect=Dialect.SNORT2,
        track_locations=False,
        include_raw_text=True,
        chunk_size=16384,
    )
    assert parser.dialect == Dialect.SNORT2
    assert parser.track_locations is False
    assert parser.include_raw_text is True
    assert parser.chunk_size == 16384


def test_stream_single_rule():
    """Test streaming a single rule from file."""
    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    with temp_file(rule_text + "\n") as temp_path:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 1
        assert rules[0].action == Action.ALERT
        assert rules[0].header.protocol == Protocol.TCP


def test_stream_multiple_rules():
    """Test streaming multiple rules from file."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
    ]

    with temp_rules_file(rules_text) as temp_path:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 3
        assert rules[0].action == Action.ALERT
        assert rules[1].action == Action.ALERT
        assert rules[2].action == Action.ALERT
        assert rules[2].header.protocol == Protocol.UDP


def test_stream_with_comments_and_blanks():
    """Test streaming with comments and blank lines."""
    content = """
# This is a comment
alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)

# Another comment
alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)

"""

    with temp_file(content) as temp_path:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 2


def test_stream_multiline_rules():
    """Test streaming multi-line rules."""
    content = """alert tcp any any -> any 443 (
    msg:"Multi-line rule";
    flow:established,to_server;
    content:"GET";
    sid:1000;
    rev:1;
)

alert tcp any any -> any 80 (
    msg:"Another multi-line";
    sid:1001;
)"""

    with temp_file(content) as temp_path:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 2


# ============================================================================
# Memory Efficiency Tests
# ============================================================================


def test_stream_raw_text_inclusion():
    """Test include_raw_text option."""
    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    with temp_file(rule_text) as temp_path:
        # With raw text
        parser_with = StreamParser(include_raw_text=True)
        rules_with = list(parser_with.stream_file(temp_path))
        assert rules_with[0].raw_text is not None
        assert "alert tcp" in rules_with[0].raw_text

        # Without raw text
        parser_without = StreamParser(include_raw_text=False)
        rules_without = list(parser_without.stream_file(temp_path))
        assert rules_without[0].raw_text is None


def test_stream_location_tracking():
    """Test track_locations option."""
    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    with temp_file(rule_text) as temp_path:
        # With location tracking
        parser_with = StreamParser(track_locations=True)
        rules_with = list(parser_with.stream_file(temp_path))
        assert rules_with[0].location is not None

        # Without location tracking (faster)
        parser_without = StreamParser(track_locations=False)
        _rules_without = list(parser_without.stream_file(temp_path))
        # Note: May still have location from origin metadata


# ============================================================================
# Batch Streaming Tests
# ============================================================================


def test_stream_batched():
    """Test batch streaming."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(25)]

    with temp_rules_file(rules_text) as temp_path:
        parser = StreamParser()
        batches = list(parser.stream_file_batched(temp_path, batch_size=10))

        assert len(batches) == 3  # 10 + 10 + 5
        assert batches[0].success_count == 10
        assert batches[1].success_count == 10
        assert batches[2].success_count == 5
        assert batches[0].batch_number == 0
        assert batches[1].batch_number == 1
        assert batches[2].batch_number == 2


def test_stream_batch_properties():
    """Test StreamBatch properties."""
    batch = StreamBatch(
        rules=[],
        errors=[(1, "error1"), (2, "error2")],
        batch_number=0,
        start_line=1,
        end_line=100,
    )

    assert batch.success_count == 0
    assert batch.error_count == 2
    assert batch.total_count == 2


# ============================================================================
# Error Handling Tests
# ============================================================================


def test_stream_skip_errors():
    """Test skip_errors option."""
    content = """alert tcp any any -> any 80 (msg:"Valid"; sid:1;)
invalid rule here
alert tcp any any -> any 443 (msg:"Valid"; sid:2;)"""

    with temp_file(content) as temp_path:
        # With skip_errors=True, should get 2 valid rules
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path, skip_errors=True))
        assert len(rules) == 2

        # With skip_errors=False, may include error diagnostics
        rules_all = list(parser.stream_file(temp_path, skip_errors=False))
        # At least the 2 valid rules
        assert len(rules_all) >= 2


def test_stream_file_not_found():
    """Test streaming non-existent file."""
    parser = StreamParser()

    with pytest.raises(FileNotFoundError):
        list(parser.stream_file(Path("/nonexistent/path.rules")))


# ============================================================================
# Progress Tracking Tests
# ============================================================================


def test_stream_with_progress_callback():
    """Test progress callback during streaming."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(10)]

    with temp_rules_file(rules_text) as temp_path:
        progress_calls = []

        def track_progress(processed, total):
            progress_calls.append((processed, total))

        parser = StreamParser()
        rules = list(parser.stream_file(temp_path, progress_callback=track_progress))

        assert len(rules) == 10
        assert len(progress_calls) == 10  # Called for each rule
        assert progress_calls[-1][0] == 10  # Final count


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("a\nb\nc\n", 3),  # trailing newline
        ("a\nb\nc", 3),  # no trailing newline: final line still counts
        ("x", 1),  # single unterminated line
        ("", 0),  # empty file
    ],
)
def test_count_lines_handles_missing_trailing_newline(content, expected):
    """``_count_lines`` must count a final line that lacks a trailing newline.

    Regression: counting only ``\\n`` bytes undercounted a file whose last line
    was unterminated, so the progress total could undershoot the rules streamed.
    """
    with temp_file(content) as temp_path:
        assert StreamParser()._count_lines(temp_path) == expected


# ============================================================================
# Source Origin Tests
# ============================================================================


def test_stream_source_origin():
    """Test source origin metadata in streamed rules."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
    ]

    with temp_rules_file(rules_text) as temp_path:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert rules[0].origin is not None
        assert rules[0].origin.file_path == str(temp_path)
        assert rules[0].origin.line_number == 1

        assert rules[1].origin is not None
        assert rules[1].origin.line_number == 2


# ============================================================================
# Parallel Streaming Tests
# ============================================================================


def test_parallel_streaming():
    """Test parallel streaming with multiprocessing."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(100)]

    with temp_rules_file(rules_text) as temp_path:
        rules = list(
            stream_parse_file_parallel(
                temp_path,
                workers=2,
                chunk_size=50,
            )
        )

        assert len(rules) == 100


def test_parallel_streaming_small_chunks():
    """Test parallel streaming with small chunks."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(20)]

    with temp_rules_file(rules_text) as temp_path:
        rules = list(
            stream_parse_file_parallel(
                temp_path,
                workers=4,
                chunk_size=5,
            )
        )

        assert len(rules) == 20


def test_parallel_streaming_reassembles_multiline_rules():
    """Parallel parsing must group multi-line rules, not parse each line alone.

    Regression: the parallel path parsed every physical line independently, so
    multi-line rules failed to parse and were dropped (while emitting spurious
    error nodes). It must reassemble rules exactly like sequential streaming.
    """
    text = (
        'alert tcp any any -> any 80 (msg:"one"; sid:1;)\n'
        "alert tcp any any -> any 80 (\n"
        '    msg:"two";\n'
        '    content:"abc";\n'
        "    sid:2;\n"
        ")\n"
        "# a comment line\n"
        'alert tcp any any -> any 80 (msg:"three"; sid:3;)\n'
    )

    def sids(rules):
        return sorted(o.value for r in rules for o in r.options if o.node_type == "SidOption")

    with temp_file(text) as temp_path:
        sequential = list(stream_parse_file(temp_path))
        parallel = list(stream_parse_file_parallel(temp_path, workers=2, chunk_size=2))

        assert sids(sequential) == [1, 2, 3]
        # Parallel must find the same rules (order is not guaranteed) and must
        # not drop the multi-line rule or emit extra error nodes.
        assert len(parallel) == 3
        assert sids(parallel) == [1, 2, 3]


# ============================================================================
# Convenience Function Tests
# ============================================================================


def test_stream_parse_file_individual():
    """Test stream_parse_file convenience function (individual rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(5)]

    with temp_rules_file(rules_text) as temp_path:
        rules = list(stream_parse_file(temp_path))
        assert len(rules) == 5


def test_stream_parse_file_batched():
    """Test stream_parse_file with batch_size."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(25)]

    with temp_rules_file(rules_text) as temp_path:
        batches = list(stream_parse_file(temp_path, batch_size=10))
        assert len(batches) == 3
        assert batches[0].success_count == 10


# ============================================================================
# Large File Simulation Tests
# ============================================================================


@pytest.mark.slow
def test_stream_large_file():
    """Test streaming a large file (1000 rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(1000)]

    with temp_rules_file(rules_text) as temp_path:
        parser = StreamParser(include_raw_text=False, track_locations=False)
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 1000


@pytest.mark.slow
def test_stream_large_file_batched():
    """Test batch streaming a large file (1000 rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(1000)]

    with temp_rules_file(rules_text) as temp_path:
        parser = StreamParser(include_raw_text=False, track_locations=False)
        batches = list(parser.stream_file_batched(temp_path, batch_size=100))

        assert len(batches) == 10
        total_rules = sum(b.success_count for b in batches)
        assert total_rules == 1000
