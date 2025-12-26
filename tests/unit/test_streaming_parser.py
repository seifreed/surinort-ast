"""
Tests for streaming parser functionality.

This module tests the streaming parser API for memory-efficient processing
of large rule files.

Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path

import pytest

from surinort_ast.core.enums import Action, Dialect, Protocol
from surinort_ast.streaming import (
    StreamBatch,
    StreamParser,
    stream_parse_file,
    stream_parse_file_parallel,
)

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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(rule_text)
        f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 1
        assert rules[0].action == Action.ALERT
        assert rules[0].header.protocol == Protocol.TCP
    finally:
        temp_path.unlink()


def test_stream_multiple_rules():
    """Test streaming multiple rules from file."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 3
        assert rules[0].action == Action.ALERT
        assert rules[1].action == Action.ALERT
        assert rules[2].action == Action.ALERT
        assert rules[2].header.protocol == Protocol.UDP
    finally:
        temp_path.unlink()


def test_stream_with_comments_and_blanks():
    """Test streaming with comments and blank lines."""
    content = """
# This is a comment
alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)

# Another comment
alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)

"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(content)
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 2
    finally:
        temp_path.unlink()


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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(content)
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 2
    finally:
        temp_path.unlink()


# ============================================================================
# Memory Efficiency Tests
# ============================================================================


def test_stream_raw_text_inclusion():
    """Test include_raw_text option."""
    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(rule_text)
        temp_path = Path(f.name)

    try:
        # With raw text
        parser_with = StreamParser(include_raw_text=True)
        rules_with = list(parser_with.stream_file(temp_path))
        assert rules_with[0].raw_text is not None
        assert "alert tcp" in rules_with[0].raw_text

        # Without raw text
        parser_without = StreamParser(include_raw_text=False)
        rules_without = list(parser_without.stream_file(temp_path))
        assert rules_without[0].raw_text is None
    finally:
        temp_path.unlink()


def test_stream_location_tracking():
    """Test track_locations option."""
    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(rule_text)
        temp_path = Path(f.name)

    try:
        # With location tracking
        parser_with = StreamParser(track_locations=True)
        rules_with = list(parser_with.stream_file(temp_path))
        assert rules_with[0].location is not None

        # Without location tracking (faster)
        parser_without = StreamParser(track_locations=False)
        _rules_without = list(parser_without.stream_file(temp_path))
        # Note: May still have location from origin metadata
    finally:
        temp_path.unlink()


# ============================================================================
# Batch Streaming Tests
# ============================================================================


def test_stream_batched():
    """Test batch streaming."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(25)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        batches = list(parser.stream_file_batched(temp_path, batch_size=10))

        assert len(batches) == 3  # 10 + 10 + 5
        assert batches[0].success_count == 10
        assert batches[1].success_count == 10
        assert batches[2].success_count == 5
        assert batches[0].batch_number == 0
        assert batches[1].batch_number == 1
        assert batches[2].batch_number == 2
    finally:
        temp_path.unlink()


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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write(content)
        temp_path = Path(f.name)

    try:
        # With skip_errors=True, should get 2 valid rules
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path, skip_errors=True))
        assert len(rules) == 2

        # With skip_errors=False, may include error diagnostics
        rules_all = list(parser.stream_file(temp_path, skip_errors=False))
        # At least the 2 valid rules
        assert len(rules_all) >= 2
    finally:
        temp_path.unlink()


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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        progress_calls = []

        def track_progress(processed, total):
            progress_calls.append((processed, total))

        parser = StreamParser()
        rules = list(parser.stream_file(temp_path, progress_callback=track_progress))

        assert len(rules) == 10
        assert len(progress_calls) == 10  # Called for each rule
        assert progress_calls[-1][0] == 10  # Final count
    finally:
        temp_path.unlink()


# ============================================================================
# Source Origin Tests
# ============================================================================


def test_stream_source_origin():
    """Test source origin metadata in streamed rules."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        rules = list(parser.stream_file(temp_path))

        assert rules[0].origin is not None
        assert rules[0].origin.file_path == str(temp_path)
        assert rules[0].origin.line_number == 1

        assert rules[1].origin is not None
        assert rules[1].origin.line_number == 2
    finally:
        temp_path.unlink()


# ============================================================================
# Parallel Streaming Tests
# ============================================================================


def test_parallel_streaming():
    """Test parallel streaming with multiprocessing."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(100)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        rules = list(
            stream_parse_file_parallel(
                temp_path,
                workers=2,
                chunk_size=50,
            )
        )

        assert len(rules) == 100
    finally:
        temp_path.unlink()


def test_parallel_streaming_small_chunks():
    """Test parallel streaming with small chunks."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(20)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        rules = list(
            stream_parse_file_parallel(
                temp_path,
                workers=4,
                chunk_size=5,
            )
        )

        assert len(rules) == 20
    finally:
        temp_path.unlink()


# ============================================================================
# Convenience Function Tests
# ============================================================================


def test_stream_parse_file_individual():
    """Test stream_parse_file convenience function (individual rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(5)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        rules = list(stream_parse_file(temp_path))
        assert len(rules) == 5
    finally:
        temp_path.unlink()


def test_stream_parse_file_batched():
    """Test stream_parse_file with batch_size."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(25)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        batches = list(stream_parse_file(temp_path, batch_size=10))
        assert len(batches) == 3
        assert batches[0].success_count == 10
    finally:
        temp_path.unlink()


# ============================================================================
# Large File Simulation Tests
# ============================================================================


@pytest.mark.slow
def test_stream_large_file():
    """Test streaming a large file (1000 rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(1000)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser(include_raw_text=False, track_locations=False)
        rules = list(parser.stream_file(temp_path))

        assert len(rules) == 1000
    finally:
        temp_path.unlink()


@pytest.mark.slow
def test_stream_large_file_batched():
    """Test batch streaming a large file (1000 rules)."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(1000)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule)
            f.write("\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser(include_raw_text=False, track_locations=False)
        batches = list(parser.stream_file_batched(temp_path, batch_size=100))

        assert len(batches) == 10
        total_rules = sum(b.success_count for b in batches)
        assert total_rules == 1000
    finally:
        temp_path.unlink()
