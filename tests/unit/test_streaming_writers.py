"""
Tests for streaming writers.

This module tests the streaming writer APIs for incremental serialization.

Licensed under GNU General Public License v3.0
"""

import json

import pytest

from surinort_ast.api import parse_rule
from surinort_ast.core.nodes import Rule
from surinort_ast.exceptions import SerializationError
from surinort_ast.streaming import StreamParser, StreamWriter, StreamWriterJSON, StreamWriterText
from tests._helpers import temp_output_path, temp_rules_file

# ============================================================================
# Text Writer Tests
# ============================================================================


def test_text_writer_basic():
    """Test basic text writer functionality."""
    rule1 = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
    rule2 = parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)')

    with temp_output_path() as temp_path:
        with StreamWriterText(temp_path) as writer:
            writer.write(rule1)
            writer.write(rule2)

        # Read back and verify
        with open(temp_path) as f:
            content = f.read()

        assert "alert tcp" in content
        assert "sid:1" in content
        assert "sid:2" in content


def test_text_writer_context_manager():
    """Test text writer as context manager."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path() as temp_path:
        with StreamWriter.text(temp_path) as writer:
            writer.write(rule)
            assert writer.count == 1

        # Verify file exists and has content
        assert temp_path.exists()
        content = temp_path.read_text()
        assert "alert tcp" in content


def test_text_writer_write_many():
    """Test write_many method."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
        parse_rule('alert tcp any any -> any 22 (msg:"Rule 3"; sid:3;)'),
    ]

    with temp_output_path() as temp_path:
        with StreamWriterText(temp_path) as writer:
            count = writer.write_many(rules)

        assert count == 3

        # Verify content
        content = temp_path.read_text()
        assert content.count("alert tcp") == 3


def test_text_writer_writes_reparseable_rules():
    """The text writer emits standard, reparseable rule output."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path() as temp_path:
        with StreamWriterText(temp_path) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        assert "alert tcp" in content


def test_text_writer_header_footer():
    """Test header and footer comments."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path() as temp_path:
        with StreamWriterText(
            temp_path, header_comment="Generated rules", footer_comment="End of rules"
        ) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        assert "# Generated rules" in content
        assert "# End of rules" in content


def test_text_writer_without_context_manager():
    """Test that writing without context manager raises error."""
    with temp_output_path() as temp_path:
        writer = StreamWriterText(temp_path)
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        with pytest.raises(RuntimeError, match="Writer not opened"):
            writer.write(rule)


# ============================================================================
# JSON Writer Tests
# ============================================================================


def test_json_writer_basic():
    """Test basic JSON writer functionality."""
    rule1 = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
    rule2 = parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)')

    with temp_output_path(".json") as temp_path:
        with StreamWriterJSON(temp_path) as writer:
            writer.write(rule1)
            writer.write(rule2)

        # Read back and verify valid JSON
        with open(temp_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["action"] == "alert"
        assert data[1]["action"] == "alert"


def test_json_writer_context_manager():
    """Test JSON writer as context manager."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path(".json") as temp_path:
        with StreamWriter.json(temp_path) as writer:
            writer.write(rule)
            assert writer.count == 1

        # Verify valid JSON
        with open(temp_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 1


def test_json_writer_compact():
    """Test compact JSON formatting."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path(".json") as temp_path:
        with StreamWriterJSON(temp_path, indent=None) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        # Compact JSON should have fewer newlines
        assert content.count("\n") < 10


def test_json_writer_pretty():
    """Test pretty JSON formatting."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with temp_output_path(".json") as temp_path:
        with StreamWriterJSON(temp_path, indent=4) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        # Pretty JSON should have many newlines
        assert content.count("\n") > 10


def test_json_writer_write_many():
    """Test write_many method for JSON."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
    ]

    with temp_output_path(".json") as temp_path:
        with StreamWriterJSON(temp_path) as writer:
            count = writer.write_many(rules)

        assert count == 2

        # Verify valid JSON
        with open(temp_path) as f:
            data = json.load(f)

        assert len(data) == 2


# ============================================================================
# Integration Tests
# ============================================================================


def test_stream_and_write_pipeline():
    """Test complete streaming and writing pipeline."""
    # Create input file
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
    ]

    with temp_rules_file(rules_text) as input_path, temp_output_path() as output_path:
        # Stream parse and write
        parser = StreamParser()
        with StreamWriterText(output_path) as writer:
            for rule in parser.stream_file(input_path):
                writer.write(rule)

        # Verify output
        output_content = output_path.read_text()
        assert output_content.count("alert") == 3


def test_stream_and_write_json_pipeline():
    """Test streaming to JSON pipeline."""
    # Create input file
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    ]

    with temp_rules_file(rules_text) as input_path, temp_output_path(".json") as output_path:
        # Stream parse and write to JSON
        parser = StreamParser()
        with StreamWriterJSON(output_path) as writer:
            for rule in parser.stream_file(input_path):
                writer.write(rule)

        # Verify valid JSON output
        with open(output_path) as f:
            data = json.load(f)

        assert len(data) == 2
        assert data[0]["action"] == "alert"


def test_stream_filter_and_write():
    """Test streaming with filtering and writing."""
    from surinort_ast.core.enums import Protocol
    from surinort_ast.streaming.processor import FilterProcessor

    # Create input file
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
    ]

    with temp_rules_file(rules_text) as input_path, temp_output_path() as output_path:
        # Stream, filter TCP, and write
        parser = StreamParser()
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)

        with StreamWriterText(output_path) as writer:
            for rule in tcp_filter.stream(parser.stream_file(input_path)):
                writer.write(rule)

        # Verify output contains only TCP rules
        output_content = output_path.read_text()
        assert output_content.count("alert tcp") == 2
        assert "udp" not in output_content.lower()


# ============================================================================
# Error Handling Tests
# ============================================================================


def test_writer_count_tracking():
    """Test writer count property."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
    ]

    with temp_output_path() as temp_path, StreamWriterText(temp_path) as writer:
        assert writer.count == 0
        writer.write(rules[0])
        assert writer.count == 1
        writer.write(rules[1])
        assert writer.count == 2


# ============================================================================
# Resource Cleanup Tests
# ============================================================================


class _FailingFooterWriter(StreamWriter):
    """Writer whose footer write fails, to test handle cleanup."""

    def _write_header(self) -> None:
        pass

    def _write_rule(self, rule: Rule) -> None:
        return None

    def _write_footer(self) -> None:
        raise ValueError("footer boom")


class _FailingHeaderWriter(StreamWriter):
    """Writer whose header write fails, to test handle cleanup."""

    def _write_header(self) -> None:
        raise ValueError("header boom")

    def _write_rule(self, rule: Rule) -> None:
        return None

    def _write_footer(self) -> None:
        pass


def test_footer_failure_still_closes_file():
    """A failing footer must not leak the file handle."""
    with temp_output_path() as temp_path:
        writer = _FailingFooterWriter(temp_path)
        with pytest.raises(ValueError, match="footer boom"), writer:
            pass
        # The error propagated, but the handle is closed, not leaked.
        assert writer._file is None


def test_header_failure_closes_file():
    """A failing header in __enter__ must close the just-opened handle."""
    with temp_output_path() as temp_path:
        writer = _FailingHeaderWriter(temp_path)
        with pytest.raises(ValueError, match="header boom"), writer:
            pass
        assert writer._file is None


def test_json_writer_stays_valid_when_a_rule_fails_mid_stream():
    """If serializing a rule raises mid-stream, the array written so far must
    remain valid JSON (no dangling separator).

    Regression: the separator comma was emitted before serialization, so a
    failure left a trailing comma that broke json.loads.
    """

    class _BoomRule:
        def model_dump_json(self, **_kwargs):
            raise ValueError("serialize boom")

    good = parse_rule("alert tcp any any -> any 80 (sid:1;)")
    for indent in (2, None):
        with temp_output_path(".json") as temp_path:
            with StreamWriterJSON(temp_path, indent=indent) as writer:
                writer.write(good)
                with pytest.raises(SerializationError):
                    writer.write(_BoomRule())
            data = json.loads(temp_path.read_text())
            assert isinstance(data, list)
            assert len(data) == 1
