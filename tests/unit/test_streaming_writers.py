"""
Tests for streaming writers.

This module tests the streaming writer APIs for incremental serialization.

Licensed under GNU General Public License v3.0
"""

import json
import tempfile
from pathlib import Path

import pytest

from surinort_ast.api import parse_rule
from surinort_ast.streaming import StreamParser, StreamWriter, StreamWriterJSON, StreamWriterText

# ============================================================================
# Text Writer Tests
# ============================================================================


def test_text_writer_basic():
    """Test basic text writer functionality."""
    rule1 = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
    rule2 = parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterText(temp_path) as writer:
            writer.write(rule1)
            writer.write(rule2)

        # Read back and verify
        with open(temp_path) as f:
            content = f.read()

        assert "alert tcp" in content
        assert "sid:1" in content
        assert "sid:2" in content
    finally:
        temp_path.unlink()


def test_text_writer_context_manager():
    """Test text writer as context manager."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriter.text(temp_path) as writer:
            writer.write(rule)
            assert writer.count == 1

        # Verify file exists and has content
        assert temp_path.exists()
        content = temp_path.read_text()
        assert "alert tcp" in content
    finally:
        temp_path.unlink()


def test_text_writer_write_many():
    """Test write_many method."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
        parse_rule('alert tcp any any -> any 22 (msg:"Rule 3"; sid:3;)'),
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterText(temp_path) as writer:
            count = writer.write_many(rules)

        assert count == 3

        # Verify content
        content = temp_path.read_text()
        assert content.count("alert tcp") == 3
    finally:
        temp_path.unlink()


def test_text_writer_stable_formatting():
    """Test stable formatting option."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterText(temp_path, stable=True) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        assert "alert tcp" in content
    finally:
        temp_path.unlink()


def test_text_writer_header_footer():
    """Test header and footer comments."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterText(
            temp_path, header_comment="Generated rules", footer_comment="End of rules"
        ) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        assert "# Generated rules" in content
        assert "# End of rules" in content
    finally:
        temp_path.unlink()


def test_text_writer_without_context_manager():
    """Test that writing without context manager raises error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        writer = StreamWriterText(temp_path)
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        with pytest.raises(RuntimeError, match="Writer not opened"):
            writer.write(rule)
    finally:
        temp_path.unlink()


# ============================================================================
# JSON Writer Tests
# ============================================================================


def test_json_writer_basic():
    """Test basic JSON writer functionality."""
    rule1 = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
    rule2 = parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = Path(f.name)

    try:
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
    finally:
        temp_path.unlink()


def test_json_writer_context_manager():
    """Test JSON writer as context manager."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriter.json(temp_path) as writer:
            writer.write(rule)
            assert writer.count == 1

        # Verify valid JSON
        with open(temp_path) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 1
    finally:
        temp_path.unlink()


def test_json_writer_compact():
    """Test compact JSON formatting."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterJSON(temp_path, indent=None) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        # Compact JSON should have fewer newlines
        assert content.count("\n") < 10
    finally:
        temp_path.unlink()


def test_json_writer_pretty():
    """Test pretty JSON formatting."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterJSON(temp_path, indent=4) as writer:
            writer.write(rule)

        content = temp_path.read_text()
        # Pretty JSON should have many newlines
        assert content.count("\n") > 10
    finally:
        temp_path.unlink()


def test_json_writer_write_many():
    """Test write_many method for JSON."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterJSON(temp_path) as writer:
            count = writer.write_many(rules)

        assert count == 2

        # Verify valid JSON
        with open(temp_path) as f:
            data = json.load(f)

        assert len(data) == 2
    finally:
        temp_path.unlink()


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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        output_path = Path(f.name)

    try:
        # Stream parse and write
        parser = StreamParser()
        with StreamWriterText(output_path) as writer:
            for rule in parser.stream_file(input_path):
                writer.write(rule)

        # Verify output
        output_content = output_path.read_text()
        assert output_content.count("alert") == 3
    finally:
        input_path.unlink()
        output_path.unlink()


def test_stream_and_write_json_pipeline():
    """Test streaming to JSON pipeline."""
    # Create input file
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_path = Path(f.name)

    try:
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
    finally:
        input_path.unlink()
        output_path.unlink()


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

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        output_path = Path(f.name)

    try:
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
    finally:
        input_path.unlink()
        output_path.unlink()


# ============================================================================
# Error Handling Tests
# ============================================================================


def test_writer_count_tracking():
    """Test writer count property."""
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)'),
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)

    try:
        with StreamWriterText(temp_path) as writer:
            assert writer.count == 0
            writer.write(rules[0])
            assert writer.count == 1
            writer.write(rules[1])
            assert writer.count == 2
    finally:
        temp_path.unlink()
