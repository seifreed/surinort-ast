"""
Integration tests for streaming API.

This module tests end-to-end streaming workflows with real-world scenarios.

Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path

import pytest

from surinort_ast.api import parse_file_streaming
from surinort_ast.core.enums import Action, Protocol
from surinort_ast.streaming import (
    AggregateProcessor,
    FilterProcessor,
    StreamParser,
    StreamWriter,
    TransformProcessor,
    ValidateProcessor,
)

# ============================================================================
# End-to-End Streaming Tests
# ============================================================================


def test_streaming_api_integration():
    """Test complete streaming API integration."""
    # Create test file
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(100)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        # Test streaming API
        count = 0
        for rule in parse_file_streaming(temp_path):
            assert rule.action == Action.ALERT
            count += 1

        assert count == 100
    finally:
        temp_path.unlink()


def test_streaming_batch_api_integration():
    """Test batch streaming API integration."""
    rules_text = [f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)' for i in range(100)]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        # Test batch streaming
        batch_count = 0
        total_rules = 0

        for batch in parse_file_streaming(temp_path, batch_size=25):
            batch_count += 1
            total_rules += batch.success_count

        assert batch_count == 4  # 100 rules / 25 per batch
        assert total_rules == 100
    finally:
        temp_path.unlink()


def test_complete_processing_pipeline():
    """Test complete rule processing pipeline."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
        'alert tcp any any -> any 22 (msg:"SSH"; sid:4;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        output_path = Path(f.name)

    try:
        # Build pipeline: parse -> filter TCP -> validate -> aggregate -> write
        parser = StreamParser()
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        validator = ValidateProcessor()
        aggregator = AggregateProcessor()

        pipeline = tcp_filter | validator | aggregator

        with StreamWriter.text(output_path) as writer:
            for rule in pipeline.stream(parser.stream_file(input_path)):
                writer.write(rule)

        # Verify results
        assert writer.count == 3  # Only TCP rules
        assert aggregator.stats.total_rules == 3
        assert aggregator.stats.rules_by_protocol[Protocol.TCP] == 3

        # Verify output file
        output_content = output_path.read_text()
        assert output_content.count("alert tcp") == 3
    finally:
        input_path.unlink()
        output_path.unlink()


def test_transform_and_write_pipeline():
    """Test transformation and writing pipeline."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        output_path = Path(f.name)

    try:
        # Transform alert to drop
        parser = StreamParser()
        transformer = TransformProcessor(lambda r: r.model_copy(update={"action": Action.DROP}))

        with StreamWriter.text(output_path) as writer:
            for rule in transformer.stream(parser.stream_file(input_path)):
                writer.write(rule)

        # Verify all rules are now drop
        output_content = output_path.read_text()
        assert output_content.count("drop tcp") == 2
        assert "alert" not in output_content
    finally:
        input_path.unlink()
        output_path.unlink()


def test_filter_aggregate_report():
    """Test filtering with aggregation reporting."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
        'drop tcp any any -> any 22 (msg:"SSH"; sid:4;)',
        'alert udp any any -> any 123 (msg:"NTP"; sid:5;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()

        # Filter alert rules only
        alert_filter = FilterProcessor(lambda r: r.action == Action.ALERT)
        aggregator = AggregateProcessor()

        pipeline = alert_filter | aggregator

        rules = list(pipeline.stream(parser.stream_file(temp_path)))

        # Verify aggregation
        assert len(rules) == 4  # 4 alert rules
        assert aggregator.stats.total_rules == 4
        assert aggregator.stats.rules_by_action[Action.ALERT] == 4
        assert aggregator.stats.rules_by_protocol[Protocol.TCP] == 2
        assert aggregator.stats.rules_by_protocol[Protocol.UDP] == 2

        # Verify stats dict
        stats_dict = aggregator.stats.to_dict()
        assert stats_dict["total_rules"] == 4
        assert stats_dict["unique_sids"] == 4
    finally:
        temp_path.unlink()


# ============================================================================
# Memory Efficiency Tests
# ============================================================================


@pytest.mark.slow
def test_large_file_streaming():
    """Test streaming a large file without memory issues."""
    # Generate large file
    num_rules = 10000

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for i in range(num_rules):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
        temp_path = Path(f.name)

    try:
        # Stream with minimal memory options
        parser = StreamParser(include_raw_text=False, track_locations=False)

        count = 0
        for _rule in parser.stream_file(temp_path):
            count += 1

        assert count == num_rules
    finally:
        temp_path.unlink()


@pytest.mark.slow
def test_large_file_batch_streaming():
    """Test batch streaming a large file."""
    num_rules = 10000
    batch_size = 500

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for i in range(num_rules):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')
        temp_path = Path(f.name)

    try:
        parser = StreamParser(include_raw_text=False, track_locations=False)

        batch_count = 0
        total_rules = 0

        for batch in parser.stream_file_batched(temp_path, batch_size=batch_size):
            batch_count += 1
            total_rules += batch.success_count

        assert batch_count == num_rules // batch_size
        assert total_rules == num_rules
    finally:
        temp_path.unlink()


# ============================================================================
# Real-World Scenario Tests
# ============================================================================


def test_rule_conversion_workflow():
    """Test rule format conversion workflow."""
    # Input: Suricata rules
    # Output: Modified rules with different action

    rules_text = [
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP Request"; sid:1;)',
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"HTTPS Request"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        input_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        output_path = Path(f.name)

    try:
        # Workflow: parse -> validate -> export to JSON
        parser = StreamParser()
        validator = ValidateProcessor()

        # Export to JSON
        with StreamWriter.json(json_path) as json_writer:
            for rule in validator.stream(parser.stream_file(input_path)):
                json_writer.write(rule)

        assert json_writer.count == 2

        # Transform and export to text
        transformer = TransformProcessor(lambda r: r.model_copy(update={"action": Action.DROP}))

        with StreamWriter.text(output_path) as text_writer:
            for rule in transformer.stream(parser.stream_file(input_path)):
                text_writer.write(rule)

        # Verify outputs
        output_content = output_path.read_text()
        assert "drop tcp" in output_content
    finally:
        input_path.unlink()
        json_path.unlink()
        output_path.unlink()


def test_rule_analysis_workflow():
    """Test rule analysis and reporting workflow."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; content:"GET"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; pcre:"/test/"; sid:2;)',
        'alert udp any any -> any 53 (msg:"DNS"; content:"query"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()

        # Custom aggregator: count content options
        def count_content(stats, rule):
            content_count = sum(1 for opt in rule.options if opt.node_type == "ContentOption")
            stats.custom_stats["total_content"] = (
                stats.custom_stats.get("total_content", 0) + content_count
            )

        aggregator = AggregateProcessor(custom_aggregators=[count_content])

        # Analyze rules
        list(aggregator.stream(parser.stream_file(temp_path)))

        # Generate report
        stats = aggregator.stats.to_dict()

        assert stats["total_rules"] == 3
        assert stats["custom_stats"]["total_content"] == 2
        assert stats["rules_by_protocol"]["tcp"] == 2
        assert stats["rules_by_protocol"]["udp"] == 1
    finally:
        temp_path.unlink()


# ============================================================================
# Error Recovery Tests
# ============================================================================


def test_streaming_with_mixed_valid_invalid():
    """Test streaming with mix of valid and invalid rules."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Valid 1"; sid:1;)',
        "invalid rule syntax here",
        'alert tcp any any -> any 443 (msg:"Valid 2"; sid:2;)',
        "another invalid rule",
        'alert tcp any any -> any 22 (msg:"Valid 3"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()

        # With skip_errors=True
        valid_rules = list(parser.stream_file(temp_path, skip_errors=True))
        assert len(valid_rules) == 3

        # Count total attempts
        all_attempts = list(parser.stream_file(temp_path, skip_errors=False))
        assert len(all_attempts) >= 3  # At least the valid ones
    finally:
        temp_path.unlink()
