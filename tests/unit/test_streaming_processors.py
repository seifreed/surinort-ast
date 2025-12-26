"""
Tests for streaming processors.

This module tests the stream processor APIs for filtering, transforming,
and validating rules during streaming.

Licensed under GNU General Public License v3.0
"""

import tempfile
from pathlib import Path

from surinort_ast.core.diagnostics import Diagnostic, DiagnosticLevel
from surinort_ast.core.enums import Action, Protocol
from surinort_ast.streaming import StreamParser
from surinort_ast.streaming.processor import (
    AggregateProcessor,
    FilterProcessor,
    TransformProcessor,
    ValidateProcessor,
)

# ============================================================================
# Filter Processor Tests
# ============================================================================


def test_filter_processor_basic():
    """Test basic filtering."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Filter TCP only
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        tcp_rules = list(tcp_filter.stream(input_stream))

        assert len(tcp_rules) == 2
        assert all(r.header.protocol == Protocol.TCP for r in tcp_rules)
    finally:
        temp_path.unlink()


def test_filter_processor_by_action():
    """Test filtering by action."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Alert"; sid:1;)',
        'drop tcp any any -> any 443 (msg:"Drop"; sid:2;)',
        'alert udp any any -> any 53 (msg:"Alert DNS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Filter alerts only
        alert_filter = FilterProcessor(lambda r: r.action == Action.ALERT)
        alert_rules = list(alert_filter.stream(input_stream))

        assert len(alert_rules) == 2
        assert all(r.action == Action.ALERT for r in alert_rules)
    finally:
        temp_path.unlink()


def test_filter_processor_by_sid():
    """Test filtering by SID range."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1000;)',
        'alert tcp any any -> any 80 (msg:"Rule 2"; sid:2000;)',
        'alert tcp any any -> any 80 (msg:"Rule 3"; sid:3000;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Filter SID range
        def sid_in_range(rule):
            for opt in rule.options:
                if opt.node_type == "SidOption" and 1500 <= opt.value <= 2500:
                    return True
            return False

        sid_filter = FilterProcessor(sid_in_range)
        filtered_rules = list(sid_filter.stream(input_stream))

        assert len(filtered_rules) == 1
    finally:
        temp_path.unlink()


def test_filter_processor_error_handling():
    """Test filter processor error handling."""
    rules_text = ['alert tcp any any -> any 80 (msg:"Test"; sid:1;)']

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Filter with error (should handle gracefully)
        def buggy_predicate(rule):
            raise ValueError("Intentional error")

        error_filter = FilterProcessor(buggy_predicate)
        filtered_rules = list(error_filter.stream(input_stream))

        # Should filter out all rules due to errors
        assert len(filtered_rules) == 0
    finally:
        temp_path.unlink()


# ============================================================================
# Transform Processor Tests
# ============================================================================


def test_transform_processor_basic():
    """Test basic transformation."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Test"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Transform alert to drop
        def alert_to_drop(rule):
            if rule.action == Action.ALERT:
                return rule.model_copy(update={"action": Action.DROP})
            return rule

        transformer = TransformProcessor(alert_to_drop)
        transformed_rules = list(transformer.stream(input_stream))

        assert len(transformed_rules) == 2
        assert all(r.action == Action.DROP for r in transformed_rules)
    finally:
        temp_path.unlink()


def test_transform_processor_error_handling():
    """Test transform processor error handling."""
    rules_text = ['alert tcp any any -> any 80 (msg:"Test"; sid:1;)']

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Transform with error
        def buggy_transform(rule):
            raise ValueError("Intentional error")

        transformer = TransformProcessor(buggy_transform)
        transformed_rules = list(transformer.stream(input_stream))

        # Should filter out all rules due to errors
        assert len(transformed_rules) == 0
    finally:
        temp_path.unlink()


# ============================================================================
# Validate Processor Tests
# ============================================================================


def test_validate_processor_basic():
    """Test basic validation."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        "alert tcp any any -> any 80 (sid:2;)",  # Missing msg
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        validator = ValidateProcessor()
        validated_rules = list(validator.stream(input_stream))

        assert len(validated_rules) == 2
        # Second rule should have diagnostic about missing msg
        assert len(validated_rules[1].diagnostics) > 0
    finally:
        temp_path.unlink()


def test_validate_processor_strict_mode():
    """Test strict validation mode."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        "alert tcp any any -> any 80 (sid:2;)",  # Missing msg
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Strict mode should filter out invalid rules
        validator = ValidateProcessor(strict=True)
        validated_rules = list(validator.stream(input_stream))

        # Note: Missing msg is a warning, not error, so both should pass
        assert len(validated_rules) == 2
    finally:
        temp_path.unlink()


def test_validate_processor_custom_validators():
    """Test custom validators."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; sid:1000;)',
        'alert tcp any any -> any 80 (msg:"Test"; sid:2000000;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Custom validator: SID must be >= 1000000
        def check_sid_range(rule):
            for opt in rule.options:
                if opt.node_type == "SidOption" and opt.value < 1000000:
                    return [
                        Diagnostic(
                            level=DiagnosticLevel.ERROR,
                            message="SID must be >= 1000000 for custom rules",
                        )
                    ]
            return []

        validator = ValidateProcessor(custom_validators=[check_sid_range])
        validated_rules = list(validator.stream(input_stream))

        assert len(validated_rules) == 2
        # First rule should have error diagnostic
        has_error = any(d.level == DiagnosticLevel.ERROR for d in validated_rules[0].diagnostics)
        assert has_error
    finally:
        temp_path.unlink()


# ============================================================================
# Aggregate Processor Tests
# ============================================================================


def test_aggregate_processor_basic():
    """Test basic aggregation."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        aggregator = AggregateProcessor()
        rules = list(aggregator.stream(input_stream))

        assert len(rules) == 3
        assert aggregator.stats.total_rules == 3
        assert aggregator.stats.rules_by_protocol[Protocol.TCP] == 2
        assert aggregator.stats.rules_by_protocol[Protocol.UDP] == 1
        assert aggregator.stats.rules_by_action[Action.ALERT] == 3
    finally:
        temp_path.unlink()


def test_aggregate_processor_sids():
    """Test SID aggregation."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        'alert tcp any any -> any 80 (msg:"Rule 2"; sid:2;)',
        'alert tcp any any -> any 80 (msg:"Rule 3"; sid:1;)',  # Duplicate SID
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        aggregator = AggregateProcessor()
        rules = list(aggregator.stream(input_stream))

        assert len(rules) == 3
        assert len(aggregator.stats.unique_sids) == 2  # Only 2 unique SIDs
    finally:
        temp_path.unlink()


def test_aggregate_processor_custom_aggregators():
    """Test custom aggregation functions."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; content:"abc"; sid:1;)',
        'alert tcp any any -> any 80 (msg:"Test"; pcre:"/test/"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Custom aggregator: count content options
        def count_content(stats, rule):
            content_count = sum(1 for opt in rule.options if opt.node_type == "ContentOption")
            stats.custom_stats["total_content"] = (
                stats.custom_stats.get("total_content", 0) + content_count
            )

        aggregator = AggregateProcessor(custom_aggregators=[count_content])
        rules = list(aggregator.stream(input_stream))

        assert len(rules) == 2
        assert aggregator.stats.custom_stats.get("total_content", 0) == 1
    finally:
        temp_path.unlink()


def test_aggregate_processor_reset():
    """Test aggregator reset."""
    rules_text = ['alert tcp any any -> any 80 (msg:"Test"; sid:1;)']

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        aggregator = AggregateProcessor()
        list(aggregator.stream(input_stream))

        assert aggregator.stats.total_rules == 1

        # Reset
        aggregator.reset()
        assert aggregator.stats.total_rules == 0
    finally:
        temp_path.unlink()


def test_aggregate_stats_to_dict():
    """Test stats to_dict conversion."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
        'alert udp any any -> any 53 (msg:"Test"; sid:2;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        aggregator = AggregateProcessor()
        list(aggregator.stream(input_stream))

        stats_dict = aggregator.stats.to_dict()

        assert stats_dict["total_rules"] == 2
        assert "tcp" in stats_dict["rules_by_protocol"]
        assert "udp" in stats_dict["rules_by_protocol"]
    finally:
        temp_path.unlink()


# ============================================================================
# Chained Processor Tests
# ============================================================================


def test_chained_processor_filter_transform():
    """Test chaining filter and transform processors."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Chain: filter TCP -> transform to DROP
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        drop_transformer = TransformProcessor(
            lambda r: r.model_copy(update={"action": Action.DROP})
        )

        pipeline = tcp_filter | drop_transformer
        result_rules = list(pipeline.stream(input_stream))

        assert len(result_rules) == 2
        assert all(r.action == Action.DROP for r in result_rules)
        assert all(r.header.protocol == Protocol.TCP for r in result_rules)
    finally:
        temp_path.unlink()


def test_chained_processor_filter_aggregate():
    """Test chaining filter and aggregate processors."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Chain: filter TCP -> aggregate
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        aggregator = AggregateProcessor()

        pipeline = tcp_filter | aggregator
        result_rules = list(pipeline.stream(input_stream))

        assert len(result_rules) == 2
        assert aggregator.stats.total_rules == 2
        assert aggregator.stats.rules_by_protocol[Protocol.TCP] == 2
    finally:
        temp_path.unlink()


def test_chained_processor_complex_pipeline():
    """Test complex multi-stage pipeline."""
    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
        'drop tcp any any -> any 22 (msg:"SSH"; sid:4;)',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        for rule in rules_text:
            f.write(rule + "\n")
        temp_path = Path(f.name)

    try:
        parser = StreamParser()
        input_stream = parser.stream_file(temp_path)

        # Complex pipeline: filter TCP -> filter ALERT -> validate -> aggregate
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        alert_filter = FilterProcessor(lambda r: r.action == Action.ALERT)
        validator = ValidateProcessor()
        aggregator = AggregateProcessor()

        pipeline = tcp_filter | alert_filter | validator | aggregator
        result_rules = list(pipeline.stream(input_stream))

        assert len(result_rules) == 2  # Only TCP ALERT rules
        assert aggregator.stats.total_rules == 2
    finally:
        temp_path.unlink()
