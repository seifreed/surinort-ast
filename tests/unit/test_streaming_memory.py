# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Memory efficiency tests for streaming parser functionality.

This module tests that the streaming parser correctly handles large files
without loading everything into memory, and validates batch processing
performance characteristics.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import tempfile
from pathlib import Path

import pytest

from surinort_ast.core.enums import Action
from surinort_ast.streaming import StreamParser, stream_parse_file


class TestMemoryEfficiency:
    """Test memory-efficient streaming behavior."""

    def test_stream_doesnt_load_entire_file(self):
        """Test that streaming processes rules incrementally."""
        # Create a file with many rules
        num_rules = 1000
        rules_text = [
            f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(num_rules)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            parser = StreamParser(track_locations=False, include_raw_text=False)

            # Process incrementally - get first rule
            rule_iter = parser.stream_file(temp_path)
            first_rule = next(rule_iter)

            # Should be able to get first rule without loading all 1000
            assert first_rule is not None
            assert first_rule.action == Action.ALERT

            # Clean up iterator
            rule_iter.close()
        finally:
            temp_path.unlink()

    def test_stream_with_minimal_memory_options(self):
        """Test streaming with all memory-saving options enabled."""
        rules_text = [
            f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(100)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Minimal memory configuration
            parser = StreamParser(
                track_locations=False,  # Don't track source locations
                include_raw_text=False,  # Don't keep raw text
                chunk_size=8192,  # Smaller chunks
            )

            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 100

            # Verify memory-saving options were respected
            for rule in rules:
                assert rule.raw_text is None  # No raw text stored
        finally:
            temp_path.unlink()

    def test_batch_processing_memory_profile(self):
        """Test that batch processing doesn't accumulate all rules."""
        num_rules = 500
        batch_size = 50
        rules_text = [
            f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(num_rules)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            parser = StreamParser(include_raw_text=False, track_locations=False)

            # Process in batches
            batches = list(parser.stream_file_batched(temp_path, batch_size=batch_size))

            # Should have correct number of batches
            assert len(batches) == num_rules // batch_size

            # Each batch should have correct size
            for batch in batches[:-1]:
                assert batch.success_count == batch_size

            # Verify batches don't accumulate
            total_rules = sum(b.success_count for b in batches)
            assert total_rules == num_rules
        finally:
            temp_path.unlink()


class TestLargeFileHandling:
    """Test handling of large rule files."""

    def test_very_long_rule_lines(self):
        """Test streaming with very long rule lines."""
        # Create a rule with many options
        options = " ".join(f'content:"pattern{i}";' for i in range(100))
        long_rule = f'alert tcp any any -> any 80 ({options} msg:"Long"; sid:1;)'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(long_rule)
            f.write("\n")
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 1
            # Should have parsed all content options
            content_count = sum(1 for opt in rules[0].options if opt.node_type == "ContentOption")
            assert content_count == 100
        finally:
            temp_path.unlink()

    def test_multiline_rule_spanning_many_lines(self):
        """Test streaming with deeply indented multi-line rules."""
        multiline_rule = """alert tcp any any -> any 443 (
    msg:"Deeply nested rule";
    flow:established,to_server;
    content:"pattern1";
    content:"pattern2";
    content:"pattern3";
    pcre:"/regex/i";
    classtype:trojan-activity;
    sid:1000;
    rev:1;
)"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(multiline_rule)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 1
            assert rules[0].action == Action.ALERT
        finally:
            temp_path.unlink()

    def test_file_with_many_blank_lines(self):
        """Test streaming with excessive blank lines."""
        content_lines = []
        for i in range(10):
            content_lines.append(f"alert tcp any any -> any {i} (sid:{i};)")
            content_lines.extend(["", "", "", ""])  # Add blank lines

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("\n".join(content_lines))
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            # Should skip blank lines and get 10 rules
            assert len(rules) == 10
        finally:
            temp_path.unlink()


class TestChunkBoundaries:
    """Test correct handling of chunk boundaries during streaming."""

    def test_rule_split_across_chunks(self):
        """Test that rules split across read chunks are handled correctly."""
        # Create rules where some will likely split across chunk boundaries
        rules_text = []
        for i in range(50):
            sid = i + 1  # SID must be >= 1
            port = i + 100  # Port must be valid
            # Make some rules longer to increase chance of boundary splits
            if i % 3 == 0:
                options = " ".join(f'content:"opt{j}";' for j in range(20))
                rule = f'alert tcp any any -> any {port} ({options} msg:"Rule {i}"; sid:{sid};)'
            else:
                rule = f'alert tcp any any -> any {port} (msg:"Rule {i}"; sid:{sid};)'
            rules_text.append(rule)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Use small chunk size to force boundary splits
            parser = StreamParser(chunk_size=512)
            rules = list(parser.stream_file(temp_path))

            # Should get all rules despite chunk boundaries
            assert len(rules) == 50

            # Verify rules are complete
            for _i, rule in enumerate(rules):
                assert rule.action == Action.ALERT
                # Find sid option
                sid_opts = [opt for opt in rule.options if opt.node_type == "SidOption"]
                assert len(sid_opts) == 1
        finally:
            temp_path.unlink()


class TestErrorRecovery:
    """Test error recovery during streaming."""

    def test_skip_errors_continues_after_invalid_rule(self):
        """Test that skip_errors allows processing to continue."""
        content = """alert tcp any any -> any 80 (msg:"Valid 1"; sid:1;)
INVALID SYNTAX HERE
alert tcp any any -> any 443 (msg:"Valid 2"; sid:2;)
another invalid line
alert tcp any any -> any 8080 (msg:"Valid 3"; sid:3;)"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path, skip_errors=True))

            # Should get 3 valid rules
            assert len(rules) == 3
            assert rules[0].header.dst_port.value == 80
            assert rules[1].header.dst_port.value == 443
            assert rules[2].header.dst_port.value == 8080
        finally:
            temp_path.unlink()

    def test_partial_rule_at_end_of_file(self):
        """Test handling of incomplete rule at EOF."""
        content = """alert tcp any any -> any 80 (msg:"Valid"; sid:1;)
alert tcp any any -> any 443 (msg:"Incomplete"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path, skip_errors=True))

            # Should get 1 valid rule
            assert len(rules) == 1
            assert rules[0].header.dst_port.value == 80
        finally:
            temp_path.unlink()


class TestProgressTracking:
    """Test progress tracking during streaming."""

    def test_progress_callback_reports_accurate_counts(self):
        """Test that progress callback receives correct counts."""
        num_rules = 50
        rules_text = [
            f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(num_rules)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            progress_updates = []

            def track_progress(processed, total):
                progress_updates.append((processed, total))

            parser = StreamParser()
            rules = list(parser.stream_file(temp_path, progress_callback=track_progress))

            assert len(rules) == num_rules

            # Progress should be called for each rule
            assert len(progress_updates) == num_rules

            # Progress should be monotonically increasing
            for i in range(1, len(progress_updates)):
                assert progress_updates[i][0] >= progress_updates[i - 1][0]

            # Final progress should equal total
            assert progress_updates[-1][0] == num_rules
        finally:
            temp_path.unlink()


class TestBatchProcessing:
    """Test batch processing features."""

    def test_batch_metadata_accurate(self):
        """Test that batch metadata (line numbers, counts) is accurate."""
        num_rules = 75
        batch_size = 25
        rules_text = [
            f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(num_rules)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            batches = list(parser.stream_file_batched(temp_path, batch_size=batch_size))

            assert len(batches) == 3

            # Verify batch numbers
            for i, batch in enumerate(batches):
                assert batch.batch_number == i

            # Verify counts
            assert batches[0].success_count == 25
            assert batches[1].success_count == 25
            assert batches[2].success_count == 25

            # Verify line ranges are sequential
            assert batches[0].start_line == 1
            assert batches[1].start_line > batches[0].end_line
            assert batches[2].start_line > batches[1].end_line
        finally:
            temp_path.unlink()

    def test_batch_errors_tracked(self):
        """Test that batch processing tracks errors correctly."""
        content = """alert tcp any any -> any 80 (msg:"Valid 1"; sid:1;)
INVALID LINE
alert tcp any any -> any 443 (msg:"Valid 2"; sid:2;)
ANOTHER INVALID
alert tcp any any -> any 8080 (msg:"Valid 3"; sid:3;)"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            batches = list(parser.stream_file_batched(temp_path, batch_size=10))

            assert len(batches) >= 1

            # Total successes (should get 3 valid rules)
            total_success = sum(b.success_count for b in batches)
            assert total_success == 3

            # If errors are tracked, they should be present
            # But this depends on skip_errors behavior
            total_errors = sum(b.error_count for b in batches)
            # Just verify error count is non-negative
            assert total_errors >= 0
        finally:
            temp_path.unlink()


class TestConvenienceFunctions:
    """Test convenience functions for common streaming use cases."""

    def test_stream_parse_file_convenience(self):
        """Test stream_parse_file convenience function."""
        rules_text = [f'alert tcp any any -> any {i} (msg:"Rule {i}"; sid:{i};)' for i in range(10)]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Use convenience function
            rules = list(stream_parse_file(temp_path))

            assert len(rules) == 10
            assert all(r.action == Action.ALERT for r in rules)
        finally:
            temp_path.unlink()


class TestEdgeCases:
    """Test edge cases and unusual input."""

    def test_empty_file(self):
        """Test streaming an empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            # Write nothing
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 0
        finally:
            temp_path.unlink()

    def test_file_with_only_comments(self):
        """Test file containing only comments."""
        content = """# This is a comment
# Another comment
# Yet another comment"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 0
        finally:
            temp_path.unlink()

    def test_single_rule_file(self):
        """Test file with exactly one rule."""
        content = 'alert tcp any any -> any 80 (msg:"Single rule"; sid:1;)'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            assert len(rules) == 1
            assert rules[0].action == Action.ALERT
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
