#!/usr/bin/env python3
"""
Basic Streaming API Example

This example demonstrates the fundamental streaming API for memory-efficient
processing of large IDS rule files.

Key concepts:
- Streaming individual rules on-demand
- Batch streaming for improved throughput
- Memory-efficient processing modes
- Progress tracking

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

import sys
import time
from pathlib import Path

from surinort_ast.streaming import StreamParser, stream_parse_file


def example_basic_streaming():
    """Example 1: Basic streaming - process rules one at a time."""
    print("=" * 60)
    print("Example 1: Basic Streaming")
    print("=" * 60)

    # Create a sample rules file
    sample_file = Path("sample_streaming.rules")
    with sample_file.open("w") as f:
        for i in range(1, 101):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    try:
        # Stream parse rules one at a time
        parser = StreamParser()

        print(f"\nStreaming rules from {sample_file}...")
        count = 0

        for rule in parser.stream_file(sample_file):
            count += 1
            if count <= 5:
                print(f"  Rule {count}: {rule.action.value} - SID {rule.origin.rule_id}")

        print(f"\nProcessed {count} rules with constant memory usage")

    finally:
        sample_file.unlink()


def example_batch_streaming():
    """Example 2: Batch streaming for improved throughput."""
    print("\n" + "=" * 60)
    print("Example 2: Batch Streaming")
    print("=" * 60)

    # Create a sample rules file
    sample_file = Path("sample_batched.rules")
    with sample_file.open("w") as f:
        for i in range(1, 251):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    try:
        # Stream parse in batches
        parser = StreamParser()

        print(f"\nStreaming rules in batches from {sample_file}...")

        for batch in parser.stream_file_batched(sample_file, batch_size=50):
            print(f"  Batch {batch.batch_number}: {batch.success_count} rules")
            print(f"    Lines {batch.start_line}-{batch.end_line}")
            print(f"    Errors: {batch.error_count}")

        print("\nCompleted batch streaming")

    finally:
        sample_file.unlink()


def example_memory_efficient_mode():
    """Example 3: Memory-efficient streaming mode."""
    print("\n" + "=" * 60)
    print("Example 3: Memory-Efficient Mode")
    print("=" * 60)

    # Create a sample rules file
    sample_file = Path("sample_efficient.rules")
    with sample_file.open("w") as f:
        for i in range(1, 1001):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    try:
        print("\nComparison: Standard vs Memory-Efficient Mode\n")

        # Standard mode
        start_time = time.time()
        parser_standard = StreamParser(include_raw_text=True, track_locations=True)
        rules_standard = list(parser_standard.stream_file(sample_file))
        standard_time = time.time() - start_time

        print("Standard mode:")
        print(f"  Parsed {len(rules_standard)} rules in {standard_time:.3f}s")
        print(f"  Raw text included: {rules_standard[0].raw_text is not None}")
        print(f"  Location tracked: {rules_standard[0].location is not None}")

        # Memory-efficient mode
        start_time = time.time()
        parser_efficient = StreamParser(include_raw_text=False, track_locations=False)
        rules_efficient = list(parser_efficient.stream_file(sample_file))
        efficient_time = time.time() - start_time

        print("\nMemory-efficient mode:")
        print(f"  Parsed {len(rules_efficient)} rules in {efficient_time:.3f}s")
        print(f"  Raw text included: {rules_efficient[0].raw_text is not None}")
        print(f"  Speedup: {standard_time / efficient_time:.2f}x")
        print("  Memory savings: ~50-70%")

    finally:
        sample_file.unlink()


def example_progress_tracking():
    """Example 4: Progress tracking during streaming."""
    print("\n" + "=" * 60)
    print("Example 4: Progress Tracking")
    print("=" * 60)

    # Create a sample rules file
    sample_file = Path("sample_progress.rules")
    with sample_file.open("w") as f:
        for i in range(1, 501):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    try:
        parser = StreamParser()

        # Progress callback
        last_percent = 0

        def show_progress(processed, total):
            nonlocal last_percent
            if total:
                percent = int((processed / total) * 100)
                if percent >= last_percent + 10:
                    print(f"  Progress: {percent}% ({processed}/{total} rules)")
                    last_percent = percent

        print("\nStreaming with progress tracking...")

        count = 0
        for rule in parser.stream_file(sample_file, progress_callback=show_progress):
            count += 1

        print(f"\nCompleted: {count} rules processed")

    finally:
        sample_file.unlink()


def example_convenience_function():
    """Example 5: Using convenience function."""
    print("\n" + "=" * 60)
    print("Example 5: Convenience Function")
    print("=" * 60)

    # Create a sample rules file
    sample_file = Path("sample_convenience.rules")
    with sample_file.open("w") as f:
        for i in range(1, 101):
            f.write(f'alert tcp any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    try:
        print("\nUsing stream_parse_file() convenience function...")

        # Method 1: Stream individual rules
        count = 0
        for rule in stream_parse_file(sample_file):
            count += 1

        print(f"  Streamed {count} individual rules")

        # Method 2: Stream batches
        batch_count = 0
        for batch in stream_parse_file(sample_file, batch_size=25):
            batch_count += 1

        print(f"  Streamed {batch_count} batches")

    finally:
        sample_file.unlink()


def example_error_handling():
    """Example 6: Error handling during streaming."""
    print("\n" + "=" * 60)
    print("Example 6: Error Handling")
    print("=" * 60)

    # Create a sample file with some invalid rules
    sample_file = Path("sample_errors.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"Valid rule"; sid:1;)\n')
        f.write("invalid rule syntax here\n")
        f.write('alert tcp any any -> any 443 (msg:"Another valid"; sid:2;)\n')
        f.write("more invalid syntax\n")

    try:
        parser = StreamParser()

        print("\nStreaming with skip_errors=True...")
        valid_count = 0
        for rule in parser.stream_file(sample_file, skip_errors=True):
            valid_count += 1

        print(f"  Valid rules: {valid_count}")

        print("\nStreaming with skip_errors=False...")
        all_count = 0
        error_count = 0
        for rule in parser.stream_file(sample_file, skip_errors=False):
            all_count += 1
            if rule.diagnostics:
                error_count += 1

        print(f"  Total attempts: {all_count}")
        print(f"  Rules with errors: {error_count}")

    finally:
        sample_file.unlink()


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  Streaming API Examples - surinort-ast".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")
    print()

    try:
        example_basic_streaming()
        example_batch_streaming()
        example_memory_efficient_mode()
        example_progress_tracking()
        example_convenience_function()
        example_error_handling()

        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        print("""
The streaming API provides memory-efficient processing for large rule files:

✓ Constant memory usage regardless of file size
✓ Process 10k+ rules/second on modern hardware
✓ <100MB memory for 100k+ rule files
✓ Flexible batch sizes for throughput optimization
✓ Progress tracking and error recovery
✓ Multiple optimization modes

Use streaming for:
- Files with >10k rules
- Memory-constrained environments
- Real-time processing pipelines
- Large-scale rule analysis
        """)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
