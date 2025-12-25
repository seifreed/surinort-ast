#!/usr/bin/env python3
"""
Streaming Pipeline Example

This example demonstrates building complex processing pipelines using
stream processors for filtering, transforming, and analyzing rules.

Key concepts:
- Stream processors (Filter, Transform, Validate, Aggregate)
- Pipeline composition with | operator
- Writing processed rules to files
- Real-world processing workflows

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

import sys
from pathlib import Path

from surinort_ast.core.enums import Action, Protocol
from surinort_ast.streaming import (
    AggregateProcessor,
    FilterProcessor,
    StreamParser,
    StreamWriter,
    TransformProcessor,
    ValidateProcessor,
)


def example_filter_pipeline():
    """Example 1: Filtering rules."""
    print("=" * 60)
    print("Example 1: Filter Pipeline")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_filter.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n')
        f.write('alert udp any any -> any 53 (msg:"DNS"; sid:2;)\n')
        f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)\n')
        f.write('drop tcp any any -> any 22 (msg:"SSH"; sid:4;)\n')

    output_file = Path("filtered_output.rules")

    try:
        parser = StreamParser()

        # Filter TCP protocols only
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)

        print("\nFiltering TCP rules...")
        with StreamWriter.text(output_file) as writer:
            for rule in tcp_filter.stream(parser.stream_file(sample_file)):
                writer.write(rule)
                print(f"  Wrote: {rule.action.value} - {rule.header.protocol.value}")

        print(f"\nFiltered {writer.count} TCP rules to {output_file}")

    finally:
        sample_file.unlink()
        if output_file.exists():
            output_file.unlink()


def example_transform_pipeline():
    """Example 2: Transforming rules."""
    print("\n" + "=" * 60)
    print("Example 2: Transform Pipeline")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_transform.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n')
        f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)\n')

    output_file = Path("transformed_output.rules")

    try:
        parser = StreamParser()

        # Transform: convert alert to drop
        def alert_to_drop(rule):
            if rule.action == Action.ALERT:
                return rule.model_copy(update={"action": Action.DROP})
            return rule

        transformer = TransformProcessor(alert_to_drop)

        print("\nTransforming alert -> drop...")
        with StreamWriter.text(output_file) as writer:
            for rule in transformer.stream(parser.stream_file(sample_file)):
                writer.write(rule)
                print(f"  Wrote: {rule.action.value}")

        print(f"\nTransformed {writer.count} rules to {output_file}")

    finally:
        sample_file.unlink()
        if output_file.exists():
            output_file.unlink()


def example_validate_pipeline():
    """Example 3: Validating rules."""
    print("\n" + "=" * 60)
    print("Example 3: Validate Pipeline")
    print("=" * 60)

    # Create sample file with missing options
    sample_file = Path("sample_validate.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"Complete"; sid:1;)\n')
        f.write("alert tcp any any -> any 80 (sid:2;)\n")  # Missing msg
        f.write('alert tcp any any -> any 80 (msg:"Missing SID";)\n')  # Missing sid

    try:
        parser = StreamParser()
        validator = ValidateProcessor()

        print("\nValidating rules...")
        for rule in validator.stream(parser.stream_file(sample_file)):
            if rule.diagnostics:
                print("  Rule with warnings:")
                for diag in rule.diagnostics:
                    print(f"    - {diag.level.value}: {diag.message}")
            else:
                print(f"  Rule OK: {rule.origin.rule_id}")

    finally:
        sample_file.unlink()


def example_aggregate_pipeline():
    """Example 4: Aggregating statistics."""
    print("\n" + "=" * 60)
    print("Example 4: Aggregate Pipeline")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_aggregate.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n')
        f.write('alert udp any any -> any 53 (msg:"DNS"; sid:2;)\n')
        f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)\n')
        f.write('drop tcp any any -> any 22 (msg:"SSH"; sid:4;)\n')

    try:
        parser = StreamParser()
        aggregator = AggregateProcessor()

        print("\nAggregating statistics...")
        rules = list(aggregator.stream(parser.stream_file(sample_file)))

        print("\nStatistics:")
        print(f"  Total rules: {aggregator.stats.total_rules}")
        print("  By action:")
        for action, count in aggregator.stats.rules_by_action.items():
            print(f"    {action.value}: {count}")
        print("  By protocol:")
        for protocol, count in aggregator.stats.rules_by_protocol.items():
            print(f"    {protocol.value}: {count}")
        print(f"  Unique SIDs: {len(aggregator.stats.unique_sids)}")

    finally:
        sample_file.unlink()


def example_chained_pipeline():
    """Example 5: Chaining multiple processors."""
    print("\n" + "=" * 60)
    print("Example 5: Chained Pipeline")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_chained.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)\n')
        f.write('alert udp any any -> any 53 (msg:"DNS"; sid:2;)\n')
        f.write('alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)\n')
        f.write('drop tcp any any -> any 22 (msg:"SSH"; sid:4;)\n')

    output_file = Path("chained_output.rules")

    try:
        parser = StreamParser()

        # Build pipeline: filter TCP -> filter ALERT -> validate -> aggregate
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        alert_filter = FilterProcessor(lambda r: r.action == Action.ALERT)
        validator = ValidateProcessor()
        aggregator = AggregateProcessor()

        pipeline = tcp_filter | alert_filter | validator | aggregator

        print("\nProcessing with chained pipeline:")
        print("  TCP filter -> ALERT filter -> Validator -> Aggregator")

        with StreamWriter.text(output_file) as writer:
            for rule in pipeline.stream(parser.stream_file(sample_file)):
                writer.write(rule)

        print("\nResults:")
        print(f"  Rules written: {writer.count}")
        print(f"  Total processed: {aggregator.stats.total_rules}")
        print(
            f"  Actions: {dict((a.value, c) for a, c in aggregator.stats.rules_by_action.items())}"
        )

    finally:
        sample_file.unlink()
        if output_file.exists():
            output_file.unlink()


def example_custom_aggregation():
    """Example 6: Custom aggregation."""
    print("\n" + "=" * 60)
    print("Example 6: Custom Aggregation")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_custom_agg.rules")
    with sample_file.open("w") as f:
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; content:"GET"; sid:1;)\n')
        f.write('alert tcp any any -> any 80 (msg:"HTTP"; pcre:"/test/"; sid:2;)\n')
        f.write('alert tcp any any -> any 443 (msg:"HTTPS"; content:"POST"; sid:3;)\n')

    try:
        parser = StreamParser()

        # Custom aggregator: count content and pcre options
        def count_options(stats, rule):
            content_count = sum(1 for opt in rule.options if opt.node_type == "ContentOption")
            pcre_count = sum(1 for opt in rule.options if opt.node_type == "PcreOption")

            stats.custom_stats["total_content"] = (
                stats.custom_stats.get("total_content", 0) + content_count
            )
            stats.custom_stats["total_pcre"] = stats.custom_stats.get("total_pcre", 0) + pcre_count

        aggregator = AggregateProcessor(custom_aggregators=[count_options])

        print("\nAggregating with custom statistics...")
        rules = list(aggregator.stream(parser.stream_file(sample_file)))

        print("\nResults:")
        print(f"  Total rules: {aggregator.stats.total_rules}")
        print(f"  Content options: {aggregator.stats.custom_stats.get('total_content', 0)}")
        print(f"  PCRE options: {aggregator.stats.custom_stats.get('total_pcre', 0)}")

    finally:
        sample_file.unlink()


def example_real_world_workflow():
    """Example 7: Real-world processing workflow."""
    print("\n" + "=" * 60)
    print("Example 7: Real-World Workflow")
    print("=" * 60)

    # Create sample file
    sample_file = Path("sample_workflow.rules")
    with sample_file.open("w") as f:
        for i in range(100):
            protocol = "tcp" if i % 2 == 0 else "udp"
            action = "alert" if i % 3 != 0 else "drop"
            f.write(f'{action} {protocol} any any -> any 80 (msg:"Rule {i}"; sid:{i};)\n')

    json_output = Path("workflow_output.json")
    text_output = Path("workflow_filtered.rules")

    try:
        parser = StreamParser(include_raw_text=False, track_locations=False)

        print("\nWorkflow: Parse -> Filter -> Validate -> Export")

        # Step 1: Filter alert rules only
        alert_filter = FilterProcessor(lambda r: r.action == Action.ALERT)
        validator = ValidateProcessor()
        aggregator = AggregateProcessor()

        pipeline = alert_filter | validator | aggregator

        # Step 2: Export to JSON for analysis
        print("\nExporting to JSON...")
        with StreamWriter.json(json_output) as json_writer:
            for rule in pipeline.stream(parser.stream_file(sample_file)):
                json_writer.write(rule)

        # Step 3: Export TCP alerts to text file
        tcp_filter = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        pipeline2 = alert_filter | tcp_filter

        print("Exporting TCP alerts to text...")
        with StreamWriter.text(text_output) as text_writer:
            for rule in pipeline2.stream(parser.stream_file(sample_file)):
                text_writer.write(rule)

        print("\nWorkflow complete:")
        print(f"  JSON export: {json_output} ({json_writer.count} rules)")
        print(f"  Text export: {text_output} ({text_writer.count} rules)")
        print(f"  Total processed: {aggregator.stats.total_rules}")

    finally:
        sample_file.unlink()
        if json_output.exists():
            json_output.unlink()
        if text_output.exists():
            text_output.unlink()


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  Streaming Pipeline Examples - surinort-ast".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "═" * 58 + "╝")
    print()

    try:
        example_filter_pipeline()
        example_transform_pipeline()
        example_validate_pipeline()
        example_aggregate_pipeline()
        example_chained_pipeline()
        example_custom_aggregation()
        example_real_world_workflow()

        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        print("""
Stream processors enable complex processing pipelines:

✓ FilterProcessor: Select rules by criteria
✓ TransformProcessor: Modify rules on-the-fly
✓ ValidateProcessor: Add diagnostic information
✓ AggregateProcessor: Collect statistics
✓ Chain with | operator for complex workflows
✓ Write results to text or JSON formats

Use pipelines for:
- Rule format conversion
- Quality assurance workflows
- Statistical analysis
- Custom rule transformations
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
