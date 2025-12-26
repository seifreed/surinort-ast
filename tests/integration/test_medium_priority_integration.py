# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for MEDIUM PRIORITY modules working together.

Tests the interaction between query, analysis, streaming, and builder
modules in realistic scenarios.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import tempfile
from pathlib import Path

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis.coverage import CoverageAnalyzer
from surinort_ast.analysis.estimator import PerformanceEstimator
from surinort_ast.analysis.lsh import LSHIndex
from surinort_ast.analysis.minhash import MinHashSignature
from surinort_ast.analysis.optimizer import RuleOptimizer
from surinort_ast.analysis.strategies import (
    FastPatternStrategy,
)
from surinort_ast.builder import RuleBuilder
from surinort_ast.core.enums import Protocol
from surinort_ast.query import query, query_exists, query_first
from surinort_ast.streaming import StreamParser, stream_parse_file


class TestQueryAndAnalysisIntegration:
    """Test query module working with analysis modules."""

    def test_query_then_analyze_coverage(self):
        """Test querying rules and then analyzing coverage."""
        # Create a diverse rule set
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)'),
            parse_rule('alert udp any any -> any 53 (msg:"DNS"; sid:3;)'),
            parse_rule('drop tcp any any -> any 22 (msg:"SSH"; sid:4;)'),
        ]

        # Query for specific rule types
        alert_rules = [r for r in rules if query_exists(r, "Rule[action=alert]")]
        drop_rules = [r for r in rules if query_exists(r, "Rule[action=drop]")]

        # Analyze coverage separately
        analyzer = CoverageAnalyzer()
        alert_report = analyzer.analyze(alert_rules)
        drop_report = analyzer.analyze(drop_rules)

        assert alert_report.total_rules == 3
        assert drop_report.total_rules == 1

        # Alert rules should have TCP and UDP
        assert Protocol.TCP in alert_report.protocol_distribution
        assert Protocol.UDP in alert_report.protocol_distribution

    def test_query_high_cost_rules_with_estimator(self):
        """Test finding expensive rules using query and cost estimator."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (content:"simple"; sid:1;)'),
            parse_rule(
                'alert tcp any any -> any 80 (pcre:"/complex.*regex/i"; '
                'content:"a"; content:"b"; content:"c"; sid:2;)'
            ),
            parse_rule('alert tcp any any -> any 80 (msg:"minimal"; sid:3;)'),
        ]

        estimator = PerformanceEstimator()

        # Estimate cost for all rules
        costs = [(rule, estimator.estimate_cost(rule)) for rule in rules]

        # Find rules with PCRE (should be expensive)
        pcre_rules = [r for r in rules if query_exists(r, "PcreOption")]

        assert len(pcre_rules) == 1

        # PCRE rule should have higher cost
        pcre_costs = [cost for rule, cost in costs if rule in pcre_rules]
        non_pcre_costs = [cost for rule, cost in costs if rule not in pcre_rules]

        assert max(pcre_costs) > min(non_pcre_costs)

    def test_query_similar_rules_with_minhash(self):
        """Test finding similar rules using query and MinHash."""
        rules = [
            parse_rule(
                'alert tcp any any -> any 80 (msg:"SQL Injection"; content:"SELECT"; sid:1;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (msg:"SQL Injection Attack"; content:"SELECT"; sid:2;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; sid:3;)'
            ),
        ]

        signature_gen = MinHashSignature(num_perm=128)

        # Generate signatures
        signatures = []
        for rule in rules:
            sig = signature_gen.create_signature(rule)
            signatures.append((rule, sig))

        # Compare first two (should be similar due to "SQL Injection" content)
        sim_12 = signature_gen.estimate_similarity(signatures[0][1], signatures[1][1])
        sim_13 = signature_gen.estimate_similarity(signatures[0][1], signatures[2][1])

        # Rules 1 and 2 should be more similar than 1 and 3
        assert sim_12 >= sim_13

    def test_query_and_optimize_strategies(self):
        """Test querying rules and applying optimization strategies."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (content:"test"; sid:5000;)'),
            parse_rule('alert tcp any any -> any 80 (content:"admin"; sid:1000;)'),
            parse_rule('alert tcp any any -> any 80 (content:"login"; sid:3000;)'),
        ]

        # Apply fast pattern strategy
        optimizer = RuleOptimizer(strategies=[FastPatternStrategy()])

        results = optimizer.optimize_ruleset(rules)

        # All rules should have been processed
        assert len(results) == 3


class TestStreamingAndAnalysisIntegration:
    """Test streaming module working with analysis modules."""

    def test_stream_and_analyze_coverage(self):
        """Test streaming rules and analyzing coverage incrementally."""
        # Create a test file with many rules
        rules_text = [
            'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
            'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
            'alert icmp any any -> any any (msg:"ICMP"; sid:4;)',
            'drop tcp any any -> any 22 (msg:"SSH"; sid:5;)',
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Stream parse the file
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            # Analyze coverage
            analyzer = CoverageAnalyzer()
            report = analyzer.analyze(rules)

            assert report.total_rules == 5
            assert Protocol.TCP in report.protocol_distribution
            assert Protocol.UDP in report.protocol_distribution
            assert Protocol.ICMP in report.protocol_distribution
        finally:
            temp_path.unlink()

    def test_stream_batches_and_estimate_costs(self):
        """Test streaming in batches and estimating costs."""
        num_rules = 50
        rules_text = [
            f'alert tcp any any -> any {i} (content:"pattern{i}"; pcre:"/regex{i}/"; sid:{i};)'
            for i in range(num_rules)
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            estimator = PerformanceEstimator()

            total_cost = 0
            rule_count = 0

            # Process in batches
            for batch in parser.stream_file_batched(temp_path, batch_size=10):
                for rule in batch.rules:
                    cost = estimator.estimate_cost(rule)
                    total_cost += cost
                    rule_count += 1

            assert rule_count == num_rules
            assert total_cost > 0
        finally:
            temp_path.unlink()


class TestBuilderAndQueryIntegration:
    """Test builder module working with query module."""

    def test_build_and_query_rule(self):
        """Test building a rule and querying it."""
        # Build a complex rule
        rule = (
            RuleBuilder()
            .alert()
            .http()
            .source_ip("$EXTERNAL_NET")
            .source_port("any")
            .dest_ip("$HOME_NET")
            .dest_port(80)
            .msg("HTTP Admin Access")
            .flow_builder()
            .established()
            .to_server()
            .done()
            .content_builder()
            .pattern(b"GET")
            .http_method()
            .done()
            .content_builder()
            .pattern(b"/admin")
            .http_uri()
            .done()
            .sid(1000001)
            .rev(1)
            .build()
        )

        # Query the built rule
        assert query_exists(rule, "Rule[action=alert]")
        assert query_exists(rule, "FlowOption")

        content_opts = query(rule, "ContentOption")
        assert len(content_opts) == 2

        sid = query_first(rule, "SidOption")
        assert sid.value == 1000001

    def test_build_multiple_and_analyze(self):
        """Test building multiple rules and analyzing them."""
        rules = []

        # Build several rules
        for i in range(5):
            rule = (
                RuleBuilder()
                .alert()
                .tcp()
                .source_ip("any")
                .source_port("any")
                .dest_ip("any")
                .dest_port(80 + i)
                .msg(f"Rule {i}")
                .sid(1000 + i)
                .build()
            )
            rules.append(rule)

        # Analyze coverage
        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        assert report.total_rules == 5
        assert Protocol.TCP in report.protocol_distribution
        assert report.protocol_distribution[Protocol.TCP] == 5


class TestBuilderStreamingAnalysisIntegration:
    """Test all three modules working together."""

    def test_build_stream_analyze_workflow(self):
        """Test building rules, streaming to file, and analyzing."""
        # Build rules
        rules = []
        for i in range(10):
            rule = (
                RuleBuilder()
                .alert()
                .tcp()
                .source_ip("any")
                .source_port("any")
                .dest_ip("any")
                .dest_port(80 + i * 10)
                .msg(f"Test rule {i}")
                .content(b"pattern")
                .sid(1000 + i)
                .build()
            )
            rules.append(rule)

        # Write to file (manual write since we don't have a rule printer in scope)
        from surinort_ast.printer import print_rule

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules:
                f.write(print_rule(rule))
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Stream parse the file
            streamed_rules = list(stream_parse_file(temp_path))

            assert len(streamed_rules) == 10

            # Analyze the streamed rules
            analyzer = CoverageAnalyzer()
            report = analyzer.analyze(streamed_rules)

            assert report.total_rules == 10
            assert Protocol.TCP in report.protocol_distribution
        finally:
            temp_path.unlink()


class TestQueryStreamingIntegration:
    """Test query and streaming modules together."""

    def test_stream_and_query_filter(self):
        """Test streaming rules and filtering with queries."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"HTTP"; sid:1000;)',
            'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2000;)',
            'drop tcp any any -> any 22 (msg:"SSH"; sid:3000;)',
            'alert udp any any -> any 53 (msg:"DNS"; sid:4000;)',
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Stream and filter
            parser = StreamParser()
            alert_rules = []
            high_sid_rules = []

            for rule in parser.stream_file(temp_path):
                if query_exists(rule, "Rule[action=alert]"):
                    alert_rules.append(rule)

                sid = query_first(rule, "SidOption")
                if sid and sid.value > 2000:
                    high_sid_rules.append(rule)

            assert len(alert_rules) == 3
            assert len(high_sid_rules) == 2
        finally:
            temp_path.unlink()


class TestComplexRealWorldScenarios:
    """Test complex real-world scenarios using all modules."""

    def test_rule_optimization_pipeline(self):
        """Test a complete rule optimization pipeline."""
        # Build initial rules (unoptimized order)
        rules = [
            parse_rule("alert tcp any any -> any 80 (sid:5000;)"),
            parse_rule("alert tcp any any -> any 80 (flow:established,to_server; sid:1000;)"),
            parse_rule('alert tcp any any -> any 80 (content:"test"; fast_pattern; sid:3000;)'),
        ]

        # 1. Analyze initial coverage
        analyzer = CoverageAnalyzer()
        initial_report = analyzer.analyze(rules)
        assert initial_report.total_rules == 3

        # 2. Estimate costs
        estimator = PerformanceEstimator()
        _ = [estimator.estimate_cost(r) for r in rules]

        # 3. Optimize with strategies
        optimizer = RuleOptimizer(
            strategies=[
                FastPatternStrategy(),
            ]
        )
        results = optimizer.optimize_ruleset(rules)

        # 4. Query optimized rules
        optimized = [result.optimized for result in results]
        fast_pattern_rules = [r for r in optimized if query_exists(r, "FastPatternOption")]
        flow_rules = [r for r in optimized if query_exists(r, "FlowOption")]

        # At least one rule should have fast_pattern added
        assert len(fast_pattern_rules) >= 1
        # Flow rule already exists in the original rules
        assert len(flow_rules) >= 1

    def test_similarity_detection_pipeline(self):
        """Test detecting similar rules in a large set."""
        # Create similar rule pairs with distinctive content
        rules = [
            parse_rule(
                'alert tcp any any -> any 80 (msg:"SQL Injection detected"; content:"SELECT"; sid:1;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (msg:"SQL Injection found"; content:"SELECT"; sid:2;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (msg:"XSS Attack detected"; content:"<script>"; sid:3;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (msg:"XSS Attack found"; content:"<script>"; sid:4;)'
            ),
        ]

        # Use MinHash and LSH for similarity detection
        signature_gen = MinHashSignature(num_perm=128)
        lsh = LSHIndex(num_bands=16, rows_per_band=8)

        # Add rules to LSH
        for rule in rules:
            sig = signature_gen.create_signature(rule)
            lsh.add(rule, sig)

        # Query for similar rules
        sig_1 = signature_gen.create_signature(rules[0])
        candidates = lsh.query(sig_1)

        # Should find at least the rule itself
        assert len(candidates) >= 1
        # Should include rules[0] (candidates are tuples of (rule, signature))
        assert any(id(rule) == id(rules[0]) for rule, _ in candidates)

    def test_coverage_analysis_with_filtering(self):
        """Test coverage analysis on filtered rule sets."""
        rules_text = []

        # Create diverse rules
        for i in range(20):
            protocol = "tcp" if i % 2 == 0 else "udp"
            port = 80 if i < 10 else 443
            action = "alert" if i % 3 != 0 else "drop"
            rules_text.append(
                f'{action} {protocol} any any -> any {port} (msg:"Rule {i}"; sid:{i};)'
            )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            for rule in rules_text:
                f.write(rule)
                f.write("\n")
            temp_path = Path(f.name)

        try:
            # Stream and filter
            parser = StreamParser()
            all_rules = list(parser.stream_file(temp_path))

            # Filter to alert rules only
            alert_rules = [r for r in all_rules if query_exists(r, "Rule[action=alert]")]

            # Analyze both sets
            analyzer = CoverageAnalyzer()
            all_report = analyzer.analyze(all_rules)
            alert_report = analyzer.analyze(alert_rules)

            assert all_report.total_rules == 20
            assert alert_report.total_rules < all_report.total_rules

            # Both should have TCP and UDP
            assert Protocol.TCP in all_report.protocol_distribution
            assert Protocol.UDP in all_report.protocol_distribution
        finally:
            temp_path.unlink()


class TestErrorHandlingAcrossModules:
    """Test error handling when modules interact."""

    def test_query_on_malformed_built_rule(self):
        """Test querying on edge case built rules."""
        # Build minimal rule
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )

        # Query should work even on minimal rule
        assert query_exists(rule, "Rule")
        assert query_exists(rule, "MsgOption")

        # Query for non-existent option
        assert not query_exists(rule, "PcreOption")

    def test_analyze_empty_streamed_ruleset(self):
        """Test analyzing an empty streamed ruleset."""
        # Create empty file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            temp_path = Path(f.name)

        try:
            parser = StreamParser()
            rules = list(parser.stream_file(temp_path))

            # Analyze empty set
            analyzer = CoverageAnalyzer()
            report = analyzer.analyze(rules)

            assert report.total_rules == 0
            assert len(report.protocol_distribution) == 0
        finally:
            temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
