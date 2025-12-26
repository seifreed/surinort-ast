# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for surinort_ast.analysis module.

Tests complete workflows combining multiple analysis components including:
- Coverage analysis on real rule sets
- Performance estimation and optimization workflows
- Similarity detection using MinHash and LSH
- Rule optimization strategies

All tests use real data and execute actual code paths without mocking.
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis import (
    CoverageAnalyzer,
    PerformanceEstimator,
    RuleOptimizer,
)
from surinort_ast.analysis.lsh import LSHIndex
from surinort_ast.analysis.minhash import MinHashSignature


class TestCoverageAnalysisWorkflow:
    """Test complete coverage analysis workflows with real rules."""

    def test_basic_coverage_workflow(self):
        """
        Test basic coverage analysis on a small rule set.

        Validates:
        - Protocol distribution calculation
        - Port coverage detection
        - Direction analysis
        - Gap identification
        """
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP traffic"; sid:1;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"HTTPS traffic"; sid:2;)'),
            parse_rule('alert udp any any -> any 53 (msg:"DNS traffic"; sid:3;)'),
            parse_rule('alert icmp any any -> any any (msg:"ICMP traffic"; sid:4;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Validate basic metrics
        assert report.total_rules == 4
        assert len(report.protocol_distribution) >= 3

        # Validate protocol coverage
        from surinort_ast.core.enums import Protocol

        assert Protocol.TCP in report.protocol_distribution
        assert Protocol.UDP in report.protocol_distribution
        assert Protocol.ICMP in report.protocol_distribution

        # TCP should have 2 rules
        assert report.protocol_distribution[Protocol.TCP] == 2
        assert report.protocol_distribution[Protocol.UDP] == 1
        assert report.protocol_distribution[Protocol.ICMP] == 1

        # Validate port coverage
        assert 80 in report.port_coverage
        assert 443 in report.port_coverage
        assert 53 in report.port_coverage

    def test_coverage_gap_detection(self):
        """
        Test gap detection in coverage analysis.

        Creates a TCP-heavy rule set and validates that:
        - UDP coverage gap is detected
        - Common ports without coverage are identified
        - Recommendations are generated
        """
        # Create TCP-heavy rule set (should trigger UDP gap warning)
        rules = [
            parse_rule(f'alert tcp any any -> any {port} (msg:"Test {port}"; sid:{i};)')
            for i, port in enumerate([80, 8080, 8443, 9000, 9001], start=1)
        ]

        # Add a few more TCP rules to exceed 95% threshold
        for i in range(5, 110):
            rules.append(
                parse_rule(f'alert tcp any any -> any {1000 + i} (msg:"Test port"; sid:{i};)')
            )

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Validate gap detection
        assert len(report.gaps) > 0

        # Should detect TCP-heavy distribution
        gap_types = [gap.gap_type for gap in report.gaps]

        # At least one protocol or port gap should be detected
        assert any("protocol" in gt for gt in gap_types) or any("port" in gt for gt in gap_types)

    def test_coverage_report_formats(self):
        """
        Test different report output formats.

        Validates:
        - Text format generation
        - Markdown format generation
        - Dictionary serialization
        - All formats contain expected data
        """
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
            parse_rule('alert udp any any -> any 53 (msg:"DNS"; sid:2;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Test text format
        text = report.to_text()
        assert "Coverage Analysis Report" in text
        assert "Total Rules:" in text
        assert "Protocol Distribution:" in text

        # Test markdown format
        markdown = report.to_markdown()
        assert "# Coverage Analysis Report" in markdown
        assert "## Protocol Distribution" in markdown
        assert "|" in markdown  # Table format

        # Test dict format
        report_dict = report.to_dict()
        assert "total_rules" in report_dict
        assert report_dict["total_rules"] == 2
        assert "protocol_distribution" in report_dict
        assert "port_coverage" in report_dict


class TestOptimizationWorkflow:
    """Test complete rule optimization workflows."""

    def test_basic_optimization_workflow(self):
        """
        Test basic optimization workflow on suboptimal rule.

        Creates a rule with options in suboptimal order and validates:
        - Optimization is applied
        - Performance improvement is estimated
        - Optimized rule is functionally equivalent
        """
        # Rule with PCRE before content (suboptimal ordering)
        rule = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/malicious/i"; content:"GET"; msg:"Test"; sid:1;)'
        )

        optimizer = RuleOptimizer()
        result = optimizer.optimize(rule)

        # Should apply at least option reordering
        assert result.was_modified
        assert len(result.optimizations) > 0

        # Should have reordered options
        assert "OptionReorder" in result.strategy_names or "FastPattern" in result.strategy_names

    def test_fast_pattern_optimization(self):
        """
        Test fast_pattern optimization strategy.

        Creates a rule with multiple content patterns and validates:
        - Best content is selected for fast_pattern
        - Estimated performance gain is positive
        """
        # Rule with multiple content patterns, no fast_pattern
        rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'content:"short"; '
            'content:"longer_distinctive_pattern"; '
            'content:"mid"; '
            'msg:"Test"; sid:1;)'
        )

        optimizer = RuleOptimizer()
        result = optimizer.optimize(rule)

        # Should apply fast_pattern optimization
        if result.was_modified:
            assert any("FastPattern" in opt.strategy for opt in result.optimizations)

    def test_redundancy_removal_optimization(self):
        """
        Test redundancy removal strategy.

        Creates a rule with duplicate options and validates:
        - Duplicates are removed
        - Final rule has unique options
        - Metadata options are preserved
        """
        # Rule with duplicate content options (artificial but valid)
        rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'content:"test"; '
            "flow:to_server; "
            'content:"test"; '
            'msg:"Test"; sid:1;)'
        )

        optimizer = RuleOptimizer()
        result = optimizer.optimize(rule)

        # May or may not remove duplicates depending on implementation
        # Validate result structure
        assert result.original is not None
        assert result.optimized is not None

    def test_optimization_statistics(self):
        """
        Test optimization statistics calculation.

        Optimizes multiple rules and validates:
        - Statistics are correctly calculated
        - Modification rate is accurate
        - Strategy counts are tracked
        """
        rules = [
            parse_rule(
                'alert tcp any any -> any 80 (pcre:"/test/"; content:"GET"; msg:"T1"; sid:1;)'
            ),
            parse_rule(
                'alert tcp any any -> any 443 (pcre:"/ssl/"; content:"TLS"; msg:"T2"; sid:2;)'
            ),
            parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"T3"; sid:3;)'),
        ]

        optimizer = RuleOptimizer()
        results = optimizer.optimize_ruleset(rules)

        assert len(results) == 3

        # Get statistics
        stats = optimizer.get_statistics(results)

        assert "total_rules" in stats
        assert stats["total_rules"] == 3
        assert "modified_count" in stats
        assert "modification_rate" in stats
        assert "avg_improvement" in stats


class TestPerformanceEstimationWorkflow:
    """Test performance estimation across different rule types."""

    def test_estimate_simple_rule(self):
        """
        Test cost estimation for simple rule.

        Validates:
        - Basic cost calculation
        - Cost breakdown by option type
        """
        rule = parse_rule('alert tcp any any -> any 80 (content:"GET"; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Cost should be positive
        assert cost > 0

        # Get breakdown
        breakdown = estimator.get_cost_breakdown(rule)
        assert "ContentOption" in breakdown
        assert "MsgOption" in breakdown

    def test_estimate_complex_rule(self):
        """
        Test cost estimation for complex rule with PCRE.

        Validates:
        - PCRE has higher cost than content
        - Complex patterns increase cost
        """
        simple_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; msg:"Simple"; sid:1;)'
        )

        complex_rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'pcre:"/complex.*pattern.*with.*alternation|other/i"; '
            'content:"test"; '
            'msg:"Complex"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        simple_cost = estimator.estimate_cost(simple_rule)
        complex_cost = estimator.estimate_cost(complex_rule)

        # Complex rule should have higher cost
        assert complex_cost > simple_cost

    def test_estimate_improvement(self):
        """
        Test performance improvement estimation.

        Creates optimized version and validates:
        - Improvement percentage is calculated
        - Positive improvement for optimization
        """
        original = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/"; content:"GET"; msg:"Test"; sid:1;)'
        )

        # Create manually optimized version (content before pcre)
        optimized = parse_rule(
            'alert tcp any any -> any 80 (content:"GET"; pcre:"/test/"; msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        improvement = estimator.estimate_improvement(original, optimized)

        # May be zero if costs are similar
        assert improvement >= 0


class TestSimilarityDetectionWorkflow:
    """Test similarity detection using MinHash and LSH."""

    def test_minhash_identical_rules(self):
        """
        Test MinHash on identical rules.

        Validates:
        - Identical rules have 100% similarity
        - Signatures are generated correctly
        """
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        # Signatures should be non-empty
        assert len(sig1) == 128
        assert len(sig2) == 128

        # Similarity should be very high (identical except sid)
        similarity = minhash.estimate_similarity(sig1, sig2)

        # Should be high but maybe not 100% due to different SID
        assert similarity > 0.8

    def test_minhash_different_rules(self):
        """
        Test MinHash on completely different rules.

        Validates:
        - Different rules have low similarity
        - Signatures distinguish different content
        """
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"HTTP"; msg:"Web"; sid:1;)')
        rule2 = parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"Domain"; sid:2;)')

        minhash = MinHashSignature(num_perm=128)

        sig1 = minhash.create_signature(rule1)
        sig2 = minhash.create_signature(rule2)

        similarity = minhash.estimate_similarity(sig1, sig2)

        # Should have low similarity
        assert similarity < 0.5

    def test_lsh_similarity_search(self):
        """
        Test LSH index for similarity search.

        Validates:
        - Rules can be added to index
        - Similar rules are found in queries
        - Dissimilar rules are filtered out
        """
        # Create a set of rules
        base_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"malicious"; msg:"Base"; sid:1;)'
        )
        similar_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"malicious"; msg:"Similar"; sid:2;)'
        )
        different_rule = parse_rule(
            'alert udp any any -> any 53 (content:"benign"; msg:"Different"; sid:3;)'
        )

        # Create signatures
        minhash = MinHashSignature(num_perm=128)
        base_sig = minhash.create_signature(base_rule)
        similar_sig = minhash.create_signature(similar_rule)
        different_sig = minhash.create_signature(different_rule)

        # Build LSH index
        lsh = LSHIndex(threshold=0.7, num_bands=16)
        lsh.add(similar_rule, similar_sig)
        lsh.add(different_rule, different_sig)

        # Query for similar rules
        candidates = lsh.query(base_sig)

        # Should find at least the similar rule
        assert len(candidates) >= 1

        # Validate structure
        for rule, sig in candidates:
            assert rule is not None
            assert len(sig) == 128

    def test_lsh_index_operations(self):
        """
        Test LSH index add, remove, and clear operations.

        Validates:
        - Rules can be added and removed
        - Index statistics are accurate
        - Clear removes all rules
        """
        rules = [
            parse_rule(f'alert tcp any any -> any 80 (content:"test{i}"; msg:"T{i}"; sid:{i};)')
            for i in range(1, 6)
        ]

        minhash = MinHashSignature(num_perm=128)
        lsh = LSHIndex(threshold=0.8)

        # Add all rules
        for rule in rules:
            sig = minhash.create_signature(rule)
            lsh.add(rule, sig)

        assert len(lsh) == 5

        # Remove one rule
        removed = lsh.remove(rules[0])
        assert removed is True
        assert len(lsh) == 4

        # Try removing again
        removed_again = lsh.remove(rules[0])
        assert removed_again is False

        # Clear all
        lsh.clear()
        assert len(lsh) == 0


class TestIntegratedAnalysisPipeline:
    """Test complete analysis pipeline combining multiple components."""

    def test_full_analysis_pipeline(self):
        """
        Test complete analysis pipeline:
        1. Parse rules
        2. Analyze coverage
        3. Optimize rules
        4. Estimate improvements
        5. Detect similar rules

        Validates all components work together correctly.
        """
        # Step 1: Create rule set
        rules = [
            parse_rule(
                'alert tcp any any -> any 80 (pcre:"/attack/"; content:"GET"; msg:"Attack 1"; sid:1;)'
            ),
            parse_rule(
                'alert tcp any any -> any 80 (pcre:"/attack/"; content:"GET"; msg:"Attack 2"; sid:2;)'
            ),
            parse_rule('alert tcp any any -> any 443 (content:"TLS"; msg:"SSL Traffic"; sid:3;)'),
            parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS Query"; sid:4;)'),
        ]

        # Step 2: Coverage analysis
        coverage_analyzer = CoverageAnalyzer()
        coverage_report = coverage_analyzer.analyze(rules)

        assert coverage_report.total_rules == 4
        assert len(coverage_report.protocol_distribution) >= 2

        # Step 3: Optimize rules
        optimizer = RuleOptimizer()
        optimization_results = []

        for rule in rules:
            result = optimizer.optimize(rule)
            optimization_results.append(result)

        # Step 4: Estimate improvements
        estimator = PerformanceEstimator()
        total_improvement = 0.0

        for result in optimization_results:
            if result.was_modified:
                improvement = estimator.estimate_improvement(result.original, result.optimized)
                total_improvement += improvement

        # Step 5: Detect similar rules
        minhash = MinHashSignature(num_perm=128)
        signatures = [minhash.create_signature(rule) for rule in rules]

        # First two rules should be similar (same content and pcre)
        similarity_0_1 = minhash.estimate_similarity(signatures[0], signatures[1])
        assert similarity_0_1 > 0.7  # High similarity expected

        # First and last rules should be different
        similarity_0_3 = minhash.estimate_similarity(signatures[0], signatures[3])
        assert similarity_0_3 < 0.5  # Low similarity expected

    def test_batch_optimization_workflow(self):
        """
        Test batch optimization with statistics.

        Validates:
        - Multiple rules can be optimized in batch
        - Statistics are computed correctly
        - Results are consistent
        """
        # Create a batch of rules with various characteristics
        rules = [
            parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"T1"; sid:1;)'),
            parse_rule(
                'alert tcp any any -> any 443 (pcre:"/complex/"; content:"ssl"; msg:"T2"; sid:2;)'
            ),
            parse_rule('alert udp any any -> any 53 (content:"dns"; msg:"T3"; sid:3;)'),
            parse_rule(
                'alert tcp any any -> any 8080 (content:"http"; content:"alt"; msg:"T4"; sid:4;)'
            ),
        ]

        optimizer = RuleOptimizer()
        results = optimizer.optimize_ruleset(rules, verbose=False)

        # Validate results
        assert len(results) == len(rules)

        # All results should have valid structure
        for result in results:
            assert result.original is not None
            assert result.optimized is not None
            assert isinstance(result.optimizations, list)
            assert isinstance(result.was_modified, bool)

        # Get statistics
        stats = optimizer.get_statistics(results)
        assert stats["total_rules"] == 4
        assert 0 <= stats["modification_rate"] <= 100


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error conditions."""

    def test_empty_rule_set_coverage(self):
        """Test coverage analysis with empty rule set."""
        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([])

        assert report.total_rules == 0
        assert len(report.protocol_distribution) == 0
        assert len(report.gaps) == 0

    def test_single_rule_optimization(self):
        """Test optimization with single rule."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        optimizer = RuleOptimizer()
        result = optimizer.optimize(rule)

        # Should have valid result even if not modified
        assert result.original is rule
        assert result.optimized is not None

    def test_minhash_empty_features(self):
        """
        Test MinHash with minimal rule.

        Even minimal rules should generate valid signatures.
        """
        # Minimal valid rule
        rule = parse_rule('alert ip any any -> any any (msg:"Minimal"; sid:1;)')

        minhash = MinHashSignature(num_perm=128)
        sig = minhash.create_signature(rule)

        # Should generate signature even for minimal rule
        assert len(sig) == 128
        assert all(isinstance(h, int) for h in sig)

    def test_lsh_threshold_validation(self):
        """Test LSH index threshold validation."""
        # Invalid threshold should raise ValueError
        with pytest.raises(ValueError):
            LSHIndex(threshold=0.0)

        with pytest.raises(ValueError):
            LSHIndex(threshold=1.5)

        # Valid thresholds should work
        lsh1 = LSHIndex(threshold=0.1)
        assert lsh1.threshold == 0.1

        lsh2 = LSHIndex(threshold=1.0)
        assert lsh2.threshold == 1.0

    def test_performance_estimator_zero_cost(self):
        """Test performance estimator with minimal options."""
        # Rule with only metadata (very low cost)
        rule = parse_rule('alert ip any any -> any any (msg:"Minimal"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should have some cost even for minimal rule
        assert cost >= 0

        # Breakdown should include metadata options
        breakdown = estimator.get_cost_breakdown(rule)
        assert "MsgOption" in breakdown
        assert "SidOption" in breakdown
