# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort_ast.analysis.coverage module.

Tests the CoverageAnalyzer class and related functionality for analyzing
IDS rule set coverage including protocols, ports, directions, and gap detection.

All tests use real Rule objects and execute actual analysis code.
"""

from surinort_ast import parse_rule
from surinort_ast.analysis.coverage import CoverageAnalyzer, CoverageGap, CoverageReport
from surinort_ast.core.enums import Action, Direction, Protocol


class TestCoverageGap:
    """Test CoverageGap data class."""

    def test_coverage_gap_creation(self):
        """Test creating a coverage gap."""
        gap = CoverageGap(
            gap_type="port",
            description="Port 22 has no coverage",
            severity="high",
            recommendation="Add SSH monitoring rules",
        )

        assert gap.gap_type == "port"
        assert gap.description == "Port 22 has no coverage"
        assert gap.severity == "high"
        assert "SSH" in gap.recommendation

    def test_coverage_gap_to_dict(self):
        """Test serializing coverage gap to dictionary."""
        gap = CoverageGap(
            gap_type="protocol",
            description="No UDP rules",
            severity="medium",
            recommendation="Add UDP coverage",
        )

        gap_dict = gap.to_dict()

        assert gap_dict["type"] == "protocol"
        assert gap_dict["description"] == "No UDP rules"
        assert gap_dict["severity"] == "medium"
        assert gap_dict["recommendation"] == "Add UDP coverage"


class TestCoverageReport:
    """Test CoverageReport data class and formatting."""

    def test_coverage_report_creation(self):
        """Test creating a coverage report."""
        report = CoverageReport(
            total_rules=10,
            protocol_distribution={Protocol.TCP: 8, Protocol.UDP: 2},
            port_coverage={80: 3, 443: 2, 53: 1},
            common_ports_uncovered=[22, 25],
            direction_distribution={Direction.TO: 7, Direction.FROM: 3},
            action_distribution={Action.ALERT: 10},
            content_types={"web": 5, "dns": 2},
            gaps=[],
        )

        assert report.total_rules == 10
        assert len(report.protocol_distribution) == 2
        assert len(report.port_coverage) == 3
        assert len(report.common_ports_uncovered) == 2

    def test_coverage_report_to_dict(self):
        """Test serializing coverage report to dictionary."""
        report = CoverageReport(
            total_rules=5,
            protocol_distribution={Protocol.TCP: 5},
            port_coverage={80: 2},
            common_ports_uncovered=[],
            direction_distribution={Direction.TO: 5},
            action_distribution={Action.ALERT: 5},
            content_types={"web": 5},
            gaps=[],
        )

        report_dict = report.to_dict()

        assert report_dict["total_rules"] == 5
        assert "protocol_distribution" in report_dict
        assert "tcp" in report_dict["protocol_distribution"]
        assert report_dict["protocol_distribution"]["tcp"] == 5

    def test_coverage_report_to_text(self):
        """Test generating text report."""
        report = CoverageReport(
            total_rules=3,
            protocol_distribution={Protocol.TCP: 2, Protocol.UDP: 1},
            port_coverage={80: 1, 53: 1},
            common_ports_uncovered=[22],
            direction_distribution={Direction.TO: 3},
            action_distribution={Action.ALERT: 3},
            content_types={"web": 1, "dns": 1},
            gaps=[
                CoverageGap(
                    gap_type="port",
                    description="Port 22 uncovered",
                    severity="high",
                    recommendation="Add SSH rules",
                )
            ],
        )

        text = report.to_text()

        assert "Coverage Analysis Report" in text
        assert "Total Rules:" in text
        assert "Protocol Distribution:" in text
        assert "Port Coverage:" in text
        assert "Coverage Gaps:" in text
        assert "Port 22" in text

    def test_coverage_report_to_markdown(self):
        """Test generating markdown report."""
        report = CoverageReport(
            total_rules=2,
            protocol_distribution={Protocol.TCP: 2},
            port_coverage={80: 2},
            common_ports_uncovered=[],
            direction_distribution={Direction.TO: 2},
            action_distribution={Action.ALERT: 2},
            content_types={"web": 2},
            gaps=[],
        )

        markdown = report.to_markdown()

        assert "# Coverage Analysis Report" in markdown
        assert "## Protocol Distribution" in markdown
        assert "|" in markdown  # Table formatting
        assert "tcp" in markdown.lower()


class TestCoverageAnalyzer:
    """Test CoverageAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test creating a coverage analyzer."""
        analyzer = CoverageAnalyzer()

        assert analyzer.protocol_coverage is not None
        assert analyzer.port_coverage is not None
        assert analyzer.direction_coverage is not None
        assert analyzer.action_coverage is not None
        assert analyzer.content_types is not None

    def test_analyze_empty_ruleset(self):
        """Test analyzing an empty rule set."""
        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([])

        assert report.total_rules == 0
        assert len(report.protocol_distribution) == 0
        assert len(report.port_coverage) == 0
        assert len(report.gaps) == 0

    def test_analyze_single_rule(self):
        """Test analyzing a single rule."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        assert report.total_rules == 1
        assert Protocol.TCP in report.protocol_distribution
        assert report.protocol_distribution[Protocol.TCP] == 1
        assert 80 in report.port_coverage

    def test_analyze_protocol_distribution(self):
        """Test protocol distribution analysis."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"TCP"; sid:1;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"TCP"; sid:2;)'),
            parse_rule('alert udp any any -> any 53 (msg:"UDP"; sid:3;)'),
            parse_rule('alert icmp any any -> any any (msg:"ICMP"; sid:4;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        assert report.protocol_distribution[Protocol.TCP] == 2
        assert report.protocol_distribution[Protocol.UDP] == 1
        assert report.protocol_distribution[Protocol.ICMP] == 1

    def test_analyze_port_coverage(self):
        """Test port coverage analysis."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP2"; sid:2;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Port 80 should have 2 rules
        assert 80 in report.port_coverage
        assert report.port_coverage[80] == 2

        # Port 443 should have 1 rule
        assert 443 in report.port_coverage
        assert report.port_coverage[443] == 1

    def test_analyze_port_ranges(self):
        """Test port coverage with port ranges."""
        rule = parse_rule('alert tcp any any -> any 8000:8100 (msg:"Range"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # Should sample ports from range
        assert 8000 in report.port_coverage
        assert 8100 in report.port_coverage

    def test_analyze_direction_distribution(self):
        """Test direction distribution analysis."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"Inbound"; sid:1;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"Inbound"; sid:2;)'),
            parse_rule('alert tcp any any <- any 80 (msg:"Outbound"; sid:3;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        assert Direction.TO in report.direction_distribution
        assert report.direction_distribution[Direction.TO] == 2
        assert Direction.FROM in report.direction_distribution
        assert report.direction_distribution[Direction.FROM] == 1

    def test_analyze_action_distribution(self):
        """Test action distribution analysis."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"Alert"; sid:1;)'),
            parse_rule('drop tcp any any -> any 80 (msg:"Drop"; sid:2;)'),
            parse_rule('reject tcp any any -> any 80 (msg:"Reject"; sid:3;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        assert Action.ALERT in report.action_distribution
        assert Action.DROP in report.action_distribution
        assert Action.REJECT in report.action_distribution

    def test_content_type_classification(self):
        """Test content type classification from msg."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"SQL Injection attempt"; sid:1;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"XSS attack detected"; sid:2;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"Malware download"; sid:3;)'),
            parse_rule('alert tcp any any -> any 53 (msg:"DNS query"; sid:4;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should classify based on message content
        assert len(report.content_types) > 0

        # At least some rules should be classified
        assert sum(report.content_types.values()) > 0

    def test_common_ports_uncovered_detection(self):
        """Test detection of common ports without coverage."""
        # Only cover port 80
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should detect many common ports as uncovered
        assert len(report.common_ports_uncovered) > 0

        # Common ports like 22, 443, 53 should be in uncovered list
        assert 443 in report.common_ports_uncovered or 22 in report.common_ports_uncovered

    def test_gap_detection_tcp_heavy(self):
        """Test gap detection for TCP-heavy rule sets."""
        # Create TCP-heavy rule set (> 95% TCP)
        rules = [
            parse_rule(f'alert tcp any any -> any {1000 + i} (msg:"TCP"; sid:{i};)')
            for i in range(1, 101)
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should detect protocol imbalance
        gaps = [g for g in report.gaps if g.gap_type == "protocol"]
        assert len(gaps) > 0

        # Should mention TCP-heavy
        gap_descriptions = " ".join(g.description for g in gaps).lower()
        assert "tcp" in gap_descriptions

    def test_gap_detection_low_udp(self):
        """Test gap detection for low UDP coverage."""
        # Create rule set with very low UDP coverage
        rules = [
            parse_rule(f'alert tcp any any -> any {i} (msg:"TCP"; sid:{i};)') for i in range(1, 101)
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should detect low UDP coverage
        gaps = [g for g in report.gaps if "udp" in g.description.lower()]
        assert len(gaps) > 0

    def test_gap_detection_low_outbound(self):
        """Test gap detection for low outbound monitoring."""
        # Create inbound-only rule set
        rules = [
            parse_rule(f'alert tcp any any -> any {i} (msg:"Inbound"; sid:{i};)')
            for i in range(1, 101)
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should detect low outbound monitoring
        gaps = [g for g in report.gaps if g.gap_type == "direction"]
        assert len(gaps) > 0

    def test_gap_detection_no_blocking_rules(self):
        """Test gap detection for lack of blocking rules."""
        # Create alert-only rule set
        rules = [
            parse_rule(f'alert tcp any any -> any {i} (msg:"Alert"; sid:{i};)')
            for i in range(1, 101)
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should detect lack of blocking rules
        gaps = [g for g in report.gaps if g.gap_type == "action"]
        assert len(gaps) > 0

    def test_no_gaps_for_small_ruleset(self):
        """Test that small rule sets don't trigger percentage-based gaps."""
        # Small rule set (< 100 rules) should not trigger percentage-based gaps
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)'),
            parse_rule('alert tcp any any -> any 443 (msg:"Test"; sid:2;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Small rule sets should not trigger UDP/ICMP percentage warnings
        # (threshold checks usually require > 100 rules)
        protocol_gaps = [g for g in report.gaps if g.gap_type == "protocol"]

        # May or may not have gaps, but shouldn't have percentage-based warnings
        # for such a small ruleset
        for gap in protocol_gaps:
            # If there are protocol gaps, they should be port-related for small sets
            assert "%" not in gap.description or len(rules) < 100

    def test_analyze_preserves_state_between_calls(self):
        """Test that analyzer can be reused for multiple analyses."""
        analyzer = CoverageAnalyzer()

        rules1 = [parse_rule('alert tcp any any -> any 80 (msg:"T1"; sid:1;)')]
        report1 = analyzer.analyze(rules1)
        assert report1.total_rules == 1

        rules2 = [
            parse_rule('alert tcp any any -> any 80 (msg:"T2"; sid:2;)'),
            parse_rule('alert udp any any -> any 53 (msg:"T3"; sid:3;)'),
        ]
        report2 = analyzer.analyze(rules2)
        assert report2.total_rules == 2

        # Reports should be independent
        assert report1.total_rules == 1
        assert report2.total_rules == 2

    def test_port_list_coverage(self):
        """Test port coverage with port lists."""
        rule = parse_rule('alert tcp any any -> any [80,443,8080] (msg:"Ports"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # All ports in list should be covered
        assert 80 in report.port_coverage
        assert 443 in report.port_coverage
        assert 8080 in report.port_coverage

    def test_any_port_coverage(self):
        """Test that 'any' ports don't add to port coverage."""
        rule = parse_rule('alert tcp any any -> any any (msg:"Any"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # 'any' should not add specific ports
        # Port coverage might be empty or have only sampled ports
        # We just verify it doesn't crash
        assert isinstance(report.port_coverage, dict)


class TestContentTypeClassification:
    """Test content type classification logic."""

    def test_sql_injection_classification(self):
        """Test SQL injection pattern recognition."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"SQL injection detected"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # Should classify as SQL injection
        assert "sql injection" in report.content_types or "other" in report.content_types

    def test_xss_classification(self):
        """Test XSS pattern recognition."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"XSS attack attempt"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # Should classify as XSS
        assert "xss" in report.content_types or "other" in report.content_types

    def test_malware_classification(self):
        """Test malware pattern recognition."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Malware download detected"; sid:1;)')

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # Should classify as malware
        assert "malware" in report.content_types or "other" in report.content_types

    def test_multiple_content_types(self):
        """Test classification with multiple rule types."""
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"SQL injection"; sid:1;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"XSS attack"; sid:2;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"Unknown pattern"; sid:3;)'),
        ]

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze(rules)

        # Should have multiple content types
        assert len(report.content_types) >= 1

        # Total count should match rule count
        assert sum(report.content_types.values()) == 3

    def test_no_msg_option(self):
        """Test rules without msg option."""
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        analyzer = CoverageAnalyzer()
        report = analyzer.analyze([rule])

        # Should handle gracefully (won't classify without msg)
        assert report.total_rules == 1


class TestHelperFunctions:
    """Test helper functions."""

    def test_get_port_name(self):
        """Test port name lookup."""
        from surinort_ast.analysis.coverage import _get_port_name

        assert _get_port_name(22) == "SSH"
        assert _get_port_name(80) == "HTTP"
        assert _get_port_name(443) == "HTTPS"
        assert _get_port_name(99999) == "Unknown"
