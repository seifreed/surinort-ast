#!/usr/bin/env python3
"""
Coverage Analysis Example for surinort-ast

Demonstrates how to analyze IDS rule coverage to identify gaps in monitoring.
This example shows:
- Protocol distribution analysis
- Port coverage analysis
- Direction and action distribution
- Gap detection and recommendations

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from surinort_ast import parse_rule
from surinort_ast.analysis import CoverageAnalyzer


def main():
    """
    Analyze coverage of a rule set and generate reports.
    """
    print("=" * 80)
    print("Coverage Analysis Example")
    print("=" * 80)
    print()

    # Create a sample rule set representing typical IDS deployment
    rules = [
        # HTTP/HTTPS Rules
        parse_rule(
            'alert tcp any any -> any 80 (content:"GET"; content:"/admin"; msg:"HTTP admin access"; sid:1;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"POST"; content:"login"; msg:"HTTP login attempt"; sid:2;)'
        ),
        parse_rule('alert tcp any any -> any 443 (content:"TLS"; msg:"HTTPS traffic"; sid:3;)'),
        parse_rule(
            'alert tcp any any -> any 8080 (content:"HTTP"; msg:"HTTP alternate port"; sid:4;)'
        ),
        parse_rule(
            'alert tcp any any -> any 8443 (content:"HTTPS"; msg:"HTTPS alternate port"; sid:5;)'
        ),
        # DNS Rules
        parse_rule('alert udp any any -> any 53 (content:"DNS"; msg:"DNS query"; sid:6;)'),
        parse_rule('alert tcp any any -> any 53 (content:"DNS"; msg:"DNS over TCP"; sid:7;)'),
        # Email Rules
        parse_rule('alert tcp any any -> any 25 (content:"MAIL FROM"; msg:"SMTP traffic"; sid:8;)'),
        parse_rule('alert tcp any any -> any 587 (content:"EHLO"; msg:"SMTP submission"; sid:9;)'),
        # Database Rules
        parse_rule(
            'alert tcp any any -> any 3306 (content:"SELECT"; msg:"MySQL traffic"; sid:10;)'
        ),
        parse_rule(
            'alert tcp any any -> any 5432 (content:"postgres"; msg:"PostgreSQL traffic"; sid:11;)'
        ),
        # SMB Rules
        parse_rule('alert tcp any any -> any 445 (content:"SMB"; msg:"SMB traffic"; sid:12;)'),
        parse_rule(
            'alert tcp any any -> any 139 (content:"NetBIOS"; msg:"NetBIOS traffic"; sid:13;)'
        ),
        # ICMP Rules
        parse_rule('alert icmp any any -> any any (itype:8; msg:"ICMP Echo Request"; sid:14;)'),
        parse_rule('alert icmp any any -> any any (itype:0; msg:"ICMP Echo Reply"; sid:15;)'),
        # Attack Detection Rules
        parse_rule(
            'alert tcp any any -> any 80 (pcre:"/\\.(exe|dll|bat)$/"; msg:"Malware download"; sid:16;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"union select"; nocase; msg:"SQL injection"; sid:17;)'
        ),
        parse_rule(
            'alert tcp any any -> any 80 (content:"<script>"; nocase; msg:"XSS attempt"; sid:18;)'
        ),
        # Outbound Monitoring
        parse_rule(
            'alert tcp any any <- any 80 (content:"passwd"; msg:"Possible data exfiltration"; sid:19;)'
        ),
        parse_rule(
            'alert tcp any any <- any 443 (content:"password"; msg:"Outbound password leak"; sid:20;)'
        ),
    ]

    print(f"Analyzing {len(rules)} IDS rules...")
    print()

    # Create analyzer and run analysis
    analyzer = CoverageAnalyzer()
    report = analyzer.analyze(rules)

    # Display text report
    print(report.to_text())
    print()

    # Display additional insights
    print("=" * 80)
    print("Analysis Insights")
    print("=" * 80)
    print()

    # Protocol breakdown with percentages
    print("Protocol Coverage:")
    for protocol, count in sorted(
        report.protocol_distribution.items(), key=lambda x: x[1], reverse=True
    ):
        percentage = (count / report.total_rules) * 100
        print(f"  {protocol.value:10s}: {count:3d} rules ({percentage:5.1f}%)")
    print()

    # Top monitored ports
    print("Top 10 Monitored Ports:")
    sorted_ports = sorted(report.port_coverage.items(), key=lambda x: x[1], reverse=True)[:10]
    for port, count in sorted_ports:
        from surinort_ast.analysis.coverage import _get_port_name

        port_name = _get_port_name(port)
        print(f"  Port {port:5d} ({port_name:15s}): {count} rules")
    print()

    # Direction analysis
    print("Traffic Direction Coverage:")
    for direction, count in report.direction_distribution.items():
        percentage = (count / report.total_rules) * 100
        print(f"  {direction.value:15s}: {count:3d} rules ({percentage:5.1f}%)")
    print()

    # Action distribution
    print("Rule Actions:")
    for action, count in report.action_distribution.items():
        percentage = (count / report.total_rules) * 100
        print(f"  {action.value:10s}: {count:3d} rules ({percentage:5.1f}%)")
    print()

    # Content type distribution
    if report.content_types:
        print("Attack Types Covered:")
        for content_type, count in sorted(
            report.content_types.items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / report.total_rules) * 100
            print(f"  {content_type:20s}: {count:3d} rules ({percentage:5.1f}%)")
        print()

    # Gaps and recommendations
    if report.gaps:
        print("=" * 80)
        print(f"Found {len(report.gaps)} Coverage Gaps")
        print("=" * 80)
        print()

        for i, gap in enumerate(report.gaps, 1):
            print(f"Gap #{i}: [{gap.severity.upper()}] {gap.gap_type.title()}")
            print(f"  Description: {gap.description}")
            print(f"  Recommendation: {gap.recommendation}")
            print()
    else:
        print("✓ No significant coverage gaps detected")
        print()

    # Export reports
    print("=" * 80)
    print("Exporting Reports")
    print("=" * 80)
    print()

    # Export as Markdown
    markdown_content = report.to_markdown()
    with open("/tmp/coverage_report.md", "w") as f:
        f.write(markdown_content)
    print("✓ Markdown report saved to: /tmp/coverage_report.md")

    # Export as JSON
    import json

    json_content = json.dumps(report.to_dict(), indent=2)
    with open("/tmp/coverage_report.json", "w") as f:
        f.write(json_content)
    print("✓ JSON report saved to: /tmp/coverage_report.json")
    print()

    # Summary statistics
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Total Rules Analyzed: {report.total_rules}")
    print(f"Protocols Covered: {len(report.protocol_distribution)}")
    print(f"Unique Ports Monitored: {len(report.port_coverage)}")
    print(f"Common Ports Uncovered: {len(report.common_ports_uncovered)}")
    print(f"Coverage Gaps Found: {len(report.gaps)}")
    print()


if __name__ == "__main__":
    main()
