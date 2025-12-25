#!/usr/bin/env python3
"""
Example 06: Rule Analysis and Statistics

This example demonstrates:
- Analyzing rule corpus
- Collecting statistics
- Finding patterns
- Protocol and action distribution

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
"""

from collections import Counter
from pathlib import Path

from surinort_ast import parse_file


def main():
    """Demonstrate rule corpus analysis."""
    # Create sample rules file
    sample_rules = Path("analysis_sample.rules")
    sample_rules.write_text("""# Sample IDS Rules for Analysis
alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET"; sid:1; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP POST"; content:"POST"; sid:2; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS"; sid:3; rev:1;)
alert udp any any -> any 53 (msg:"DNS Query"; sid:4; rev:1;)
alert udp any any -> any 53 (msg:"DNS Response"; sid:5; rev:1;)
alert icmp any any -> any any (msg:"ICMP Ping"; sid:6; rev:1;)
alert tcp any any -> any 22 (msg:"SSH"; pcre:"/SSH/"; sid:7; rev:1;)
alert tcp any any -> any 21 (msg:"FTP"; sid:8; rev:1;)
""")

    print("Rule Corpus Analysis")
    print("=" * 60)

    # Parse rules
    rules = parse_file(sample_rules)
    print(f"\nTotal rules: {len(rules)}")

    # Analyze protocols
    protocols = Counter(r.header.protocol for r in rules)
    print("\nProtocol Distribution:")
    for protocol, count in protocols.most_common():
        percentage = (count / len(rules)) * 100
        print(f"  {protocol.value:6s}: {count:3d} ({percentage:5.1f}%)")

    # Analyze destination ports
    dst_ports = []
    for rule in rules:
        port = rule.header.dst_port
        if hasattr(port, "value") and isinstance(port.value, int):
            dst_ports.append(port.value)

    port_counts = Counter(dst_ports)
    print("\nTop Destination Ports:")
    for port, count in port_counts.most_common(5):
        percentage = (count / len(dst_ports)) * 100 if dst_ports else 0
        print(f"  Port {port:5d}: {count:3d} ({percentage:5.1f}%)")

    # Find rules with PCRE
    pcre_rules = []
    for rule in rules:
        for option in rule.options:
            if option.node_type == "PcreOption":
                pcre_rules.append(rule)
                break

    print(f"\nRules with PCRE: {len(pcre_rules)} ({len(pcre_rules) / len(rules) * 100:.1f}%)")

    # Find rules with content matching
    content_rules = []
    for rule in rules:
        for option in rule.options:
            if option.node_type == "ContentOption":
                content_rules.append(rule)
                break

    print(
        f"Rules with content: {len(content_rules)} ({len(content_rules) / len(rules) * 100:.1f}%)"
    )

    # Cleanup
    sample_rules.unlink()
    print("\n✓ Analysis complete")


if __name__ == "__main__":
    main()
