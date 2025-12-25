"""
Coverage analysis for IDS rule sets.

This module provides functionality to analyze coverage gaps in IDS rule sets,
identifying which protocols, ports, and traffic patterns are monitored and
which are not.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, ClassVar

from ..core.enums import Action, Direction, Protocol
from ..core.nodes import (
    AnyPort,
    Port,
    PortExpr,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    Rule,
)

# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class CoverageGap:
    """
    Represents a gap in rule coverage.

    Attributes:
        gap_type: Type of gap (protocol, port, direction, content)
        description: Human-readable description
        severity: Severity level (high, medium, low)
        recommendation: Suggested action to address gap
    """

    gap_type: str
    description: str
    severity: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.gap_type,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


@dataclass
class CoverageReport:
    """
    Complete coverage analysis report.

    Attributes:
        total_rules: Total number of rules analyzed
        protocol_distribution: Count of rules per protocol
        port_coverage: Count of rules per port
        common_ports_uncovered: List of common ports without coverage
        direction_distribution: Count of rules per direction
        action_distribution: Count of rules per action
        content_types: Count of rules by attack/content type
        gaps: List of identified coverage gaps
    """

    total_rules: int
    protocol_distribution: dict[Protocol, int]
    port_coverage: dict[int, int]
    common_ports_uncovered: list[int]
    direction_distribution: dict[Direction, int]
    action_distribution: dict[Action, int]
    content_types: dict[str, int]
    gaps: list[CoverageGap] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_rules": self.total_rules,
            "protocol_distribution": {
                protocol.value: count for protocol, count in self.protocol_distribution.items()
            },
            "port_coverage": {str(port): count for port, count in self.port_coverage.items()},
            "common_ports_uncovered": self.common_ports_uncovered,
            "direction_distribution": {
                direction.value: count for direction, count in self.direction_distribution.items()
            },
            "action_distribution": {
                action.value: count for action, count in self.action_distribution.items()
            },
            "content_types": self.content_types,
            "gaps": [gap.to_dict() for gap in self.gaps],
        }

    def to_text(self) -> str:
        """Generate plain text report."""
        lines = [
            "Coverage Analysis Report",
            "=" * 80,
            "",
            f"Total Rules: {self.total_rules:,}",
            "",
            "Protocol Distribution:",
            "-" * 80,
        ]

        # Protocol distribution
        for protocol, count in sorted(
            self.protocol_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"  {protocol.value:15s} {count:6,d} rules ({pct:5.1f}%)")

        # Port coverage summary
        lines.extend(
            [
                "",
                "Port Coverage:",
                "-" * 80,
                f"  Total ports covered: {len(self.port_coverage):,}",
            ]
        )

        if self.common_ports_uncovered:
            lines.append("")
            lines.append("  Common Ports Without Coverage:")
            for port in sorted(self.common_ports_uncovered):
                port_name = _get_port_name(port)
                lines.append(f"    Port {port:5d} ({port_name})")

        # Direction distribution
        lines.extend(["", "Direction Distribution:", "-" * 80])
        for direction, count in sorted(
            self.direction_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"  {direction.value:15s} {count:6,d} rules ({pct:5.1f}%)")

        # Action distribution
        lines.extend(["", "Action Distribution:", "-" * 80])
        for action, count in sorted(
            self.action_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"  {action.value:15s} {count:6,d} rules ({pct:5.1f}%)")

        # Content types
        if self.content_types:
            lines.extend(["", "Content Type Distribution:", "-" * 80])
            for content_type, count in sorted(
                self.content_types.items(), key=lambda x: x[1], reverse=True
            )[:10]:  # Top 10
                pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
                lines.append(f"  {content_type:20s} {count:6,d} rules ({pct:5.1f}%)")

        # Coverage gaps
        if self.gaps:
            lines.extend(["", "Coverage Gaps:", "-" * 80])
            for gap in self.gaps:
                lines.append(f"  [{gap.severity.upper():6s}] {gap.description}")
                lines.append(f"           Recommendation: {gap.recommendation}")
                lines.append("")

        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            "# Coverage Analysis Report",
            "",
            f"**Total Rules:** {self.total_rules:,}",
            "",
            "## Protocol Distribution",
            "",
            "| Protocol | Count | Percentage |",
            "|----------|------:|-----------:|",
        ]

        # Protocol distribution
        for protocol, count in sorted(
            self.protocol_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"| {protocol.value} | {count:,} | {pct:.1f}% |")

        # Port coverage
        lines.extend(
            [
                "",
                "## Port Coverage",
                "",
                f"**Total ports covered:** {len(self.port_coverage):,}",
                "",
            ]
        )

        if self.common_ports_uncovered:
            lines.extend(
                [
                    "### Common Ports Without Coverage",
                    "",
                    "| Port | Service |",
                    "|-----:|---------|",
                ]
            )
            for port in sorted(self.common_ports_uncovered):
                port_name = _get_port_name(port)
                lines.append(f"| {port} | {port_name} |")
            lines.append("")

        # Direction distribution
        lines.extend(
            [
                "## Direction Distribution",
                "",
                "| Direction | Count | Percentage |",
                "|-----------|------:|-----------:|",
            ]
        )
        for direction, count in sorted(
            self.direction_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"| {direction.value} | {count:,} | {pct:.1f}% |")

        # Action distribution
        lines.extend(
            [
                "",
                "## Action Distribution",
                "",
                "| Action | Count | Percentage |",
                "|--------|------:|-----------:|",
            ]
        )
        for action, count in sorted(
            self.action_distribution.items(), key=lambda x: x[1], reverse=True
        ):
            pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
            lines.append(f"| {action.value} | {count:,} | {pct:.1f}% |")

        # Content types
        if self.content_types:
            lines.extend(
                [
                    "",
                    "## Content Type Distribution",
                    "",
                    "Top 10 most common content types:",
                    "",
                    "| Type | Count | Percentage |",
                    "|------|------:|-----------:|",
                ]
            )
            for content_type, count in sorted(
                self.content_types.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                pct = (count / self.total_rules) * 100 if self.total_rules > 0 else 0
                lines.append(f"| {content_type} | {count:,} | {pct:.1f}% |")

        # Coverage gaps
        if self.gaps:
            lines.extend(["", "## Coverage Gaps", ""])
            for gap in self.gaps:
                lines.append(f"### [{gap.severity.upper()}] {gap.gap_type.title()} Gap")
                lines.append("")
                lines.append(f"**Description:** {gap.description}")
                lines.append("")
                lines.append(f"**Recommendation:** {gap.recommendation}")
                lines.append("")

        return "\n".join(lines)


# ============================================================================
# Coverage Analyzer
# ============================================================================


class CoverageAnalyzer:
    """
    Analyzes rule coverage to identify gaps in monitoring.

    This analyzer examines a rule set to determine:
    - Which protocols are covered (TCP, UDP, HTTP, DNS, etc.)
    - Which ports are monitored
    - Traffic directions covered (inbound, outbound, bidirectional)
    - Types of attacks/content being monitored
    - Gaps in coverage that may leave blind spots

    Attributes:
        COMMON_PORTS: List of commonly-used ports to check for coverage
    """

    # Well-known ports that should typically have coverage
    COMMON_PORTS: ClassVar[list[int]] = [
        20,  # FTP Data
        21,  # FTP Control
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        80,  # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        445,  # SMB
        993,  # IMAPS
        995,  # POP3S
        1433,  # MS SQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    ]

    def __init__(self) -> None:
        """Initialize the coverage analyzer."""
        self.protocol_coverage: Counter[Protocol] = Counter()
        self.port_coverage: dict[int, list[Rule]] = defaultdict(list)
        self.direction_coverage: Counter[Direction] = Counter()
        self.action_coverage: Counter[Action] = Counter()
        self.content_types: Counter[str] = Counter()

    def analyze(self, rules: list[Rule]) -> CoverageReport:
        """
        Analyze coverage of rule set.

        Args:
            rules: List of Rule AST objects to analyze

        Returns:
            CoverageReport with complete analysis results

        Example:
            >>> analyzer = CoverageAnalyzer()
            >>> rules = parse_file("suricata.rules")
            >>> report = analyzer.analyze(rules)
            >>> print(report.to_text())
        """
        # Reset state
        self.protocol_coverage = Counter()
        self.port_coverage = defaultdict(list)
        self.direction_coverage = Counter()
        self.action_coverage = Counter()
        self.content_types = Counter()

        # Analyze each rule
        for rule in rules:
            self._analyze_rule(rule)

        # Identify gaps
        gaps = self._find_gaps(rules)

        # Build report
        port_count: dict[int, int] = {
            port: len(rule_list) for port, rule_list in self.port_coverage.items()
        }

        common_ports_uncovered = [
            port for port in self.COMMON_PORTS if port not in self.port_coverage
        ]

        return CoverageReport(
            total_rules=len(rules),
            protocol_distribution=dict(self.protocol_coverage),
            port_coverage=port_count,
            common_ports_uncovered=common_ports_uncovered,
            direction_distribution=dict(self.direction_coverage),
            action_distribution=dict(self.action_coverage),
            content_types=dict(self.content_types),
            gaps=gaps,
        )

    def _analyze_rule(self, rule: Rule) -> None:
        """Analyze a single rule for coverage metrics."""
        # Protocol coverage
        self.protocol_coverage[rule.header.protocol] += 1

        # Direction coverage
        self.direction_coverage[rule.header.direction] += 1

        # Action coverage
        self.action_coverage[rule.action] += 1

        # Port coverage - extract all ports from src and dst
        src_ports = self._extract_ports(rule.header.src_port)
        dst_ports = self._extract_ports(rule.header.dst_port)

        for port in src_ports | dst_ports:
            self.port_coverage[port].append(rule)

        # Content type analysis from msg option
        content_type = self._classify_content_type(rule)
        if content_type:
            self.content_types[content_type] += 1

    def _extract_ports(self, port_expr: PortExpr) -> set[int]:
        """
        Extract concrete port numbers from port expression.

        Args:
            port_expr: Port expression from rule header

        Returns:
            Set of port numbers (empty if 'any' or variable)
        """
        ports: set[int] = set()

        if isinstance(port_expr, Port):
            ports.add(port_expr.value)
        elif isinstance(port_expr, PortRange):
            # For ranges, include start, end, and sample some intermediate
            ports.add(port_expr.start)
            ports.add(port_expr.end)
            # Sample a few intermediate ports for large ranges
            if port_expr.end - port_expr.start > 10:
                step = (port_expr.end - port_expr.start) // 5
                for i in range(1, 5):
                    ports.add(port_expr.start + i * step)
        elif isinstance(port_expr, PortList):
            for element in port_expr.elements:
                ports.update(self._extract_ports(element))
        elif isinstance(port_expr, PortNegation):
            # For negations, we can't determine specific ports
            pass
        elif isinstance(port_expr, (AnyPort, PortVariable)):
            # Can't extract specific ports from 'any' or variables
            pass

        return ports

    def _classify_content_type(self, rule: Rule) -> str | None:
        """
        Classify rule by content/attack type based on msg and options.

        Args:
            rule: Rule to classify

        Returns:
            Content type string or None
        """
        # Extract msg from options
        msg = ""
        for option in rule.options:
            if option.node_type == "MsgOption":
                # MsgOption has 'text' attribute, not 'value'
                msg = str(getattr(option, "text", "")).lower()
                break

        if not msg:
            return None

        # Classification patterns
        patterns = {
            "sql injection": r"(sql|sqli|injection|union\s+select)",
            "xss": r"(xss|cross.?site|script.?inject)",
            "rce": r"(rce|remote\s+code|command\s+injection|shell)",
            "malware": r"(malware|trojan|virus|backdoor|ransomware)",
            "exploit": r"(exploit|cve-|vulnerability)",
            "phishing": r"(phish|fake\s+login|credential)",
            "dos/ddos": r"(dos|ddos|denial|flood|amplification)",
            "scan/probe": r"(scan|probe|recon|enumerat)",
            "bruteforce": r"(brute.?force|password\s+guess|auth\s+fail)",
            "dns": r"(dns|domain|nxdomain)",
            "web": r"(http|web|uri|url|request)",
            "tls/ssl": r"(tls|ssl|certificate)",
            "smtp/email": r"(smtp|email|mail)",
            "ftp": r"(ftp|file\s+transfer)",
            "ssh": r"(ssh|secure\s+shell)",
            "smb": r"(smb|cifs|samba)",
            "policy violation": r"(policy|unauthorized|forbidden)",
        }

        for content_type, pattern in patterns.items():
            if re.search(pattern, msg):
                return content_type

        return "other"

    def _find_gaps(self, rules: list[Rule]) -> list[CoverageGap]:
        """
        Identify coverage gaps in the rule set.

        Args:
            rules: List of rules being analyzed

        Returns:
            List of identified gaps
        """
        gaps: list[CoverageGap] = []

        if not rules:
            return gaps

        # Check common ports
        for port in self.COMMON_PORTS:
            if port not in self.port_coverage:
                port_name = _get_port_name(port)
                severity = "high" if port in [80, 443, 22, 445] else "medium"
                gaps.append(
                    CoverageGap(
                        gap_type="port",
                        description=f"Common port {port} ({port_name}) has no coverage",
                        severity=severity,
                        recommendation=f"Consider adding rules to monitor {port_name} traffic on port {port}",
                    )
                )

        # Check protocol balance
        tcp_count = self.protocol_coverage.get(Protocol.TCP, 0)
        udp_count = self.protocol_coverage.get(Protocol.UDP, 0)
        icmp_count = self.protocol_coverage.get(Protocol.ICMP, 0)

        total = len(rules)
        tcp_pct = (tcp_count / total * 100) if total > 0 else 0
        udp_pct = (udp_count / total * 100) if total > 0 else 0
        icmp_pct = (icmp_count / total * 100) if total > 0 else 0

        if tcp_pct > 95:
            gaps.append(
                CoverageGap(
                    gap_type="protocol",
                    description=f"TCP-heavy ruleset ({tcp_pct:.1f}% TCP, {udp_pct:.1f}% UDP)",
                    severity="medium",
                    recommendation="Review UDP-based attacks (DNS amplification, NTP DDoS, etc.)",
                )
            )

        if udp_pct < 2 and total >= 100:
            gaps.append(
                CoverageGap(
                    gap_type="protocol",
                    description=f"Very low UDP coverage ({udp_pct:.1f}%)",
                    severity="medium",
                    recommendation="Add rules for DNS, SNMP, NTP, and other UDP services",
                )
            )

        if icmp_pct < 0.5 and total >= 100:
            gaps.append(
                CoverageGap(
                    gap_type="protocol",
                    description=f"Very low ICMP coverage ({icmp_pct:.1f}%)",
                    severity="low",
                    recommendation="Consider adding ICMP rules for ping sweeps and tunneling",
                )
            )

        # Check direction balance
        self.direction_coverage.get(Direction.TO, 0)
        outbound = self.direction_coverage.get(Direction.FROM, 0)
        self.direction_coverage.get(Direction.BIDIRECTIONAL, 0)

        outbound_pct = (outbound / total * 100) if total > 0 else 0

        if outbound_pct < 2 and total >= 100:
            gaps.append(
                CoverageGap(
                    gap_type="direction",
                    description=f"Very low outbound traffic monitoring ({outbound_pct:.1f}%)",
                    severity="medium",
                    recommendation="Add rules for data exfiltration, C2 callbacks, and outbound attacks",
                )
            )

        # Check action distribution
        self.action_coverage.get(Action.ALERT, 0)
        drop_count = self.action_coverage.get(Action.DROP, 0)
        reject_count = self.action_coverage.get(Action.REJECT, 0)

        block_pct = ((drop_count + reject_count) / total * 100) if total > 0 else 0

        if block_pct < 1 and total >= 100:
            gaps.append(
                CoverageGap(
                    gap_type="action",
                    description=f"Very few blocking rules ({block_pct:.1f}% drop/reject)",
                    severity="low",
                    recommendation="Consider converting high-confidence alerts to drop/reject for IPS mode",
                )
            )

        return gaps


# ============================================================================
# Helper Functions
# ============================================================================


def _get_port_name(port: int) -> str:
    """Get common service name for port number."""
    port_names = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MS SQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    return port_names.get(port, "Unknown")


__all__ = [
    "CoverageAnalyzer",
    "CoverageGap",
    "CoverageReport",
]
