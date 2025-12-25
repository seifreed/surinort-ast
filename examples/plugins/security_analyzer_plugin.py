"""
Example security analyzer plugin for surinort-ast.

This plugin demonstrates how to create a custom analysis plugin that performs
security auditing on IDS rules to identify potential security issues and
performance problems.

Usage:
    >>> from surinort_ast.plugins import get_registry
    >>> from surinort_ast.parsing import parse_rule
    >>>
    >>> # Plugin auto-registers on import
    >>> import security_analyzer_plugin
    >>>
    >>> # Get analyzer from registry
    >>> registry = get_registry()
    >>> analyzer = registry.get_analyzer("security_auditor")
    >>>
    >>> # Analyze rule
    >>> rule = parse_rule('alert tcp any any -> any any (msg:"Test"; sid:1;)')
    >>> results = analyzer.analyze(rule)
    >>> print(results)

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from surinort_ast.plugins import AnalysisPlugin, get_registry

if TYPE_CHECKING:
    from surinort_ast.core.nodes import Rule
    from surinort_ast.plugins.registry import PluginRegistry


class SecurityAnalyzerPlugin(AnalysisPlugin):
    """
    Security analyzer plugin for IDS rules.

    This plugin analyzes rules for common security and performance issues:
        - Overly broad rules (any/any)
        - Missing fast_pattern optimization
        - PCRE without content anchor
        - High-volume ports without thresholds
        - Missing metadata or classification

    Features:
        - Multi-severity issue reporting (low, medium, high, critical)
        - Scoring system (0-100)
        - Performance impact analysis
        - Actionable recommendations

    Example:
        >>> plugin = SecurityAnalyzerPlugin(threshold="medium")
        >>> results = plugin.analyze(rule)
        >>> print(f"Score: {results['score']}")
        >>> for issue in results['issues']:
        ...     print(f"{issue['severity']}: {issue['message']}")
    """

    def __init__(self, threshold: str = "low"):
        """
        Initialize security analyzer.

        Args:
            threshold: Minimum severity to report (low, medium, high, critical)
        """
        self.threshold = threshold
        self._severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    @property
    def name(self) -> str:
        """Plugin name."""
        return "security_auditor"

    @property
    def version(self) -> str:
        """Plugin version."""
        return "1.0.0"

    def analyze(self, rule: Rule) -> dict[str, Any]:
        """
        Analyze rule for security and performance issues.

        Args:
            rule: Rule AST node to analyze

        Returns:
            Analysis results dictionary with:
                - issues: List of issue dicts with severity and message
                - score: Quality score (0-100, higher is better)
                - metrics: Rule complexity metrics
                - suggestions: Improvement recommendations

        Example:
            >>> results = plugin.analyze(rule)
            >>> print(results)
            {
                'issues': [
                    {'severity': 'high', 'message': 'Rule matches any source and destination'},
                    {'severity': 'medium', 'message': 'Missing fast_pattern optimization'}
                ],
                'score': 60,
                'metrics': {'pattern_count': 2, 'complexity': 5},
                'suggestions': ['Add specific IP/port constraints', 'Add fast_pattern']
            }
        """
        issues = []
        suggestions = []
        metrics = self._calculate_metrics(rule)

        # Check for overly broad rules
        issues.extend(self._check_broad_rules(rule))

        # Check for missing optimizations
        issues.extend(self._check_optimizations(rule))

        # Check for PCRE issues
        issues.extend(self._check_pcre_issues(rule))

        # Check for metadata issues
        issues.extend(self._check_metadata_issues(rule))

        # Check for threshold issues
        issues.extend(self._check_threshold_issues(rule))

        # Filter by threshold
        threshold_level = self._severity_levels.get(self.threshold, 0)
        filtered_issues = [
            issue
            for issue in issues
            if self._severity_levels.get(issue["severity"], 0) >= threshold_level
        ]

        # Generate suggestions
        suggestions = self._generate_suggestions(rule, filtered_issues)

        # Calculate score (100 - deductions)
        score = self._calculate_score(filtered_issues)

        return {
            "issues": filtered_issues,
            "score": score,
            "metrics": metrics,
            "suggestions": suggestions,
        }

    def _check_broad_rules(self, rule: Rule) -> list[dict[str, str]]:
        """Check for overly broad address/port matching."""
        issues = []

        # Check if both source and destination are 'any'
        if rule.header.src_addr.node_type == "AnyAddress":
            if rule.header.dst_addr.node_type == "AnyAddress":
                issues.append(
                    {
                        "severity": "high",
                        "message": "Rule matches any source and destination address",
                        "recommendation": "Specify explicit IP ranges or use $HOME_NET/$EXTERNAL_NET",
                    }
                )

        # Check if both ports are 'any'
        if rule.header.src_port.node_type == "AnyPort":
            if rule.header.dst_port.node_type == "AnyPort":
                issues.append(
                    {
                        "severity": "medium",
                        "message": "Rule matches any source and destination port",
                        "recommendation": "Specify explicit ports or port ranges",
                    }
                )

        return issues

    def _check_optimizations(self, rule: Rule) -> list[dict[str, str]]:
        """Check for missing performance optimizations."""
        issues = []

        # Check for content options
        has_content = any(opt.node_type == "ContentOption" for opt in rule.options)
        has_fast_pattern = any(opt.node_type == "FastPatternOption" for opt in rule.options)

        if has_content and not has_fast_pattern:
            # Multiple content options without fast_pattern
            content_count = sum(1 for opt in rule.options if opt.node_type == "ContentOption")
            if content_count > 1:
                issues.append(
                    {
                        "severity": "medium",
                        "message": f"Rule has {content_count} content patterns without fast_pattern",
                        "recommendation": "Add fast_pattern to most specific content",
                    }
                )

        return issues

    def _check_pcre_issues(self, rule: Rule) -> list[dict[str, str]]:
        """Check for PCRE-related performance issues."""
        issues = []

        has_pcre = any(opt.node_type == "PcreOption" for opt in rule.options)
        has_content = any(opt.node_type == "ContentOption" for opt in rule.options)

        if has_pcre and not has_content:
            issues.append(
                {
                    "severity": "high",
                    "message": "PCRE without content anchor may cause severe performance issues",
                    "recommendation": "Add content pattern before PCRE to anchor matching",
                }
            )

        # Check for complex PCRE patterns
        if has_pcre:
            for opt in rule.options:
                if opt.node_type == "PcreOption":
                    pattern = opt.pattern  # type: ignore
                    if ".*" in pattern or ".+" in pattern:
                        issues.append(
                            {
                                "severity": "medium",
                                "message": "PCRE contains greedy quantifiers (.*/.+)",
                                "recommendation": "Use non-greedy quantifiers or specific patterns",
                            }
                        )
                    break

        return issues

    def _check_metadata_issues(self, rule: Rule) -> list[dict[str, str]]:
        """Check for missing metadata and classification."""
        issues = []

        has_msg = any(opt.node_type == "MsgOption" for opt in rule.options)
        has_sid = any(opt.node_type == "SidOption" for opt in rule.options)
        has_classtype = any(opt.node_type == "ClasstypeOption" for opt in rule.options)
        has_reference = any(opt.node_type == "ReferenceOption" for opt in rule.options)

        if not has_msg:
            issues.append(
                {
                    "severity": "low",
                    "message": "Rule missing msg option",
                    "recommendation": "Add descriptive msg for alert identification",
                }
            )

        if not has_sid:
            issues.append(
                {
                    "severity": "critical",
                    "message": "Rule missing sid (signature ID)",
                    "recommendation": "Add unique sid for rule tracking",
                }
            )

        if not has_classtype:
            issues.append(
                {
                    "severity": "low",
                    "message": "Rule missing classtype classification",
                    "recommendation": "Add classtype for alert categorization",
                }
            )

        if not has_reference:
            issues.append(
                {
                    "severity": "low",
                    "message": "Rule missing reference to CVE/advisory",
                    "recommendation": "Add reference for threat context",
                }
            )

        return issues

    def _check_threshold_issues(self, rule: Rule) -> list[dict[str, str]]:
        """Check for high-volume scenarios without thresholds."""
        issues = []

        # Common high-volume ports
        high_volume_ports = {80, 443, 8080, 8443, 53}

        # Check if rule targets high-volume port without threshold
        has_threshold = any(opt.node_type == "ThresholdOption" for opt in rule.options)
        has_detection_filter = any(opt.node_type == "DetectionFilterOption" for opt in rule.options)

        if not has_threshold and not has_detection_filter:
            # Check destination port
            if rule.header.dst_port.node_type == "Port":
                port_value = rule.header.dst_port.value  # type: ignore
                if port_value in high_volume_ports:
                    issues.append(
                        {
                            "severity": "medium",
                            "message": f"Rule targets high-volume port {port_value} without threshold",
                            "recommendation": "Add threshold or detection_filter to prevent alert floods",
                        }
                    )

        return issues

    def _calculate_metrics(self, rule: Rule) -> dict[str, int]:
        """Calculate rule complexity metrics."""
        metrics = {
            "option_count": len(rule.options),
            "content_count": sum(1 for opt in rule.options if opt.node_type == "ContentOption"),
            "pcre_count": sum(1 for opt in rule.options if opt.node_type == "PcreOption"),
            "byte_test_count": sum(1 for opt in rule.options if opt.node_type == "ByteTestOption"),
        }

        # Calculate complexity score
        complexity = (
            metrics["content_count"] * 2
            + metrics["pcre_count"] * 5
            + metrics["byte_test_count"] * 3
        )
        metrics["complexity"] = complexity

        return metrics

    def _generate_suggestions(self, rule: Rule, issues: list[dict[str, str]]) -> list[str]:
        """Generate actionable improvement suggestions."""
        suggestions = []

        # Extract recommendations from issues
        for issue in issues:
            if "recommendation" in issue:
                suggestions.append(issue["recommendation"])

        return suggestions

    def _calculate_score(self, issues: list[dict[str, str]]) -> int:
        """Calculate quality score (0-100)."""
        # Deduction per severity
        deductions = {"low": 5, "medium": 10, "high": 20, "critical": 30}

        total_deduction = sum(deductions.get(issue["severity"], 0) for issue in issues)

        # Clamp to 0-100
        score = max(0, 100 - total_deduction)

        return score

    def register(self, registry: PluginRegistry) -> None:
        """
        Register plugin with the global registry.

        Args:
            registry: Global plugin registry
        """
        registry.register_analyzer(self.name, self)


# ============================================================================
# Auto-register on import
# ============================================================================

# Create plugin instance and register
_security_plugin = SecurityAnalyzerPlugin()
_security_plugin.register(get_registry())

# ============================================================================
# License Information
# ============================================================================

__all__ = ["SecurityAnalyzerPlugin"]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
