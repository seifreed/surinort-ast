"""
Stream processors for filtering, transforming, and validating rules during streaming.

This module provides composable stream processors that can be chained together
to create processing pipelines.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.enums import Action, Protocol
from ..core.nodes import Rule, SidOption

logger = logging.getLogger(__name__)


# ============================================================================
# Base Stream Processor
# ============================================================================


class StreamProcessor(ABC):
    """
    Abstract base class for stream processors.

    Stream processors transform or filter rules as they flow through the
    streaming pipeline. They can be chained together for complex processing.

    Examples:
        >>> # Create custom processor
        >>> class MyProcessor(StreamProcessor):
        ...     def process(self, rule):
        ...         # Custom processing logic
        ...         return rule
        ...
        >>> processor = MyProcessor()
        >>> for rule in processor.stream(input_stream):
        ...     output(rule)
    """

    @abstractmethod
    def process(self, rule: Rule) -> Rule | None:
        """
        Process a single rule.

        Args:
            rule: Input rule

        Returns:
            Processed rule, or None to filter out the rule
        """

    def stream(self, rules: Iterable[Rule]) -> Generator[Rule, None, None]:
        """
        Stream process rules through this processor.

        Args:
            rules: Input rule stream

        Yields:
            Processed rules
        """
        for rule in rules:
            result = self.process(rule)
            if result is not None:
                yield result

    def __or__(self, other: StreamProcessor) -> ChainedProcessor:
        """
        Chain processors using | operator.

        Examples:
            >>> pipeline = FilterProcessor(...) | TransformProcessor(...) | ValidateProcessor(...)
            >>> for rule in pipeline.stream(input_stream):
            ...     output(rule)
        """
        return ChainedProcessor([self, other])


class ChainedProcessor(StreamProcessor):
    """
    Chains multiple processors into a pipeline.

    Examples:
        >>> pipeline = ChainedProcessor([
        ...     FilterProcessor(lambda r: r.header.protocol == Protocol.TCP),
        ...     TransformProcessor(lambda r: normalize(r)),
        ...     ValidateProcessor(),
        ... ])
        >>> for rule in pipeline.stream(input_stream):
        ...     output(rule)
    """

    def __init__(self, processors: list[StreamProcessor]):
        """
        Initialize chained processor.

        Args:
            processors: List of processors to chain
        """
        self.processors = processors

    def process(self, rule: Rule) -> Rule | None:
        """
        Process rule through all processors in sequence.

        Args:
            rule: Input rule

        Returns:
            Final processed rule, or None if filtered
        """
        current: Rule | None = rule

        for processor in self.processors:
            if current is None:
                return None

            current = processor.process(current)

        return current

    def __or__(self, other: StreamProcessor) -> ChainedProcessor:
        """Extend chain with another processor."""
        return ChainedProcessor([*self.processors, other])


# ============================================================================
# Filter Processor
# ============================================================================


class FilterProcessor(StreamProcessor):
    """
    Filters rules based on a predicate function.

    Examples:
        >>> # Filter by protocol
        >>> tcp_only = FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        >>> for rule in tcp_only.stream(input_stream):
        ...     process(rule)

        >>> # Filter by action
        >>> alerts_only = FilterProcessor(lambda r: r.action == Action.ALERT)

        >>> # Filter by SID range
        >>> sid_filter = FilterProcessor(
        ...     lambda r: any(opt.node_type == "SidOption" and 1000 <= opt.value < 2000
        ...                   for opt in r.options)
        ... )

        >>> # Chain filters
        >>> pipeline = (
        ...     FilterProcessor(lambda r: r.header.protocol == Protocol.TCP)
        ...     | FilterProcessor(lambda r: r.action == Action.ALERT)
        ... )
    """

    def __init__(self, predicate: Callable[[Rule], bool]):
        """
        Initialize filter processor.

        Args:
            predicate: Function that returns True to keep rule, False to filter out
        """
        self.predicate = predicate

    def process(self, rule: Rule) -> Rule | None:
        """
        Filter rule based on predicate.

        Args:
            rule: Input rule

        Returns:
            Rule if predicate returns True, None otherwise
        """
        try:
            if self.predicate(rule):
                return rule
            return None
        except Exception as e:
            logger.warning(f"Filter predicate error: {e}")
            return None


# ============================================================================
# Transform Processor
# ============================================================================


class TransformProcessor(StreamProcessor):
    """
    Transforms rules using a transformation function.

    Examples:
        >>> # Normalize rule formatting
        >>> def normalize(rule):
        ...     # Apply normalization logic
        ...     return rule.model_copy(update={...})
        ...
        >>> normalizer = TransformProcessor(normalize)

        >>> # Add custom metadata
        >>> def add_metadata(rule):
        ...     # Add custom fields
        ...     return rule.model_copy(...)
        ...
        >>> enricher = TransformProcessor(add_metadata)

        >>> # Update actions
        >>> def alert_to_drop(rule):
        ...     if rule.action == Action.ALERT:
        ...         return rule.model_copy(update={"action": Action.DROP})
        ...     return rule
        ...
        >>> converter = TransformProcessor(alert_to_drop)
    """

    def __init__(self, transformer: Callable[[Rule], Rule]):
        """
        Initialize transform processor.

        Args:
            transformer: Function that transforms a rule
        """
        self.transformer = transformer

    def process(self, rule: Rule) -> Rule | None:
        """
        Transform rule using transformation function.

        Args:
            rule: Input rule

        Returns:
            Transformed rule, or None on error
        """
        try:
            return self.transformer(rule)
        except Exception as e:
            logger.error(f"Transform error: {e}")
            return None


# ============================================================================
# Validate Processor
# ============================================================================


class ValidateProcessor(StreamProcessor):
    """
    Validates rules and adds diagnostic information.

    Examples:
        >>> # Basic validation
        >>> validator = ValidateProcessor()
        >>> for rule in validator.stream(input_stream):
        ...     if rule.diagnostics:
        ...         print(f"Warnings: {rule.diagnostics}")

        >>> # Strict validation (filter invalid rules)
        >>> strict_validator = ValidateProcessor(strict=True)

        >>> # Custom validators
        >>> def check_sid_range(rule):
        ...     for opt in rule.options:
        ...         if opt.node_type == "SidOption" and opt.value < 1000000:
        ...             return [Diagnostic(
        ...                 level=DiagnosticLevel.ERROR,
        ...                 message="SID must be >= 1000000 for custom rules"
        ...             )]
        ...     return []
        ...
        >>> custom_validator = ValidateProcessor(custom_validators=[check_sid_range])
    """

    def __init__(
        self,
        strict: bool = False,
        custom_validators: list[Callable[[Rule], list[Diagnostic]]] | None = None,
    ):
        """
        Initialize validate processor.

        Args:
            strict: If True, filter out rules with error-level diagnostics
            custom_validators: List of custom validation functions
        """
        self.strict = strict
        self.custom_validators = custom_validators or []

    def process(self, rule: Rule) -> Rule | None:
        """
        Validate rule and add diagnostics.

        Args:
            rule: Input rule

        Returns:
            Rule with diagnostics, or None if strict and has errors
        """
        diagnostics = list(rule.diagnostics)

        # Run built-in validators
        diagnostics.extend(self._validate_required_options(rule))
        diagnostics.extend(self._validate_sid_uniqueness(rule))

        # Run custom validators
        for validator in self.custom_validators:
            try:
                custom_diags = validator(rule)
                diagnostics.extend(custom_diags)
            except Exception as e:
                logger.error(f"Custom validator error: {e}")

        # Update rule with diagnostics
        if diagnostics != rule.diagnostics:
            rule = rule.model_copy(update={"diagnostics": diagnostics})

        # Filter if strict and has errors
        if self.strict:
            has_errors = any(d.level == DiagnosticLevel.ERROR for d in diagnostics)
            if has_errors:
                return None

        return rule

    def _validate_required_options(self, rule: Rule) -> list[Diagnostic]:
        """
        Validate required options are present.

        Args:
            rule: Rule to validate

        Returns:
            List of diagnostics
        """
        diagnostics: list[Diagnostic] = []

        # Check for required options
        has_sid = any(opt.node_type == "SidOption" for opt in rule.options)
        has_msg = any(opt.node_type == "MsgOption" for opt in rule.options)

        if not has_sid:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    message="Missing required option 'sid'",
                    code="missing_sid",
                )
            )

        if not has_msg:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    message="Missing required option 'msg'",
                    code="missing_msg",
                )
            )

        return diagnostics

    def _validate_sid_uniqueness(self, rule: Rule) -> list[Diagnostic]:
        """
        Validate SID uniqueness (placeholder for multi-rule context).

        Args:
            rule: Rule to validate

        Returns:
            List of diagnostics
        """
        # Note: True SID uniqueness requires tracking across multiple rules
        # This is a placeholder for single-rule validation
        return []


# ============================================================================
# Aggregate Processor
# ============================================================================


@dataclass
class AggregateStats:
    """
    Statistics collected during streaming.

    Attributes:
        total_rules: Total number of rules processed
        rules_by_action: Count of rules by action type
        rules_by_protocol: Count of rules by protocol
        rules_with_errors: Number of rules with error diagnostics
        rules_with_warnings: Number of rules with warning diagnostics
        unique_sids: Set of unique SID values
        custom_stats: Dictionary for custom statistics
    """

    total_rules: int = 0
    rules_by_action: dict[Action, int] = field(default_factory=dict)
    rules_by_protocol: dict[Protocol, int] = field(default_factory=dict)
    rules_with_errors: int = 0
    rules_with_warnings: int = 0
    unique_sids: set[int] = field(default_factory=set)
    custom_stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert stats to dictionary.

        Returns:
            Dictionary representation of stats
        """
        return {
            "total_rules": self.total_rules,
            "rules_by_action": {
                action.value: count for action, count in self.rules_by_action.items()
            },
            "rules_by_protocol": {
                protocol.value: count for protocol, count in self.rules_by_protocol.items()
            },
            "rules_with_errors": self.rules_with_errors,
            "rules_with_warnings": self.rules_with_warnings,
            "unique_sids": len(self.unique_sids),
            "custom_stats": self.custom_stats,
        }


class AggregateProcessor(StreamProcessor):
    """
    Collects statistics while streaming rules.

    This processor passes rules through unchanged but collects aggregate
    statistics for analysis.

    Examples:
        >>> # Basic aggregation
        >>> aggregator = AggregateProcessor()
        >>> for rule in aggregator.stream(input_stream):
        ...     process(rule)
        >>> print(f"Total rules: {aggregator.stats.total_rules}")
        >>> print(f"By protocol: {aggregator.stats.rules_by_protocol}")

        >>> # Custom aggregation
        >>> def count_pcre(stats, rule):
        ...     pcre_count = sum(1 for opt in rule.options if opt.node_type == "PcreOption")
        ...     stats.custom_stats["total_pcre"] = stats.custom_stats.get("total_pcre", 0) + pcre_count
        ...
        >>> aggregator = AggregateProcessor(custom_aggregators=[count_pcre])

        >>> # Pipeline with aggregation
        >>> pipeline = FilterProcessor(...) | AggregateProcessor() | TransformProcessor(...)
        >>> for rule in pipeline.stream(input_stream):
        ...     output(rule)
        >>> print(pipeline.processors[1].stats.to_dict())
    """

    def __init__(
        self,
        custom_aggregators: list[Callable[[AggregateStats, Rule], None]] | None = None,
    ):
        """
        Initialize aggregate processor.

        Args:
            custom_aggregators: List of custom aggregation functions that
                               update stats based on rule
        """
        self.stats = AggregateStats()
        self.custom_aggregators = custom_aggregators or []

    def process(self, rule: Rule) -> Rule:
        """
        Aggregate statistics and pass rule through.

        Args:
            rule: Input rule

        Returns:
            Unmodified rule
        """
        # Update total count
        self.stats.total_rules += 1

        # Count by action
        action = rule.action
        self.stats.rules_by_action[action] = self.stats.rules_by_action.get(action, 0) + 1

        # Count by protocol
        protocol = rule.header.protocol
        self.stats.rules_by_protocol[protocol] = self.stats.rules_by_protocol.get(protocol, 0) + 1

        # Count diagnostics
        if rule.diagnostics:
            has_error = any(d.level == DiagnosticLevel.ERROR for d in rule.diagnostics)
            has_warning = any(d.level == DiagnosticLevel.WARNING for d in rule.diagnostics)

            if has_error:
                self.stats.rules_with_errors += 1
            if has_warning:
                self.stats.rules_with_warnings += 1

        # Extract SID
        for opt in rule.options:
            if isinstance(opt, SidOption):
                self.stats.unique_sids.add(opt.value)

        # Run custom aggregators
        for aggregator in self.custom_aggregators:
            try:
                aggregator(self.stats, rule)
            except Exception as e:
                logger.error(f"Custom aggregator error: {e}")

        return rule

    def reset(self) -> None:
        """Reset statistics to initial state."""
        self.stats = AggregateStats()
