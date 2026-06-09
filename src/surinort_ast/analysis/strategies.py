"""
Optimization strategies for IDS rules.

Individual strategies that improve rule performance through various techniques:
- Option reordering (fail-fast)
- Fast pattern selection
- Redundancy removal
- Content combination

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from ..core.nodes import ContentOption, Option, Rule

from .optimizer import Optimization

# Options whose meaning depends on their position in the option sequence: sticky
# content modifiers, relative offsets, sticky-buffer selection, and the byte_*
# family (which defines and consumes extracted variables in order). Reordering
# them, or removing a "duplicate", detaches them from the content they qualify
# and silently changes detection semantics, so strategies must treat their
# presence as order-significant.
POSITIONAL_OPTIONS: frozenset[str] = frozenset(
    {
        "DepthOption",
        "OffsetOption",
        "DistanceOption",
        "WithinOption",
        "NocaseOption",
        "RawbytesOption",
        "StartswithOption",
        "EndswithOption",
        "FastPatternOption",
        "BufferSelectOption",
        "LuaOption",
        "LuajitOption",
    }
)

# These keywords parse to a keyword-tagged GenericOption rather than a dedicated
# node, yet each is position- and state-significant, so moving or deduplicating
# them changes what the rule matches:
#   - byte inspection (byte_test/byte_jump/byte_extract/byte_math/isdataat)
#     inspects bytes at a position, often relative to the preceding match, and
#     can define or reference byte_extract variables;
#   - cursor navigation (ber_data/ber_skip) advances a BER/ASN.1 cursor, so two
#     identical steps descend into different nested elements (not duplicates);
#   - buffer transforms (base64_decode/base64_data/from_base64, the to_* hashes,
#     url_decode, the *_whitespace ops, dotprefix/dotsuffix, header_lowercase,
#     strip_pseudo_headers, pcrexform, xor) rewrite or re-base the inspection
#     buffer for the content that follows, so order and repetition are
#     meaningful;
#   - sticky-buffer re-basers that fall through to GenericOption (raw_data,
#     dce_stub_data, http_param) re-scope which buffer following content binds
#     to.
# Stateless predicate keywords (dsize, ttl, flags, itype, urilen, ...) are
# deliberately excluded so legitimate dedup/reorder still applies.
_STATEFUL_GENERIC_KEYWORDS: frozenset[str] = frozenset(
    {
        "byte_test",
        "byte_jump",
        "byte_extract",
        "byte_math",
        "isdataat",
        "ber_data",
        "ber_skip",
        "base64_decode",
        "base64_data",
        "from_base64",
        "to_md5",
        "to_sha1",
        "to_sha256",
        "url_decode",
        "strip_whitespace",
        "compress_whitespace",
        "dotprefix",
        "dotsuffix",
        "header_lowercase",
        "strip_pseudo_headers",
        "pcrexform",
        "xor",
        "raw_data",
        "dce_stub_data",
        "http_param",
    }
)


def _is_order_significant(opt: Option) -> bool:
    """True if reordering or removing ``opt`` would change detection semantics.

    Besides the fixed POSITIONAL_OPTIONS set:
    - a PCRE carrying the ``R`` flag matches relative to the buffer position of
      the preceding content match, so it is position-dependent like distance/
      within and must not be moved;
    - a byte_* / isdataat GenericOption is position- and variable-stateful, and
      any GenericOption carrying a ``relative`` modifier is anchored to the
      preceding match.
    """
    if opt.node_type in POSITIONAL_OPTIONS:
        return True
    if opt.node_type == "PcreOption" and "R" in (getattr(opt, "flags", "") or ""):
        return True
    if opt.node_type == "GenericOption":
        if (getattr(opt, "keyword", "") or "") in _STATEFUL_GENERIC_KEYWORDS:
            return True
        if "relative" in (getattr(opt, "value", "") or ""):
            return True
    return False


class OptimizationStrategy(ABC):
    """
    Base class for optimization strategies.

    Each strategy implements a specific optimization technique that may
    improve rule performance while preserving detection logic.
    """

    @abstractmethod
    def apply(self, rule: Rule) -> tuple[Rule | None, list[Optimization]]:
        """
        Apply optimization strategy to a rule.

        Args:
            rule: Rule to optimize

        Returns:
            Tuple of (optimized_rule, optimizations).
            If no optimization was possible, returns (None, []).

        Example:
            >>> optimized, opts = strategy.apply(rule)
            >>> if optimized is not None:
            ...     print(f"Applied {len(opts)} optimizations")
        """

    @abstractmethod
    def estimate_gain(self, rule: Rule) -> float:
        """
        Estimate potential performance gain.

        Args:
            rule: Rule to analyze

        Returns:
            Estimated gain (0.0 to 100.0 percentage)

        Example:
            >>> gain = strategy.estimate_gain(rule)
            >>> if gain > 5.0:
            ...     print(f"Potential {gain:.1f}% improvement")
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Get strategy name."""


class OptionReorderStrategy(OptimizationStrategy):
    """
    Reorder options for fail-fast evaluation.

    Fast options (flow, content) should come before slow options (pcre)
    to enable early rejection of non-matching packets.

    Strategy:
        1. Assign priority to each option type
        2. Sort options by priority (stable sort preserves relative order)
        3. Keep metadata options at the end
    """

    # Priority mapping (lower = evaluated first)
    # Based on typical IDS engine evaluation performance
    OPTION_PRIORITY: ClassVar[dict[str, int]] = {
        # Fast filters - evaluate first for early rejection
        "FlowOption": 1,
        "FlowbitsOption": 2,
        # Content matching - fast with fast_pattern
        "ContentOption": 3,
        "FastPatternOption": 3,  # Usually associated with content
        # Buffer selection
        "BufferSelectOption": 4,
        # Byte operations - medium cost
        "ByteTestOption": 5,
        "ByteJumpOption": 5,
        "ByteExtractOption": 5,
        # Position modifiers
        "DepthOption": 6,
        "OffsetOption": 6,
        "DistanceOption": 6,
        "WithinOption": 6,
        "NocaseOption": 6,
        "RawbytesOption": 6,
        "StartswithOption": 6,
        "EndswithOption": 6,
        # Expensive operations - evaluate last
        "PcreOption": 10,
        # Actions and filters
        "ThresholdOption": 15,
        "DetectionFilterOption": 15,
        "TagOption": 15,
        "FilestoreOption": 15,
        # Metadata - no performance impact, keep at end
        "MsgOption": 100,
        "SidOption": 100,
        "RevOption": 100,
        "GidOption": 100,
        "ClasstypeOption": 100,
        "PriorityOption": 100,
        "ReferenceOption": 100,
        "MetadataOption": 100,
        # Generic fallback
        "GenericOption": 50,
    }

    @property
    def name(self) -> str:
        """Get strategy name."""
        return "OptionReorder"

    def apply(self, rule: Rule) -> tuple[Rule | None, list[Optimization]]:
        """
        Reorder options by priority.

        Args:
            rule: Rule to optimize

        Returns:
            Optimized rule with reordered options, or None if already optimal
        """
        if len(rule.options) < 2:
            # Nothing to reorder
            return None, []

        if any(_is_order_significant(opt) for opt in rule.options):
            # A positional option (sticky modifier, relative offset, sticky
            # buffer, byte_* variable, or relative PCRE) is present; reordering
            # would detach it from the content it qualifies and change
            # detection. Leave as-is.
            return None, []

        # Sort options by priority (stable sort)
        sorted_options = sorted(
            rule.options,
            key=lambda opt: self.OPTION_PRIORITY.get(opt.node_type, 50),
        )

        # Check if order changed
        if list(sorted_options) == list(rule.options):
            return None, []

        # Create optimized rule
        optimized = rule.model_copy(update={"options": sorted_options})

        # Import printer for before/after text
        from ..printer.text_printer import TextPrinter

        printer = TextPrinter()
        before_text = printer.print_rule(rule)
        after_text = printer.print_rule(optimized)

        # Calculate estimated gain
        estimated_gain = self.estimate_gain(rule)

        optimization = Optimization(
            strategy=self.name,
            description="Reordered options for fail-fast evaluation",
            estimated_gain=estimated_gain,
            before=before_text,
            after=after_text,
            details={
                "option_count": len(rule.options),
                "reordered": True,
            },
        )

        return optimized, [optimization]

    def estimate_gain(self, rule: Rule) -> float:
        """
        Estimate gain from reordering.

        Higher gain when expensive options are early in the current order.
        """
        from .estimator import PerformanceEstimator

        if any(_is_order_significant(opt) for opt in rule.options):
            # Reordering is unsafe for these rules (see apply), so no gain.
            return 0.0

        estimator = PerformanceEstimator()

        # Calculate position penalty before optimization
        current_penalty = estimator.estimate_position_penalty(list(rule.options))

        # Simulate optimal ordering
        sorted_options = sorted(
            rule.options,
            key=lambda opt: self.OPTION_PRIORITY.get(opt.node_type, 50),
        )
        optimal_penalty = estimator.estimate_position_penalty(sorted_options)

        if current_penalty == 0:
            return 0.0

        # Return percentage improvement
        return ((current_penalty - optimal_penalty) / current_penalty) * 100.0


class FastPatternStrategy(OptimizationStrategy):
    """
    Select optimal content for fast_pattern.

    IDS engines use fast_pattern to quickly filter packets before full
    rule evaluation. The best content should be:
    - Distinctive (long, specific)
    - Not case-insensitive (faster matching)
    - Not at beginning/end of buffer (more flexible)

    Strategy:
        1. Find all content options
        2. Score each by distinctiveness
        3. If no fast_pattern is set, add to best content
        4. If suboptimal fast_pattern exists, suggest moving it
    """

    @property
    def name(self) -> str:
        """Get strategy name."""
        return "FastPattern"

    def apply(self, rule: Rule) -> tuple[Rule | None, list[Optimization]]:
        """
        Optimize fast_pattern selection.

        Args:
            rule: Rule to optimize

        Returns:
            Optimized rule with better fast_pattern, or None if already optimal
        """
        # Find all content options
        from ..core.nodes import ContentOption

        contents: list[ContentOption] = [
            opt for opt in rule.options if isinstance(opt, ContentOption)
        ]

        if len(contents) < 2:
            # Need at least 2 content options to optimize
            return None, []

        # Find if any content already has fast_pattern (as modifier or standalone option)
        has_fast_pattern_modifier = any(
            any(
                (
                    mod.name.value == "fast_pattern"
                    if hasattr(mod.name, "value")
                    else str(mod.name) == "fast_pattern"
                )
                for mod in content.modifiers
            )
            for content in contents
        )

        # Check for standalone FastPatternOption
        has_fast_pattern_option = any(opt.node_type == "FastPatternOption" for opt in rule.options)

        if has_fast_pattern_modifier or has_fast_pattern_option:
            # Already has fast_pattern - could optimize which one, but skip for now
            return None, []

        # Score each content and find best. Negated content is excluded: Suricata
        # rejects fast_pattern on a negated content match, so adding it there
        # would produce a rule that fails to load.
        scored_contents = [
            (content, self._score_distinctiveness(content))
            for content in contents
            if not content.negated
        ]
        if not scored_contents:
            return None, []

        best_content, best_score = max(scored_contents, key=lambda x: x[1])

        if best_score <= 0:
            # No good candidate
            return None, []

        # Add fast_pattern modifier to best content
        from ..core.enums import ContentModifierType
        from ..core.nodes import ContentModifier

        new_modifiers = [
            *list(best_content.modifiers),
            ContentModifier(name=ContentModifierType.FAST_PATTERN, value=None),
        ]

        new_content = best_content.model_copy(update={"modifiers": new_modifiers})

        # Replace in options list
        new_options: list[Option] = []
        for opt in rule.options:
            if opt is best_content:
                new_options.append(new_content)
            else:
                new_options.append(opt)

        optimized = rule.model_copy(update={"options": new_options})

        # Create optimization record
        from ..printer.text_printer import TextPrinter

        printer = TextPrinter()
        before_text = printer.print_rule(rule)
        after_text = printer.print_rule(optimized)

        estimated_gain = self.estimate_gain(rule)

        optimization = Optimization(
            strategy=self.name,
            description=f"Added fast_pattern to most distinctive content ({len(best_content.pattern)} bytes)",
            estimated_gain=estimated_gain,
            before=before_text,
            after=after_text,
            details={
                "content_count": len(contents),
                "best_score": best_score,
                "pattern_length": len(best_content.pattern),
            },
        )

        return optimized, [optimization]

    def estimate_gain(self, rule: Rule) -> float:
        """
        Estimate gain from fast_pattern optimization.

        Significant gain when rule has multiple content matches without
        fast_pattern hint.
        """
        from ..core.nodes import ContentOption

        contents = [opt for opt in rule.options if isinstance(opt, ContentOption)]

        if len(contents) < 2:
            return 0.0

        # More content options = higher gain from fast_pattern
        # Typical improvement: 10-30% depending on content count
        return min(10.0 + (len(contents) * 5.0), 30.0)

    def _score_distinctiveness(self, content: ContentOption) -> float:
        """
        Score content by distinctiveness for fast_pattern.

        Higher score = better candidate.

        Args:
            content: Content option to score

        Returns:
            Distinctiveness score
        """
        score = 0.0

        # Longer patterns are more distinctive
        pattern_len = len(content.pattern)
        score += pattern_len * 10.0

        # Penalize very short patterns
        if pattern_len < 4:
            score *= 0.5

        # Penalize patterns with hex wildcards (less distinctive)
        if b"|" in content.pattern:
            score *= 0.8

        # Check modifiers
        for modifier in content.modifiers:
            mod_name = (
                modifier.name.value if hasattr(modifier.name, "value") else str(modifier.name)
            )

            # Penalize case-insensitive (slower matching)
            if mod_name == "nocase":
                score *= 0.7

            # Penalize positional constraints (less flexible)
            if mod_name in ["offset", "depth", "distance", "within"]:
                score *= 0.9

            # Already has fast_pattern - zero score
            if mod_name == "fast_pattern":
                return 0.0

        return score


class RedundancyRemovalStrategy(OptimizationStrategy):
    """
    Remove duplicate options.

    Duplicate options provide no additional detection value but increase
    evaluation cost. This strategy identifies and removes exact duplicates.

    Strategy:
        1. Create canonical representation of each option
        2. Track seen options
        3. Keep only first occurrence of each unique option
        4. Preserve metadata options (msg, sid, etc.) even if duplicate
    """

    # Option types that should never be deduplicated. Beyond metadata (where
    # repetition is meaningful), this covers every position-dependent option
    # plus the content/pcre anchors they attach to: a repeated sticky modifier
    # or a repeated content can belong to a different match, so dropping the
    # "duplicate" would change detection semantics.
    PRESERVE_DUPLICATES: ClassVar[set[str]] = {
        "MsgOption",
        "SidOption",
        "RevOption",
        "GidOption",
        "ReferenceOption",
        "MetadataOption",
        "ContentOption",
        "PcreOption",
        *POSITIONAL_OPTIONS,
    }

    @property
    def name(self) -> str:
        """Get strategy name."""
        return "RedundancyRemoval"

    def apply(self, rule: Rule) -> tuple[Rule | None, list[Optimization]]:
        """
        Remove duplicate options.

        Args:
            rule: Rule to optimize

        Returns:
            Optimized rule without duplicates, or None if no duplicates found
        """
        seen: set[tuple[str, str]] = set()
        unique_options: list[Option] = []
        removed_count = 0

        for option in rule.options:
            option_type = option.node_type

            # Always preserve certain option types, plus any position-/state-
            # significant option (e.g. a relative byte_test/isdataat) whose
            # textual duplicate belongs to a different match anchor.
            if option_type in self.PRESERVE_DUPLICATES or _is_order_significant(option):
                unique_options.append(option)
                continue

            # Create hashable key from option
            key = self._create_option_key(option)

            if key not in seen:
                seen.add(key)
                unique_options.append(option)
            else:
                removed_count += 1

        if removed_count == 0:
            # No duplicates found
            return None, []

        # Create optimized rule
        optimized = rule.model_copy(update={"options": unique_options})

        # Create optimization record
        from ..printer.text_printer import TextPrinter

        printer = TextPrinter()
        before_text = printer.print_rule(rule)
        after_text = printer.print_rule(optimized)

        estimated_gain = self.estimate_gain(rule)

        optimization = Optimization(
            strategy=self.name,
            description=f"Removed {removed_count} duplicate option(s)",
            estimated_gain=estimated_gain,
            before=before_text,
            after=after_text,
            details={
                "removed_count": removed_count,
                "original_count": len(rule.options),
                "final_count": len(unique_options),
            },
        )

        return optimized, [optimization]

    def estimate_gain(self, rule: Rule) -> float:
        """
        Estimate gain from removing duplicates.

        Gain is proportional to number of duplicates and their cost.
        """
        from .estimator import PerformanceEstimator

        estimator = PerformanceEstimator()

        seen: set[tuple[str, str]] = set()
        duplicate_cost = 0.0

        for option in rule.options:
            if option.node_type in self.PRESERVE_DUPLICATES or _is_order_significant(option):
                continue

            key = self._create_option_key(option)

            if key in seen:
                # This is a duplicate
                duplicate_cost += estimator._estimate_option_cost(option)
            else:
                seen.add(key)

        if duplicate_cost == 0:
            return 0.0

        # Calculate percentage of total cost
        total_cost = estimator.estimate_cost(rule)
        if total_cost == 0:
            return 0.0

        return (duplicate_cost / total_cost) * 100.0

    def _create_option_key(self, option: Option) -> tuple[str, str]:
        """
        Create hashable key for option comparison.

        Args:
            option: Option to create key for

        Returns:
            Tuple of (option_type, canonical_representation)
        """
        option_type = option.node_type

        # Create canonical string representation
        # Use model_dump for consistent representation
        option_dict = option.model_dump(exclude_none=True)

        # Remove location and comments for comparison
        option_dict.pop("location", None)
        option_dict.pop("comments", None)

        # Sort dict for consistent ordering
        canonical = str(sorted(option_dict.items()))

        return (option_type, canonical)
