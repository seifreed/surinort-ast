"""
Helpers that pull conflict-relevant facts out of a Rule AST.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ...core.nodes import (
    AnyAddress,
    AnyPort,
    ContentOption,
    FlowbitsOption,
    PcreOption,
    Rule,
    extract_sid,
)

# ``extract_sid`` is re-exported from core (single implementation) so callers
# can keep using ``extractors.extract_sid``.
__all__ = [
    "compute_specificity",
    "content_count",
    "extract_flowbits",
    "extract_sid",
    "has_pcre",
]


def extract_flowbits(rule: Rule) -> list[tuple[str, str]]:
    """Return (action, name) pairs for every flowbits option on the rule."""
    pairs: list[tuple[str, str]] = []
    for option in rule.options:
        if isinstance(option, FlowbitsOption):
            pairs.append((option.action, option.name))
    return pairs


def has_pcre(rule: Rule) -> bool:
    return any(isinstance(option, PcreOption) for option in rule.options)


def content_count(rule: Rule) -> int:
    return sum(1 for option in rule.options if isinstance(option, ContentOption))


def compute_specificity(rule: Rule) -> int:
    """A coarse score: more constrained rules score higher.

    Used only to order pairwise comparisons (general rules first); it is never
    the correctness criterion for a conflict.
    """
    score = 0
    header = rule.header
    if header is None:
        return content_count(rule) + (1 if has_pcre(rule) else 0)
    if not isinstance(header.src_addr, AnyAddress):
        score += 1
    if not isinstance(header.dst_addr, AnyAddress):
        score += 1
    if not isinstance(header.src_port, AnyPort):
        score += 1
    if not isinstance(header.dst_port, AnyPort):
        score += 1
    score += content_count(rule)
    if has_pcre(rule):
        score += 1
    return score
