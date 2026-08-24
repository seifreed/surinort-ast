"""Semantic differences between two rule ASTs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.nodes import Rule


def _semantic_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _semantic_value(item)
            for key, item in value.items()
            if key not in {"location", "comments", "raw_text", "origin", "diagnostics"}
        }
    if isinstance(value, list):
        return [_semantic_value(item) for item in value]
    return value


def _option_value(option: Any) -> Any:
    return _semantic_value(option.model_dump(mode="json"))


@dataclass(frozen=True)
class RuleDiff:
    """Explain a rule change without claiming behavioral equivalence."""

    sid: int | None
    changed: bool
    header_changes: tuple[str, ...]
    detection_changes: tuple[str, ...]
    risk: tuple[str, ...]
    engine_verified: bool = False
    behavior_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "changed": self.changed,
            "header_changes": list(self.header_changes),
            "detection_changes": list(self.detection_changes),
            "risk": list(self.risk),
            "engine_verified": self.engine_verified,
            "behavior_verified": self.behavior_verified,
        }

    def __str__(self) -> str:
        lines = [f"SID {self.sid if self.sid is not None else '<unknown>'}"]
        for section, values in (
            ("Header", self.header_changes),
            ("Detection", self.detection_changes),
            ("Risk", self.risk),
        ):
            if values:
                lines.append(f"{section}:")
                lines.extend(f"  {value}" for value in values)
        return "\n".join(lines)


def _sid(rule: Rule) -> int | None:
    for option in rule.options:
        if option.node_type == "SidOption":
            value = getattr(option, "value", None)
            return value if isinstance(value, int) else None
    return None


def semantic_diff(before: Rule, after: Rule) -> RuleDiff:
    """Compare headers and ordered option semantics, ignoring source metadata."""
    header_changes: list[str] = []
    before_header = _semantic_value(before.header.model_dump(mode="json"))
    after_header = _semantic_value(after.header.model_dump(mode="json"))
    for field in ("protocol", "src_addr", "src_port", "direction", "dst_addr", "dst_port"):
        if before_header.get(field) != after_header.get(field):
            header_changes.append(f"{field}: changed")

    before_options = [_option_value(option) for option in before.options]
    after_options = [_option_value(option) for option in after.options]
    detection_changes: list[str] = []
    for index, (left, right) in enumerate(zip(before_options, after_options, strict=False), 1):
        if left != right:
            detection_changes.append(f"option #{index}: changed")
    if len(before_options) != len(after_options):
        detection_changes.append(f"option count: {len(before_options)} -> {len(after_options)}")
    before_types = [option.node_type for option in before.options]
    after_types = [option.node_type for option in after.options]
    if before_types != after_types and sorted(before_types) == sorted(after_types):
        detection_changes.append("option order changed")

    changed = bool(header_changes or detection_changes or before.form != after.form)
    risk = []
    if changed:
        risk.append("behavioral equivalence is unverified")
    if any("ContentOption" in item or "PcreOption" in item for item in detection_changes):
        risk.append("match space may have changed")
    return RuleDiff(
        _sid(after), changed, tuple(header_changes), tuple(detection_changes), tuple(risk)
    )


__all__ = ["RuleDiff", "semantic_diff"]
