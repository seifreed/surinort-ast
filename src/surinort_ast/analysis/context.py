"""Deployment configuration used to resolve rule variables conservatively."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RulesetContext:
    """Known rule variables loaded from an engine configuration."""

    variables: dict[str, str] = field(default_factory=dict)
    source: str | None = None

    @classmethod
    def from_suricata_yaml(cls, path: Path | str) -> RulesetContext:
        import yaml  # type: ignore[import-untyped]

        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        variables: dict[str, str] = {}
        for group in data.get("vars", {}).values():
            if isinstance(group, dict):
                variables.update({str(key): str(value) for key, value in group.items()})
        return cls(variables, str(path))

    @classmethod
    def from_snort_config(cls, path: Path | str) -> RulesetContext:
        variables: dict[str, str] = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*(?:ip|port)?var\s+([A-Za-z_][\w]*)\s+(.+?)\s*$", line)
            if match:
                variables[match.group(1)] = match.group(2).split("#", 1)[0].strip()
        return cls(variables, str(path))

    def resolve(self, name: str, max_depth: int = 8) -> str | None:
        value = self.variables.get(name)
        for _ in range(max_depth):
            if value is None:
                return None
            reference = re.fullmatch(r"\$([A-Za-z_][\w]*)", value.strip())
            if not reference:
                return value
            value = self.variables.get(reference.group(1))
        return None

    def resolve_port_intervals(self, name: str) -> list[tuple[int, int]] | None:
        value = self.resolve(name)
        if value is None or re.search(r"\bany\b|\$", value, re.IGNORECASE):
            return None
        intervals: list[tuple[int, int]] = []
        for start, end in re.findall(r"(?<!\d)(\d{1,5})(?::(\d{1,5}))?(?!\d)", value):
            first, last = int(start), int(end or start)
            if 0 <= first <= last <= 65535:
                intervals.append((first, last))
        return intervals or None


__all__ = ["RulesetContext"]
