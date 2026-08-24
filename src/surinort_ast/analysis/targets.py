"""Versioned engine capability targets."""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class EngineTarget:
    """Capabilities observed for one engine/version target."""

    engine: str
    version: str
    keywords: frozenset[str] = frozenset()
    features: frozenset[str] = frozenset()

    def supports(self, keyword: str) -> bool | None:
        """Return true/false when known, or ``None`` when not catalogued."""
        if not self.keywords:
            return None
        return keyword in self.keywords

    def with_keywords(self, keywords: set[str] | frozenset[str]) -> EngineTarget:
        """Return a target populated from an engine keyword listing."""
        return replace(self, keywords=frozenset(keywords))


class CapabilityRegistry:
    """Small registry for engine/version capability snapshots."""

    def __init__(self, targets: tuple[EngineTarget, ...] = ()) -> None:
        self._targets = {(_normalize(item.engine), item.version): item for item in targets}

    def register(self, target: EngineTarget) -> None:
        self._targets[(_normalize(target.engine), target.version)] = target

    def resolve(self, engine: str, version: str) -> EngineTarget | None:
        """Resolve exact versions before major-version wildcards."""
        key = _normalize(engine)
        return self._targets.get((key, version)) or self._targets.get((key, _major(version)))

    def targets(self) -> tuple[EngineTarget, ...]:
        return tuple(self._targets.values())


def _major(version: str) -> str:
    return f"{version.split('.', 1)[0]}.x"


def _normalize(engine: str) -> str:
    return engine.strip().lower()


def default_capability_registry() -> CapabilityRegistry:
    """Return conservative common-keyword targets for the supported engines."""
    common = frozenset(
        {
            "content",
            "detection_filter",
            "flow",
            "msg",
            "pcre",
            "reference",
            "rev",
            "sid",
        }
    )
    return CapabilityRegistry(
        (
            EngineTarget("suricata", "8.x", common, frozenset({"app-layer", "sticky-buffer"})),
            EngineTarget("snort", "2.x", common, frozenset()),
            EngineTarget("snort", "3.x", common, frozenset({"sticky-buffer"})),
        )
    )


__all__ = ["CapabilityRegistry", "EngineTarget", "default_capability_registry"]
