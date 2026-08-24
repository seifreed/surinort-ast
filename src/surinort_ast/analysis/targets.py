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
    actions: frozenset[str] = frozenset()
    protocols: frozenset[str] = frozenset()
    aliases: tuple[tuple[str, str], ...] = ()
    deprecated_keywords: frozenset[str] = frozenset()

    def supports(self, keyword: str) -> bool | None:
        """Return true/false when known, or ``None`` when not catalogued."""
        if not self.keywords:
            return None
        return self.canonical_keyword(keyword) in self.keywords

    def canonical_keyword(self, keyword: str) -> str:
        """Resolve an engine-specific alias to its canonical keyword."""
        normalized = _normalize(keyword)
        aliases = {_normalize(alias): _normalize(value) for alias, value in self.aliases}
        return aliases.get(normalized, normalized)

    def is_deprecated(self, keyword: str) -> bool:
        """Return whether a known keyword is deprecated for this target."""
        return self.canonical_keyword(keyword) in {
            _normalize(item) for item in self.deprecated_keywords
        }

    def supports_action(self, action: str) -> bool | None:
        """Return action support when the target publishes an action list."""
        return _supports(self.actions, action)

    def supports_protocol(self, protocol: str) -> bool | None:
        """Return protocol support when the target publishes a protocol list."""
        return _supports(self.protocols, protocol)

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


def _supports(values: frozenset[str], value: str) -> bool | None:
    if not values:
        return None
    return _normalize(value) in {_normalize(item) for item in values}


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
