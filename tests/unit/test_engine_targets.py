from surinort_ast.analysis import EngineTarget, default_capability_registry


def test_registry_prefers_exact_version_then_major_snapshot() -> None:
    registry = default_capability_registry()

    assert registry.resolve("Suricata", "8.0") is not None
    assert registry.resolve("snort", "3.1").supports("content") is True
    assert registry.resolve("snort", "3.1").supports("unknown") is False
    assert registry.resolve("other", "1.0") is None


def test_engine_keyword_listing_can_populate_target() -> None:
    target = EngineTarget("suricata", "9.x").with_keywords({"content"})

    assert target.supports("content") is True
    assert target.supports("pcre") is False
