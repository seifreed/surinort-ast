from surinort_ast.analysis import EngineTarget, default_capability_registry, parse_keyword_listing


def test_registry_prefers_exact_version_then_major_snapshot() -> None:
    registry = default_capability_registry()

    assert registry.resolve("Suricata", "8.0") is not None
    assert registry.resolve("snort", "3.1").supports("content") is True
    assert registry.resolve("snort", "3.1").supports("unknown") is None
    assert registry.resolve("other", "1.0") is None


def test_engine_keyword_listing_can_populate_target() -> None:
    target = EngineTarget("suricata", "9.x").with_keywords({"content"})

    assert target.supports("content") is True
    assert target.supports("pcre") is False
    assert target.keyword_catalog_complete is True


def test_engine_feature_listing_is_tri_state() -> None:
    target = EngineTarget("suricata", "8.x").with_features({"sticky-buffer"})

    assert target.supports_feature("sticky-buffer") is True
    assert target.supports_feature("byte-ops") is False
    assert EngineTarget("suricata", "8.x").supports_feature("sticky-buffer") is None


def test_engine_keyword_listing_parser_handles_headers_and_descriptions() -> None:
    listing = """
    Keyword                 Description
    ----------------------- -----------
    content                 payload match
    http.header.raw         sticky buffer
    # implementation note
    """

    assert parse_keyword_listing(listing) == frozenset({"content", "http.header.raw"})
    target = EngineTarget.from_keyword_listing("suricata", "8.x", listing)
    assert target.supports("content") is True
    assert target.supports("missing") is False


def test_engine_keyword_listing_parser_handles_suricata_bullets() -> None:
    target = EngineTarget.from_keyword_listing(
        "suricata",
        "8.0.6",
        "=====Supported keywords=====\n- sid\n- content\n- http.uri\n",
    )

    assert target.supports("sid") is True
    assert target.supports("http.uri") is True
    assert target.supports("missing") is False


def test_target_models_aliases_deprecations_and_domains() -> None:
    target = EngineTarget(
        "suricata",
        "8.x",
        keywords=frozenset({"buffer_select"}),
        actions=frozenset({"alert"}),
        protocols=frozenset({"tcp"}),
        aliases=(("sticky_buffer", "buffer_select"),),
        deprecated_keywords=frozenset({"buffer_select"}),
    )

    assert target.canonical_keyword("sticky_buffer") == "buffer_select"
    assert target.supports("sticky_buffer") is True
    assert target.is_deprecated("sticky_buffer") is True
    assert target.supports_action("alert") is True
    assert target.supports_protocol("udp") is False


def test_capability_registry_json_roundtrip(tmp_path) -> None:
    from surinort_ast.analysis import CapabilityRegistry

    target = EngineTarget(
        "suricata",
        "8.0.6",
        keywords=frozenset({"content", "sid"}),
        features=frozenset({"sticky-buffer"}),
        actions=frozenset({"alert"}),
        protocols=frozenset({"tcp"}),
        aliases=(("http.uri", "http_uri"),),
        keyword_catalog_complete=True,
        feature_catalog_complete=True,
    )
    registry = CapabilityRegistry((target,))
    path = tmp_path / "capabilities.json"

    registry.write_json(path)
    restored = CapabilityRegistry.from_json(path)

    assert restored.resolve("SURICATA", "8.0.6") == target
    assert restored.resolve("suricata", "8.0.6").supports("missing") is False


def test_capability_registry_rejects_non_object_json(tmp_path) -> None:
    from surinort_ast.analysis import CapabilityRegistry

    path = tmp_path / "invalid.json"
    path.write_text("[]", encoding="utf-8")

    import pytest

    with pytest.raises(ValueError, match="root must be a JSON object"):
        CapabilityRegistry.from_json(path)
