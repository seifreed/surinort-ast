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
