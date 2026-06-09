# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for analysis/minhash.py.

Targets the header-feature, normalization, and fallback branches of feature
extraction, plus the None-signature handling. Real Rule objects and real AST
option nodes are used throughout.
"""

from __future__ import annotations

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis.minhash import MinHashSignature
from surinort_ast.core.enums import ContentModifierType
from surinort_ast.core.nodes import (
    ContentModifier,
    ContentOption,
    FastPatternOption,
    PcreOption,
    Rule,
)


@pytest.fixture
def minhash() -> MinHashSignature:
    return MinHashSignature(num_perm=16)


class TestHeaderFeatures:
    def test_specific_ports_and_addresses(self, minhash):
        rule = parse_rule('alert tcp 1.2.3.4 1024 -> 5.6.7.8 80 (msg:"x"; sid:1;)')

        features = minhash._extract_features(rule)

        assert any(f.startswith("src_port:1024") for f in features)
        assert any(f.startswith("dst_port:80") for f in features)
        assert any("1.2.3.4" in f for f in features)
        assert any("5.6.7.8" in f for f in features)

    def test_port_variable_falls_back_to_str(self, minhash):
        rule = parse_rule('alert tcp any any -> any $HTTP_PORTS (msg:"x"; sid:1;)')

        # dst_port is a PortVariable with none of value/start/end/elements.
        assert minhash._port_to_string(rule.header.dst_port)

    def test_address_variable_uses_name(self, minhash):
        rule = parse_rule('alert tcp $HOME_NET any -> any any (msg:"x"; sid:1;)')

        assert minhash._addr_to_string(rule.header.src_addr).startswith("$")

    def test_negated_address_falls_back_to_str(self, minhash):
        rule = parse_rule('alert tcp !1.2.3.4 any -> any any (msg:"x"; sid:1;)')

        # AddressNegation has none of value/network/elements/name.
        assert minhash._addr_to_string(rule.header.src_addr)


class TestOptionFeatures:
    def test_empty_content_pattern_adds_only_type(self, minhash):
        features = minhash._extract_option_features(ContentOption(pattern=b""))

        assert features == {"option:ContentOption"}

    def test_content_modifiers_enum_and_str(self, minhash):
        content = ContentOption(
            pattern=b"GET",
            modifiers=(
                ContentModifier(name=ContentModifierType.NOCASE),
                ContentModifier(name="custom_mod"),
            ),
        )

        features = minhash._extract_option_features(content)

        assert "content_mod:nocase" in features
        assert "content_mod:custom_mod" in features

    def test_empty_pcre_pattern_adds_only_type(self, minhash):
        features = minhash._extract_option_features(PcreOption(pattern=""))

        assert features == {"option:PcreOption"}

    def test_other_option_skips_none_fields(self, minhash):
        # FastPatternOption.offset and .length default to None and must be
        # skipped by the generic field walk.
        features = minhash._extract_option_features(FastPatternOption())

        assert "option:FastPatternOption" in features
        assert not any(f.startswith("offset:") for f in features)


class TestNormalization:
    def test_normalize_binary_content_to_hex(self, minhash):
        assert minhash._normalize_content(b"\xff\xfe") == "fffe"

    def test_normalize_str_content_lowercases(self, minhash):
        assert minhash._normalize_content("ABC") == "abc"

    def test_normalize_pcre_strips_delimiters(self, minhash):
        assert minhash._normalize_pcre("/Foo.Bar/i") == "foo.bar"


class TestSignatureEdgeCases:
    def test_signature_none_when_no_features(self, minhash):
        class Featureless(MinHashSignature):
            def _extract_features(self, rule: Rule) -> set[str]:
                return set()

        empty = Featureless(num_perm=16)
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')

        assert empty.create_signature(rule) is None

    def test_estimate_similarity_with_none_signature(self, minhash):
        assert minhash.estimate_similarity(None, [1, 2, 3]) == 0.0
        assert minhash.estimate_similarity([1, 2, 3], None) == 0.0
