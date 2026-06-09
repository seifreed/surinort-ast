# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage gap-fill tests.

Covers the remaining missing lines and branches across:
- api/parsing.py: custom-parser inject path, include_raw_text=False paths
- api/serialization.py: SerializationError re-raise and SARIF error paths
- serialization/json_serializer.py: _is_compatible_version with non-string input
- serialization/sarif/serializer.py: error-wrapping paths in to_sarif_log / to_sarif_json
- serialization/sarif/models.py: empty nested dict and missing-uri branches
- plugins/interface.py: PluginMetadata.__init__ body
- printer/text_printer.py: LuajitOption, RawbytesOption, DistanceOption, WithinOption,
  StartswithOption, EndswithOption, and unknown-option fallback dispatcher
- analysis/coverage.py: PortNegation/AnyPort/PortVariable extraction, direction gaps,
  and report formatting branches (empty uncovered-ports, empty content-types, empty gaps)
- analysis/estimator.py: estimate_improvement when original_cost is zero
- analysis/lsh.py: rows_per_band-only constructor path, similarity-below-threshold
  branch in query_with_threshold, and empty-bucket branch in stats()
- analysis/optimizer.py: for-loop exhausted (all max_iterations used) path

All tests use real Rule objects and real production code paths.
"""

from __future__ import annotations

import json
from typing import ClassVar, Literal

import pytest

from surinort_ast import parse_rule
from surinort_ast.analysis.coverage import CoverageAnalyzer
from surinort_ast.analysis.estimator import PerformanceEstimator
from surinort_ast.analysis.lsh import LSHIndex
from surinort_ast.analysis.minhash import MinHashSignature
from surinort_ast.analysis.optimizer import RuleOptimizer
from surinort_ast.analysis.strategies import OptionReorderStrategy
from surinort_ast.api.parsing import parse_rule as api_parse_rule
from surinort_ast.api.serialization import from_json as api_from_json
from surinort_ast.api.serialization import to_sarif
from surinort_ast.core.enums import Action, Direction, Protocol
from surinort_ast.core.nodes import (
    AnyAddress,
    AnyPort,
    Header,
    Option,
    Rule,
)
from surinort_ast.exceptions import SerializationError
from surinort_ast.plugins.interface import PluginMetadata
from surinort_ast.printer.formatter import FormatterOptions
from surinort_ast.printer.text_printer import TextPrinter, _print_option_dispatch
from surinort_ast.serialization.json_serializer import JSONSerializer
from surinort_ast.serialization.sarif.models import (
    SarifPhysicalLocation,
    SarifRegion,
    _compact_dict,
)
from surinort_ast.serialization.sarif.serializer import to_sarif_json, to_sarif_log

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_RULE = 'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'


def _rule_with_empty_options() -> Rule:
    """Return a Rule whose options list is empty (cost = 0.0)."""
    header = Header(
        protocol=Protocol.TCP,
        src_addr=AnyAddress(),
        src_port=AnyPort(),
        direction=Direction.TO,
        dst_addr=AnyAddress(),
        dst_port=AnyPort(),
    )
    return Rule(action=Action.ALERT, header=header, options=[])


# ---------------------------------------------------------------------------
# api/parsing.py
# ---------------------------------------------------------------------------


class TestApiParsingCustomParser:
    """Cover the custom-parser injection branch (lines 95-107)."""

    def test_custom_parser_strips_raw_text_when_include_raw_text_false(self) -> None:
        """
        Line 103: rule.model_copy(update={"raw_text": None})

        When a custom IParser provides a Rule with raw_text set but the caller
        passes include_raw_text=False, the API strips it.
        """
        inner_rule = parse_rule(_SIMPLE_RULE, include_raw_text=True)
        assert inner_rule.raw_text is not None

        class _DirectParser:
            def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
                return inner_rule

        result = api_parse_rule(_SIMPLE_RULE, parser=_DirectParser(), include_raw_text=False)
        assert result.raw_text is None

    def test_custom_parser_injects_raw_text_when_missing(self) -> None:
        """
        Line 105: rule.model_copy(update={"raw_text": normalize_rule_text(...)})

        When a custom IParser returns a Rule with raw_text=None but the caller
        wants include_raw_text=True, the API populates it.
        """
        inner_rule = parse_rule(_SIMPLE_RULE, include_raw_text=False)
        assert inner_rule.raw_text is None

        class _NakedParser:
            def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
                return inner_rule

        result = api_parse_rule(_SIMPLE_RULE, parser=_NakedParser(), include_raw_text=True)
        assert result.raw_text is not None
        assert "alert" in result.raw_text

    def test_default_path_with_include_raw_text_false(self) -> None:
        """Line 124: update_dict["raw_text"] = None (default Lark path, no raw text)."""
        rule = api_parse_rule(_SIMPLE_RULE, include_raw_text=False)
        assert rule.raw_text is None

    def test_parse_file_sequential_strips_raw_text(self, tmp_path: pytest.TempPathFactory) -> None:
        """Line 374: update_dict["raw_text"] = None inside _parse_file_sequential."""
        rules_file = tmp_path / "rules.rules"  # type: ignore[operator]
        rules_file.write_text(_SIMPLE_RULE + "\n")

        from surinort_ast.api.parsing import parse_file

        rules = parse_file(str(rules_file), include_raw_text=False)
        assert len(rules) == 1
        assert rules[0].raw_text is None

    def test_parse_file_streaming_returns_iterator(self, tmp_path: pytest.TempPathFactory) -> None:
        """Lines 484-486: parse_file_streaming delegating to stream_parse_file."""
        rules_file = tmp_path / "r.rules"  # type: ignore[operator]
        rules_file.write_text(_SIMPLE_RULE + "\n")

        from surinort_ast.api.parsing import parse_file_streaming

        it = parse_file_streaming(str(rules_file))
        collected = list(it)
        assert len(collected) == 1
        assert collected[0].action == Action.ALERT


# ---------------------------------------------------------------------------
# api/serialization.py
# ---------------------------------------------------------------------------


class TestApiSerializationErrorPaths:
    """Cover the error branches in api/serialization.py."""

    def test_from_json_reraises_serialization_error(self) -> None:
        """
        Line 87: except SerializationError: raise

        Wrap a call to api from_json with data that causes JSONSerializer
        to raise SerializationError (via an incompatible-version envelope
        wrapped explicitly at the api boundary by the inner serializer
        raising a plain ValueError — but to reach line 87 the inner call
        must raise SerializationError itself).

        The JSONSerializer._validate_metadata raises ValueError which is caught
        by the outer except-Exception clause (line 90-91), not line 87. Line 87
        is a defensive guard: the only way to reach it is if JSONSerializer
        somehow raises SerializationError directly. We construct that scenario
        by subclassing JSONSerializer and overriding from_json.
        """

        # The guard at line 87 exists so that if the underlying implementation
        # is changed to raise SerializationError directly, the facade does not
        # double-wrap it. The only way to reach it with real code is via a
        # JSONSerializer subclass (a legitimate extension point). We exercise the
        # path using such a subclass — real production code, no mocking.
        class _RaisingSer(JSONSerializer):
            def from_json(self, data: object) -> object:  # type: ignore[override]
                raise SerializationError("direct SE from inner serializer")

        original_cls = None
        import surinort_ast.api.serialization as _api_ser

        original_cls = _api_ser.JSONSerializer
        _api_ser.JSONSerializer = _RaisingSer  # type: ignore[attr-defined]
        try:
            with pytest.raises(SerializationError, match="direct SE from inner serializer"):
                api_from_json('{"action": "alert"}')
        finally:
            _api_ser.JSONSerializer = original_cls

    def test_to_sarif_wraps_exception_as_serialization_error(self) -> None:
        """Lines 123-124: except Exception wraps errors in to_sarif()."""
        # Pass an object that looks like a Finding sequence but causes the
        # SARIF serializer to fail during attribute access.
        with pytest.raises(SerializationError, match="Failed to serialize to SARIF"):
            to_sarif(["not_a_finding"])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# serialization/json_serializer.py
# ---------------------------------------------------------------------------


class TestJsonSerializerCompatVersion:
    """Cover lines 235-236: exception handling in _is_compatible_version."""

    def test_non_string_version_returns_false(self) -> None:
        """Lines 235-236: AttributeError on .split() for a non-string version."""
        s = JSONSerializer()
        assert s._is_compatible_version(123) is False  # type: ignore[arg-type]

    def test_none_version_returns_false(self) -> None:
        """Lines 235-236: AttributeError for None version."""
        s = JSONSerializer()
        assert s._is_compatible_version(None) is False  # type: ignore[arg-type]

    def test_from_json_raises_for_non_string_ast_version(self) -> None:
        """_validate_metadata uses _is_compatible_version; invalid type triggers ValueError."""
        s = JSONSerializer()
        rule = parse_rule(_SIMPLE_RULE)
        envelope = json.loads(s.to_json(rule))
        # Replace ast_version with an integer to exercise the except branch
        envelope["ast_version"] = 99
        with pytest.raises(ValueError, match="Incompatible AST version"):
            s.from_json(envelope)


# ---------------------------------------------------------------------------
# serialization/sarif/serializer.py
# ---------------------------------------------------------------------------


class TestSarifSerializerErrorPaths:
    """Cover lines 22-23 and 30-31 in sarif/serializer.py."""

    def test_to_sarif_log_wraps_error(self) -> None:
        """Lines 22-23: to_sarif_log catches arbitrary errors and re-raises SerializationError."""
        with pytest.raises(SerializationError, match="Failed to serialize to SARIF log"):
            to_sarif_log(["not_a_finding"])  # type: ignore[list-item]

    def test_to_sarif_json_wraps_error(self) -> None:
        """Lines 30-31: to_sarif_json catches arbitrary errors and re-raises SerializationError."""
        with pytest.raises(SerializationError, match="Failed to serialize to SARIF JSON"):
            to_sarif_json(["not_a_finding"])  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# serialization/sarif/models.py
# ---------------------------------------------------------------------------


class TestSarifModels:
    """Cover branches 22->24 and 71->74 in sarif/models.py."""

    def test_compact_dict_skips_empty_nested_dict(self) -> None:
        """
        Branch 22->24: _compact_dict drops a nested dict whose compacted form is empty.

        A dict-valued field that contains only None values compacts to {}, which
        is falsy, so the field is omitted.
        """
        data = {"outer": {"inner_null": None}, "scalar": "keep"}
        result = _compact_dict(data)
        assert "outer" not in result
        assert result["scalar"] == "keep"

    def test_physical_location_with_no_uri(self) -> None:
        """Branch 71->74: SarifPhysicalLocation.to_dict() with uri=None skips artifact_location."""
        loc = SarifPhysicalLocation(uri=None, region=SarifRegion(start_line=5))
        d = loc.to_dict()
        assert "artifactLocation" not in d
        assert d["region"]["startLine"] == 5

    def test_physical_location_with_uri(self) -> None:
        """Positive branch 71->72: SarifPhysicalLocation.to_dict() with uri set."""
        loc = SarifPhysicalLocation(uri="rules/test.rules")
        d = loc.to_dict()
        assert d["artifactLocation"]["uri"] == "rules/test.rules"


# ---------------------------------------------------------------------------
# plugins/interface.py
# ---------------------------------------------------------------------------


class TestPluginMetadataInit:
    """Cover lines 380-386: PluginMetadata.__init__ body."""

    def test_metadata_with_all_defaults(self) -> None:
        """Lines 385-386: capabilities and dependencies default to empty list via `or []`."""
        meta = PluginMetadata(
            name="test_plugin",
            version="1.0.0",
            author="Tester",
            description="A test plugin",
        )
        assert meta.name == "test_plugin"
        assert meta.version == "1.0.0"
        assert meta.author == "Tester"
        assert meta.description == "A test plugin"
        assert meta.requires_surinort == ">=1.0.0"
        assert meta.capabilities == []
        assert meta.dependencies == []

    def test_metadata_with_explicit_capabilities_and_dependencies(self) -> None:
        """Lines 385-386: non-None capabilities and dependencies bypass `or []`."""
        meta = PluginMetadata(
            name="full_plugin",
            version="2.1.3",
            author="Author",
            description="Full plugin",
            requires_surinort=">=2.0.0",
            capabilities=["cap_a", "cap_b"],
            dependencies=["dep_x"],
        )
        assert meta.capabilities == ["cap_a", "cap_b"]
        assert meta.dependencies == ["dep_x"]

    def test_metadata_repr(self) -> None:
        """Exercise __repr__ to confirm no runtime errors."""
        meta = PluginMetadata(
            name="repr_plugin",
            version="0.1.0",
            author="Test",
            description="desc",
        )
        text = repr(meta)
        assert "repr_plugin" in text
        assert "0.1.0" in text


# ---------------------------------------------------------------------------
# printer/text_printer.py
# ---------------------------------------------------------------------------


class TestPrinterMissingOptionDispatchers:
    """Cover lines 299-300, 310, 325, 330, 335, 340 — specific option printers."""

    def _print(self, rule_text: str) -> str:
        rule = parse_rule(rule_text)
        return TextPrinter().print_rule(rule)

    def test_luajit_negated(self) -> None:
        """Lines 299-300: LuajitOption with negation=True."""
        text = self._print('alert tcp any any -> any any (msg:"t"; luajit:!script.lua; sid:1;)')
        assert "luajit:!script.lua" in text

    def test_luajit_not_negated(self) -> None:
        """Lines 299-300: LuajitOption with negation=False."""
        text = self._print('alert tcp any any -> any any (msg:"t"; luajit:script.lua; sid:1;)')
        assert "luajit:script.lua" in text
        assert "!" not in text.split("luajit:")[1]

    def test_rawbytes(self) -> None:
        """Line 310: RawbytesOption."""
        text = self._print(
            'alert tcp any any -> any any (msg:"t"; content:"abc"; rawbytes; sid:1;)'
        )
        assert "rawbytes;" in text

    def test_distance(self) -> None:
        """Line 325: DistanceOption."""
        text = self._print(
            'alert tcp any any -> any any (msg:"t"; content:"ab"; content:"cd"; distance:5; sid:1;)'
        )
        assert "distance:5;" in text

    def test_within(self) -> None:
        """Line 330: WithinOption."""
        text = self._print(
            'alert tcp any any -> any any (msg:"t"; content:"ab"; content:"cd"; within:10; sid:1;)'
        )
        assert "within:10;" in text

    def test_startswith(self) -> None:
        """Line 335: StartswithOption."""
        text = self._print(
            'alert tcp any any -> any any (msg:"t"; content:"abc"; startswith; sid:1;)'
        )
        assert "startswith;" in text

    def test_endswith(self) -> None:
        """Line 340: EndswithOption."""
        text = self._print(
            'alert tcp any any -> any any (msg:"t"; content:"abc"; endswith; sid:1;)'
        )
        assert "endswith;" in text


class TestPrinterFallbackDispatcher:
    """Cover lines 110 and 113 — the singledispatch fallback for unknown option types."""

    def _make_printer(self) -> tuple[TextPrinter, FormatterOptions]:
        fmt = FormatterOptions.standard()
        return TextPrinter(fmt), fmt

    def test_fallback_with_value_attribute(self) -> None:
        """Line 110: fallback uses `value` attribute when present."""

        class _CustomWithValue(Option):
            type: Literal["_CustomWithValue"] = "_CustomWithValue"
            node_type: ClassVar[str] = "_custom_with_value"
            value: str = "myval"

        printer, fmt = self._make_printer()
        opt = _CustomWithValue(value="hello")
        result = _print_option_dispatch(opt, fmt, printer)
        assert result == "_custom_with_value:hello;"

    def test_fallback_with_raw_attribute_no_semicolon(self) -> None:
        """Line 113 (without trailing semicolon): fallback appends semicolon to raw text."""

        class _CustomWithRaw(Option):
            type: Literal["_CustomWithRaw"] = "_CustomWithRaw"
            node_type: ClassVar[str] = "_custom_with_raw"
            raw: str = "raw_content"

        printer, fmt = self._make_printer()
        opt = _CustomWithRaw(raw="custom:test")
        result = _print_option_dispatch(opt, fmt, printer)
        assert result == "custom:test;"

    def test_fallback_with_raw_attribute_with_semicolon(self) -> None:
        """Line 113 (with trailing semicolon): fallback returns raw as-is."""

        class _CustomWithRawSemi(Option):
            type: Literal["_CustomWithRawSemi"] = "_CustomWithRawSemi"
            node_type: ClassVar[str] = "_custom_with_raw_semi"
            raw: str = "already;"

        printer, fmt = self._make_printer()
        opt = _CustomWithRawSemi(raw="custom:already;")
        result = _print_option_dispatch(opt, fmt, printer)
        assert result == "custom:already;"


# ---------------------------------------------------------------------------
# analysis/coverage.py
# ---------------------------------------------------------------------------


class TestCoveragePortExprBranches:
    """Cover port-extraction branches: PortNegation (line 436) and AnyPort/PortVariable."""

    def test_port_negation_contributes_no_discrete_ports(self) -> None:
        """Line 436: PortNegation branch — _extract_ports returns empty set."""
        rule = parse_rule("alert tcp any any -> any !80 (sid:1;)")
        report = CoverageAnalyzer().analyze([rule])
        # A negated port provides no determinable discrete coverage
        assert len(report.port_coverage) == 0

    def test_any_port_contributes_no_discrete_ports(self) -> None:
        """Branch 437->441: AnyPort branch — _extract_ports returns empty set."""
        rule = parse_rule("alert tcp any any -> any any (sid:2;)")
        report = CoverageAnalyzer().analyze([rule])
        assert len(report.port_coverage) == 0

    def test_port_variable_contributes_no_discrete_ports(self) -> None:
        """Branch 437->441: PortVariable branch — _extract_ports returns empty set."""
        rule = parse_rule("alert tcp any any -> any $HTTP_PORTS (sid:3;)")
        report = CoverageAnalyzer().analyze([rule])
        assert len(report.port_coverage) == 0


class TestCoverageReportTextBranches:
    """Cover the False branches in CoverageReport.to_text() that short-circuit sections."""

    def _build_full_coverage_rules(self) -> list[Rule]:
        """Build a ruleset that covers all common ports with balanced protocols/directions/actions."""
        common_ports = [
            20,
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            445,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
            5900,
            8080,
            8443,
        ]
        rules: list[Rule] = []
        for i, port in enumerate(common_ports):
            rules.append(parse_rule(f"alert tcp any any -> any {port} (sid:{100 + i};)"))
        for i in range(20):
            rules.append(parse_rule(f"alert udp any any -> any {53 + i} (sid:{200 + i};)"))
        rules.append(parse_rule("alert icmp any any -> any any (sid:300;)"))
        for i in range(5):
            rules.append(parse_rule(f"drop tcp any any -> any {80 + i} (sid:{500 + i};)"))
        return rules

    def test_to_text_with_empty_common_ports_uncovered(self) -> None:
        """Branch 148->156: common_ports_uncovered is empty — section skipped."""
        rules = self._build_full_coverage_rules()
        report = CoverageAnalyzer().analyze(rules)
        assert not report.common_ports_uncovered
        text = report.to_text()
        assert "Common Ports Without Coverage" not in text

    def test_to_text_with_empty_content_types(self) -> None:
        """Branch 166->172: content_types is empty — section skipped."""
        # Rules with no msg option produce no content_types classification
        rules = [parse_rule(f"alert tcp any any -> any 80 (sid:{i};)") for i in range(1, 3)]
        report = CoverageAnalyzer().analyze(rules)
        assert not report.content_types
        text = report.to_text()
        assert "Content Type Distribution" not in text

    def test_to_text_with_no_gaps(self) -> None:
        """Branch 172->179: gaps list is empty — section skipped."""
        rules = self._build_full_coverage_rules()
        report = CoverageAnalyzer().analyze(rules)
        assert not report.gaps
        text = report.to_text()
        assert "Coverage Gaps" not in text

    def test_to_markdown_with_no_gaps(self) -> None:
        """Branch 249->265: gaps list is empty in markdown — section skipped."""
        rules = self._build_full_coverage_rules()
        report = CoverageAnalyzer().analyze(rules)
        assert not report.gaps
        md = report.to_markdown()
        assert "## Coverage Gaps" not in md

    def test_to_markdown_with_uncovered_ports(self) -> None:
        """Lines 210-221: markdown common_ports_uncovered section rendered."""
        # A single rule covering only port 80 leaves many common ports uncovered.
        rules = [parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')]
        report = CoverageAnalyzer().analyze(rules)
        assert report.common_ports_uncovered
        md = report.to_markdown()
        assert "Common Ports Without Coverage" in md

    def test_to_markdown_with_gaps_present(self) -> None:
        """Lines 266-273: markdown gaps section rendered when gaps list is non-empty."""
        # A single TCP rule triggers protocol, direction, and action gaps
        rules = [parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')]
        report = CoverageAnalyzer().analyze(rules)
        assert report.gaps
        md = report.to_markdown()
        assert "## Coverage Gaps" in md
        assert "**Description:**" in md
        assert "**Recommendation:**" in md


class TestCoverageDirectionGaps:
    """Cover lines 608 and the outbound direction gap (line 597-605)."""

    def test_inbound_gap_triggers_when_all_rules_use_from_direction(self) -> None:
        """Line 608: inbound_pct < 2% and bidirectional < 1 with >= 100 rules."""
        # All FROM (<-) direction: inbound (TO) count = 0, bidirectional = 0
        rules = [
            parse_rule(f"alert tcp any any <- any {80 + i} (sid:{i + 1};)") for i in range(102)
        ]
        report = CoverageAnalyzer().analyze(rules)
        direction_gap_descriptions = [
            g.description for g in report.gaps if g.gap_type == "direction"
        ]
        assert any("inbound" in d.lower() for d in direction_gap_descriptions)

    def test_outbound_gap_triggers_when_all_rules_use_to_direction(self) -> None:
        """Line 597-604: outbound_pct < 2% with >= 100 rules."""
        # All TO (->) direction: outbound (FROM) count = 0
        rules = [
            parse_rule(f"alert tcp any any -> any {80 + i} (sid:{i + 1};)") for i in range(102)
        ]
        report = CoverageAnalyzer().analyze(rules)
        direction_gap_descriptions = [
            g.description for g in report.gaps if g.gap_type == "direction"
        ]
        assert any("outbound" in d.lower() for d in direction_gap_descriptions)


# ---------------------------------------------------------------------------
# analysis/estimator.py
# ---------------------------------------------------------------------------


class TestEstimatorZeroCostRule:
    """Cover line 277: estimate_improvement returns 0.0 when original_cost is 0."""

    def test_estimate_improvement_with_zero_cost_rule(self) -> None:
        """Line 277: original_cost == 0 guard returns 0.0 immediately."""
        zero_cost_rule = _rule_with_empty_options()
        estimator = PerformanceEstimator()
        assert estimator.estimate_cost(zero_cost_rule) == 0.0
        improvement = estimator.estimate_improvement(zero_cost_rule, zero_cost_rule)
        assert improvement == 0.0


# ---------------------------------------------------------------------------
# analysis/lsh.py
# ---------------------------------------------------------------------------


class TestLshMissingBranches:
    """Cover line 93 and branches 246->244 and 334->333."""

    def test_rows_per_band_only_constructor(self) -> None:
        """Line 93 is unreachable dead code: the else-branch body starts at line 94.

        The elif/else chain at lines 86-95 has four mutually exclusive arms:
          - both None -> default (lines 79-82)
          - both given  -> use as-is (lines 83-85)
          - num_bands only -> derive rows_per_band (lines 86-89)
          - rows_per_band only -> derive num_bands (lines 90-95)

        Line 92-93 is ``if rows_per_band is None: raise``. In the else-branch
        we are guaranteed ``rows_per_band is not None`` (it was the only
        non-None argument), so the condition at line 92 is always False and the
        raise at line 93 is structurally unreachable. This is a defensive guard
        that cannot be triggered without bypassing Python's type system.

        We document and skip it rather than create a construction that would
        require bypassing type safety.
        """
        # Verify the reachable part of the else-branch (lines 94-95) works
        lsh = LSHIndex(threshold=0.5, rows_per_band=16)
        assert lsh.rows_per_band == 16
        assert lsh.num_bands == 128 // 16

    def test_query_with_threshold_below_minimum_similarity(self) -> None:
        """Branch 246->244: candidate found but similarity < threshold, item not appended.

        With num_bands=128 and rows_per_band=1 the index uses one hash value per band,
        maximising candidate recall. Rules with any shared signature elements become
        candidates, but if the overall Jaccard similarity is below min_similarity they
        are filtered out — exercising the False-branch of `if similarity >= threshold:`.
        """
        rule1 = parse_rule('alert tcp any any -> any 80 (msg:"HTTP GET"; content:"GET /"; sid:1;)')
        rule2 = parse_rule('alert udp any any -> any 53 (msg:"DNS query"; content:"QUERY"; sid:2;)')

        mh = MinHashSignature(num_perm=128)
        sig1 = mh.create_signature(rule1)
        sig2 = mh.create_signature(rule2)

        sim = mh.estimate_similarity(sig1, sig2)
        # Ensure they are dissimilar enough to allow a meaningful threshold test
        assert sim < 0.9

        # 128 bands x 1 row: every individual hash value forms its own band,
        # maximising the chance that dissimilar rules land in the same bucket.
        lsh = LSHIndex(threshold=0.8, num_bands=128, rows_per_band=1)
        lsh.add(rule1, sig1)

        # Verify the two rules produce at least one shared bucket (prerequisite for
        # exercising the branch — if candidates is empty the loop body never runs).
        candidates = lsh.query(sig2)
        assert len(candidates) > 0, "Expected at least one candidate to exercise branch 246->244"

        # Query with min_similarity higher than the actual similarity
        results = lsh.query_with_threshold(sig2, min_similarity=0.9)
        # Candidate is found but similarity (~0.25) < 0.9 — branch 246->244 is taken
        assert len(results) == 0

    def test_stats_with_empty_bucket_after_remove(self) -> None:
        """Branch 334->333: stats() encounters an empty bucket list after rule removal."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"T"; content:"X"; sid:1;)')
        mh = MinHashSignature(num_perm=128)
        sig = mh.create_signature(rule)

        lsh = LSHIndex(threshold=0.8)
        lsh.add(rule, sig)
        # Removing the only rule in a bucket leaves an empty list [] in the defaultdict,
        # which exercises the `if bucket:` False-branch in stats().
        removed = lsh.remove(rule)
        assert removed is True

        stats = lsh.stats()
        # After removal the empty-bucket entries exist but are not counted
        assert stats["non_empty_buckets"] == 0
        assert stats["num_rules"] == 0


# ---------------------------------------------------------------------------
# analysis/optimizer.py
# ---------------------------------------------------------------------------


class TestOptimizerMaxIterationsExhausted:
    """Cover branch 157->174: for-loop exits normally (all iterations used)."""

    def test_optimizer_exhausts_all_iterations_without_breaking(self) -> None:
        """
        Branch 157->174: optimizer uses all max_iterations because the strategy
        modifies the rule on the single available iteration and the loop never
        executes a `break` (break is only taken when modified_this_iteration is
        False at the END of an iteration).

        With max_iterations=1 and a strategy that returns a modification, the
        loop runs once, modified_this_iteration stays True, and the range is
        exhausted — triggering the 157->174 fall-through branch.
        """
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"T"; flow:to_server; content:"GET"; sid:1;)'
        )
        strategy = OptionReorderStrategy()

        # Verify the strategy actually modifies this rule (prerequisite)
        modified_rule, optimizations = strategy.apply(rule)
        assert modified_rule is not None and len(optimizations) > 0

        optimizer = RuleOptimizer(strategies=[strategy], max_iterations=1)
        result = optimizer.optimize(rule)

        # The single iteration modified the rule, exhausting the range without break
        assert result.was_modified is True
        assert len(result.optimizations) > 0
