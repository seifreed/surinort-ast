"""Tests for the rule-conflict detection engine."""

from __future__ import annotations

import json

from surinort_ast import parse_rule
from surinort_ast.analysis.conflicts import (
    ConflictDetectorConfig,
    ConflictType,
    Severity,
    detect_conflicts,
    filter_conflicts,
)
from surinort_ast.analysis.conflicts import matchspace as ms


def _rules(*texts):
    return [parse_rule(t) for t in texts]


def _header(text):
    return parse_rule(text).header


def _types(report):
    return {c.conflict_type for c in report.conflicts}


# ---------------------------------------------------------------------------
# Match-space algebra
# ---------------------------------------------------------------------------


class TestMatchspace:
    def test_tri_combinators(self):
        assert ms.tri_and(ms.Tri.TRUE, ms.Tri.FALSE) == ms.Tri.FALSE
        assert ms.tri_and(ms.Tri.TRUE, ms.Tri.UNKNOWN) == ms.Tri.UNKNOWN
        assert ms.tri_and(ms.Tri.TRUE, ms.Tri.TRUE) == ms.Tri.TRUE
        assert ms.tri_or(ms.Tri.FALSE, ms.Tri.TRUE) == ms.Tri.TRUE
        assert ms.tri_or(ms.Tri.FALSE, ms.Tri.UNKNOWN) == ms.Tri.UNKNOWN
        assert ms.tri_or(ms.Tri.FALSE, ms.Tri.FALSE) == ms.Tri.FALSE

    def test_addr_subset_concrete(self):
        a = ms.build_addr_set(_header("alert tcp 10.0.0.0/24 any -> any 80 (sid:1;)").src_addr)
        b = ms.build_addr_set(_header("alert tcp 10.0.0.0/8 any -> any 80 (sid:2;)").src_addr)
        assert ms.addr_subset(a, b) == ms.Tri.TRUE
        assert ms.addr_subset(b, a) == ms.Tri.FALSE

    def test_addr_intersect_disjoint(self):
        a = ms.build_addr_set(_header("alert tcp 10.0.0.0/24 any -> any 80 (sid:1;)").src_addr)
        b = ms.build_addr_set(_header("alert tcp 192.168.1.0/24 any -> any 80 (sid:2;)").src_addr)
        assert ms.addr_intersects(a, b) == ms.Tri.FALSE

    def test_addr_variable_by_name(self):
        a = ms.build_addr_set(_header("alert tcp $HOME_NET any -> any 80 (sid:1;)").src_addr)
        concrete = ms.build_addr_set(_header("alert tcp 10.0.0.1 any -> any 80 (sid:2;)").src_addr)
        assert ms.addr_subset(a, a) == ms.Tri.TRUE
        assert ms.addr_subset(concrete, a) == ms.Tri.UNKNOWN

    def test_any_subsumes(self):
        a = ms.build_addr_set(_header("alert tcp 10.0.0.0/24 any -> any 80 (sid:1;)").src_addr)
        any_addr = ms.build_addr_set(_header("alert tcp any any -> any 80 (sid:2;)").src_addr)
        assert ms.addr_subset(a, any_addr) == ms.Tri.TRUE
        assert ms.addr_subset(any_addr, a) == ms.Tri.FALSE

    def test_port_intervals(self):
        p1 = ms.build_port_set(_header("alert tcp any any -> any [80,443] (sid:1;)").dst_port)
        p2 = ms.build_port_set(_header("alert tcp any any -> any [443,8080] (sid:2;)").dst_port)
        assert ms.port_intersects(p1, p2) == ms.Tri.TRUE
        narrow = ms.build_port_set(_header("alert tcp any any -> any 443 (sid:3;)").dst_port)
        wide = ms.build_port_set(_header("alert tcp any any -> any any (sid:4;)").dst_port)
        assert ms.port_subset(narrow, wide) == ms.Tri.TRUE

    def test_ipv4_v6_disjoint(self):
        v4 = ms.build_addr_set(_header("alert tcp 1.2.3.4 any -> any 80 (sid:1;)").src_addr)
        v6 = ms.build_addr_set(_header("alert tcp ::1 any -> any 80 (sid:2;)").src_addr)
        assert ms.addr_intersects(v4, v6) == ms.Tri.FALSE

    def test_protocol_hierarchy_optin(self):
        from surinort_ast.core.enums import Protocol

        assert ms.proto_subset(Protocol.TCP, Protocol.HTTP) is False
        assert ms.proto_subset(Protocol.TCP, Protocol.HTTP, hierarchy=True) is True
        assert ms.proto_subset(Protocol.IP, Protocol.TCP, hierarchy=True) is True


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


class TestDetectors:
    def test_duplicate_sid(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; sid:1000001; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; sid:1000001; rev:1;)',
            )
        )
        assert ConflictType.DUPLICATE_SID in _types(report)
        dup = next(c for c in report.conflicts if c.conflict_type == ConflictType.DUPLICATE_SID)
        assert dup.metadata["sid"] == 1000001

    def test_conflicting_action_pass_vs_alert(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> 10.0.0.0/24 80 (msg:"d"; content:"evil"; sid:1000002; rev:1;)',
                'pass tcp any any -> 10.0.0.0/24 80 (msg:"a"; sid:1000003; rev:1;)',
            )
        )
        conflict = next(
            c for c in report.conflicts if c.conflict_type == ConflictType.CONFLICTING_ACTION
        )
        assert conflict.severity == Severity.HIGH
        assert set(conflict.rule_ids) == {1000002, 1000003}

    def test_alert_vs_log_not_conflicting_action(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"a"; content:"x"; sid:1; rev:1;)',
                'log tcp any any -> any 80 (msg:"b"; content:"x"; sid:2; rev:1;)',
            )
        )
        assert ConflictType.CONFLICTING_ACTION not in _types(report)

    def test_shadowing_general_pass_first(self):
        report = detect_conflicts(
            _rules(
                'pass tcp any any -> any any (msg:"blanket"; sid:1000004; rev:1;)',
                'alert tcp any any -> 10.0.0.0/24 443 (msg:"s"; content:"x"; sid:1000005; rev:1;)',
            )
        )
        shadow = next(c for c in report.conflicts if c.conflict_type == ConflictType.SHADOWING)
        assert shadow.rule_ids == [1000004, 1000005]

    def test_no_shadowing_when_specific_first(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> 10.0.0.0/24 443 (msg:"s"; content:"x"; sid:1; rev:1;)',
                'alert tcp any any -> any any (msg:"blanket"; sid:2; rev:1;)',
            )
        )
        assert ConflictType.SHADOWING not in _types(report)

    def test_overlapping_shared_port(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any [80,443] (msg:"1"; content:"a"; sid:1000006; rev:1;)',
                'alert tcp any any -> any [443,8080] (msg:"2"; content:"a"; sid:1000007; rev:1;)',
            )
        )
        overlap = next(c for c in report.conflicts if c.conflict_type == ConflictType.OVERLAPPING)
        assert overlap.severity == Severity.MEDIUM

    def test_overlapping_unknown_variable_is_low(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> $HOME_NET 80 (msg:"v"; sid:1000008; rev:1;)',
                'alert tcp any any -> 192.168.1.0/24 80 (msg:"c"; sid:1000009; rev:1;)',
            )
        )
        overlaps = [c for c in report.conflicts if c.conflict_type == ConflictType.OVERLAPPING]
        assert overlaps
        assert overlaps[0].severity == Severity.LOW
        assert overlaps[0].metadata["confidence"] == "unknown"

    def test_missing_flowbit_dependency(self):
        report = detect_conflicts(
            _rules('alert tcp any any -> any 80 (msg:"c"; flowbits:isset,stage1; sid:1000010;)')
        )
        dep = next(
            c for c in report.conflicts if c.conflict_type == ConflictType.MISSING_DEPENDENCY
        )
        assert dep.metadata["flowbit"] == "stage1"

    def test_flowbit_with_setter_no_conflict(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"c"; flowbits:isset,stage1; sid:1000010;)',
                'alert tcp any any -> any 80 (msg:"s"; flowbits:set,stage1; sid:1000011;)',
            )
        )
        assert ConflictType.MISSING_DEPENDENCY not in _types(report)

    def test_external_flowbits_suppresses(self):
        config = ConflictDetectorConfig(external_flowbits={"stage1"})
        report = detect_conflicts(
            _rules('alert tcp any any -> any 80 (msg:"c"; flowbits:isset,stage1; sid:1;)'),
            config,
        )
        assert ConflictType.MISSING_DEPENDENCY not in _types(report)


# ---------------------------------------------------------------------------
# Report / config
# ---------------------------------------------------------------------------


class TestReportAndConfig:
    def test_report_serialization(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)',
            )
        )
        data = report.to_dict()
        assert data["total_conflicts"] == report.total_conflicts
        assert json.loads(report.to_json())["total_rules"] == 2
        assert "Conflict report" in report.to_text(verbose=True)
        assert report.to_markdown().startswith("# Conflict Report")

    def test_min_severity_filter(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> $HOME_NET 80 (msg:"v"; sid:1;)',
                'alert tcp any any -> 192.168.1.0/24 80 (msg:"c"; sid:2;)',
            ),
            ConflictDetectorConfig(min_severity=Severity.HIGH),
        )
        assert all(c.severity in (Severity.HIGH, Severity.CRITICAL) for c in report.conflicts)

    def test_ignore_sids(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; sid:1000001; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; sid:1000001; rev:1;)',
            ),
            ConflictDetectorConfig(ignore_sids={1000001}),
        )
        assert report.total_conflicts == 0

    def test_enabled_detectors(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)',
            ),
            ConflictDetectorConfig(enabled_detectors={ConflictType.SHADOWING}),
        )
        assert ConflictType.DUPLICATE_SID not in _types(report)

    def test_filter_conflicts_helper(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)',
            )
        )
        filtered = filter_conflicts(report, min_severity=Severity.CRITICAL)
        assert filtered.total_conflicts == 0

    def test_no_conflicts_clean_ruleset(self):
        report = detect_conflicts(
            _rules(
                'alert tcp any any -> any 80 (msg:"A"; content:"a"; sid:1; rev:1;)',
                'alert udp any any -> any 53 (msg:"B"; content:"b"; sid:2; rev:1;)',
            )
        )
        assert report.total_conflicts == 0


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


class TestConflictsCLI:
    def _write(self, tmp_path, *texts):
        path = tmp_path / "rules.rules"
        path.write_text("\n".join(texts) + "\n", encoding="utf-8")
        return path

    def test_cli_text(self, tmp_path):
        from typer.testing import CliRunner

        from surinort_ast.cli.main import app

        rules_file = self._write(
            tmp_path,
            'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)',
            'alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)',
        )
        result = CliRunner().invoke(app, ["conflicts", str(rules_file)])
        assert result.exit_code == 0
        assert "duplicate_sid" in result.stdout

    def test_cli_json(self, tmp_path):
        import json

        from typer.testing import CliRunner

        from surinort_ast.cli.main import app

        rules_file = self._write(
            tmp_path,
            'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)',
            'alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)',
        )
        result = CliRunner().invoke(app, ["conflicts", str(rules_file), "--format", "json"])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["total_conflicts"] >= 1

    def test_cli_bad_format(self, tmp_path):
        from typer.testing import CliRunner

        from surinort_ast.cli.main import app

        rules_file = self._write(tmp_path, 'alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)')
        result = CliRunner().invoke(app, ["conflicts", str(rules_file), "--format", "xml"])
        assert result.exit_code == 1
