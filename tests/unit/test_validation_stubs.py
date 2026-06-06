"""Tests for streaming SID-uniqueness validation and validate_rule's rev check."""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.api.validation import validate_rule
from surinort_ast.streaming.processor import ValidateProcessor


def _codes(rule):
    return {d.code for d in rule.diagnostics}


class TestSidUniquenessStreaming:
    def test_duplicate_sid_flagged_across_stream(self):
        processor = ValidateProcessor()
        first = processor.process(
            parse_rule('alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)')
        )
        second = processor.process(
            parse_rule('alert udp any any -> any 53 (msg:"B"; sid:1; rev:1;)')
        )
        assert "duplicate_sid" not in _codes(first)
        assert "duplicate_sid" in _codes(second)

    def test_unique_sids_not_flagged(self):
        processor = ValidateProcessor()
        r1 = processor.process(parse_rule('alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)'))
        r2 = processor.process(parse_rule('alert tcp any any -> any 80 (msg:"B"; sid:2; rev:1;)'))
        assert "duplicate_sid" not in _codes(r1)
        assert "duplicate_sid" not in _codes(r2)

    def test_reset_clears_seen_sids(self):
        processor = ValidateProcessor()
        processor.process(parse_rule('alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)'))
        processor.reset()
        again = processor.process(
            parse_rule('alert tcp any any -> any 80 (msg:"A"; sid:1; rev:1;)')
        )
        assert "duplicate_sid" not in _codes(again)


class TestValidateRuleRev:
    def test_missing_rev_info_when_sid_present(self):
        diags = validate_rule(parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:1;)'))
        assert any(d.code == "missing_rev" for d in diags)

    def test_no_missing_rev_when_rev_present(self):
        diags = validate_rule(parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:1; rev:2;)'))
        assert not any(d.code == "missing_rev" for d in diags)

    def test_no_missing_rev_when_no_sid(self):
        # Without a sid the rev recommendation does not apply (sid is the primary gap).
        diags = validate_rule(parse_rule('alert tcp any any -> any 80 (msg:"t"; content:"a";)'))
        assert not any(d.code == "missing_rev" for d in diags)
