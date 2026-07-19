"""Regression coverage for issue #167 grammar gaps."""

from __future__ import annotations

import pytest

from surinort_ast import Dialect, parse_rule
from surinort_ast.core.nodes import GenericOption


@pytest.mark.parametrize(
    ("dialect", "rule_text"),
    [
        (
            Dialect.SURICATA,
            r'alert http any any -> any any (msg:"HTTP with pcrexform"; http.request_line; '
            r'pcrexform:"[a-zA-Z]+\s+(.*)\s+HTTP"; content:"/dropper.php"; sid:1;)',
        ),
        (
            Dialect.SURICATA,
            r'alert http1 $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; http.header; '
            r'pcrexform:"X-(.*)\x0d\x0a"; content:"Forwarded-For|3a 20|"; '
            r"isdataat:50,relative; sid:2061292; rev:1;)",
        ),
        (
            Dialect.SNORT2,
            r'alert tcp any any -> any any (msg:"t"; content:"a"; '
            r"isdataat:128,relative,rawbytes; sid:1;)",
        ),
        (
            Dialect.SNORT2,
            r'alert tcp any any -> any any (msg:"t"; content:"a"; '
            r"isdataat:128,rawbytes,relative; sid:1;)",
        ),
        (
            Dialect.SNORT2,
            r'alert tcp any any -> any any (msg:"t"; content:"a"; '
            r"isdataat:!0,relative,rawbytes; sid:1;)",
        ),
    ],
)
def test_issue_167_rules_parse(dialect: Dialect, rule_text: str) -> None:
    parse_rule(rule_text, dialect=dialect)


def test_issue_167_preserves_values() -> None:
    rule = parse_rule(
        r'alert http any any -> any any (msg:"t"; '
        r'pcrexform:"[a-zA-Z]+\s+(.*)\s+HTTP"; '
        r"isdataat:128,relative,rawbytes; sid:1;)",
        dialect=Dialect.SURICATA,
    )

    options = [option for option in rule.options if isinstance(option, GenericOption)]
    assert any(
        option.keyword == "pcrexform" and option.value == r"[a-zA-Z]+\s+(.*)\s+HTTP"
        for option in options
    )
    assert any(
        option.keyword == "isdataat" and option.value == "128,relative,rawbytes"
        for option in options
    )
