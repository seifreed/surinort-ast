"""Regression coverage for issue #177 sd_pattern parsing."""

from __future__ import annotations

import pytest

from surinort_ast import Dialect, parse_rule
from surinort_ast.core.nodes import GenericOption


@pytest.mark.parametrize("dialect", [Dialect.SNORT2, Dialect.SNORT3, Dialect.SURICATA])
def test_sd_pattern_accepts_literal_parentheses(dialect: Dialect) -> None:
    rule = parse_rule(
        r'alert tcp any any -> any any (msg:"t"; content:"a"; '
        r"sd_pattern:20,(\d{3}) ?\d{3}-\d{4}; sid:6; rev:1;)",
        dialect=dialect,
    )

    sd_pattern = next(
        option
        for option in rule.options
        if isinstance(option, GenericOption) and option.keyword == "sd_pattern"
    )
    assert sd_pattern.value == r"20,(\d{3}) ?\d{3}-\d{4}"


def test_snort_builtin_phone_sd_pattern_parses() -> None:
    parse_rule(
        r"alert tcp $HOME_NET any -> $EXTERNAL_NET [80,20,25,143,110] "
        r'(msg:"SENSITIVE-DATA U.S. Phone Numbers"; '
        r"metadata:service http, service smtp, service ftp-data, service imap, service pop3; "
        r"sd_pattern:20,(\d{3}) ?\d{3}-\d{4}; classtype:sdf; sid:6; gid:138; rev:1;)",
        dialect=Dialect.SNORT2,
    )
