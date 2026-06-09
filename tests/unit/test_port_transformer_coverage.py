# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for parsing/mixins/port_transformer.py.

Covers port negation, port lists (including a variable element), the
out-of-range / inverted port-range diagnostics (clamping start, end, and
upper-bound), and the empty port_elem guard. Out-of-range ports parse into
clamped nodes carrying ERROR diagnostics, so these are exercised through real
parsing; the empty-element guard is reached by a direct transformer call.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.core.enums import DiagnosticLevel, Dialect
from surinort_ast.core.nodes import PortList, PortNegation, PortRange, PortVariable
from surinort_ast.parsing.transformer import RuleTransformer


def _dst_port(port_expr: str):
    return parse_rule(f'alert tcp any any -> any {port_expr} (msg:"x"; sid:1;)')


def _errors(rule):
    return [d for d in rule.diagnostics if d.level == DiagnosticLevel.ERROR]


class TestPortStructures:
    def test_port_negation(self):
        rule = _dst_port("!80")
        assert isinstance(rule.header.dst_port, PortNegation)

    def test_port_list(self):
        rule = _dst_port("[80,443]")
        assert isinstance(rule.header.dst_port, PortList)
        assert len(rule.header.dst_port.elements) == 2

    def test_port_list_with_variable_element(self):
        rule = _dst_port("[$HTTP_PORTS,80]")
        assert isinstance(rule.header.dst_port, PortList)
        assert any(isinstance(e, PortVariable) for e in rule.header.dst_port.elements)


class TestPortRangeDiagnostics:
    def test_start_out_of_range_clamped_and_swapped(self):
        rule = _dst_port("99999:100")
        port = rule.header.dst_port
        assert isinstance(port, PortRange)
        assert 0 <= port.start <= 65535
        assert 0 <= port.end <= 65535
        # Out-of-range start and the resulting start>end swap both diagnose.
        assert len(_errors(rule)) >= 2

    def test_end_out_of_range_clamped(self):
        rule = _dst_port("1024:99999")
        assert rule.header.dst_port.end == 65535
        assert any("out of range" in d.message for d in _errors(rule))

    def test_upper_range_out_of_range_clamped(self):
        rule = _dst_port(":99999")
        port = rule.header.dst_port
        assert isinstance(port, PortRange)
        assert port.end == 65535
        assert any("out of range" in d.message for d in _errors(rule))


def _token(token_type: str, value: str):
    from lark import Token

    token = Token(token_type, value)
    token.line = 1
    token.column = 1
    token.start_pos = 0
    token.end_line = 1
    token.end_column = len(value)
    token.end_pos = len(value)
    return token


class TestPortElemGuard:
    def test_empty_port_elem_returns_none(self):
        assert RuleTransformer(dialect=Dialect.SURICATA).port_elem([]) is None

    def test_port_elem_variable_without_dollar_marker(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        result = transformer.port_elem([_token("VARIABLE", "HTTP_PORTS")])

        assert isinstance(result, PortVariable)
        assert result.name == "HTTP_PORTS"
