"""Regression tests for empty-string / NUL-byte round-trip fidelity.

These cover defects where a present-but-empty string field was treated as
absent (truthiness guards), or where a NUL sentinel corrupted quoted-string
parsing. Each was a silent data-loss bug not exercised by the broader suite.

Licensed under GNU General Public License v3.0
"""

from __future__ import annotations

import pytest

from surinort_ast import parse_rule
from surinort_ast.core.location import Location, Position, Span
from surinort_ast.core.nodes import SourceOrigin
from surinort_ast.parsing.mixins.options._helpers import parse_quoted_string
from surinort_ast.serialization.protobuf import from_protobuf, to_protobuf


def test_parse_quoted_string_preserves_nul_byte() -> None:
    """A literal NUL byte must survive parsing (it was used as a sentinel)."""
    assert parse_quoted_string('"a\x00b\\\\c"') == "a\x00b\\c"


def test_parse_quoted_string_escapes_unchanged() -> None:
    """The single-pass scan keeps existing escape behavior intact."""
    assert parse_quoted_string('"a\\"b"') == 'a"b'
    assert parse_quoted_string('"line\\nbreak"') == "line\nbreak"
    assert parse_quoted_string('"esc\\;sep"') == "esc;sep"
    assert parse_quoted_string('"back\\\\slash"') == "back\\slash"
    # Unknown escape is preserved verbatim, as before.
    assert parse_quoted_string('"pcre\\d"') == "pcre\\d"


def test_generic_option_empty_value_roundtrips() -> None:
    """foobar:"" carries an empty value, distinct from a value-less foobar."""
    rule = parse_rule('alert tcp any any -> any any (sid:1; foobar:"";)')
    generic = next(o for o in rule.options if getattr(o, "keyword", None) == "foobar")
    assert generic.value == ""
    assert generic.raw == "foobar:"


def _make_rule_with_empty_strings():
    rule = parse_rule("alert tcp any any -> any any (sid:1;)")
    span = Span(
        start=Position(line=1, column=1, offset=0), end=Position(line=1, column=2, offset=1)
    )
    return rule.model_copy(
        update={
            "raw_text": "",
            "location": Location(span=span, file_path=""),
            "origin": SourceOrigin(file_path="", line_number=1, rule_id=""),
        }
    )


def test_protobuf_preserves_empty_raw_text() -> None:
    pytest.importorskip("google.protobuf")
    rule = _make_rule_with_empty_strings()
    restored = from_protobuf(to_protobuf(rule))
    assert restored.raw_text == ""


def test_protobuf_preserves_empty_location_file_path() -> None:
    pytest.importorskip("google.protobuf")
    rule = _make_rule_with_empty_strings()
    restored = from_protobuf(to_protobuf(rule))
    assert restored.location is not None
    assert restored.location.file_path == ""


def test_protobuf_preserves_empty_origin_strings() -> None:
    pytest.importorskip("google.protobuf")
    rule = _make_rule_with_empty_strings()
    restored = from_protobuf(to_protobuf(rule))
    assert restored.origin is not None
    assert restored.origin.file_path == ""
    assert restored.origin.rule_id == ""
