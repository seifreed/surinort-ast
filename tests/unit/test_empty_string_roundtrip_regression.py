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
from surinort_ast.parsing.mixins.options._helpers import (
    parse_quoted_string,
    strip_outer_quotes,
)
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


def test_strip_outer_quotes_distinguishes_escaped_closing_quote() -> None:
    """The trailing quote is a real closing quote only when preceded by an even
    number of backslashes.

    Regression: a string the grammar tolerates as ``"...\\";`` (escaped quote,
    no separate closing quote) was stripped as if the escaped quote were the
    closing quote, dropping it to a literal backslash. The escaped-quote branch
    was also unreachable dead code because the generic ``s[-1] == '"'`` check
    always fired first.
    """
    # Even backslash count before the final quote => real closing quote.
    assert strip_outer_quotes('"hello"') == "hello"
    assert strip_outer_quotes('"hello\\""') == 'hello\\"'  # escaped quote + close
    assert strip_outer_quotes('"foo\\\\"') == "foo\\\\"  # escaped backslash + close
    # Odd backslash count => the final quote is an escaped ``\"`` kept verbatim.
    assert strip_outer_quotes('"hello\\"') == 'hello\\"'
    # Single quotes are unaffected.
    assert strip_outer_quotes("'hello'") == "hello"


def test_parse_quoted_string_tolerated_trailing_escaped_quote() -> None:
    """A string terminated as ``"...\\"`` unescapes its trailing quote rather
    than collapsing it to a stray backslash."""
    assert parse_quoted_string('"hello\\"') == 'hello"'


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
