"""
Unit tests for missing coverage lines in location.py

Tests for:
- Line 27: Position.__str__() return statement
- Line 57: Span.length property return statement

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from surinort_ast.core.location import Position, Span


def test_position_str():
    """Test Position.__str__() method (line 27).

    This test creates a Position object and calls str() on it,
    which exercises the return statement on line 27.
    """
    pos = Position(line=10, column=5, offset=100)
    result = str(pos)
    assert result == "10:5"


def test_span_length():
    """Test Span.length property (line 57).

    This test creates a Span and accesses the .length property,
    which exercises the return statement on line 57 that calculates
    end.offset - start.offset.
    """
    start = Position(line=1, column=1, offset=0)
    end = Position(line=1, column=10, offset=9)
    span = Span(start=start, end=end)
    length = span.length
    assert length == 9
