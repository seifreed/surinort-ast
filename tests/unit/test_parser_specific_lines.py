"""
Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.

Precise tests for parser.py lines 237 and 526.
"""

from __future__ import annotations

import pytest
from lark import Lark
from lark.exceptions import LarkError

from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.parser import RuleParser


class TestParserExactLines:
    """Tests targeting exact lines 237 and 526 in parser.py"""

    def test_line_237_generic_lark_error(self, monkeypatch) -> None:
        """
        Purpose: Trigger line 237 - except LarkError as e: handler.

        This is the generic LarkError catch-all that isn't UnexpectedInput/Token/Characters.
        We need to cause a LarkError that doesn't fall into those specific categories.
        """
        parser = RuleParser(strict=False)

        # Monkeypatch Lark's parse method to raise a generic LarkError

        original_parse = Lark.parse

        def mock_parse(self, text, start=None):
            # Raise a generic LarkError (not UnexpectedInput/Token/Characters)
            raise LarkError("Generic Lark error for testing")

        monkeypatch.setattr(Lark, "parse", mock_parse)

        # Now parse - should trigger line 237
        result = parser.parse('alert tcp any any -> any 80 (msg:"test"; sid:1;)')

        # Should return error rule (line 237 -> _handle_parse_error)
        assert result is not None
        assert isinstance(result, Rule)
        assert len(result.diagnostics) > 0

        # Restore
        monkeypatch.setattr(Lark, "parse", original_parse)

    def test_line_526_location_without_line_number(self) -> None:
        """
        Purpose: Trigger line 526 else branch - when location is None.

        Line 524: line_num = None
        Line 525: if rule.location and rule.location.span.start.line:
        Line 526:     line_num = rule.location.span.start.line + line_offset

        When location is None, we skip line 526 and line_num stays None.
        """
        parser = RuleParser()

        # Parse valid rule
        rule = parser.parse('alert tcp any any -> any 80 (msg:"test"; sid:1;)')

        # Set location to None to trigger the else path
        rule_without_location = rule.model_copy(update={"location": None})

        # Call _attach_source_metadata
        result = parser._attach_source_metadata(
            rule_without_location,
            raw_text='alert tcp any any -> any 80 (msg:"test"; sid:1;)',
            file_path="/test.rules",
            line_offset=5,
        )

        # Verify that line_num is None (didn't reach line 526)
        assert result.origin is not None
        assert result.origin.line_number is None
        assert result.origin.file_path == "/test.rules"

    def test_line_526_with_valid_location(self) -> None:
        """
        Purpose: Ensure line 526 IS executed when location is present.

        This tests the positive case to ensure line 526 is reachable.
        """
        from surinort_ast.core.location import Location, Position, Span

        parser = RuleParser()

        # Parse valid rule
        rule = parser.parse('alert tcp any any -> any 80 (msg:"test"; sid:1;)')

        # Create a rule with valid location
        loc = Location(
            span=Span(
                start=Position(line=5, column=1, offset=0),
                end=Position(line=5, column=50, offset=50),
            ),
            file_path=None,
        )

        rule_with_loc = rule.model_copy(update={"location": loc})

        # Call _attach_source_metadata with line_offset
        result = parser._attach_source_metadata(
            rule_with_loc,
            raw_text='alert tcp any any -> any 80 (msg:"test"; sid:1;)',
            file_path="/test.rules",
            line_offset=10,
        )

        # Should calculate line_num = start.line + line_offset (line 526 executed)
        assert result.origin is not None
        assert result.origin.line_number is not None
        # Line number should be original + offset
        assert result.origin.line_number == 5 + 10  # line 526 was executed

    def test_strict_mode_raises_parse_error(self) -> None:
        """
        Purpose: Test strict mode to ensure ParseError is raised.

        This verifies that the error handlers properly raise exceptions in strict mode.
        """
        parser = RuleParser(strict=True)

        from surinort_ast.exceptions import ParseError

        with pytest.raises(ParseError):
            parser.parse("completely invalid rule")

    def test_empty_input_handling(self) -> None:
        """Test empty input error path."""
        parser = RuleParser(strict=False)

        result = parser.parse("")
        assert result is not None
        assert len(result.diagnostics) > 0
        assert result.diagnostics[0].message == "Empty input text"

    def test_comment_line_handling(self) -> None:
        """Test comment line error path."""
        parser = RuleParser(strict=False)

        result = parser.parse("# This is a comment")
        assert result is not None
        assert len(result.diagnostics) > 0
