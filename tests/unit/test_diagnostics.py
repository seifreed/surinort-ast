"""
Comprehensive test suite for diagnostics module to achieve 100% coverage.

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

import pytest

from surinort_ast.core.diagnostics import Diagnostic, DiagnosticList
from surinort_ast.core.enums import DiagnosticLevel
from surinort_ast.core.location import Location, Position, Span


class TestDiagnosticFormatting:
    """Test Diagnostic string representations."""

    def test_str_with_all_fields(self):
        """Test __str__ with all fields populated."""
        # Arrange: Create diagnostic with all optional fields
        loc = Location(
            span=Span(
                start=Position(line=1, column=5, offset=4),
                end=Position(line=1, column=10, offset=9),
            ),
            file_path="test.rules",
        )
        diag = Diagnostic(
            level=DiagnosticLevel.ERROR,
            message="Invalid syntax",
            location=loc,
            code="E001",
            hint="Check your parentheses",
        )

        # Act: Convert to string
        result = str(diag)

        # Assert: Verify complete format
        assert "[ERROR]" in result
        assert "[E001]" in result
        assert "Invalid syntax" in result
        assert "at test.rules:1:5-10" in result
        assert "hint: Check your parentheses" in result

    def test_str_without_code(self):
        """Test __str__ without error code."""
        # Arrange: Create diagnostic without code
        diag = Diagnostic(
            level=DiagnosticLevel.WARNING,
            message="Deprecated option used",
        )

        # Act: Convert to string
        result = str(diag)

        # Assert: Verify code is absent (should only have level, not code)
        assert "[WARNING]" in result
        assert "Deprecated option used" in result
        # Verify no bracketed code like [E001] or [W001]
        assert result.count("[") == 1  # Only [WARNING]
        assert result.count("]") == 1

    def test_str_without_location(self):
        """Test __str__ without location."""
        # Arrange: Create diagnostic without location
        diag = Diagnostic(
            level=DiagnosticLevel.INFO,
            message="Processing complete",
            code="I001",
        )

        # Act: Convert to string
        result = str(diag)

        # Assert: Verify location is absent
        assert "[INFO]" in result
        assert "[I001]" in result
        assert "Processing complete" in result
        assert " at " not in result

    def test_str_without_hint(self):
        """Test __str__ without hint."""
        # Arrange: Create diagnostic without hint
        diag = Diagnostic(
            level=DiagnosticLevel.ERROR,
            message="Parse failed",
        )

        # Act: Convert to string
        result = str(diag)

        # Assert: Verify hint is absent
        assert "[ERROR]" in result
        assert "Parse failed" in result
        assert "hint:" not in result

    def test_repr_format(self):
        """Test __repr__ format."""
        # Arrange: Create diagnostic
        loc = Location(
            span=Span(
                start=Position(line=2, column=3, offset=15),
                end=Position(line=2, column=8, offset=20),
            )
        )
        diag = Diagnostic(
            level=DiagnosticLevel.WARNING,
            message="Test message",
            location=loc,
            code="W001",
        )

        # Act: Get repr
        result = repr(diag)

        # Assert: Verify repr format contains key components
        assert "Diagnostic(" in result
        assert "level=" in result
        assert "message=" in result
        assert "Test message" in result
        assert "location=" in result
        assert "code=" in result


class TestDiagnosticListAdd:
    """Test DiagnosticList.add() method."""

    def test_add_with_all_parameters(self):
        """Test add() method with all parameters."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()
        loc = Location(
            span=Span(
                start=Position(line=5, column=10, offset=50),
                end=Position(line=5, column=15, offset=55),
            ),
            file_path="rules.txt",
        )

        # Act: Add diagnostic with all parameters
        diag_list.add(
            level=DiagnosticLevel.ERROR,
            message="Syntax error found",
            location=loc,
            code="E100",
            hint="Add missing semicolon",
        )

        # Assert: Verify diagnostic was added correctly
        assert len(diag_list) == 1
        added = next(iter(diag_list))
        assert added.level == DiagnosticLevel.ERROR
        assert added.message == "Syntax error found"
        assert added.location == loc
        assert added.code == "E100"
        assert added.hint == "Add missing semicolon"

    def test_add_without_optional_parameters(self):
        """Test add() method with only required parameters."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()

        # Act: Add diagnostic with minimal parameters
        diag_list.add(
            level=DiagnosticLevel.INFO,
            message="Information message",
        )

        # Assert: Verify diagnostic was added
        assert len(diag_list) == 1
        added = next(iter(diag_list))
        assert added.level == DiagnosticLevel.INFO
        assert added.message == "Information message"
        assert added.location is None
        assert added.code is None
        assert added.hint is None

    def test_add_multiple_diagnostics(self):
        """Test adding multiple diagnostics."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()

        # Act: Add multiple diagnostics
        diag_list.add(DiagnosticLevel.ERROR, "Error 1")
        diag_list.add(DiagnosticLevel.WARNING, "Warning 1")
        diag_list.add(DiagnosticLevel.INFO, "Info 1")

        # Assert: Verify all were added in order
        assert len(diag_list) == 3
        diagnostics = list(diag_list)
        assert diagnostics[0].message == "Error 1"
        assert diagnostics[1].message == "Warning 1"
        assert diagnostics[2].message == "Info 1"


class TestDiagnosticListConvenienceMethods:
    """Test DiagnosticList convenience methods (error, warning, info)."""

    def test_error_method(self):
        """Test error() convenience method."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()
        loc = Location(
            span=Span(
                start=Position(line=3, column=1, offset=20),
                end=Position(line=3, column=5, offset=24),
            )
        )

        # Act: Add error using convenience method
        diag_list.error(
            message="Critical error",
            location=loc,
            code="E999",
            hint="Fix this immediately",
        )

        # Assert: Verify error was added with correct level
        assert len(diag_list) == 1
        added = next(iter(diag_list))
        assert added.level == DiagnosticLevel.ERROR
        assert added.message == "Critical error"
        assert added.location == loc
        assert added.code == "E999"
        assert added.hint == "Fix this immediately"

    def test_warning_method(self):
        """Test warning() convenience method."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()

        # Act: Add warning using convenience method
        diag_list.warning(
            message="Potential issue",
            code="W200",
        )

        # Assert: Verify warning was added with correct level
        assert len(diag_list) == 1
        added = next(iter(diag_list))
        assert added.level == DiagnosticLevel.WARNING
        assert added.message == "Potential issue"
        assert added.code == "W200"

    def test_info_method(self):
        """Test info() convenience method."""
        # Arrange: Create empty diagnostic list
        diag_list = DiagnosticList()

        # Act: Add info using convenience method
        diag_list.info(
            message="Informational notice",
            hint="This is just FYI",
        )

        # Assert: Verify info was added with correct level
        assert len(diag_list) == 1
        added = next(iter(diag_list))
        assert added.level == DiagnosticLevel.INFO
        assert added.message == "Informational notice"
        assert added.hint == "This is just FYI"


class TestDiagnosticListCheckers:
    """Test DiagnosticList checking methods."""

    def test_has_errors_true(self):
        """Test has_errors() returns True when errors exist."""
        # Arrange: Create list with error
        diag_list = DiagnosticList()
        diag_list.error("Error message")
        diag_list.warning("Warning message")

        # Act: Check for errors
        result = diag_list.has_errors()

        # Assert: Verify errors detected
        assert result is True

    def test_has_errors_false(self):
        """Test has_errors() returns False when no errors exist."""
        # Arrange: Create list without errors
        diag_list = DiagnosticList()
        diag_list.warning("Warning only")
        diag_list.info("Info only")

        # Act: Check for errors
        result = diag_list.has_errors()

        # Assert: Verify no errors detected
        assert result is False

    def test_has_errors_empty_list(self):
        """Test has_errors() returns False for empty list."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Check for errors
        result = diag_list.has_errors()

        # Assert: Verify no errors in empty list
        assert result is False

    def test_has_warnings_true(self):
        """Test has_warnings() returns True when warnings exist."""
        # Arrange: Create list with warning
        diag_list = DiagnosticList()
        diag_list.info("Info message")
        diag_list.warning("Warning message")

        # Act: Check for warnings
        result = diag_list.has_warnings()

        # Assert: Verify warnings detected
        assert result is True

    def test_has_warnings_false(self):
        """Test has_warnings() returns False when no warnings exist."""
        # Arrange: Create list without warnings
        diag_list = DiagnosticList()
        diag_list.error("Error only")
        diag_list.info("Info only")

        # Act: Check for warnings
        result = diag_list.has_warnings()

        # Assert: Verify no warnings detected
        assert result is False

    def test_has_warnings_empty_list(self):
        """Test has_warnings() returns False for empty list."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Check for warnings
        result = diag_list.has_warnings()

        # Assert: Verify no warnings in empty list
        assert result is False


class TestDiagnosticListCounters:
    """Test DiagnosticList counting properties."""

    def test_error_count_with_multiple_errors(self):
        """Test error_count property with multiple errors."""
        # Arrange: Create list with multiple errors
        diag_list = DiagnosticList()
        diag_list.error("Error 1")
        diag_list.warning("Warning 1")
        diag_list.error("Error 2")
        diag_list.info("Info 1")
        diag_list.error("Error 3")

        # Act: Get error count
        count = diag_list.error_count

        # Assert: Verify correct count
        assert count == 3

    def test_error_count_zero(self):
        """Test error_count property with no errors."""
        # Arrange: Create list without errors
        diag_list = DiagnosticList()
        diag_list.warning("Warning 1")
        diag_list.info("Info 1")

        # Act: Get error count
        count = diag_list.error_count

        # Assert: Verify zero count
        assert count == 0

    def test_warning_count_with_multiple_warnings(self):
        """Test warning_count property with multiple warnings."""
        # Arrange: Create list with multiple warnings
        diag_list = DiagnosticList()
        diag_list.warning("Warning 1")
        diag_list.error("Error 1")
        diag_list.warning("Warning 2")
        diag_list.warning("Warning 3")
        diag_list.info("Info 1")

        # Act: Get warning count
        count = diag_list.warning_count

        # Assert: Verify correct count
        assert count == 3

    def test_warning_count_zero(self):
        """Test warning_count property with no warnings."""
        # Arrange: Create list without warnings
        diag_list = DiagnosticList()
        diag_list.error("Error 1")
        diag_list.info("Info 1")

        # Act: Get warning count
        count = diag_list.warning_count

        # Assert: Verify zero count
        assert count == 0


class TestDiagnosticListProtocols:
    """Test DiagnosticList protocol implementations."""

    def test_len_with_items(self):
        """Test __len__ with multiple items."""
        # Arrange: Create list with multiple items
        diag_list = DiagnosticList()
        diag_list.error("Error 1")
        diag_list.warning("Warning 1")
        diag_list.info("Info 1")

        # Act: Get length
        length = len(diag_list)

        # Assert: Verify correct length
        assert length == 3

    def test_len_empty(self):
        """Test __len__ with empty list."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Get length
        length = len(diag_list)

        # Assert: Verify zero length
        assert length == 0

    def test_iter_multiple_items(self):
        """Test __iter__ with multiple items."""
        # Arrange: Create list with multiple items
        diag_list = DiagnosticList()
        diag_list.error("Error 1")
        diag_list.warning("Warning 1")
        diag_list.info("Info 1")

        # Act: Iterate over list
        messages = [d.message for d in diag_list]

        # Assert: Verify all items iterated
        assert messages == ["Error 1", "Warning 1", "Info 1"]

    def test_iter_empty(self):
        """Test __iter__ with empty list."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Iterate over list
        items = list(diag_list)

        # Assert: Verify no items
        assert items == []

    def test_bool_true_with_items(self):
        """Test __bool__ returns True when list has items."""
        # Arrange: Create list with items
        diag_list = DiagnosticList()
        diag_list.info("Info message")

        # Act: Convert to bool
        result = bool(diag_list)

        # Assert: Verify truthy
        assert result is True

    def test_bool_false_when_empty(self):
        """Test __bool__ returns False when list is empty."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Convert to bool
        result = bool(diag_list)

        # Assert: Verify falsy
        assert result is False

    def test_bool_in_conditional(self):
        """Test __bool__ works correctly in conditional statements."""
        # Arrange: Create list with diagnostics
        diag_list = DiagnosticList()

        # Act & Assert: Test in if statement (empty)
        if diag_list:
            pytest.fail("Empty list should be falsy")

        # Act & Assert: Add item and test again
        diag_list.error("Error occurred")
        if not diag_list:
            pytest.fail("Non-empty list should be truthy")


class TestDiagnosticListIntegration:
    """Integration tests combining multiple DiagnosticList features."""

    def test_mixed_diagnostic_workflow(self):
        """Test complete workflow with mixed diagnostics."""
        # Arrange: Create empty list
        diag_list = DiagnosticList()

        # Act: Add various diagnostics through different methods
        diag_list.add(DiagnosticLevel.ERROR, "Parse error", code="E001")
        diag_list.warning("Deprecated syntax", code="W001")
        diag_list.info("Processing file")
        diag_list.error("Missing semicolon", code="E002")

        # Assert: Verify all checks work correctly
        assert len(diag_list) == 4
        assert diag_list.has_errors()
        assert diag_list.has_warnings()
        assert diag_list.error_count == 2
        assert diag_list.warning_count == 1
        assert bool(diag_list) is True

        # Assert: Verify iteration order
        messages = [d.message for d in diag_list]
        assert messages == [
            "Parse error",
            "Deprecated syntax",
            "Processing file",
            "Missing semicolon",
        ]

    def test_filtering_by_level(self):
        """Test filtering diagnostics by level."""
        # Arrange: Create list with mixed diagnostics
        diag_list = DiagnosticList()
        diag_list.error("Error 1")
        diag_list.warning("Warning 1")
        diag_list.error("Error 2")
        diag_list.info("Info 1")

        # Act: Filter errors
        errors = [d for d in diag_list if d.level == DiagnosticLevel.ERROR]

        # Assert: Verify correct errors filtered
        assert len(errors) == 2
        assert all(d.level == DiagnosticLevel.ERROR for d in errors)

    def test_string_formatting_integration(self):
        """Test string formatting for entire diagnostic list."""
        # Arrange: Create list with diagnostics
        diag_list = DiagnosticList()
        diag_list.error("Syntax error", code="E100", hint="Check line 5")
        diag_list.warning("Deprecated", code="W200")

        # Act: Format all diagnostics as strings
        formatted = [str(d) for d in diag_list]

        # Assert: Verify all formatted correctly
        assert len(formatted) == 2
        assert "[ERROR]" in formatted[0]
        assert "[E100]" in formatted[0]
        assert "hint:" in formatted[0]
        assert "[WARNING]" in formatted[1]
        assert "[W200]" in formatted[1]
