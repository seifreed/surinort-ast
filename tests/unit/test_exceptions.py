# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort-ast exceptions.

Tests exception hierarchy, message formatting, and location tracking.
NO MOCKS - all tests use real exception instances.
"""

from surinort_ast.core.location import Location, Position, Span
from surinort_ast.exceptions import (
    ParseError,
    SerializationError,
    SurinortASTError,
    UnsupportedDialectError,
    ValidationError,
)


class TestSurinortASTError:
    """Test base exception class."""

    def test_is_exception(self):
        """Test that SurinortASTError is an Exception."""
        error = SurinortASTError("test error")
        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that SurinortASTError can be raised and caught."""
        try:
            raise SurinortASTError("test error")
        except SurinortASTError as e:
            assert str(e) == "test error"

    def test_can_be_caught_as_exception(self):
        """Test that SurinortASTError can be caught as Exception."""
        try:
            raise SurinortASTError("test error")
        except Exception as e:
            assert isinstance(e, SurinortASTError)

    def test_message_preserved(self):
        """Test that error message is preserved."""
        message = "This is a detailed error message"
        error = SurinortASTError(message)
        assert str(error) == message

    def test_empty_message(self):
        """Test error with empty message."""
        error = SurinortASTError("")
        assert str(error) == ""


class TestParseError:
    """Test ParseError exception."""

    def test_is_surinort_error(self):
        """Test that ParseError inherits from SurinortASTError."""
        error = ParseError("parse failed")
        assert isinstance(error, SurinortASTError)
        assert isinstance(error, Exception)

    def test_simple_message_without_location(self):
        """Test ParseError with message only."""
        message = "Invalid token"
        error = ParseError(message)

        assert error.message == message
        assert error.location is None
        assert str(error) == message

    def test_message_with_location(self):
        """Test ParseError with location information."""
        message = "Unexpected token"
        position = Position(line=10, column=5, offset=100)
        span = Span(start=position, end=Position(line=10, column=10, offset=105))
        location = Location(span=span)

        error = ParseError(message, location=location)

        assert error.message == message
        assert error.location is location
        assert "10:5" in str(error)
        assert message in str(error)

    def test_location_formatting(self):
        """Test that location is properly formatted in error message."""
        position = Position(line=5, column=12, offset=50)
        span = Span(start=position, end=Position(line=5, column=20, offset=58))
        location = Location(span=span)

        error = ParseError("syntax error", location=location)
        error_str = str(error)

        # Should contain location and message
        assert "5:12" in error_str
        assert "syntax error" in error_str

    def test_location_with_file_path(self):
        """Test ParseError with file path in location."""
        position = Position(line=42, column=1, offset=1000)
        span = Span(start=position, end=Position(line=42, column=10, offset=1009))
        location = Location(span=span, file_path="/path/to/rules.txt")

        error = ParseError("invalid rule", location=location)
        error_str = str(error)

        # Should contain file path, location, and message
        assert "/path/to/rules.txt" in error_str
        assert "42:1" in error_str
        assert "invalid rule" in error_str

    def test_format_message_called(self):
        """Test that _format_message is called during initialization."""
        location = Location(
            span=Span(
                start=Position(line=1, column=1, offset=0), end=Position(line=1, column=5, offset=4)
            )
        )
        error = ParseError("test", location=location)

        # The formatted message should be the string representation
        formatted = str(error)
        assert "1:1" in formatted
        assert "test" in formatted

    def test_location_preserved(self):
        """Test that location object is preserved."""
        position = Position(line=7, column=3, offset=70)
        span = Span(start=position, end=Position(line=7, column=8, offset=75))
        location = Location(span=span)

        error = ParseError("error", location=location)

        # Location should be accessible
        assert error.location is not None
        assert error.location.span.start.line == 7
        assert error.location.span.start.column == 3

    def test_multiline_location(self):
        """Test ParseError with location spanning multiple lines."""
        start = Position(line=10, column=5, offset=100)
        end = Position(line=15, column=20, offset=200)
        span = Span(start=start, end=end)
        location = Location(span=span)

        error = ParseError("multiline error", location=location)
        error_str = str(error)

        # Should show span across lines
        assert "10:5" in error_str or "15:20" in error_str


class TestValidationError:
    """Test ValidationError exception."""

    def test_is_surinort_error(self):
        """Test that ValidationError inherits from SurinortASTError."""
        error = ValidationError("validation failed")
        assert isinstance(error, SurinortASTError)
        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that ValidationError can be raised and caught."""
        try:
            raise ValidationError("Invalid AST node")
        except ValidationError as e:
            assert "Invalid AST node" in str(e)

    def test_message_preserved(self):
        """Test that validation error message is preserved."""
        message = "Field 'sid' is required"
        error = ValidationError(message)
        assert str(error) == message

    def test_caught_as_base_error(self):
        """Test that ValidationError can be caught as SurinortASTError."""
        try:
            raise ValidationError("validation issue")
        except SurinortASTError as e:
            assert isinstance(e, ValidationError)


class TestSerializationError:
    """Test SerializationError exception."""

    def test_is_surinort_error(self):
        """Test that SerializationError inherits from SurinortASTError."""
        error = SerializationError("serialization failed")
        assert isinstance(error, SurinortASTError)
        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that SerializationError can be raised and caught."""
        try:
            raise SerializationError("Failed to serialize AST")
        except SerializationError as e:
            assert "Failed to serialize AST" in str(e)

    def test_message_preserved(self):
        """Test that serialization error message is preserved."""
        message = "JSON encoding failed"
        error = SerializationError(message)
        assert str(error) == message

    def test_caught_as_base_error(self):
        """Test that SerializationError can be caught as SurinortASTError."""
        try:
            raise SerializationError("serialization issue")
        except SurinortASTError as e:
            assert isinstance(e, SerializationError)


class TestUnsupportedDialectError:
    """Test UnsupportedDialectError exception."""

    def test_is_surinort_error(self):
        """Test that UnsupportedDialectError inherits from SurinortASTError."""
        error = UnsupportedDialectError("unsupported dialect")
        assert isinstance(error, SurinortASTError)
        assert isinstance(error, Exception)

    def test_can_be_raised(self):
        """Test that UnsupportedDialectError can be raised and caught."""
        try:
            raise UnsupportedDialectError("Snort 4 not supported")
        except UnsupportedDialectError as e:
            assert "Snort 4 not supported" in str(e)

    def test_message_preserved(self):
        """Test that dialect error message is preserved."""
        message = "Feature 'xbits' not supported in Suricata"
        error = UnsupportedDialectError(message)
        assert str(error) == message

    def test_caught_as_base_error(self):
        """Test that UnsupportedDialectError can be caught as SurinortASTError."""
        try:
            raise UnsupportedDialectError("dialect issue")
        except SurinortASTError as e:
            assert isinstance(e, UnsupportedDialectError)


class TestExceptionHierarchy:
    """Test exception hierarchy and inheritance."""

    def test_all_inherit_from_base(self):
        """Test that all exceptions inherit from SurinortASTError."""
        errors = [
            ParseError("test"),
            ValidationError("test"),
            SerializationError("test"),
            UnsupportedDialectError("test"),
        ]

        for error in errors:
            assert isinstance(error, SurinortASTError)
            assert isinstance(error, Exception)

    def test_base_error_catches_all(self):
        """Test that SurinortASTError can catch all specific errors."""
        error_types = [
            ParseError,
            ValidationError,
            SerializationError,
            UnsupportedDialectError,
        ]

        for error_type in error_types:
            try:
                raise error_type("test error")
            except SurinortASTError as e:
                assert isinstance(e, error_type)

    def test_specific_catch_order(self):
        """Test that specific exceptions are caught before base."""
        caught_type = None

        try:
            raise ParseError("test")
        except ParseError:
            caught_type = "parse"
        except SurinortASTError:
            caught_type = "base"

        assert caught_type == "parse"

    def test_exception_catch_prevents_base(self):
        """Test that catching Exception catches all surinort errors."""
        error_types = [
            SurinortASTError,
            ParseError,
            ValidationError,
            SerializationError,
            UnsupportedDialectError,
        ]

        for error_type in error_types:
            try:
                raise error_type("test")
            except Exception as e:
                assert isinstance(e, SurinortASTError)


class TestExceptionUsage:
    """Test realistic exception usage patterns."""

    def test_parse_error_in_parser_context(self):
        """Test ParseError as it would be used in parser."""

        def fake_parse(text):
            if "invalid" in text:
                pos = Position(
                    line=1, column=text.index("invalid") + 1, offset=text.index("invalid")
                )
                span = Span(
                    start=pos, end=Position(line=1, column=pos.column + 7, offset=pos.offset + 7)
                )
                raise ParseError("Invalid keyword", location=Location(span=span))
            return "parsed"

        # Valid text
        result = fake_parse("valid text")
        assert result == "parsed"

        # Invalid text
        try:
            fake_parse("invalid text")
            raise AssertionError("Should have raised ParseError")
        except ParseError as e:
            assert "Invalid keyword" in str(e)
            assert e.location is not None

    def test_validation_error_in_validator_context(self):
        """Test ValidationError as it would be used in validation."""

        def validate_sid(sid):
            if sid is None:
                raise ValidationError("SID is required")
            if not isinstance(sid, int):
                raise ValidationError("SID must be an integer")
            if sid <= 0:
                raise ValidationError("SID must be positive")
            return True

        # Valid SID
        assert validate_sid(1000001) is True

        # Invalid SIDs
        for invalid_sid, expected_msg in [
            (None, "required"),
            ("123", "integer"),
            (-5, "positive"),
        ]:
            try:
                validate_sid(invalid_sid)
                raise AssertionError(f"Should have raised ValidationError for {invalid_sid}")
            except ValidationError as e:
                assert expected_msg in str(e)

    def test_serialization_error_in_serializer_context(self):
        """Test SerializationError as it would be used in serializer."""

        def serialize(obj):
            if not hasattr(obj, "to_dict"):
                raise SerializationError(f"Object {type(obj).__name__} is not serializable")
            return obj.to_dict()

        class Serializable:
            def to_dict(self):
                return {"data": "value"}

        class NotSerializable:
            pass

        # Valid object
        result = serialize(Serializable())
        assert result == {"data": "value"}

        # Invalid object
        try:
            serialize(NotSerializable())
            raise AssertionError("Should have raised SerializationError")
        except SerializationError as e:
            assert "not serializable" in str(e)

    def test_dialect_error_in_feature_check_context(self):
        """Test UnsupportedDialectError in dialect checking."""

        def check_feature_support(feature, dialect):
            unsupported = {
                "suricata": ["detection_filter", "threshold"],
                "snort": ["app-layer-event", "krb5"],
            }

            if feature in unsupported.get(dialect, []):
                raise UnsupportedDialectError(f"Feature '{feature}' is not supported in {dialect}")
            return True

        # Supported features
        assert check_feature_support("content", "suricata") is True
        assert check_feature_support("pcre", "snort") is True

        # Unsupported features
        try:
            check_feature_support("detection_filter", "suricata")
            raise AssertionError("Should have raised UnsupportedDialectError")
        except UnsupportedDialectError as e:
            assert "detection_filter" in str(e)
            assert "suricata" in str(e)


class TestExceptionAttributes:
    """Test exception attributes and properties."""

    def test_parse_error_has_message_attribute(self):
        """Test that ParseError exposes message attribute."""
        error = ParseError("test message")
        assert hasattr(error, "message")
        assert error.message == "test message"

    def test_parse_error_has_location_attribute(self):
        """Test that ParseError exposes location attribute."""
        error = ParseError("test")
        assert hasattr(error, "location")
        assert error.location is None

        location = Location(
            span=Span(
                start=Position(line=1, column=1, offset=0), end=Position(line=1, column=5, offset=4)
            )
        )
        error_with_loc = ParseError("test", location=location)
        assert error_with_loc.location is location

    def test_other_errors_standard_attributes(self):
        """Test that other errors have standard Exception attributes."""
        errors = [
            ValidationError("test"),
            SerializationError("test"),
            UnsupportedDialectError("test"),
        ]

        for error in errors:
            # Should have args attribute
            assert hasattr(error, "args")
            assert len(error.args) > 0
