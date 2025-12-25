"""
Exceptions for surinort-ast.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .core.location import Location


class SurinortASTError(Exception):
    """Base exception for surinort-ast."""


class ParseError(SurinortASTError):
    """
    Parse error exception.

    Raised when rule parsing fails unrecoverably.

    Attributes:
        message: Error message
        location: Optional source location
    """

    def __init__(
        self,
        message: str,
        location: Location | None = None,
    ):
        self.message = message
        self.location = location
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format error message with location if available."""
        if self.location:
            return f"{self.location}: {self.message}"
        return self.message


class ValidationError(SurinortASTError):
    """
    Validation error exception.

    Raised when AST node validation fails.
    """


class SerializationError(SurinortASTError):
    """
    Serialization error exception.

    Raised when serialization/deserialization fails.
    """


class UnsupportedDialectError(SurinortASTError):
    """
    Unsupported dialect exception.

    Raised when encountering dialect-specific features that aren't supported.
    """
