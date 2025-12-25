"""
Error and diagnostic reporting for parser.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from collections.abc import Iterator
from dataclasses import dataclass, field

from pydantic import BaseModel

from .enums import DiagnosticLevel
from .location import Location


class Diagnostic(BaseModel):
    """
    A diagnostic message (error, warning, or info).

    Attributes:
        level: Severity level
        message: Human-readable message
        location: Optional source location
        code: Optional error code (e.g., E001, W003)
        hint: Optional suggestion for fixing
    """

    level: DiagnosticLevel
    message: str
    location: Location | None = None
    code: str | None = None
    hint: str | None = None

    def __str__(self) -> str:
        """Format: [level] message (at location)"""
        parts = [f"[{self.level.value.upper()}]"]

        if self.code:
            parts.append(f"[{self.code}]")

        parts.append(self.message)

        if self.location:
            parts.append(f"at {self.location}")

        result = " ".join(parts)

        if self.hint:
            result += f"\n  hint: {self.hint}"

        return result

    def __repr__(self) -> str:
        return (
            f"Diagnostic(level={self.level!r}, message={self.message!r}, "
            f"location={self.location!r}, code={self.code!r})"
        )


@dataclass
class DiagnosticList:
    """
    Collection of diagnostics with helper methods.

    Attributes:
        diagnostics: List of diagnostic messages
    """

    diagnostics: list[Diagnostic] = field(default_factory=list)

    def add(
        self,
        level: DiagnosticLevel,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Add a diagnostic message."""
        diag = Diagnostic(
            level=level,
            message=message,
            location=location,
            code=code,
            hint=hint,
        )
        self.diagnostics.append(diag)

    def error(
        self,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Add an error diagnostic."""
        self.add(DiagnosticLevel.ERROR, message, location, code, hint)

    def warning(
        self,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Add a warning diagnostic."""
        self.add(DiagnosticLevel.WARNING, message, location, code, hint)

    def info(
        self,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Add an info diagnostic."""
        self.add(DiagnosticLevel.INFO, message, location, code, hint)

    def has_errors(self) -> bool:
        """Check if any errors exist."""
        return any(d.level == DiagnosticLevel.ERROR for d in self.diagnostics)

    def has_warnings(self) -> bool:
        """Check if any warnings exist."""
        return any(d.level == DiagnosticLevel.WARNING for d in self.diagnostics)

    @property
    def error_count(self) -> int:
        """Get number of errors."""
        return sum(1 for d in self.diagnostics if d.level == DiagnosticLevel.ERROR)

    @property
    def warning_count(self) -> int:
        """Get number of warnings."""
        return sum(1 for d in self.diagnostics if d.level == DiagnosticLevel.WARNING)

    def __len__(self) -> int:
        return len(self.diagnostics)

    def __iter__(self) -> Iterator[Diagnostic]:
        """
        Iterate over diagnostics.

        Allows natural iteration: `for diag in diagnostics:`

        Returns:
            Iterator over Diagnostic objects
        """
        return iter(self.diagnostics)

    def __bool__(self) -> bool:
        return len(self.diagnostics) > 0


__all__ = ["Diagnostic", "DiagnosticLevel", "DiagnosticList"]
