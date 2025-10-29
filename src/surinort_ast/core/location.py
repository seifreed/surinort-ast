"""
Source location and span tracking for AST nodes.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""


from pydantic import BaseModel, Field


class Position(BaseModel):
    """
    Position in source file.

    Attributes:
        line: Line number (1-indexed)
        column: Column number (1-indexed)
        offset: Byte offset from start of file (0-indexed)
    """

    line: int = Field(ge=1, description="Line number (1-indexed)")
    column: int = Field(ge=1, description="Column number (1-indexed)")
    offset: int = Field(ge=0, description="Byte offset (0-indexed)")

    def __str__(self) -> str:
        """Format: line:column"""
        return f"{self.line}:{self.column}"

    def __repr__(self) -> str:
        return f"Position(line={self.line}, column={self.column}, offset={self.offset})"


class Span(BaseModel):
    """
    Source code span from start to end position.

    Attributes:
        start: Start position (inclusive)
        end: End position (exclusive)
    """

    start: Position
    end: Position

    def __str__(self) -> str:
        """Format: start-end"""
        if self.start.line == self.end.line:
            return f"{self.start.line}:{self.start.column}-{self.end.column}"
        return f"{self.start.line}:{self.start.column}-{self.end.line}:{self.end.column}"

    def __repr__(self) -> str:
        return f"Span({self.start!r}, {self.end!r})"

    @property
    def length(self) -> int:
        """Get span length in bytes."""
        return self.end.offset - self.start.offset


class Location(BaseModel):
    """
    Full location with file context.

    Attributes:
        span: Source span
        file_path: Optional file path
    """

    span: Span
    file_path: str | None = None

    def __str__(self) -> str:
        """Format: [file_path:]span"""
        prefix = f"{self.file_path}:" if self.file_path else ""
        return f"{prefix}{self.span}"

    def __repr__(self) -> str:
        return f"Location(span={self.span!r}, file_path={self.file_path!r})"
