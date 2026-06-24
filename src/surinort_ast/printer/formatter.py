"""
Formatting options and styles for text printer.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class FormatStyle(str, Enum):
    """
    Predefined formatting styles.

    Attributes:
        COMPACT: Minimal whitespace for dense output
        STANDARD: Balanced, readable output (the default)
    """

    COMPACT = "compact"
    STANDARD = "standard"


class FormatterOptions(BaseModel):
    """
    Configuration options for rule text formatting.

    Attributes:
        preserve_comments: Whether to include comments in output
        space_after_commas: Add space after commas in lists
        hex_uppercase: Use uppercase for hex bytes (e.g., |41| vs |41|)
        option_separator: Separator between options (default: space)
    """

    preserve_comments: bool = Field(default=True, description="Include comments in output")
    space_after_commas: bool = Field(default=True, description="Space after commas in lists")
    hex_uppercase: bool = Field(default=True, description="Uppercase hex bytes")
    option_separator: str = Field(default=" ", description="Separator between options")

    @classmethod
    def compact(cls) -> FormatterOptions:
        """
        Create compact formatting style.

        Minimizes whitespace for dense output.
        """
        return cls(space_after_commas=False, preserve_comments=False, option_separator="")

    @classmethod
    def standard(cls) -> FormatterOptions:
        """
        Create standard formatting style (the default).

        Balanced, readable output. The printer builds rules directly from the
        AST, so this output is already deterministic and reproducible.
        """
        return cls()

    @classmethod
    def from_style(cls, style: FormatStyle) -> FormatterOptions:
        """
        Create formatter options from a predefined style.

        Args:
            style: The predefined style to use

        Returns:
            FormatterOptions configured for the given style
        """
        if style == FormatStyle.COMPACT:
            return cls.compact()
        return cls.standard()

    def format_list_separator(self) -> str:
        """
        Get the list separator with optional spacing.

        Returns:
            Comma with optional space
        """
        return ", " if self.space_after_commas else ","
