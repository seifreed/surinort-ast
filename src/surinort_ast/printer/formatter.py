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
        COMPACT: Minimal whitespace, single line where possible
        STANDARD: Balanced readability and compactness
        VERBOSE: Maximum readability with extra spacing
        STABLE: Canonical format for deterministic output
    """

    COMPACT = "compact"
    STANDARD = "standard"
    VERBOSE = "verbose"
    STABLE = "stable"


class FormatterOptions(BaseModel):
    """
    Configuration options for rule text formatting.

    Attributes:
        indent: Indentation string (default: 4 spaces)
        line_width: Maximum line width before wrapping (0 = no limit)
        preserve_comments: Whether to include comments in output
        space_after_commas: Add space after commas in lists
        space_around_operators: Add spaces around operators (=, <>, etc.)
        normalize_whitespace: Normalize whitespace to single spaces
        sort_options: Sort options alphabetically (breaks semantics, use carefully)
        stable_mode: Enable deterministic output (overrides other settings)
        quote_style: Quote style for strings ('single' or 'double')
        hex_uppercase: Use uppercase for hex bytes (e.g., |41| vs |41|)
        option_separator: Separator between options (default: space)
    """

    # Basic formatting
    indent: str = Field(default="    ", description="Indentation string")
    line_width: int = Field(default=100, ge=0, description="Max line width (0=unlimited)")

    # Whitespace control
    preserve_comments: bool = Field(default=True, description="Include comments in output")
    space_after_commas: bool = Field(default=True, description="Space after commas in lists")
    space_around_operators: bool = Field(
        default=True, description="Spaces around operators (=, <>, etc.)"
    )
    normalize_whitespace: bool = Field(
        default=True, description="Normalize whitespace to single spaces"
    )

    # Option ordering
    sort_options: bool = Field(
        default=False, description="Sort options alphabetically (may break semantics)"
    )

    # Output mode
    stable_mode: bool = Field(default=False, description="Enable deterministic output")

    # Style preferences
    quote_style: str = Field(default="double", pattern="^(single|double)$")
    hex_uppercase: bool = Field(default=True, description="Uppercase hex bytes")
    option_separator: str = Field(default=" ", description="Separator between options")

    @classmethod
    def compact(cls) -> FormatterOptions:
        """
        Create compact formatting style.

        Minimizes whitespace and line width for dense output.
        """
        return cls(
            indent="",
            line_width=0,
            space_after_commas=False,
            space_around_operators=False,
            normalize_whitespace=True,
            preserve_comments=False,
            stable_mode=False,
            option_separator="",
        )

    @classmethod
    def standard(cls) -> FormatterOptions:
        """
        Create standard formatting style.

        Balanced readability and compactness (default style).
        """
        return cls(
            indent="    ",
            line_width=100,
            space_after_commas=True,
            space_around_operators=True,
            normalize_whitespace=True,
            preserve_comments=True,
            stable_mode=False,
        )

    @classmethod
    def verbose(cls) -> FormatterOptions:
        """
        Create verbose formatting style.

        Maximizes readability with extra spacing and longer lines.
        """
        return cls(
            indent="    ",
            line_width=120,
            space_after_commas=True,
            space_around_operators=True,
            normalize_whitespace=True,
            preserve_comments=True,
            stable_mode=False,
            option_separator=" ",
        )

    @classmethod
    def stable(cls) -> FormatterOptions:
        """
        Create stable formatting style.

        Canonical, deterministic output for reproducible formatting.
        Ensures same input always produces same output.
        """
        return cls(
            indent="    ",
            line_width=100,
            space_after_commas=True,
            space_around_operators=True,
            normalize_whitespace=True,
            preserve_comments=True,
            sort_options=False,  # Don't sort to preserve semantic order
            stable_mode=True,
            quote_style="double",
            hex_uppercase=True,
            option_separator=" ",
        )

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
        if style == FormatStyle.STANDARD:
            return cls.standard()
        if style == FormatStyle.VERBOSE:
            return cls.verbose()
        # style == FormatStyle.STABLE
        return cls.stable()

    def get_quote_char(self) -> str:
        """
        Get the quote character based on quote_style.

        Returns:
            Quote character (single or double)
        """
        return '"' if self.quote_style == "double" else "'"

    def format_list_separator(self) -> str:
        """
        Get the list separator with optional spacing.

        Returns:
            Comma with optional space
        """
        return ", " if self.space_after_commas else ","

    def format_operator(self, operator: str) -> str:
        """
        Format an operator with optional spacing.

        Args:
            operator: The operator to format

        Returns:
            Formatted operator with optional surrounding spaces
        """
        if self.space_around_operators:
            return f" {operator} "
        return operator
