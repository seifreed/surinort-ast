# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for formatter options and styles.

Tests formatting configuration, style presets, and helper methods.
NO MOCKS - all tests use real FormatterOptions instances.
"""

from surinort_ast.printer.formatter import FormatStyle, FormatterOptions


class TestFormatStyle:
    """Test the FormatStyle enum."""

    def test_styles_defined(self):
        assert FormatStyle.COMPACT.value == "compact"
        assert FormatStyle.STANDARD.value == "standard"

    def test_style_is_string_enum(self):
        assert isinstance(FormatStyle.COMPACT, str)

    def test_members_distinct(self):
        values = [s.value for s in FormatStyle]
        assert len(values) == len(set(values))


class TestFormatterOptionsInit:
    """Test FormatterOptions construction and defaults."""

    def test_default_initialization(self):
        opts = FormatterOptions()
        assert opts.preserve_comments is True
        assert opts.space_after_commas is True
        assert opts.hex_uppercase is True
        assert opts.option_separator == " "

    def test_custom_initialization(self):
        opts = FormatterOptions(
            preserve_comments=False,
            space_after_commas=False,
            hex_uppercase=False,
            option_separator="; ",
        )
        assert opts.preserve_comments is False
        assert opts.space_after_commas is False
        assert opts.hex_uppercase is False
        assert opts.option_separator == "; "

    def test_partial_initialization(self):
        opts = FormatterOptions(hex_uppercase=False)
        assert opts.hex_uppercase is False
        # Defaults preserved for the rest.
        assert opts.preserve_comments is True
        assert opts.option_separator == " "


class TestCompactStyle:
    """Test FormatterOptions.compact()."""

    def test_compact_settings(self):
        opts = FormatterOptions.compact()
        assert opts.space_after_commas is False
        assert opts.preserve_comments is False
        assert opts.option_separator == ""

    def test_compact_list_separator_has_no_space(self):
        assert FormatterOptions.compact().format_list_separator() == ","


class TestStandardStyle:
    """Test FormatterOptions.standard()."""

    def test_standard_settings(self):
        opts = FormatterOptions.standard()
        assert opts.space_after_commas is True
        assert opts.preserve_comments is True
        assert opts.option_separator == " "

    def test_standard_equals_default(self):
        assert FormatterOptions.standard() == FormatterOptions()

    def test_standard_list_separator_has_space(self):
        assert FormatterOptions.standard().format_list_separator() == ", "


class TestFromStyle:
    """Test FormatterOptions.from_style()."""

    def test_from_style_compact(self):
        assert FormatterOptions.from_style(FormatStyle.COMPACT) == FormatterOptions.compact()

    def test_from_style_standard(self):
        assert FormatterOptions.from_style(FormatStyle.STANDARD) == FormatterOptions.standard()

    def test_from_style_all_members(self):
        for style in FormatStyle:
            assert isinstance(FormatterOptions.from_style(style), FormatterOptions)


class TestFormatListSeparator:
    """Test the format_list_separator helper."""

    def test_with_space(self):
        assert FormatterOptions(space_after_commas=True).format_list_separator() == ", "

    def test_without_space(self):
        assert FormatterOptions(space_after_commas=False).format_list_separator() == ","


class TestSerialization:
    """Test FormatterOptions serialization round-trips."""

    def test_model_validate(self):
        data = {"hex_uppercase": False, "option_separator": "; "}
        opts = FormatterOptions.model_validate(data)
        assert opts.hex_uppercase is False
        assert opts.option_separator == "; "

    def test_round_trip(self):
        opts = FormatterOptions(preserve_comments=False, option_separator="")
        assert FormatterOptions.model_validate(opts.model_dump()) == opts
