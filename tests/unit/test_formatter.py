# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for formatter options and styles.

Tests formatting configuration, style presets, and helper methods.
NO MOCKS - all tests use real FormatterOptions instances.
"""

from pydantic import ValidationError as PydanticValidationError

from surinort_ast.printer.formatter import FormatStyle, FormatterOptions


class TestFormatStyle:
    """Test FormatStyle enum."""

    def test_all_styles_defined(self):
        """Test that all expected styles are defined."""
        expected_styles = {"COMPACT", "STANDARD", "VERBOSE", "STABLE"}
        actual_styles = {style.name for style in FormatStyle}

        assert expected_styles == actual_styles

    def test_style_values(self):
        """Test that style enum values are lowercase strings."""
        assert FormatStyle.COMPACT.value == "compact"
        assert FormatStyle.STANDARD.value == "standard"
        assert FormatStyle.VERBOSE.value == "verbose"
        assert FormatStyle.STABLE.value == "stable"

    def test_style_is_string_enum(self):
        """Test that FormatStyle values are strings."""
        for style in FormatStyle:
            assert isinstance(style.value, str)

    def test_style_comparison(self):
        """Test enum comparison."""
        assert FormatStyle.COMPACT == FormatStyle.COMPACT
        assert FormatStyle.COMPACT != FormatStyle.STANDARD

    def test_style_membership(self):
        """Test that values are in enum."""
        assert FormatStyle.COMPACT in FormatStyle
        assert FormatStyle.STANDARD in FormatStyle


class TestFormatterOptionsInit:
    """Test FormatterOptions initialization."""

    def test_default_initialization(self):
        """Test FormatterOptions with default values."""
        opts = FormatterOptions()

        # Basic formatting
        assert opts.indent == "    "
        assert opts.line_width == 100

        # Whitespace control
        assert opts.preserve_comments is True
        assert opts.space_after_commas is True
        assert opts.space_around_operators is True
        assert opts.normalize_whitespace is True

        # Option ordering
        assert opts.sort_options is False

        # Output mode
        assert opts.stable_mode is False

        # Style preferences
        assert opts.quote_style == "double"
        assert opts.hex_uppercase is True
        assert opts.option_separator == " "

    def test_custom_initialization(self):
        """Test FormatterOptions with custom values."""
        opts = FormatterOptions(
            indent="  ",
            line_width=80,
            preserve_comments=False,
            space_after_commas=False,
            space_around_operators=False,
            normalize_whitespace=False,
            sort_options=True,
            stable_mode=True,
            quote_style="single",
            hex_uppercase=False,
            option_separator="; ",
        )

        assert opts.indent == "  "
        assert opts.line_width == 80
        assert opts.preserve_comments is False
        assert opts.space_after_commas is False
        assert opts.space_around_operators is False
        assert opts.normalize_whitespace is False
        assert opts.sort_options is True
        assert opts.stable_mode is True
        assert opts.quote_style == "single"
        assert opts.hex_uppercase is False
        assert opts.option_separator == "; "

    def test_partial_initialization(self):
        """Test FormatterOptions with some custom values."""
        opts = FormatterOptions(indent="\t", line_width=120)

        # Custom values
        assert opts.indent == "\t"
        assert opts.line_width == 120

        # Defaults for others
        assert opts.preserve_comments is True
        assert opts.space_after_commas is True


class TestFormatterOptionsValidation:
    """Test FormatterOptions validation."""

    def test_invalid_quote_style(self):
        """Test that invalid quote_style is rejected."""
        try:
            FormatterOptions(quote_style="triple")
            raise AssertionError("Should have raised validation error")
        except PydanticValidationError:
            pass  # Expected

    def test_valid_quote_styles(self):
        """Test that valid quote styles are accepted."""
        single = FormatterOptions(quote_style="single")
        assert single.quote_style == "single"

        double = FormatterOptions(quote_style="double")
        assert double.quote_style == "double"

    def test_negative_line_width_rejected(self):
        """Test that negative line_width is rejected."""
        try:
            FormatterOptions(line_width=-1)
            raise AssertionError("Should have raised validation error")
        except PydanticValidationError:
            pass  # Expected

    def test_zero_line_width_allowed(self):
        """Test that zero line_width (unlimited) is allowed."""
        opts = FormatterOptions(line_width=0)
        assert opts.line_width == 0


class TestCompactStyle:
    """Test compact formatting style."""

    def test_compact_method(self):
        """Test FormatterOptions.compact() class method."""
        opts = FormatterOptions.compact()

        assert opts.indent == ""
        assert opts.line_width == 0
        assert opts.space_after_commas is False
        assert opts.space_around_operators is False
        assert opts.normalize_whitespace is True
        assert opts.preserve_comments is False
        assert opts.stable_mode is False
        assert opts.option_separator == ""

    def test_compact_produces_minimal_whitespace(self):
        """Test that compact style minimizes whitespace."""
        opts = FormatterOptions.compact()

        # No indentation
        assert opts.indent == ""

        # No spacing
        assert opts.space_after_commas is False
        assert opts.space_around_operators is False
        assert opts.option_separator == ""

        # No line width limit
        assert opts.line_width == 0


class TestStandardStyle:
    """Test standard formatting style."""

    def test_standard_method(self):
        """Test FormatterOptions.standard() class method."""
        opts = FormatterOptions.standard()

        assert opts.indent == "    "
        assert opts.line_width == 100
        assert opts.space_after_commas is True
        assert opts.space_around_operators is True
        assert opts.normalize_whitespace is True
        assert opts.preserve_comments is True
        assert opts.stable_mode is False

    def test_standard_is_default(self):
        """Test that standard style matches default initialization."""
        standard = FormatterOptions.standard()
        default = FormatterOptions()

        # Key properties should match
        assert standard.indent == default.indent
        assert standard.line_width == default.line_width
        assert standard.space_after_commas == default.space_after_commas
        assert standard.space_around_operators == default.space_around_operators


class TestVerboseStyle:
    """Test verbose formatting style."""

    def test_verbose_method(self):
        """Test FormatterOptions.verbose() class method."""
        opts = FormatterOptions.verbose()

        assert opts.indent == "    "
        assert opts.line_width == 120
        assert opts.space_after_commas is True
        assert opts.space_around_operators is True
        assert opts.normalize_whitespace is True
        assert opts.preserve_comments is True
        assert opts.stable_mode is False
        assert opts.option_separator == " "

    def test_verbose_wider_lines(self):
        """Test that verbose style has wider line width."""
        verbose = FormatterOptions.verbose()
        standard = FormatterOptions.standard()

        assert verbose.line_width > standard.line_width


class TestStableStyle:
    """Test stable formatting style."""

    def test_stable_method(self):
        """Test FormatterOptions.stable() class method."""
        opts = FormatterOptions.stable()

        assert opts.indent == "    "
        assert opts.line_width == 100
        assert opts.space_after_commas is True
        assert opts.space_around_operators is True
        assert opts.normalize_whitespace is True
        assert opts.preserve_comments is True
        assert opts.sort_options is False
        assert opts.stable_mode is True
        assert opts.quote_style == "double"
        assert opts.hex_uppercase is True
        assert opts.option_separator == " "

    def test_stable_mode_enabled(self):
        """Test that stable style has stable_mode enabled."""
        opts = FormatterOptions.stable()
        assert opts.stable_mode is True

    def test_stable_deterministic_settings(self):
        """Test that stable style uses deterministic settings."""
        opts = FormatterOptions.stable()

        # Fixed quote style
        assert opts.quote_style == "double"

        # Fixed hex case
        assert opts.hex_uppercase is True

        # Preserves semantic order (no sorting)
        assert opts.sort_options is False


class TestFromStyle:
    """Test from_style class method."""

    def test_from_style_compact(self):
        """Test creating options from COMPACT style."""
        opts = FormatterOptions.from_style(FormatStyle.COMPACT)
        expected = FormatterOptions.compact()

        assert opts.indent == expected.indent
        assert opts.line_width == expected.line_width
        assert opts.space_after_commas == expected.space_after_commas

    def test_from_style_standard(self):
        """Test creating options from STANDARD style."""
        opts = FormatterOptions.from_style(FormatStyle.STANDARD)
        expected = FormatterOptions.standard()

        assert opts.indent == expected.indent
        assert opts.line_width == expected.line_width
        assert opts.preserve_comments == expected.preserve_comments

    def test_from_style_verbose(self):
        """Test creating options from VERBOSE style."""
        opts = FormatterOptions.from_style(FormatStyle.VERBOSE)
        expected = FormatterOptions.verbose()

        assert opts.indent == expected.indent
        assert opts.line_width == expected.line_width
        assert opts.space_around_operators == expected.space_around_operators

    def test_from_style_stable(self):
        """Test creating options from STABLE style."""
        opts = FormatterOptions.from_style(FormatStyle.STABLE)
        expected = FormatterOptions.stable()

        assert opts.stable_mode == expected.stable_mode
        assert opts.quote_style == expected.quote_style
        assert opts.hex_uppercase == expected.hex_uppercase

    def test_from_style_all_styles(self):
        """Test from_style with all enum values."""
        for style in FormatStyle:
            opts = FormatterOptions.from_style(style)
            assert isinstance(opts, FormatterOptions)

    def test_from_style_unknown_defaults_to_standard(self):
        """Test from_style with unknown value defaults to standard."""

        # This tests the default branch in from_style
        # In practice, this shouldn't happen, but we test the fallback
        class UnknownStyle:
            pass

        unknown = UnknownStyle()
        opts = FormatterOptions.from_style(unknown)  # type: ignore
        expected = FormatterOptions.standard()

        # Should return standard style as fallback
        assert opts.indent == expected.indent
        assert opts.line_width == expected.line_width


class TestGetQuoteChar:
    """Test get_quote_char method."""

    def test_double_quote_char(self):
        """Test get_quote_char with double quote style."""
        opts = FormatterOptions(quote_style="double")
        assert opts.get_quote_char() == '"'

    def test_single_quote_char(self):
        """Test get_quote_char with single quote style."""
        opts = FormatterOptions(quote_style="single")
        assert opts.get_quote_char() == "'"

    def test_quote_char_from_styles(self):
        """Test get_quote_char from different style presets."""
        # Stable uses double quotes
        stable = FormatterOptions.stable()
        assert stable.get_quote_char() == '"'

        # Can be customized
        custom = FormatterOptions(quote_style="single")
        assert custom.get_quote_char() == "'"


class TestFormatListSeparator:
    """Test format_list_separator method."""

    def test_separator_with_space(self):
        """Test list separator with space after comma."""
        opts = FormatterOptions(space_after_commas=True)
        assert opts.format_list_separator() == ", "

    def test_separator_without_space(self):
        """Test list separator without space after comma."""
        opts = FormatterOptions(space_after_commas=False)
        assert opts.format_list_separator() == ","

    def test_separator_standard_style(self):
        """Test list separator in standard style."""
        opts = FormatterOptions.standard()
        assert opts.format_list_separator() == ", "

    def test_separator_compact_style(self):
        """Test list separator in compact style."""
        opts = FormatterOptions.compact()
        assert opts.format_list_separator() == ","


class TestFormatOperator:
    """Test format_operator method."""

    def test_operator_with_spaces(self):
        """Test operator formatting with spaces."""
        opts = FormatterOptions(space_around_operators=True)

        assert opts.format_operator("=") == " = "
        assert opts.format_operator("<>") == " <> "
        assert opts.format_operator("!=") == " != "

    def test_operator_without_spaces(self):
        """Test operator formatting without spaces."""
        opts = FormatterOptions(space_around_operators=False)

        assert opts.format_operator("=") == "="
        assert opts.format_operator("<>") == "<>"
        assert opts.format_operator("!=") == "!="

    def test_operator_standard_style(self):
        """Test operator formatting in standard style."""
        opts = FormatterOptions.standard()

        assert opts.format_operator("=") == " = "
        assert " " in opts.format_operator("!=")

    def test_operator_compact_style(self):
        """Test operator formatting in compact style."""
        opts = FormatterOptions.compact()

        assert opts.format_operator("=") == "="
        assert " " not in opts.format_operator("!=")

    def test_operator_various_operators(self):
        """Test formatting various operators."""
        opts_with = FormatterOptions(space_around_operators=True)
        opts_without = FormatterOptions(space_around_operators=False)

        operators = ["=", "!=", "<", ">", "<=", ">=", "<>"]

        for op in operators:
            # With spaces
            formatted_with = opts_with.format_operator(op)
            assert formatted_with.strip() == op
            assert formatted_with.startswith(" ")
            assert formatted_with.endswith(" ")

            # Without spaces
            formatted_without = opts_without.format_operator(op)
            assert formatted_without == op


class TestStyleComparison:
    """Test comparison between different styles."""

    def test_compact_vs_standard(self):
        """Test differences between compact and standard styles."""
        compact = FormatterOptions.compact()
        standard = FormatterOptions.standard()

        # Compact should have less spacing
        assert len(compact.indent) < len(standard.indent)
        assert compact.space_after_commas is False
        assert standard.space_after_commas is True

        # Compact has unlimited line width
        assert compact.line_width == 0
        assert standard.line_width > 0

    def test_standard_vs_verbose(self):
        """Test differences between standard and verbose styles."""
        standard = FormatterOptions.standard()
        verbose = FormatterOptions.verbose()

        # Verbose should have wider lines
        assert verbose.line_width > standard.line_width

        # Both should have similar spacing
        assert standard.space_after_commas == verbose.space_after_commas
        assert standard.space_around_operators == verbose.space_around_operators

    def test_stable_vs_standard(self):
        """Test differences between stable and standard styles."""
        stable = FormatterOptions.stable()
        standard = FormatterOptions.standard()

        # Stable should have stable_mode enabled
        assert stable.stable_mode is True
        assert standard.stable_mode is False

        # Other settings should be similar
        assert stable.indent == standard.indent
        assert stable.line_width == standard.line_width


class TestEdgeCases:
    """Test edge cases and special values."""

    def test_empty_indent(self):
        """Test with empty indent string."""
        opts = FormatterOptions(indent="")
        assert opts.indent == ""

    def test_tab_indent(self):
        """Test with tab indentation."""
        opts = FormatterOptions(indent="\t")
        assert opts.indent == "\t"

    def test_large_line_width(self):
        """Test with very large line width."""
        opts = FormatterOptions(line_width=10000)
        assert opts.line_width == 10000

    def test_custom_separator(self):
        """Test with custom option separator."""
        opts = FormatterOptions(option_separator="; ")
        assert opts.option_separator == "; "

        opts2 = FormatterOptions(option_separator="\n")
        assert opts2.option_separator == "\n"

    def test_all_flags_disabled(self):
        """Test with all boolean flags disabled."""
        opts = FormatterOptions(
            preserve_comments=False,
            space_after_commas=False,
            space_around_operators=False,
            normalize_whitespace=False,
            sort_options=False,
            stable_mode=False,
            hex_uppercase=False,
        )

        assert opts.preserve_comments is False
        assert opts.space_after_commas is False
        assert opts.space_around_operators is False
        assert opts.normalize_whitespace is False
        assert opts.sort_options is False
        assert opts.stable_mode is False
        assert opts.hex_uppercase is False


class TestPydanticFeatures:
    """Test Pydantic model features."""

    def test_is_pydantic_model(self):
        """Test that FormatterOptions is a Pydantic BaseModel."""
        opts = FormatterOptions()
        assert hasattr(opts, "model_dump")
        assert hasattr(opts, "model_validate")

    def test_model_dump(self):
        """Test model_dump serialization."""
        opts = FormatterOptions(indent="  ", line_width=80)
        data = opts.model_dump()

        assert isinstance(data, dict)
        assert data["indent"] == "  "
        assert data["line_width"] == 80

    def test_model_validate(self):
        """Test model validation from dict."""
        data = {"indent": "\t", "line_width": 120, "quote_style": "single"}

        opts = FormatterOptions.model_validate(data)
        assert opts.indent == "\t"
        assert opts.line_width == 120
        assert opts.quote_style == "single"

    def test_field_descriptions(self):
        """Test that fields have descriptions."""
        schema = FormatterOptions.model_json_schema()

        # Should have properties
        assert "properties" in schema

        # Key fields should have descriptions
        if "indent" in schema["properties"]:
            assert "description" in schema["properties"]["indent"]


class TestImmutabilityAndCopying:
    """Test that options can be copied and modified."""

    def test_create_modified_copy(self):
        """Test creating a modified copy of options."""
        original = FormatterOptions.standard()
        modified = FormatterOptions(
            indent=original.indent,
            line_width=original.line_width,
            space_after_commas=False,  # Change this
        )

        # Original unchanged
        assert original.space_after_commas is True

        # Modified has new value
        assert modified.space_after_commas is False

    def test_model_copy_with_changes(self):
        """Test Pydantic model_copy with changes."""
        original = FormatterOptions.standard()
        modified = original.model_copy(update={"line_width": 80})

        # Original unchanged
        assert original.line_width == 100

        # Modified has new value
        assert modified.line_width == 80
