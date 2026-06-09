# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for parsing/parser_config.py validation.

Each ParserConfig limit rejects non-positive (or negative) values in
__post_init__, and validate_option_count rejects rules over the configured
option ceiling.
"""

from __future__ import annotations

import pytest

from surinort_ast.parsing.parser_config import ParserConfig


class TestPostInitValidation:
    def test_rejects_non_positive_max_rule_length(self):
        with pytest.raises(ValueError, match="max_rule_length must be positive"):
            ParserConfig(max_rule_length=0)

    def test_rejects_non_positive_max_options(self):
        with pytest.raises(ValueError, match="max_options must be positive"):
            ParserConfig(max_options=0)

    def test_rejects_non_positive_max_nesting_depth(self):
        with pytest.raises(ValueError, match="max_nesting_depth must be positive"):
            ParserConfig(max_nesting_depth=0)

    def test_rejects_negative_timeout(self):
        with pytest.raises(ValueError, match="timeout_seconds must be non-negative"):
            ParserConfig(timeout_seconds=-1.0)

    def test_rejects_non_positive_max_input_size(self):
        with pytest.raises(ValueError, match="max_input_size must be positive"):
            ParserConfig(max_input_size=0)


class TestValidateOptionCount:
    def test_rejects_excessive_option_count(self):
        config = ParserConfig(max_options=10)
        with pytest.raises(ValueError, match="exceeds maximum options"):
            config.validate_option_count(11)

    def test_accepts_count_within_limit(self):
        config = ParserConfig(max_options=10)
        config.validate_option_count(10)  # no raise
