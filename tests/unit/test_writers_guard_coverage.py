# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for the not-opened guards in streaming/writers.py.

The internal _write_header/_write_rule/_write_footer methods and __exit__ all
guard against a missing file handle so they degrade gracefully if invoked
before __enter__ (or after close). These tests exercise those guards directly
on un-opened writers.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.streaming.writers import StreamWriterJSON, StreamWriterText

_RULE = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')


class TestTextWriterGuards:
    def test_exit_without_open_is_noop(self, tmp_path):
        writer = StreamWriterText(tmp_path / "out.rules")

        # No file opened; __exit__ must not raise.
        writer.__exit__(None, None, None)

        assert writer._file is None

    def test_write_rule_without_open_returns(self, tmp_path):
        writer = StreamWriterText(tmp_path / "out.rules")

        # Should return early instead of touching a None file handle.
        writer._write_rule(_RULE)


class TestJsonWriterGuards:
    def test_write_header_without_open_returns(self, tmp_path):
        writer = StreamWriterJSON(tmp_path / "out.json")

        writer._write_header()

    def test_write_rule_without_open_returns(self, tmp_path):
        writer = StreamWriterJSON(tmp_path / "out.json")

        writer._write_rule(_RULE)

    def test_write_footer_without_open_returns(self, tmp_path):
        writer = StreamWriterJSON(tmp_path / "out.json")

        writer._write_footer()
