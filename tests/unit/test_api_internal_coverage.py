# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for api/_internal.py.

Covers the grammar-cache module-override sync and clear, the path-resolution
failure branches of _validate_file_path, and the batch worker's no-raw-text
path. The resolution failures are forced by redirecting Path.resolve; the
grammar-cache state is restored afterwards.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import surinort_ast.api._internal as internal
from surinort_ast.api._internal import _GrammarCache, _parse_batch_worker, _validate_file_path
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError


class TestGrammarCache:
    def test_module_override_syncs_into_cache(self):
        try:
            internal._GRAMMAR_CACHE = "CUSTOM GRAMMAR"
            _GrammarCache._cache = None

            assert _GrammarCache.get() == "CUSTOM GRAMMAR"
        finally:
            _GrammarCache.clear()

    def test_clear_resets_cache(self):
        _GrammarCache.get()  # populate
        _GrammarCache.clear()

        assert _GrammarCache._cache is None
        assert internal._GRAMMAR_CACHE is None


class TestValidateFilePath:
    def test_unresolvable_path_raises(self, tmp_path, monkeypatch):
        target = tmp_path / "f.rules"
        target.write_text("x", encoding="utf-8")

        def boom(self, *args, **kwargs):
            raise OSError("cannot resolve")

        monkeypatch.setattr(Path, "resolve", boom)

        with pytest.raises(ParseError, match="Invalid path"):
            _validate_file_path(target)

    def test_unresolvable_allowed_base_raises(self, tmp_path, monkeypatch):
        target = tmp_path / "f.rules"
        target.write_text("x", encoding="utf-8")
        base = tmp_path / "base"
        base.mkdir()

        real_resolve = Path.resolve

        def fake_resolve(self, *args, **kwargs):
            if self == base:
                raise OSError("cannot resolve base")
            return real_resolve(self, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", fake_resolve)

        with pytest.raises(ParseError, match="Invalid base directory"):
            _validate_file_path(target, allowed_base=base)


class TestBatchWorker:
    def test_worker_without_raw_text(self):
        args = (
            [(1, 'alert tcp any any -> any 80 (msg:"x"; sid:1;)')],
            Dialect.SURICATA,
            True,
            "file.rules",
            False,  # include_raw_text
        )

        results = _parse_batch_worker(args)

        assert len(results) == 1
        _line_num, rule, error = results[0]
        assert error is None
        assert rule is not None
        assert rule.raw_text is None  # raw_text omitted when include_raw_text=False
