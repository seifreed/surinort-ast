# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for plugins/loader.py.

Directory loading, plugin discovery, validation, and the convenience
helpers are driven with real plugin source files and real plugin classes.
Entry-point loading is exercised with real ``importlib.metadata.EntryPoint``
objects resolving to real plugin classes; only the *discovery* call
(``entry_points``) is redirected via monkeypatch, since no plugin package is
installed in the test environment. The plugins themselves and their
registration are real — nothing about the loader's behaviour is stubbed.
"""

from __future__ import annotations

import importlib.metadata
from pathlib import Path
from typing import Any

import pytest

from surinort_ast.core.nodes import Rule
from surinort_ast.plugins import (
    AnalysisPlugin,
    PluginRegistry,
)
from surinort_ast.plugins.loader import (
    PluginDiscoveryError,
    PluginLoader,
    PluginLoadError,
    PluginValidationError,
    load_plugins,
)

_GROUP = "surinort_ast.plugins"

pytestmark = pytest.mark.usefixtures("clean_registry")


class GoodAnalyzer(AnalysisPlugin):
    """A valid analysis plugin used as an entry-point target."""

    @property
    def name(self) -> str:
        return "good_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, rule: Rule) -> dict[str, Any]:
        return {"score": 1}

    def register(self, registry: PluginRegistry) -> None:
        registry.register_analyzer(self.name, self)


class NotAPlugin:
    """A class missing the plugin interface (fails validation)."""


def _entry_point(name: str, target: str) -> importlib.metadata.EntryPoint:
    return importlib.metadata.EntryPoint(name=name, value=f"{__name__}:{target}", group=_GROUP)


# ---------------------------------------------------------------------------
# _validate_plugin
# ---------------------------------------------------------------------------


class TestValidatePlugin:
    def test_missing_register(self):
        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginValidationError, match="register"):
            loader._validate_plugin(object())

    def test_missing_name(self):
        class HasRegister:
            def register(self, registry):
                return None

        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginValidationError, match="name"):
            loader._validate_plugin(HasRegister())

    def test_missing_version(self):
        class HasName:
            name = "x"

            def register(self, registry):
                return None

        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginValidationError, match="version"):
            loader._validate_plugin(HasName())

    def test_unsupported_api_version(self):
        class FuturePlugin:
            name = "future"
            version = "1.0.0"
            api_version = "2"

            def register(self, registry):
                return None

        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginValidationError, match="unsupported API version"):
            loader._validate_plugin(FuturePlugin())


# ---------------------------------------------------------------------------
# load_directory
# ---------------------------------------------------------------------------


def _write_plugin(tmp_path: Path, filename: str, body: str) -> Path:
    path = tmp_path / filename
    path.write_text(body, encoding="utf-8")
    return path


class TestLoadDirectory:
    def test_nonexistent_directory_raises(self, tmp_path):
        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginDiscoveryError, match="does not exist"):
            loader.load_directory(tmp_path / "missing")

    def test_path_not_a_directory_raises(self, tmp_path):
        a_file = _write_plugin(tmp_path, "afile.txt", "data")
        loader = PluginLoader(auto_load=False)
        with pytest.raises(PluginDiscoveryError, match="not a directory"):
            loader.load_directory(a_file)

    def test_spec_none_for_non_python_file(self, tmp_path):
        _write_plugin(tmp_path, "thing.txt", "not python")
        loader = PluginLoader(auto_load=False)

        assert loader.load_directory(tmp_path, pattern="*.txt") == 0

    def test_file_without_plugin_classes(self, tmp_path):
        _write_plugin(tmp_path, "empty_plugin.py", "VALUE = 1\n")
        loader = PluginLoader(auto_load=False)

        assert loader.load_directory(tmp_path, pattern="*_plugin.py") == 0

    def test_instantiation_failure_is_skipped(self, tmp_path):
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class Boom(AnalysisPlugin):\n"
            "    def __init__(self):\n"
            "        raise RuntimeError('cannot build')\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'boom'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        registry.register_analyzer(self.name, self)\n"
        )
        _write_plugin(tmp_path, "boom_plugin.py", body)
        loader = PluginLoader(auto_load=False)

        # Instantiation fails, so no plugin is loaded; load returns 0 but the
        # failure is recorded (not silently dropped) so it is observable.
        assert loader.load_directory(tmp_path, pattern="*_plugin.py") == 0
        assert "Boom" in loader.get_failed_plugins()

    def test_instantiation_failure_strict_raises(self, tmp_path):
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class Boom(AnalysisPlugin):\n"
            "    def __init__(self):\n"
            "        raise RuntimeError('cannot build')\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'boom'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        registry.register_analyzer(self.name, self)\n"
        )
        _write_plugin(tmp_path, "boom_plugin.py", body)
        loader = PluginLoader(auto_load=False)

        # With ignore_errors=False an instantiation failure must surface, just
        # like a registration failure, rather than being swallowed.
        with pytest.raises(PluginLoadError):
            loader.load_directory(tmp_path, pattern="*_plugin.py", ignore_errors=False)

        # Recorded exactly once, under the plugin name. Regression: the strict
        # path re-caught the already-recorded PluginLoadError in the outer
        # handler and recorded a second, doubly-wrapped entry under the file name.
        failed = loader.get_failed_plugins()
        assert list(failed) == ["Boom"]
        assert failed["Boom"] == "cannot build"

    def test_register_failure_strict_raises(self, tmp_path):
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class Failing(AnalysisPlugin):\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'failing'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        raise RuntimeError('register exploded')\n"
        )
        _write_plugin(tmp_path, "failing_plugin.py", body)
        loader = PluginLoader(auto_load=False)

        with pytest.raises(PluginLoadError):
            loader.load_directory(tmp_path, pattern="*_plugin.py", ignore_errors=False)

        # Recorded exactly once, under the plugin name (no duplicate file-name entry).
        failed = loader.get_failed_plugins()
        assert list(failed) == ["failing"]

    def test_register_failure_ignored(self, tmp_path):
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class Failing(AnalysisPlugin):\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'failing'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        raise RuntimeError('register exploded')\n"
        )
        _write_plugin(tmp_path, "failing_plugin.py", body)
        loader = PluginLoader(auto_load=False)

        count = loader.load_directory(tmp_path, pattern="*_plugin.py", ignore_errors=True)

        assert count == 0
        assert "failing" in loader.get_failed_plugins()

    def test_import_error_strict_raises(self, tmp_path):
        _write_plugin(tmp_path, "broken_plugin.py", "raise RuntimeError('boom at import')\n")
        loader = PluginLoader(auto_load=False)

        with pytest.raises(PluginLoadError):
            loader.load_directory(tmp_path, pattern="*_plugin.py", ignore_errors=False)

    def test_import_error_ignored(self, tmp_path):
        _write_plugin(tmp_path, "broken_plugin.py", "raise RuntimeError('boom at import')\n")
        loader = PluginLoader(auto_load=False)

        count = loader.load_directory(tmp_path, pattern="*_plugin.py", ignore_errors=True)

        assert count == 0
        assert "broken_plugin.py" in loader.get_failed_plugins()

    def test_successful_load_tracks_plugin(self, tmp_path):
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class WorkingAnalyzer(AnalysisPlugin):\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'working'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        registry.register_analyzer(self.name, self)\n"
        )
        _write_plugin(tmp_path, "working_plugin.py", body)
        loader = PluginLoader(auto_load=False)

        count = loader.load_directory(tmp_path, pattern="*_plugin.py")

        assert count == 1
        assert "working" in loader.get_loaded_plugins()


# ---------------------------------------------------------------------------
# Entry-point loading
# ---------------------------------------------------------------------------


class TestEntryPointLoading:
    def test_loads_valid_and_isolates_invalid(self, monkeypatch):
        eps = [_entry_point("good", "GoodAnalyzer"), _entry_point("bad", "NotAPlugin")]
        monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: eps)
        loader = PluginLoader(auto_load=False)

        count = loader.load_entry_points(group=_GROUP)

        assert count == 1
        assert "good" in loader.get_loaded_plugins()
        assert "bad" in loader.get_failed_plugins()

    def test_strict_mode_raises_discovery_error(self, monkeypatch):
        eps = [_entry_point("bad", "NotAPlugin")]
        monkeypatch.setattr(importlib.metadata, "entry_points", lambda group: eps)
        loader = PluginLoader(auto_load=False)

        with pytest.raises(PluginDiscoveryError):
            loader.load_entry_points(group=_GROUP, ignore_errors=False)

    def test_discovery_failure_is_swallowed_when_ignoring(self, monkeypatch):
        def _boom(group):
            raise RuntimeError("discovery exploded")

        monkeypatch.setattr(importlib.metadata, "entry_points", _boom)
        loader = PluginLoader(auto_load=False)

        assert loader.load_entry_points(group=_GROUP, ignore_errors=True) == 0

    def test_auto_load_failure_is_logged(self):
        class _BoomLoader(PluginLoader):
            def load_entry_points(self, *args: Any, **kwargs: Any) -> int:
                raise RuntimeError("auto load boom")

        # __init__ with auto_load=True must swallow the failure.
        loader = _BoomLoader(auto_load=True)

        assert loader.get_loaded_plugins() == set()


# ---------------------------------------------------------------------------
# load_plugins convenience function
# ---------------------------------------------------------------------------


class TestLoadPluginsHelper:
    def test_directories_and_entry_points(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            importlib.metadata,
            "entry_points",
            lambda group: [_entry_point("good", "GoodAnalyzer")],
        )
        body = (
            "from surinort_ast.plugins import AnalysisPlugin\n"
            "class DirAnalyzer(AnalysisPlugin):\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 'dir_analyzer'\n"
            "    @property\n"
            "    def version(self):\n"
            "        return '1.0.0'\n"
            "    def analyze(self, rule):\n"
            "        return {}\n"
            "    def register(self, registry):\n"
            "        registry.register_analyzer(self.name, self)\n"
        )
        _write_plugin(tmp_path, "dir_plugin.py", body)

        summary = load_plugins(entry_points=True, directories=[tmp_path])

        assert summary["loaded"] >= 2
        # Entry-point plugins are tracked by their entry-point name.
        assert "good" in summary["loaded_plugins"]
        assert "dir_analyzer" in summary["loaded_plugins"]

    def test_no_sources_returns_empty_summary(self):
        summary = load_plugins(entry_points=False, directories=None)

        assert summary == {
            "loaded": 0,
            "failed": 0,
            "loaded_plugins": [],
            "failed_plugins": {},
        }
