# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for the ``plugins`` CLI command group (list/info/load/analyze).

Commands are driven through the real Typer app with real plugin classes
registered in the process-global registry. The broad ``except`` handlers are
exercised by registering plugins or redirecting a discovery import so the
guarded failure actually occurs; nothing about the commands' behaviour is
stubbed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import surinort_ast.plugins as plugins_pkg
from surinort_ast import parse_rule
from surinort_ast.cli.main import app
from surinort_ast.core.nodes import Rule
from surinort_ast.plugins import (
    AnalysisPlugin,
    PluginRegistry,
    SerializerPlugin,
    get_registry,
    reset_registry,
)

runner = CliRunner()

_RULE = 'alert tcp any any -> any 80 (msg:"r"; sid:42; rev:1;)\n'


@pytest.fixture(autouse=True)
def _clean_registry():
    reset_registry()
    yield
    reset_registry()


class DemoSerializer(SerializerPlugin):
    @property
    def name(self) -> str:
        return "demo_serializer"

    @property
    def version(self) -> str:
        return "2.1.0"

    def get_format_name(self) -> str:
        return "demofmt"

    def serialize(self, rule: Rule) -> str:
        return "demo"

    def deserialize(self, data: str | bytes) -> Rule:
        return parse_rule(_RULE.strip())

    def register(self, registry: PluginRegistry) -> None:
        registry.register_serializer(self.get_format_name(), self)


class DemoAnalyzer(AnalysisPlugin):
    @property
    def name(self) -> str:
        return "demo_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, rule: Rule) -> dict[str, Any]:
        return {"score": 42, "issues": [{"severity": "high", "message": "suspicious"}]}

    def register(self, registry: PluginRegistry) -> None:
        registry.register_analyzer(self.name, self)


class ExplodingAnalyzer(AnalysisPlugin):
    @property
    def name(self) -> str:
        return "exploding_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, rule: Rule) -> dict[str, Any]:
        raise RuntimeError("analysis exploded")

    def register(self, registry: PluginRegistry) -> None:
        registry.register_analyzer(self.name, self)


def _rule_file(tmp_path: Path) -> Path:
    path = tmp_path / "rules.rules"
    path.write_text(_RULE, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# plugins list
# ---------------------------------------------------------------------------


class TestListCommand:
    def test_list_with_and_without_plugins(self):
        DemoAnalyzer().register(get_registry())

        result = runner.invoke(app, ["plugins", "list"])

        assert result.exit_code == 0
        assert "demo_analyzer" in result.output
        assert "None" in result.output  # empty plugin categories
        assert "Total:" in result.output

    def test_list_unexpected_error_exits(self, monkeypatch):
        monkeypatch.setattr(
            plugins_pkg, "get_registry", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        result = runner.invoke(app, ["plugins", "list"])

        assert result.exit_code == 1
        assert "Error:" in result.output

    def test_list_propagates_typer_exit(self, monkeypatch):
        import typer

        def _raise_exit():
            raise typer.Exit(7)

        monkeypatch.setattr(plugins_pkg, "get_registry", _raise_exit)

        result = runner.invoke(app, ["plugins", "list"])

        assert result.exit_code == 7


# ---------------------------------------------------------------------------
# plugins info
# ---------------------------------------------------------------------------


class TestInfoCommand:
    def test_info_serializer_shows_format(self):
        DemoSerializer().register(get_registry())

        result = runner.invoke(app, ["plugins", "info", "demofmt", "--type", "serializer"])

        assert result.exit_code == 0
        assert "Format:" in result.output
        assert "demofmt" in result.output
        assert "Version:" in result.output

    def test_info_analyzer(self):
        DemoAnalyzer().register(get_registry())

        result = runner.invoke(app, ["plugins", "info", "demo_analyzer", "--type", "analyzer"])

        assert result.exit_code == 0
        assert "demo_analyzer" in result.output

    @pytest.mark.parametrize("ptype", ["parser", "query"])
    def test_info_not_found_for_unregistered_types(self, ptype):
        result = runner.invoke(app, ["plugins", "info", "missing", "--type", ptype])

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_info_invalid_type(self):
        result = runner.invoke(app, ["plugins", "info", "x", "--type", "bogus"])

        assert result.exit_code == 1
        assert "Invalid plugin type" in result.output

    def test_info_unexpected_error_exits(self, monkeypatch):
        monkeypatch.setattr(
            plugins_pkg, "get_registry", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        result = runner.invoke(app, ["plugins", "info", "x", "--type", "serializer"])

        assert result.exit_code == 1
        assert "Error:" in result.output

    def test_info_plugin_without_name_or_version(self):
        # AnalysisPlugin only requires analyze(), so name/version may be absent;
        # info_command must skip those rows rather than crash.
        class NamelessAnalyzer(AnalysisPlugin):
            def analyze(self, rule: Rule) -> dict[str, Any]:
                return {}

        get_registry().register_analyzer("nameless", NamelessAnalyzer())

        result = runner.invoke(app, ["plugins", "info", "nameless", "--type", "analyzer"])

        assert result.exit_code == 0
        assert "NamelessAnalyzer" in result.output
        assert "Version:" not in result.output


# ---------------------------------------------------------------------------
# plugins load
# ---------------------------------------------------------------------------


_PLUGIN_SRC = (
    "from surinort_ast.plugins import AnalysisPlugin\n"
    "class FileAnalyzer(AnalysisPlugin):\n"
    "    @property\n"
    "    def name(self):\n"
    "        return 'file_analyzer'\n"
    "    @property\n"
    "    def version(self):\n"
    "        return '1.0.0'\n"
    "    def analyze(self, rule):\n"
    "        return {}\n"
    "    def register(self, registry):\n"
    "        registry.register_analyzer(self.name, self)\n"
)

_FAILING_PLUGIN_SRC = (
    "from surinort_ast.plugins import AnalysisPlugin\n"
    "class BrokenAnalyzer(AnalysisPlugin):\n"
    "    @property\n"
    "    def name(self):\n"
    "        return 'broken_analyzer'\n"
    "    @property\n"
    "    def version(self):\n"
    "        return '1.0.0'\n"
    "    def analyze(self, rule):\n"
    "        return {}\n"
    "    def register(self, registry):\n"
    "        raise RuntimeError('register fail')\n"
)


class TestLoadCommand:
    def test_load_directory_not_found(self, tmp_path):
        result = runner.invoke(app, ["plugins", "load", str(tmp_path / "missing")])

        assert result.exit_code == 1
        assert "Directory not found" in result.output

    def test_load_path_not_a_directory(self, tmp_path):
        a_file = tmp_path / "afile.txt"
        a_file.write_text("data", encoding="utf-8")

        result = runner.invoke(app, ["plugins", "load", str(a_file)])

        assert result.exit_code == 1
        assert "Not a directory" in result.output

    def test_load_success_lists_loaded(self, tmp_path):
        (tmp_path / "good_plugin.py").write_text(_PLUGIN_SRC, encoding="utf-8")

        result = runner.invoke(app, ["plugins", "load", str(tmp_path)])

        assert result.exit_code == 0
        assert "file_analyzer" in result.output
        assert "Loaded" in result.output

    def test_load_reports_failures(self, tmp_path):
        (tmp_path / "broken_plugin.py").write_text(_FAILING_PLUGIN_SRC, encoding="utf-8")

        result = runner.invoke(app, ["plugins", "load", str(tmp_path)])

        assert "Failed plugins:" in result.output
        assert "broken_analyzer" in result.output

    def test_load_unexpected_error_exits(self, tmp_path, monkeypatch):
        class _Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("loader boom")

        monkeypatch.setattr(plugins_pkg, "PluginLoader", _Boom)

        result = runner.invoke(app, ["plugins", "load", str(tmp_path)])

        assert result.exit_code == 1
        assert "Error:" in result.output


# ---------------------------------------------------------------------------
# plugins analyze
# ---------------------------------------------------------------------------


class TestAnalyzeCommand:
    def test_analyze_file_not_found(self, tmp_path):
        result = runner.invoke(
            app, ["plugins", "analyze", str(tmp_path / "missing.rules"), "-a", "demo_analyzer"]
        )

        assert result.exit_code == 1
        assert "File not found" in result.output

    def test_analyze_plugin_dir_not_a_directory(self, tmp_path):
        rules = _rule_file(tmp_path)
        not_dir = tmp_path / "nope.txt"
        not_dir.write_text("x", encoding="utf-8")

        result = runner.invoke(
            app,
            ["plugins", "analyze", str(rules), "-a", "demo_analyzer", "-p", str(not_dir)],
        )

        assert result.exit_code == 1
        assert "Directory not found" in result.output

    def test_analyze_analyzer_not_found_lists_available(self, tmp_path):
        rules = _rule_file(tmp_path)
        DemoAnalyzer().register(get_registry())

        result = runner.invoke(app, ["plugins", "analyze", str(rules), "-a", "ghost"])

        assert result.exit_code == 1
        assert "not found" in result.output
        assert "demo_analyzer" in result.output  # listed as available

    def test_analyze_success_with_output(self, tmp_path):
        rules = _rule_file(tmp_path)
        DemoAnalyzer().register(get_registry())
        out = tmp_path / "results.json"

        result = runner.invoke(
            app,
            ["plugins", "analyze", str(rules), "-a", "demo_analyzer", "-o", str(out)],
        )

        assert result.exit_code == 0
        assert out.exists()
        assert "Score 42" in result.output
        assert "suspicious" in result.output  # issue rendered

    def test_analyze_loads_plugins_from_dir(self, tmp_path):
        rules = _rule_file(tmp_path)
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "good_plugin.py").write_text(_PLUGIN_SRC, encoding="utf-8")

        result = runner.invoke(
            app,
            ["plugins", "analyze", str(rules), "-a", "file_analyzer", "-p", str(plugin_dir)],
        )

        assert result.exit_code == 0
        assert "Parsed" in result.output

    def test_analyze_unexpected_error_exits(self, tmp_path):
        rules = _rule_file(tmp_path)
        ExplodingAnalyzer().register(get_registry())

        result = runner.invoke(app, ["plugins", "analyze", str(rules), "-a", "exploding_analyzer"])

        assert result.exit_code == 1
        assert "Error:" in result.output
