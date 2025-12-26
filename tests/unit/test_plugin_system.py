"""
Tests for plugin system (registry, loader, interfaces).

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from surinort_ast.core.nodes import Rule
from surinort_ast.plugins import (
    AnalysisPlugin,
    PluginAlreadyRegisteredError,
    PluginLoader,
    PluginRegistry,
    SerializerPlugin,
    get_registry,
    reset_registry,
)

# ============================================================================
# Test Plugins
# ============================================================================


class TestSerializerPlugin(SerializerPlugin):
    """Test serializer plugin for testing."""

    @property
    def name(self) -> str:
        return "test_serializer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def get_format_name(self) -> str:
        return "test"

    def serialize(self, rule: Rule) -> str:
        return f"TEST:{rule.action.value}"

    def deserialize(self, data: str) -> Rule:
        # Minimal implementation for testing
        from surinort_ast.parsing import parse_rule

        return parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    def register(self, registry: PluginRegistry) -> None:
        registry.register_serializer(self.get_format_name(), self)


class TestAnalyzerPlugin(AnalysisPlugin):
    """Test analyzer plugin for testing."""

    @property
    def name(self) -> str:
        return "test_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def analyze(self, rule: Rule) -> dict[str, Any]:
        return {"score": 100, "issues": []}

    def register(self, registry: PluginRegistry) -> None:
        registry.register_analyzer(self.name, self)


# ============================================================================
# Plugin Registry Tests
# ============================================================================


class TestPluginRegistry:
    """Test PluginRegistry functionality."""

    def setup_method(self) -> None:
        """Reset registry before each test."""
        reset_registry()

    def test_registry_singleton(self) -> None:
        """Test registry is singleton."""
        registry1 = get_registry()
        registry2 = get_registry()
        assert registry1 is registry2

    def test_register_serializer(self) -> None:
        """Test serializer plugin registration."""
        registry = get_registry()
        plugin = TestSerializerPlugin()

        registry.register_serializer("test", plugin)

        retrieved = registry.get_serializer("test")
        assert retrieved is plugin

    def test_register_analyzer(self) -> None:
        """Test analyzer plugin registration."""
        registry = get_registry()
        plugin = TestAnalyzerPlugin()

        registry.register_analyzer("test", plugin)

        retrieved = registry.get_analyzer("test")
        assert retrieved is plugin

    def test_duplicate_registration_error(self) -> None:
        """Test error on duplicate registration without overwrite."""
        registry = get_registry()
        plugin1 = TestSerializerPlugin()
        plugin2 = TestSerializerPlugin()

        registry.register_serializer("test", plugin1)

        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register_serializer("test", plugin2, overwrite=False)

    def test_duplicate_registration_overwrite(self) -> None:
        """Test overwriting existing plugin."""
        registry = get_registry()
        plugin1 = TestSerializerPlugin()
        plugin2 = TestSerializerPlugin()

        registry.register_serializer("test", plugin1)
        registry.register_serializer("test", plugin2, overwrite=True)

        retrieved = registry.get_serializer("test")
        assert retrieved is plugin2

    def test_list_plugins(self) -> None:
        """Test listing all plugins."""
        registry = get_registry()

        # Register multiple plugins
        serializer = TestSerializerPlugin()
        analyzer = TestAnalyzerPlugin()

        registry.register_serializer("test", serializer)
        registry.register_analyzer("test", analyzer)

        plugins = registry.list_plugins()

        assert "test" in plugins["serializers"]
        assert "test" in plugins["analyzers"]

    def test_list_serializers(self) -> None:
        """Test listing serializer plugins."""
        registry = get_registry()

        plugin1 = TestSerializerPlugin()
        registry.register_serializer("test1", plugin1)

        serializers = registry.list_serializers()

        assert "test1" in serializers
        assert len(serializers) == 1

    def test_get_nonexistent_plugin(self) -> None:
        """Test getting non-existent plugin returns None."""
        registry = get_registry()

        result = registry.get_serializer("nonexistent")
        assert result is None

    def test_unregister_plugin(self) -> None:
        """Test unregistering plugin."""
        registry = get_registry()
        plugin = TestSerializerPlugin()

        registry.register_serializer("test", plugin)
        assert registry.get_serializer("test") is not None

        result = registry.unregister_serializer("test")
        assert result is True
        assert registry.get_serializer("test") is None

    def test_unregister_nonexistent(self) -> None:
        """Test unregistering non-existent plugin returns False."""
        registry = get_registry()

        result = registry.unregister_serializer("nonexistent")
        assert result is False

    def test_clear_registry(self) -> None:
        """Test clearing all plugins."""
        registry = get_registry()

        # Register plugins
        registry.register_serializer("test", TestSerializerPlugin())
        registry.register_analyzer("test", TestAnalyzerPlugin())

        # Clear
        registry.clear()

        # Verify empty
        plugins = registry.list_plugins()
        assert len(plugins["serializers"]) == 0
        assert len(plugins["analyzers"]) == 0

    def test_thread_safety(self) -> None:
        """Test thread-safe plugin registration."""
        import threading

        registry = get_registry()
        errors = []

        def register_plugin(name: str) -> None:
            try:
                plugin = TestSerializerPlugin()
                registry.register_serializer(name, plugin)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = [
            threading.Thread(target=register_plugin, args=(f"plugin_{i}",)) for i in range(10)
        ]

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify no errors
        assert len(errors) == 0

        # Verify all registered
        assert len(registry.list_serializers()) == 10


# ============================================================================
# Plugin Loader Tests
# ============================================================================


class TestPluginLoader:
    """Test PluginLoader functionality."""

    def setup_method(self) -> None:
        """Reset registry before each test."""
        reset_registry()

    def test_loader_initialization(self) -> None:
        """Test loader initialization."""
        loader = PluginLoader(auto_load=False)
        assert loader is not None

    def test_manual_registration(self) -> None:
        """Test manual plugin registration."""
        _loader = PluginLoader(auto_load=False)
        registry = get_registry()

        plugin = TestSerializerPlugin()
        plugin.register(registry)

        retrieved = registry.get_serializer("test")
        assert retrieved is plugin

    def test_load_directory_nonexistent(self) -> None:
        """Test loading from non-existent directory fails."""
        from surinort_ast.plugins.loader import PluginDiscoveryError

        loader = PluginLoader(auto_load=False)

        with pytest.raises(PluginDiscoveryError):
            loader.load_directory(Path("/nonexistent/directory"))

    def test_load_directory_not_a_directory(self, tmp_path: Path) -> None:
        """Test loading from file instead of directory fails."""
        from surinort_ast.plugins.loader import PluginDiscoveryError

        # Create a file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        loader = PluginLoader(auto_load=False)

        with pytest.raises(PluginDiscoveryError):
            loader.load_directory(test_file)

    def test_load_directory_empty(self, tmp_path: Path) -> None:
        """Test loading from empty directory."""
        loader = PluginLoader(auto_load=False)

        count = loader.load_directory(tmp_path, pattern="*_plugin.py")
        assert count == 0

    def test_load_directory_with_plugin(self, tmp_path: Path) -> None:
        """Test loading plugin from directory."""
        # Create plugin file
        plugin_file = tmp_path / "test_plugin.py"
        plugin_code = """
from surinort_ast.plugins import SerializerPlugin

class TestPlugin(SerializerPlugin):
    @property
    def name(self):
        return "test"

    @property
    def version(self):
        return "1.0.0"

    def get_format_name(self):
        return "test"

    def serialize(self, rule):
        return "test"

    def deserialize(self, data):
        from surinort_ast.parsing import parse_rule
        return parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    def register(self, registry):
        registry.register_serializer(self.get_format_name(), self)
"""
        plugin_file.write_text(plugin_code)

        loader = PluginLoader(auto_load=False)
        count = loader.load_directory(tmp_path, pattern="*_plugin.py")

        assert count == 1

        # Verify plugin loaded
        registry = get_registry()
        plugin = registry.get_serializer("test")
        assert plugin is not None

    def test_load_summary(self) -> None:
        """Test get_load_summary."""
        loader = PluginLoader(auto_load=False)

        summary = loader.get_load_summary()

        assert "loaded" in summary
        assert "failed" in summary
        assert "loaded_plugins" in summary
        assert "failed_plugins" in summary


# ============================================================================
# Plugin Interface Tests
# ============================================================================


class TestPluginInterfaces:
    """Test plugin interface contracts."""

    def test_serializer_plugin_interface(self) -> None:
        """Test SerializerPlugin interface."""
        plugin = TestSerializerPlugin()

        # Test required methods exist
        assert hasattr(plugin, "get_format_name")
        assert hasattr(plugin, "serialize")
        assert hasattr(plugin, "deserialize")
        assert hasattr(plugin, "register")

        # Test properties
        assert plugin.name == "test_serializer"
        assert plugin.version == "1.0.0"
        assert plugin.get_format_name() == "test"

    def test_analyzer_plugin_interface(self) -> None:
        """Test AnalysisPlugin interface."""
        plugin = TestAnalyzerPlugin()

        # Test required methods exist
        assert hasattr(plugin, "analyze")
        assert hasattr(plugin, "register")

        # Test properties
        assert plugin.name == "test_analyzer"
        assert plugin.version == "1.0.0"

    def test_serializer_roundtrip(self) -> None:
        """Test serializer roundtrip functionality."""
        from surinort_ast.parsing import parse_rule

        plugin = TestSerializerPlugin()
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Serialize
        serialized = plugin.serialize(rule)
        assert isinstance(serialized, str)
        assert "TEST:" in serialized

        # Deserialize
        deserialized = plugin.deserialize(serialized)
        assert isinstance(deserialized, Rule)

    def test_analyzer_functionality(self) -> None:
        """Test analyzer functionality."""
        from surinort_ast.parsing import parse_rule

        plugin = TestAnalyzerPlugin()
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        results = plugin.analyze(rule)

        assert isinstance(results, dict)
        assert "score" in results
        assert results["score"] == 100


# ============================================================================
# Integration Tests
# ============================================================================


class TestPluginIntegration:
    """Test plugin system integration."""

    def setup_method(self) -> None:
        """Reset registry before each test."""
        reset_registry()

    def test_end_to_end_workflow(self) -> None:
        """Test complete plugin workflow."""
        from surinort_ast.parsing import parse_rule

        # Create and register plugin
        plugin = TestSerializerPlugin()
        registry = get_registry()
        plugin.register(registry)

        # Parse rule
        rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

        # Use plugin
        serialized = plugin.serialize(rule)
        assert "TEST:" in serialized

        # Retrieve from registry
        retrieved_plugin = registry.get_serializer("test")
        assert retrieved_plugin is plugin

    def test_multiple_plugins(self) -> None:
        """Test multiple plugins working together."""
        registry = get_registry()

        # Register multiple plugins
        serializer = TestSerializerPlugin()
        analyzer = TestAnalyzerPlugin()

        serializer.register(registry)
        analyzer.register(registry)

        # Verify both accessible
        assert registry.get_serializer("test") is serializer
        assert registry.get_analyzer("test_analyzer") is analyzer


# ============================================================================
# License Information
# ============================================================================

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
