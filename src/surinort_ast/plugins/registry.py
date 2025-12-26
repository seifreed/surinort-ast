"""
Plugin registry for discovering and managing surinort-ast plugins.

This module provides a centralized registry for all plugin types. The registry
is thread-safe and supports plugin discovery, registration, and retrieval.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .interface import AnalysisPlugin, ParserPlugin, QueryPlugin, SerializerPlugin

logger = logging.getLogger(__name__)


# ============================================================================
# Plugin Registry Exceptions
# ============================================================================


class PluginRegistryError(Exception):
    """Base exception for plugin registry errors."""


class PluginAlreadyRegisteredError(PluginRegistryError):
    """Raised when attempting to register a plugin that already exists."""


class PluginNotFoundError(PluginRegistryError):
    """Raised when requested plugin is not found in registry."""


class PluginVersionError(PluginRegistryError):
    """Raised when plugin version is incompatible."""


# ============================================================================
# Plugin Registry
# ============================================================================


class PluginRegistry:
    """
    Registry for surinort-ast plugins.

    This class maintains separate registries for each plugin type and provides
    thread-safe registration and retrieval. It supports plugin discovery via
    entry points and directory scanning.

    Thread Safety:
        All registry operations are protected by locks for thread-safe access.

    Example:
        >>> registry = PluginRegistry()
        >>> registry.register_serializer("yaml", YAMLSerializerPlugin())
        >>> yaml_plugin = registry.get_serializer("yaml")
        >>> yaml_plugin.serialize(rule)
    """

    def __init__(self) -> None:
        """Initialize empty plugin registry."""
        self._parsers: dict[str, ParserPlugin] = {}
        self._serializers: dict[str, SerializerPlugin] = {}
        self._analyzers: dict[str, AnalysisPlugin] = {}
        self._queries: dict[str, QueryPlugin] = {}

        # Thread safety
        self._lock = threading.RLock()

        logger.debug("Plugin registry initialized")

    # ========================================================================
    # Parser Plugin Methods
    # ========================================================================

    def register_parser(
        self,
        name: str,
        plugin: ParserPlugin,
        overwrite: bool = False,
    ) -> None:
        """
        Register a parser plugin.

        Args:
            name: Unique parser name (e.g., "custom_dialect")
            plugin: ParserPlugin instance
            overwrite: If True, allow overwriting existing plugin

        Raises:
            PluginAlreadyRegisteredError: If plugin exists and overwrite=False
            TypeError: If plugin doesn't implement ParserPlugin

        Example:
            >>> registry.register_parser("custom", CustomParser())
        """
        with self._lock:
            if name in self._parsers and not overwrite:
                raise PluginAlreadyRegisteredError(
                    f"Parser plugin '{name}' is already registered. Use overwrite=True to replace."
                )

            if not isinstance(plugin, type):  # Check if it's an ABC
                from .interface import ParserPlugin as ParserPluginABC

                if not isinstance(plugin, ParserPluginABC):
                    raise TypeError(f"Plugin must implement ParserPlugin, got {type(plugin)}")

            self._parsers[name] = plugin
            logger.info(f"Registered parser plugin: {name}")

    def get_parser(self, name: str) -> ParserPlugin | None:
        """
        Get parser plugin by name.

        Args:
            name: Parser plugin name

        Returns:
            ParserPlugin instance or None if not found

        Example:
            >>> parser = registry.get_parser("custom")
            >>> if parser:
            ...     custom_parser = parser.create_parser(config)
        """
        with self._lock:
            return self._parsers.get(name)

    def list_parsers(self) -> list[str]:
        """
        List all registered parser plugin names.

        Returns:
            List of parser plugin names

        Example:
            >>> registry.list_parsers()
            ['default', 'custom_dialect', 'fast_parser']
        """
        with self._lock:
            return sorted(self._parsers.keys())

    # ========================================================================
    # Serializer Plugin Methods
    # ========================================================================

    def register_serializer(
        self,
        format_name: str,
        plugin: SerializerPlugin,
        overwrite: bool = False,
    ) -> None:
        """
        Register a serializer plugin.

        Args:
            format_name: Serialization format name (e.g., "yaml", "toml")
            plugin: SerializerPlugin instance
            overwrite: If True, allow overwriting existing plugin

        Raises:
            PluginAlreadyRegisteredError: If plugin exists and overwrite=False
            TypeError: If plugin doesn't implement SerializerPlugin

        Example:
            >>> registry.register_serializer("yaml", YAMLSerializer())
        """
        with self._lock:
            if format_name in self._serializers and not overwrite:
                raise PluginAlreadyRegisteredError(
                    f"Serializer plugin '{format_name}' is already registered. "
                    f"Use overwrite=True to replace."
                )

            if not isinstance(plugin, type):
                from .interface import SerializerPlugin as SerializerPluginABC

                if not isinstance(plugin, SerializerPluginABC):
                    raise TypeError(f"Plugin must implement SerializerPlugin, got {type(plugin)}")

            self._serializers[format_name] = plugin
            logger.info(f"Registered serializer plugin: {format_name}")

    def get_serializer(self, format_name: str) -> SerializerPlugin | None:
        """
        Get serializer plugin by format name.

        Args:
            format_name: Serialization format (e.g., "yaml")

        Returns:
            SerializerPlugin instance or None if not found

        Example:
            >>> serializer = registry.get_serializer("yaml")
            >>> if serializer:
            ...     yaml_data = serializer.serialize(rule)
        """
        with self._lock:
            return self._serializers.get(format_name)

    def list_serializers(self) -> list[str]:
        """
        List all registered serializer format names.

        Returns:
            List of serializer format names

        Example:
            >>> registry.list_serializers()
            ['json', 'yaml', 'toml', 'msgpack']
        """
        with self._lock:
            return sorted(self._serializers.keys())

    # ========================================================================
    # Analyzer Plugin Methods
    # ========================================================================

    def register_analyzer(
        self,
        name: str,
        plugin: AnalysisPlugin,
        overwrite: bool = False,
    ) -> None:
        """
        Register an analyzer plugin.

        Args:
            name: Unique analyzer name (e.g., "security_auditor")
            plugin: AnalysisPlugin instance
            overwrite: If True, allow overwriting existing plugin

        Raises:
            PluginAlreadyRegisteredError: If plugin exists and overwrite=False
            TypeError: If plugin doesn't implement AnalysisPlugin

        Example:
            >>> registry.register_analyzer("security", SecurityAuditor())
        """
        with self._lock:
            if name in self._analyzers and not overwrite:
                raise PluginAlreadyRegisteredError(
                    f"Analyzer plugin '{name}' is already registered. "
                    f"Use overwrite=True to replace."
                )

            if not isinstance(plugin, type):
                from .interface import AnalysisPlugin as AnalysisPluginABC

                if not isinstance(plugin, AnalysisPluginABC):
                    raise TypeError(f"Plugin must implement AnalysisPlugin, got {type(plugin)}")

            self._analyzers[name] = plugin
            logger.info(f"Registered analyzer plugin: {name}")

    def get_analyzer(self, name: str) -> AnalysisPlugin | None:
        """
        Get analyzer plugin by name.

        Args:
            name: Analyzer plugin name

        Returns:
            AnalysisPlugin instance or None if not found

        Example:
            >>> analyzer = registry.get_analyzer("security")
            >>> if analyzer:
            ...     results = analyzer.analyze(rule)
        """
        with self._lock:
            return self._analyzers.get(name)

    def list_analyzers(self) -> list[str]:
        """
        List all registered analyzer plugin names.

        Returns:
            List of analyzer plugin names

        Example:
            >>> registry.list_analyzers()
            ['security', 'performance', 'coverage']
        """
        with self._lock:
            return sorted(self._analyzers.keys())

    # ========================================================================
    # Query Plugin Methods
    # ========================================================================

    def register_query(
        self,
        name: str,
        plugin: QueryPlugin,
        overwrite: bool = False,
    ) -> None:
        """
        Register a query plugin.

        Args:
            name: Unique query plugin name (e.g., "regex_selector")
            plugin: QueryPlugin instance
            overwrite: If True, allow overwriting existing plugin

        Raises:
            PluginAlreadyRegisteredError: If plugin exists and overwrite=False
            TypeError: If plugin doesn't implement QueryPlugin

        Example:
            >>> registry.register_query("regex", RegexQueryPlugin())
        """
        with self._lock:
            if name in self._queries and not overwrite:
                raise PluginAlreadyRegisteredError(
                    f"Query plugin '{name}' is already registered. Use overwrite=True to replace."
                )

            if not isinstance(plugin, type):
                from .interface import QueryPlugin as QueryPluginABC

                if not isinstance(plugin, QueryPluginABC):
                    raise TypeError(f"Plugin must implement QueryPlugin, got {type(plugin)}")

            self._queries[name] = plugin
            logger.info(f"Registered query plugin: {name}")

    def get_query(self, name: str) -> QueryPlugin | None:
        """
        Get query plugin by name.

        Args:
            name: Query plugin name

        Returns:
            QueryPlugin instance or None if not found

        Example:
            >>> query_plugin = registry.get_query("regex")
            >>> if query_plugin:
            ...     selector = query_plugin.create_selector(pattern)
        """
        with self._lock:
            return self._queries.get(name)

    def list_queries(self) -> list[str]:
        """
        List all registered query plugin names.

        Returns:
            List of query plugin names

        Example:
            >>> registry.list_queries()
            ['regex', 'xpath', 'custom']
        """
        with self._lock:
            return sorted(self._queries.keys())

    # ========================================================================
    # General Registry Methods
    # ========================================================================

    def list_plugins(self) -> dict[str, list[str]]:
        """
        List all registered plugins by type.

        Returns:
            Dictionary mapping plugin type to list of plugin names

        Example:
            >>> registry.list_plugins()
            {
                'parsers': ['default', 'custom'],
                'serializers': ['json', 'yaml', 'toml'],
                'analyzers': ['security', 'performance'],
                'queries': ['regex']
            }
        """
        with self._lock:
            return {
                "parsers": self.list_parsers(),
                "serializers": self.list_serializers(),
                "analyzers": self.list_analyzers(),
                "queries": self.list_queries(),
            }

    def clear(self) -> None:
        """
        Clear all registered plugins.

        Warning:
            This removes all plugins from the registry. Use with caution.

        Example:
            >>> registry.clear()
            >>> registry.list_plugins()
            {'parsers': [], 'serializers': [], 'analyzers': [], 'queries': []}
        """
        with self._lock:
            self._parsers.clear()
            self._serializers.clear()
            self._analyzers.clear()
            self._queries.clear()
            logger.info("All plugins cleared from registry")

    def unregister_parser(self, name: str) -> bool:
        """
        Unregister a parser plugin.

        Args:
            name: Parser plugin name

        Returns:
            True if plugin was removed, False if not found

        Example:
            >>> registry.unregister_parser("custom")
            True
        """
        with self._lock:
            if name in self._parsers:
                del self._parsers[name]
                logger.info(f"Unregistered parser plugin: {name}")
                return True
            return False

    def unregister_serializer(self, format_name: str) -> bool:
        """
        Unregister a serializer plugin.

        Args:
            format_name: Serializer format name

        Returns:
            True if plugin was removed, False if not found

        Example:
            >>> registry.unregister_serializer("yaml")
            True
        """
        with self._lock:
            if format_name in self._serializers:
                del self._serializers[format_name]
                logger.info(f"Unregistered serializer plugin: {format_name}")
                return True
            return False

    def unregister_analyzer(self, name: str) -> bool:
        """
        Unregister an analyzer plugin.

        Args:
            name: Analyzer plugin name

        Returns:
            True if plugin was removed, False if not found

        Example:
            >>> registry.unregister_analyzer("security")
            True
        """
        with self._lock:
            if name in self._analyzers:
                del self._analyzers[name]
                logger.info(f"Unregistered analyzer plugin: {name}")
                return True
            return False

    def unregister_query(self, name: str) -> bool:
        """
        Unregister a query plugin.

        Args:
            name: Query plugin name

        Returns:
            True if plugin was removed, False if not found

        Example:
            >>> registry.unregister_query("regex")
            True
        """
        with self._lock:
            if name in self._queries:
                del self._queries[name]
                logger.info(f"Unregistered query plugin: {name}")
                return True
            return False

    def __repr__(self) -> str:
        """String representation of registry."""
        with self._lock:
            return (
                f"PluginRegistry("
                f"parsers={len(self._parsers)}, "
                f"serializers={len(self._serializers)}, "
                f"analyzers={len(self._analyzers)}, "
                f"queries={len(self._queries)})"
            )


# ============================================================================
# Global Registry Instance
# ============================================================================


class _RegistrySingleton:
    """Thread-safe singleton holder for the global plugin registry."""

    _instance: PluginRegistry | None = None
    _lock = threading.Lock()

    @classmethod
    def get(cls) -> PluginRegistry:
        """Get or create the global plugin registry instance."""
        if cls._instance is None:
            with cls._lock:
                # Double-checked locking
                if cls._instance is None:
                    cls._instance = PluginRegistry()
                    logger.debug("Global plugin registry created")

        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the global registry (primarily for testing)."""
        with cls._lock:
            cls._instance = None
            logger.debug("Global plugin registry reset")


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry instance.

    This function implements lazy singleton pattern with thread-safe initialization.
    The global registry is shared across the entire application.

    Returns:
        Global PluginRegistry instance

    Example:
        >>> from surinort_ast.plugins import get_registry
        >>> registry = get_registry()
        >>> registry.register_serializer("yaml", YAMLSerializer())
    """
    return _RegistrySingleton.get()


def reset_registry() -> None:
    """
    Reset the global registry (primarily for testing).

    Warning:
        This clears all registered plugins and creates a new registry instance.
        Use only in test scenarios.

    Example:
        >>> reset_registry()  # Start with clean registry
    """
    _RegistrySingleton.reset()


# ============================================================================
# License Information
# ============================================================================

__all__ = [
    "PluginAlreadyRegisteredError",
    "PluginNotFoundError",
    "PluginRegistry",
    "PluginRegistryError",
    "PluginVersionError",
    "get_registry",
    "reset_registry",
]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
