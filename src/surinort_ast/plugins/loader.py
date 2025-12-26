"""
Plugin loader for auto-discovery and dynamic loading of surinort-ast plugins.

This module provides mechanisms for discovering and loading plugins from:
1. Entry points (recommended for production)
2. Plugin directories (useful for development)
3. Manual registration (for testing)

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .interface import SurinortPlugin

from .registry import get_registry

logger = logging.getLogger(__name__)


# ============================================================================
# Plugin Loader Exceptions
# ============================================================================


class PluginLoadError(Exception):
    """Base exception for plugin loading errors."""


class PluginDiscoveryError(PluginLoadError):
    """Raised when plugin discovery fails."""


class PluginImportError(PluginLoadError):
    """Raised when plugin import fails."""


class PluginValidationError(PluginLoadError):
    """Raised when plugin validation fails."""


# ============================================================================
# Plugin Loader
# ============================================================================


class PluginLoader:
    """
    Load and discover surinort-ast plugins.

    This class provides methods for discovering plugins via entry points,
    loading from directories, and validating plugin implementations.

    Features:
        - Entry point-based discovery (recommended)
        - Directory scanning for development
        - Lazy loading for performance
        - Error isolation (failing plugins don't crash loader)
        - Plugin validation and compatibility checking

    Example:
        >>> loader = PluginLoader()
        >>> loader.load_entry_points()
        >>> loader.load_directory(Path("./local_plugins"))
    """

    def __init__(self, auto_load: bool = True) -> None:
        """
        Initialize plugin loader.

        Args:
            auto_load: If True, automatically load entry point plugins on init

        Example:
            >>> loader = PluginLoader(auto_load=True)
            >>> # Entry point plugins are now loaded
        """
        self._loaded_plugins: set[str] = set()
        self._failed_plugins: dict[str, str] = {}

        if auto_load:
            try:
                self.load_entry_points()
            except Exception as e:
                logger.warning(f"Auto-load of entry point plugins failed: {e}")

    # ========================================================================
    # Entry Point Discovery (Recommended)
    # ========================================================================

    def load_entry_points(
        self,
        group: str = "surinort_ast.plugins",
        ignore_errors: bool = True,
    ) -> int:
        """
        Load plugins from entry points.

        This is the recommended method for production deployments. Plugins
        declare themselves via entry points in pyproject.toml:

        [project.entry-points."surinort_ast.plugins"]
        yaml_serializer = "surinort_yaml:YAMLSerializerPlugin"

        Args:
            group: Entry point group name
            ignore_errors: If True, continue loading on errors; if False, raise

        Returns:
            Number of plugins successfully loaded

        Raises:
            PluginDiscoveryError: If discovery fails and ignore_errors=False

        Example:
            >>> loader = PluginLoader(auto_load=False)
            >>> count = loader.load_entry_points()
            >>> print(f"Loaded {count} plugins")
        """
        loaded_count = 0
        registry = get_registry()

        try:
            # Discover entry points
            entry_points = importlib.metadata.entry_points(group=group)

            logger.debug(f"Discovered {len(entry_points)} entry points in group '{group}'")

            # Load each entry point
            for entry_point in entry_points:
                try:
                    plugin_name = entry_point.name
                    logger.debug(f"Loading plugin from entry point: {plugin_name}")

                    # Load plugin class
                    plugin_class = entry_point.load()

                    # Instantiate plugin
                    plugin = plugin_class() if isinstance(plugin_class, type) else plugin_class

                    # Validate plugin
                    self._validate_plugin(plugin)

                    # Register plugin
                    plugin.register(registry)

                    self._loaded_plugins.add(plugin_name)
                    loaded_count += 1
                    logger.info(f"Loaded plugin from entry point: {plugin_name}")

                except Exception as e:
                    error_msg = f"Failed to load plugin '{entry_point.name}': {e}"
                    self._failed_plugins[entry_point.name] = str(e)

                    if ignore_errors:
                        logger.error(error_msg, exc_info=True)
                    else:
                        raise PluginLoadError(error_msg) from e

        except Exception as e:
            if not ignore_errors:
                raise PluginDiscoveryError(f"Entry point discovery failed: {e}") from e
            logger.error(f"Entry point discovery failed: {e}")

        logger.info(f"Loaded {loaded_count} plugins from entry points")
        return loaded_count

    # ========================================================================
    # Directory Loading (Development)
    # ========================================================================

    def load_directory(
        self,
        plugin_dir: Path,
        pattern: str = "*_plugin.py",
        ignore_errors: bool = True,
    ) -> int:
        """
        Load plugins from a directory.

        This method is useful for development and testing. It scans a directory
        for Python files matching the pattern and attempts to import and
        register plugins.

        Args:
            plugin_dir: Directory to scan for plugins
            pattern: File pattern to match (default: "*_plugin.py")
            ignore_errors: If True, continue on errors; if False, raise

        Returns:
            Number of plugins successfully loaded

        Raises:
            PluginDiscoveryError: If directory doesn't exist or can't be read
            PluginLoadError: If plugin loading fails and ignore_errors=False

        Example:
            >>> loader = PluginLoader(auto_load=False)
            >>> count = loader.load_directory(Path("./local_plugins"))
            >>> print(f"Loaded {count} local plugins")
        """
        if not plugin_dir.exists():
            raise PluginDiscoveryError(f"Plugin directory does not exist: {plugin_dir}")

        if not plugin_dir.is_dir():
            raise PluginDiscoveryError(f"Plugin path is not a directory: {plugin_dir}")

        loaded_count = 0
        registry = get_registry()

        # Add directory to Python path temporarily
        plugin_dir_str = str(plugin_dir.absolute())
        if plugin_dir_str not in sys.path:
            sys.path.insert(0, plugin_dir_str)

        try:
            # Scan for plugin files
            plugin_files = sorted(plugin_dir.glob(pattern))
            logger.debug(f"Found {len(plugin_files)} plugin files in {plugin_dir}")

            for plugin_file in plugin_files:
                try:
                    module_name = plugin_file.stem
                    logger.debug(f"Loading plugin from file: {plugin_file.name}")

                    # Import module
                    module = importlib.import_module(module_name)

                    # Find plugin classes in module
                    plugins_found = self._discover_plugins_in_module(module)

                    if not plugins_found:
                        logger.warning(f"No plugin classes found in {plugin_file.name}")
                        continue

                    # Register plugins
                    for plugin in plugins_found:
                        self._validate_plugin(plugin)
                        plugin.register(registry)

                        plugin_name = getattr(plugin, "name", module_name)
                        self._loaded_plugins.add(plugin_name)
                        loaded_count += 1
                        logger.info(f"Loaded plugin from file: {plugin_file.name}")

                except Exception as e:
                    error_msg = f"Failed to load plugin from {plugin_file.name}: {e}"
                    self._failed_plugins[plugin_file.name] = str(e)

                    if ignore_errors:
                        logger.error(error_msg, exc_info=True)
                    else:
                        raise PluginLoadError(error_msg) from e

        finally:
            # Remove directory from path
            if plugin_dir_str in sys.path:
                sys.path.remove(plugin_dir_str)

        logger.info(f"Loaded {loaded_count} plugins from directory {plugin_dir}")
        return loaded_count

    # ========================================================================
    # Plugin Discovery in Modules
    # ========================================================================

    def _discover_plugins_in_module(self, module: Any) -> list[SurinortPlugin]:
        """
        Discover plugin classes in a module.

        Args:
            module: Python module to scan

        Returns:
            List of plugin instances found in module
        """
        from .interface import AnalysisPlugin, ParserPlugin, QueryPlugin, SerializerPlugin

        plugins = []

        # Get all classes in module
        for attr_name in dir(module):
            if attr_name.startswith("_"):
                continue

            attr = getattr(module, attr_name)

            # Check if it's a plugin class
            if (
                isinstance(attr, type)
                and issubclass(attr, (ParserPlugin, SerializerPlugin, AnalysisPlugin, QueryPlugin))
                and attr not in (ParserPlugin, SerializerPlugin, AnalysisPlugin, QueryPlugin)
            ):
                try:
                    plugin = attr()
                    plugins.append(plugin)
                except Exception as e:
                    logger.warning(f"Failed to instantiate plugin {attr_name}: {e}")

        return plugins

    # ========================================================================
    # Plugin Validation
    # ========================================================================

    def _validate_plugin(self, plugin: Any) -> None:
        """
        Validate that plugin implements required interface.

        Args:
            plugin: Plugin instance to validate

        Raises:
            PluginValidationError: If plugin doesn't implement required interface
        """
        # Check for required methods
        if not hasattr(plugin, "register"):
            raise PluginValidationError(
                f"Plugin {type(plugin).__name__} missing required method: register"
            )

        # Check for required properties (via name and version attributes or properties)
        if not (hasattr(plugin, "name") or hasattr(type(plugin), "name")):
            raise PluginValidationError(
                f"Plugin {type(plugin).__name__} missing required property: name"
            )

        if not (hasattr(plugin, "version") or hasattr(type(plugin), "version")):
            raise PluginValidationError(
                f"Plugin {type(plugin).__name__} missing required property: version"
            )

        logger.debug(f"Validated plugin: {type(plugin).__name__}")

    # ========================================================================
    # Plugin Status
    # ========================================================================

    def get_loaded_plugins(self) -> set[str]:
        """
        Get set of successfully loaded plugin names.

        Returns:
            Set of plugin names that loaded successfully

        Example:
            >>> loader.get_loaded_plugins()
            {'yaml_serializer', 'security_auditor'}
        """
        return self._loaded_plugins.copy()

    def get_failed_plugins(self) -> dict[str, str]:
        """
        Get dictionary of plugins that failed to load.

        Returns:
            Dictionary mapping plugin name to error message

        Example:
            >>> loader.get_failed_plugins()
            {'broken_plugin': 'ImportError: No module named yaml'}
        """
        return self._failed_plugins.copy()

    def get_load_summary(self) -> dict[str, Any]:
        """
        Get summary of plugin loading results.

        Returns:
            Dictionary with loading statistics

        Example:
            >>> loader.get_load_summary()
            {
                'loaded': 3,
                'failed': 1,
                'loaded_plugins': ['yaml_serializer', 'security_auditor', 'toml'],
                'failed_plugins': {'broken_plugin': 'ImportError: ...'}
            }
        """
        return {
            "loaded": len(self._loaded_plugins),
            "failed": len(self._failed_plugins),
            "loaded_plugins": sorted(self._loaded_plugins),
            "failed_plugins": self._failed_plugins,
        }

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"PluginLoader(loaded={len(self._loaded_plugins)}, failed={len(self._failed_plugins)})"
        )


# ============================================================================
# Convenience Functions
# ============================================================================


def load_plugins(
    entry_points: bool = True,
    directories: list[Path] | None = None,
    ignore_errors: bool = True,
) -> dict[str, Any]:
    """
    Load plugins from multiple sources (convenience function).

    Args:
        entry_points: Load from entry points
        directories: List of directories to scan
        ignore_errors: Continue on errors

    Returns:
        Loading summary dictionary

    Example:
        >>> from surinort_ast.plugins import load_plugins
        >>> summary = load_plugins(
        ...     entry_points=True,
        ...     directories=[Path("./local_plugins")]
        ... )
        >>> print(f"Loaded {summary['loaded']} plugins")
    """
    loader = PluginLoader(auto_load=False)

    if entry_points:
        loader.load_entry_points(ignore_errors=ignore_errors)

    if directories:
        for directory in directories:
            loader.load_directory(directory, ignore_errors=ignore_errors)

    return loader.get_load_summary()


# ============================================================================
# License Information
# ============================================================================

__all__ = [
    "PluginDiscoveryError",
    "PluginImportError",
    "PluginLoadError",
    "PluginLoader",
    "PluginValidationError",
    "load_plugins",
]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
