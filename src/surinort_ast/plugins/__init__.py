"""
Plugin system for surinort-ast extensibility.

This package provides a comprehensive plugin architecture for extending
surinort-ast with custom parsers, serializers, analyzers, and query plugins.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com

Quick Start:
    >>> from surinort_ast.plugins import get_registry
    >>> from surinort_ast.plugins import AnalysisPlugin
    >>>
    >>> # Create custom plugin
    >>> class MyAnalyzer(AnalysisPlugin):
    ...     def analyze(self, rule):
    ...         return {'score': 100}
    >>>
    >>> # Register plugin
    >>> registry = get_registry()
    >>> registry.register_analyzer("my_analyzer", MyAnalyzer())
    >>>
    >>> # Use plugin
    >>> analyzer = registry.get_analyzer("my_analyzer")
    >>> results = analyzer.analyze(rule)
"""

from __future__ import annotations

import contextlib

# ============================================================================
# Core Plugin Interfaces
# ============================================================================
from .interface import (
    AnalysisPlugin,
    ParserPlugin,
    PluginMetadata,
    QueryPlugin,
    SerializerPlugin,
    SurinortPlugin,
)

# ============================================================================
# Plugin Loader
# ============================================================================
from .loader import (
    PluginDiscoveryError,
    PluginImportError,
    PluginLoader,
    PluginLoadError,
    PluginValidationError,
    load_plugins,
)

# ============================================================================
# Plugin Registry
# ============================================================================
from .registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
    PluginRegistryError,
    PluginVersionError,
    get_registry,
    reset_registry,
)

# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "AnalysisPlugin",
    "ParserPlugin",
    "PluginAlreadyRegisteredError",
    "PluginDiscoveryError",
    "PluginImportError",
    "PluginLoadError",
    # Loader
    "PluginLoader",
    "PluginMetadata",
    "PluginNotFoundError",
    # Registry
    "PluginRegistry",
    "PluginRegistryError",
    "PluginValidationError",
    "PluginVersionError",
    "QueryPlugin",
    "SerializerPlugin",
    # Core Interfaces
    "SurinortPlugin",
    "get_registry",
    "load_plugins",
    "reset_registry",
]

# ============================================================================
# Auto-load Entry Point Plugins
# ============================================================================

# Automatically discover and load entry point plugins on import
# Silently fail if auto-load fails (plugins are optional)
with contextlib.suppress(Exception):
    _loader = PluginLoader(auto_load=True)

# ============================================================================
# License Information
# ============================================================================

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
