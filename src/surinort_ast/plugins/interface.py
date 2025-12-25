"""
Plugin interface definitions for surinort-ast extensibility.

This module defines base protocols and abstract classes for all plugin types.
All plugins must implement the SurinortPlugin protocol and extend one of the
type-specific abstract base classes.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from surinort_ast.core.nodes import Rule
    from surinort_ast.parsing.protocols import IParser

    from .registry import PluginRegistry


# ============================================================================
# Base Plugin Protocol
# ============================================================================


class SurinortPlugin(Protocol):
    """
    Base protocol for all surinort-ast plugins.

    All plugins must implement this protocol to be discoverable and loadable
    by the plugin system. This protocol defines the minimum interface required
    for plugin registration and metadata access.

    Attributes:
        name: Unique plugin identifier (e.g., "yaml_serializer")
        version: Semantic version string (e.g., "1.0.0")
    """

    @property
    def name(self) -> str:
        """
        Get unique plugin name.

        Returns:
            Plugin identifier (lowercase, underscore-separated)

        Example:
            >>> plugin.name
            'yaml_serializer'
        """
        ...

    @property
    def version(self) -> str:
        """
        Get plugin version.

        Returns:
            Semantic version string (MAJOR.MINOR.PATCH)

        Example:
            >>> plugin.version
            '1.2.3'
        """
        ...

    def register(self, registry: PluginRegistry) -> None:
        """
        Register plugin capabilities with the global registry.

        This method is called during plugin discovery to register the plugin's
        capabilities with the appropriate registries (parser, serializer, etc.).

        Args:
            registry: Global plugin registry instance

        Example:
            >>> def register(self, registry):
            ...     registry.register_serializer("yaml", self)
        """
        ...


# ============================================================================
# Parser Plugin Interface
# ============================================================================


class ParserPlugin(ABC):
    """
    Base class for parser plugins.

    Parser plugins extend parsing capabilities by providing custom parser
    implementations, middleware, or dialect-specific extensions.

    Use Cases:
        - Custom IDS dialects (proprietary formats)
        - Parser middleware for preprocessing
        - Alternative parsing backends
        - Performance-optimized parsers

    Example:
        >>> class CustomDialectParser(ParserPlugin):
        ...     def create_parser(self, config):
        ...         return MyCustomParser(config)
    """

    @abstractmethod
    def create_parser(self, config: Any) -> IParser:
        """
        Create a parser instance.

        Args:
            config: Parser configuration object (ParserConfig or custom)

        Returns:
            Parser instance implementing IParser protocol

        Raises:
            PluginError: If parser creation fails
        """
        ...


# ============================================================================
# Serialization Plugin Interface
# ============================================================================


class SerializerPlugin(ABC):
    """
    Base class for serializer plugins.

    Serialization plugins add support for additional data formats beyond JSON.
    All serializers must support bidirectional conversion (serialize/deserialize).

    Use Cases:
        - YAML serialization for human-readable config
        - TOML format for configuration files
        - MessagePack for binary efficiency
        - Protocol Buffers for cross-language compatibility
        - Compression plugins (gzip, brotli, zstd)
        - Encryption plugins for sensitive rules

    Example:
        >>> class YAMLSerializer(SerializerPlugin):
        ...     def get_format_name(self):
        ...         return "yaml"
        ...     def serialize(self, rule):
        ...         import yaml
        ...         return yaml.dump(rule.model_dump())
    """

    @abstractmethod
    def get_format_name(self) -> str:
        """
        Get serialization format name.

        Returns:
            Format identifier (lowercase, e.g., 'yaml', 'toml', 'msgpack')

        Example:
            >>> plugin.get_format_name()
            'yaml'
        """
        ...

    @abstractmethod
    def serialize(self, rule: Rule) -> str | bytes:
        """
        Serialize rule to format.

        Args:
            rule: AST Rule node to serialize

        Returns:
            Serialized data (string for text formats, bytes for binary)

        Raises:
            SerializationError: If serialization fails

        Example:
            >>> yaml_data = plugin.serialize(rule)
            >>> print(yaml_data)
            action: alert
            header:
              protocol: tcp
              ...
        """
        ...

    @abstractmethod
    def deserialize(self, data: str | bytes) -> Rule:
        """
        Deserialize rule from format.

        Args:
            data: Serialized rule data (string or bytes)

        Returns:
            Reconstructed Rule AST node

        Raises:
            DeserializationError: If deserialization fails
            ValidationError: If data is invalid

        Example:
            >>> rule = plugin.deserialize(yaml_data)
            >>> print(rule.action)
            Action.ALERT
        """
        ...


# ============================================================================
# Analysis Plugin Interface
# ============================================================================


class AnalysisPlugin(ABC):
    """
    Base class for analysis plugins.

    Analysis plugins perform static analysis, optimization, and validation
    on parsed rules. They can analyze individual rules or entire rulesets.

    Use Cases:
        - Security auditing (detect overly permissive rules)
        - Performance analysis (identify inefficient patterns)
        - Coverage analysis (find gaps in rule coverage)
        - Optimization recommendations
        - Custom linting and validation
        - Rule complexity metrics

    Example:
        >>> class SecurityAuditor(AnalysisPlugin):
        ...     def analyze(self, rule):
        ...         issues = []
        ...         if self._is_too_broad(rule):
        ...             issues.append({'severity': 'high', 'message': '...'})
        ...         return {'issues': issues}
    """

    @abstractmethod
    def analyze(self, rule: Rule) -> dict[str, Any]:
        """
        Analyze rule and return results.

        Args:
            rule: AST Rule node to analyze

        Returns:
            Analysis results dictionary with plugin-specific structure.
            Recommended keys:
                - 'issues': List of issue dicts with 'severity' and 'message'
                - 'score': Numeric quality score (0-100)
                - 'metrics': Performance/complexity metrics
                - 'suggestions': List of improvement suggestions

        Example:
            >>> results = plugin.analyze(rule)
            >>> print(results)
            {
                'issues': [
                    {'severity': 'high', 'message': 'Rule too broad'},
                    {'severity': 'medium', 'message': 'Missing fast_pattern'}
                ],
                'score': 65,
                'metrics': {'complexity': 8, 'pattern_count': 3}
            }
        """
        ...


# ============================================================================
# Query Plugin Interface
# ============================================================================


class QueryPlugin(ABC):
    """
    Base class for query plugins.

    Query plugins extend the query system with custom selectors, optimizations,
    and indexing strategies for efficient rule searching.

    Use Cases:
        - Custom selector types (e.g., regex-based selectors)
        - Query optimization strategies
        - Index providers for large rulesets
        - Caching strategies
        - Distributed query execution

    Example:
        >>> class RegexSelector(QueryPlugin):
        ...     def create_selector(self, pattern):
        ...         return MyRegexSelector(pattern)
    """

    @abstractmethod
    def get_selector_type(self) -> str:
        """
        Get custom selector type name.

        Returns:
            Selector type identifier (e.g., 'regex', 'xpath')

        Example:
            >>> plugin.get_selector_type()
            'regex'
        """
        ...

    @abstractmethod
    def create_selector(self, query: str) -> Any:
        """
        Create a custom selector instance.

        Args:
            query: Query string in plugin-specific format

        Returns:
            Selector object implementing SelectorProtocol

        Raises:
            QuerySyntaxError: If query is invalid

        Example:
            >>> selector = plugin.create_selector(r'msg:.*malware.*')
        """
        ...


# ============================================================================
# Plugin Metadata
# ============================================================================


class PluginMetadata:
    """
    Plugin metadata and capabilities descriptor.

    Plugins should define metadata for discovery and compatibility checking.

    Attributes:
        name: Plugin name
        version: Plugin version
        author: Plugin author
        description: Short description
        requires_surinort: Compatible surinort-ast version range
        capabilities: List of required capabilities
        dependencies: List of plugin dependencies
    """

    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        requires_surinort: str = ">=1.0.0",
        capabilities: list[str] | None = None,
        dependencies: list[str] | None = None,
    ):
        """
        Initialize plugin metadata.

        Args:
            name: Plugin name (lowercase, underscore-separated)
            version: Semantic version (MAJOR.MINOR.PATCH)
            author: Author name or organization
            description: Brief plugin description
            requires_surinort: Compatible surinort-ast version range
            capabilities: Required system capabilities
            dependencies: Other plugin dependencies
        """
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.requires_surinort = requires_surinort
        self.capabilities = capabilities or []
        self.dependencies = dependencies or []

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"PluginMetadata(name={self.name!r}, version={self.version!r}, author={self.author!r})"
        )


# ============================================================================
# License Information
# ============================================================================

__all__ = [
    "AnalysisPlugin",
    "ParserPlugin",
    "PluginMetadata",
    "QueryPlugin",
    "SerializerPlugin",
    "SurinortPlugin",
]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
