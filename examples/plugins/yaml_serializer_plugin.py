"""
Example YAML serializer plugin for surinort-ast.

This plugin demonstrates how to create a custom serialization plugin that
serializes IDS rules to YAML format and deserializes them back to AST nodes.

Installation:
    pip install pyyaml

Usage:
    >>> from surinort_ast.plugins import get_registry
    >>> from surinort_ast.parsing import parse_rule
    >>>
    >>> # Plugin auto-registers on import
    >>> import yaml_serializer_plugin
    >>>
    >>> # Get serializer from registry
    >>> registry = get_registry()
    >>> yaml_plugin = registry.get_serializer("yaml")
    >>>
    >>> # Use serializer
    >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
    >>> yaml_data = yaml_plugin.serialize(rule)
    >>> print(yaml_data)

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from surinort_ast.plugins import SerializerPlugin, get_registry

if TYPE_CHECKING:
    from surinort_ast.core.nodes import Rule
    from surinort_ast.plugins.registry import PluginRegistry


class YAMLSerializerPlugin(SerializerPlugin):
    """
    YAML serializer plugin for IDS rules.

    This plugin serializes Rule AST nodes to human-readable YAML format
    and deserializes YAML back to Rule objects.

    Features:
        - Human-readable YAML output
        - Customizable indentation
        - Optional key sorting
        - Full roundtrip support (serialize -> deserialize)

    Example:
        >>> plugin = YAMLSerializerPlugin(indent=2, sort_keys=True)
        >>> yaml_data = plugin.serialize(rule)
    """

    def __init__(self, indent: int = 2, sort_keys: bool = True):
        """
        Initialize YAML serializer.

        Args:
            indent: Number of spaces for indentation (default: 2)
            sort_keys: Sort dictionary keys alphabetically (default: True)
        """
        self.indent = indent
        self.sort_keys = sort_keys

    @property
    def name(self) -> str:
        """Plugin name."""
        return "yaml_serializer"

    @property
    def version(self) -> str:
        """Plugin version."""
        return "1.0.0"

    def get_format_name(self) -> str:
        """
        Get serialization format name.

        Returns:
            Format identifier: "yaml"
        """
        return "yaml"

    def serialize(self, rule: Rule) -> str:
        """
        Serialize Rule to YAML format.

        Args:
            rule: Rule AST node to serialize

        Returns:
            YAML string representation

        Raises:
            ImportError: If pyyaml is not installed
            SerializationError: If serialization fails

        Example:
            >>> yaml_data = plugin.serialize(rule)
            >>> print(yaml_data)
            action: alert
            header:
              protocol: tcp
              src_addr:
                node_type: AnyAddress
              ...
        """
        try:
            import yaml
        except ImportError as e:
            raise ImportError(
                "pyyaml is required for YAML serialization. Install it with: pip install pyyaml"
            ) from e

        try:
            # Convert Rule to dictionary using Pydantic's model_dump
            rule_dict = rule.model_dump(
                mode="python",
                exclude_none=False,
                exclude_unset=False,
            )

            # Serialize to YAML
            yaml_str = yaml.dump(
                rule_dict,
                default_flow_style=False,
                indent=self.indent,
                sort_keys=self.sort_keys,
                allow_unicode=True,
            )

            return yaml_str

        except Exception as e:
            raise RuntimeError(f"YAML serialization failed: {e}") from e

    def deserialize(self, data: str) -> Rule:
        """
        Deserialize YAML to Rule AST node.

        Args:
            data: YAML string to deserialize

        Returns:
            Reconstructed Rule object

        Raises:
            ImportError: If pyyaml is not installed
            DeserializationError: If deserialization fails
            ValidationError: If YAML data is invalid

        Example:
            >>> yaml_data = "action: alert\\nheader: ..."
            >>> rule = plugin.deserialize(yaml_data)
            >>> print(rule.action)
            Action.ALERT
        """
        try:
            import yaml
        except ImportError as e:
            raise ImportError(
                "pyyaml is required for YAML deserialization. Install it with: pip install pyyaml"
            ) from e

        try:
            # Parse YAML
            rule_dict = yaml.safe_load(data)

            if not isinstance(rule_dict, dict):
                raise ValueError("YAML data must be a dictionary")

            # Import Rule for validation
            from surinort_ast.core.nodes import Rule

            # Reconstruct Rule from dictionary using Pydantic's model_validate
            rule = Rule.model_validate(rule_dict)

            return rule

        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}") from e
        except Exception as e:
            raise RuntimeError(f"YAML deserialization failed: {e}") from e

    def register(self, registry: PluginRegistry) -> None:
        """
        Register plugin with the global registry.

        Args:
            registry: Global plugin registry
        """
        registry.register_serializer(self.get_format_name(), self)


# ============================================================================
# Auto-register on import
# ============================================================================

# Create plugin instance and register
_yaml_plugin = YAMLSerializerPlugin()
_yaml_plugin.register(get_registry())

# ============================================================================
# License Information
# ============================================================================

__all__ = ["YAMLSerializerPlugin"]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
