"""
JSON serialization for AST nodes.

This module provides JSON serialization/deserialization for Suricata/Snort
rule AST nodes with metadata and version tracking.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import TypeAdapter

from surinort_ast.core.nodes import Rule
from surinort_ast.version import __ast_version__


class JSONSerializer:
    """
    JSON serializer for AST nodes.

    Provides serialization/deserialization with metadata tracking.

    Attributes:
        include_metadata: Whether to include metadata envelope
        indent: JSON indentation (None for compact)
        sort_keys: Whether to sort keys for stable output
    """

    def __init__(
        self,
        include_metadata: bool = True,
        indent: int | None = 2,
        sort_keys: bool = True,
    ) -> None:
        """
        Initialize the JSON serializer.

        Args:
            include_metadata: Include metadata envelope (ast_version, timestamp)
            indent: JSON indentation spaces (None for compact)
            sort_keys: Sort keys for deterministic output
        """
        self.include_metadata = include_metadata
        self.indent = indent
        self.sort_keys = sort_keys

    def to_json(
        self,
        rule: Rule | Sequence[Rule],
        **kwargs: Any,
    ) -> str:
        """
        Serialize rule(s) to JSON string.

        Args:
            rule: A single rule or sequence of rules
            **kwargs: Additional arguments passed to json.dumps

        Returns:
            JSON string representation

        Example:
            >>> serializer = JSONSerializer()
            >>> json_str = serializer.to_json(rule)
            >>> print(json_str)
        """
        if isinstance(rule, Rule):
            data = self._serialize_single_rule(rule)
        else:
            data = self._serialize_multiple_rules(rule)

        # Apply defaults if not provided in kwargs
        kwargs.setdefault("indent", self.indent)
        kwargs.setdefault("sort_keys", self.sort_keys)
        kwargs.setdefault("ensure_ascii", False)

        return json.dumps(data, **kwargs)

    def from_json(self, data: str | dict[str, Any]) -> Rule | Sequence[Rule]:
        """
        Deserialize rule(s) from JSON.

        Args:
            data: JSON string or dictionary

        Returns:
            Deserialized Rule or sequence of Rules

        Raises:
            ValueError: If JSON is invalid or incompatible

        Example:
            >>> serializer = JSONSerializer()
            >>> rule = serializer.from_json(json_str)
        """
        # Parse JSON if string
        parsed = json.loads(data) if isinstance(data, str) else data

        # Check if it's a metadata envelope
        if self.include_metadata and "data" in parsed:
            self._validate_metadata(parsed)
            parsed = parsed["data"]

        # Determine if single or multiple rules
        if "rules" in parsed:
            # Multiple rules
            rules_data = parsed["rules"]
            adapter: TypeAdapter[Sequence[Rule]] = TypeAdapter(Sequence[Rule])
            return adapter.validate_python(rules_data)
        # Single rule
        adapter_single: TypeAdapter[Rule] = TypeAdapter(Rule)
        return adapter_single.validate_python(parsed)

    def to_dict(self, rule: Rule | Sequence[Rule]) -> dict[str, Any]:
        """
        Convert rule(s) to dictionary (without JSON encoding).

        Args:
            rule: A single rule or sequence of rules

        Returns:
            Dictionary representation

        Example:
            >>> serializer = JSONSerializer()
            >>> data = serializer.to_dict(rule)
        """
        if isinstance(rule, Rule):
            return self._serialize_single_rule(rule)
        return self._serialize_multiple_rules(rule)

    def from_dict(self, data: dict[str, Any]) -> Rule | Sequence[Rule]:
        """
        Create rule(s) from dictionary.

        Args:
            data: Dictionary representation

        Returns:
            Deserialized Rule or sequence of Rules
        """
        return self.from_json(data)

    def _serialize_single_rule(self, rule: Rule) -> dict[str, Any]:
        """
        Serialize a single rule.

        Args:
            rule: The rule to serialize

        Returns:
            Dictionary representation
        """
        # Use Pydantic's model_dump for serialization
        rule_data = rule.model_dump(mode="json", exclude_none=False)

        if self.include_metadata:
            return {
                "ast_version": __ast_version__,
                "timestamp": datetime.now(UTC).isoformat(),
                "count": 1,
                "data": rule_data,
            }
        return rule_data

    def _serialize_multiple_rules(self, rules: Sequence[Rule]) -> dict[str, Any]:
        """
        Serialize multiple rules.

        Args:
            rules: Sequence of rules

        Returns:
            Dictionary representation
        """
        rules_data = [rule.model_dump(mode="json", exclude_none=False) for rule in rules]

        if self.include_metadata:
            return {
                "ast_version": __ast_version__,
                "timestamp": datetime.now(UTC).isoformat(),
                "count": len(rules),
                "data": {"rules": rules_data},
            }
        return {"rules": rules_data}

    def _validate_metadata(self, data: dict[str, Any]) -> None:
        """
        Validate metadata envelope.

        Args:
            data: Dictionary with metadata

        Raises:
            ValueError: If metadata is invalid or version incompatible
        """
        if "ast_version" not in data:
            raise ValueError("Missing ast_version in metadata")

        version = data["ast_version"]
        if not self._is_compatible_version(version):
            raise ValueError(f"Incompatible AST version: {version} (current: {__ast_version__})")

    def _is_compatible_version(self, version: str) -> bool:
        """
        Check if a version is compatible with current AST version.

        Args:
            version: Version string to check

        Returns:
            True if compatible, False otherwise
        """
        # For now, exact match required
        # In future, could implement semantic versioning compatibility
        return version == __ast_version__


# Convenience functions


def to_json(
    rule: Rule | Sequence[Rule],
    include_metadata: bool = True,
    indent: int | None = 2,
    sort_keys: bool = True,
    **kwargs: Any,
) -> str:
    """
    Serialize rule(s) to JSON string.

    Args:
        rule: A single rule or sequence of rules
        include_metadata: Include metadata envelope
        indent: JSON indentation (None for compact)
        sort_keys: Sort keys for stable output
        **kwargs: Additional arguments for json.dumps

    Returns:
        JSON string

    Example:
        >>> from surinort_ast.serialization import to_json
        >>> json_str = to_json(rule)
    """
    serializer = JSONSerializer(
        include_metadata=include_metadata,
        indent=indent,
        sort_keys=sort_keys,
    )
    return serializer.to_json(rule, **kwargs)


def from_json(data: str | dict[str, Any]) -> Rule | Sequence[Rule]:
    """
    Deserialize rule(s) from JSON.

    Args:
        data: JSON string or dictionary

    Returns:
        Rule or sequence of Rules

    Example:
        >>> from surinort_ast.serialization import from_json
        >>> rule = from_json(json_str)
    """
    serializer = JSONSerializer()
    return serializer.from_json(data)


def to_dict(rule: Rule | Sequence[Rule], include_metadata: bool = True) -> dict[str, Any]:
    """
    Convert rule(s) to dictionary.

    Args:
        rule: A single rule or sequence of rules
        include_metadata: Include metadata envelope

    Returns:
        Dictionary representation

    Example:
        >>> from surinort_ast.serialization import to_dict
        >>> data = to_dict(rule)
    """
    serializer = JSONSerializer(include_metadata=include_metadata)
    return serializer.to_dict(rule)


def from_dict(data: dict[str, Any]) -> Rule | Sequence[Rule]:
    """
    Create rule(s) from dictionary.

    Args:
        data: Dictionary representation

    Returns:
        Rule or sequence of Rules

    Example:
        >>> from surinort_ast.serialization import from_dict
        >>> rule = from_dict(data)
    """
    serializer = JSONSerializer()
    return serializer.from_dict(data)
