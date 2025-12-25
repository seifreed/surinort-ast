"""
Serialization functions for surinort-ast.

This module provides functions for serializing and deserializing Rule ASTs
to/from JSON format, including schema generation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from typing import Any

from ..core.nodes import Rule
from ..exceptions import SerializationError


def to_json(rule: Rule, indent: int | None = 2) -> str:
    """
    Serialize Rule AST to JSON string.

    Args:
        rule: Rule to serialize
        indent: JSON indentation (None for compact)

    Returns:
        JSON string representation

    Raises:
        SerializationError: If serialization fails

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> json_str = to_json(rule)
        >>> print(json_str)
    """
    try:
        # Pydantic v2 model_dump_json
        return rule.model_dump_json(indent=indent, exclude_none=True)
    except Exception as e:
        raise SerializationError(f"Failed to serialize to JSON: {e}") from e


def from_json(data: str | dict[str, Any]) -> Rule:
    """
    Deserialize Rule AST from JSON.

    Args:
        data: JSON string or dict

    Returns:
        Deserialized Rule AST

    Raises:
        SerializationError: If deserialization fails

    Example:
        >>> json_str = '{"action": "alert", "header": {...}, ...}'
        >>> rule = from_json(json_str)
    """
    try:
        # Type-narrowing: data will be dict after this check
        data_dict: dict[str, Any] = json.loads(data) if isinstance(data, str) else data

        # Pydantic v2 model_validate
        return Rule.model_validate(data_dict)
    except json.JSONDecodeError as e:
        raise SerializationError(f"Invalid JSON: {e}") from e
    except Exception as e:
        raise SerializationError(f"Failed to deserialize from JSON: {e}") from e


def to_json_schema() -> dict[str, Any]:
    """
    Generate JSON Schema for Rule AST.

    Returns:
        JSON Schema dict

    Example:
        >>> schema = to_json_schema()
        >>> print(schema["$schema"])
        https://json-schema.org/draft/2020-12/schema
    """
    # Pydantic v2 model_json_schema
    return Rule.model_json_schema()


__all__ = [
    "from_json",
    "to_json",
    "to_json_schema",
]
