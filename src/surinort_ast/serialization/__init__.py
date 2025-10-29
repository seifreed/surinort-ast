"""
Serialization module for AST nodes.

This module provides JSON serialization and schema generation for AST nodes.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .json_serializer import (
    JSONSerializer,
    from_dict,
    from_json,
    to_dict,
    to_json,
)
from .schema_generator import (
    SchemaGenerator,
    generate_envelope_schema,
    generate_schema,
    generate_schema_json,
)

__all__ = [
    # JSON Serialization
    "JSONSerializer",
    # Schema Generation
    "SchemaGenerator",
    "from_dict",
    "from_json",
    "generate_envelope_schema",
    "generate_schema",
    "generate_schema_json",
    "to_dict",
    "to_json",
]
