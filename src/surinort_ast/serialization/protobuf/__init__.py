"""
Protocol Buffers serialization module for Surinort-AST.

This module provides efficient binary serialization/deserialization for
Suricata/Snort rule AST nodes using Protocol Buffers.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .serializer import (
    ProtobufError,
    ProtobufSerializer,
    from_protobuf,
    to_protobuf,
)

__all__ = [
    "ProtobufError",
    "ProtobufSerializer",
    "from_protobuf",
    "to_protobuf",
]
