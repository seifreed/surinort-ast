"""Backward compatibility interfaces for plugin definitions.

Historically plugin interfaces were exposed through ``plugins.interfaces`` in some
earlier versions. Keep this shim to preserve import compatibility.
"""

from .interface import (
    AnalysisPlugin,
    ParserPlugin,
    PluginMetadata,
    QueryPlugin,
    SerializerPlugin,
    SurinortPlugin,
)

__all__ = [
    "AnalysisPlugin",
    "ParserPlugin",
    "PluginMetadata",
    "QueryPlugin",
    "SerializerPlugin",
    "SurinortPlugin",
]
