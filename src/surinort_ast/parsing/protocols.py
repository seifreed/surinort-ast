"""Backward compatibility protocol aliases for parser interfaces.

Historically the parser interface module was named ``protocols.py`` in some
older branches. Keep this shim to preserve imports.
"""

from .interfaces import IParser

__all__ = ["IParser"]
