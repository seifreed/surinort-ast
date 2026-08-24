"""Minimal Language Server Protocol support for IDS rules."""

from .server import diagnostics_for_text, hover_for_text, main

__all__ = ["diagnostics_for_text", "hover_for_text", "main"]
