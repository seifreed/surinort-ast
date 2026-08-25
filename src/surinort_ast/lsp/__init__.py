"""Minimal Language Server Protocol support for IDS rules."""

from .server import (
    code_actions_for_text,
    completion_items,
    diagnostics_for_text,
    format_document,
    formatting_edits_for_text,
    hover_for_text,
    main,
)

__all__ = [
    "code_actions_for_text",
    "completion_items",
    "diagnostics_for_text",
    "format_document",
    "formatting_edits_for_text",
    "hover_for_text",
    "main",
]
