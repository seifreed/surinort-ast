"""Minimal Language Server Protocol support for IDS rules."""

from .server import (
    code_actions_for_text,
    completion_items,
    diagnostics_for_text,
    engine_validation_for_text,
    flowbit_locations,
    format_document,
    formatting_edits_for_text,
    hover_for_text,
    main,
    match_space_preview,
)

__all__ = [
    "code_actions_for_text",
    "completion_items",
    "diagnostics_for_text",
    "engine_validation_for_text",
    "flowbit_locations",
    "format_document",
    "formatting_edits_for_text",
    "hover_for_text",
    "main",
    "match_space_preview",
]
