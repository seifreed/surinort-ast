"""
Scripting options transformer mixin.

Handles transformation of scripting-related options including:
- lua: Lua script execution for custom detection logic
- luajit: LuaJIT script execution (optimized Lua)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token, Tree

from ....core.nodes import LuajitOption, LuaOption
from ...helpers import is_marker, token_to_str


def _script_negation(items: Sequence[Any]) -> tuple[bool, str]:
    """Return (negated, script_name) from a lua/luajit option's children."""
    negated = any(is_marker(item, "neg_bang") for item in items)
    script_name = next(
        (item for item in items if not isinstance(item, Tree)),
        "",
    )
    return negated, str(script_name) if script_name else ""


class ScriptingOptionsMixin:
    """
    Mixin for transforming scripting options.

    This mixin handles custom script execution:
    - lua: Execute Lua scripts for complex detection logic
    - luajit: Execute LuaJIT scripts (performance-optimized Lua)

    Use Cases:
        - Complex detection logic not expressible in standard syntax
        - Custom protocol parsing
        - Stateful tracking beyond flowbits/flowint
        - Advanced packet inspection

    Security Note:
        Lua scripts have full access to packet data and system resources.
        Only use trusted scripts from verified sources.
    """

    # ========================================================================
    # Lua Scripting Options
    # ========================================================================

    def lua_option(self, items: Sequence[Any]) -> LuaOption:
        """
        Transform lua option (Lua script execution).

        Args:
            items: List containing optional "!" and script name

        Returns:
            LuaOption node with script name and negation flag

        Usage:
            lua:script.lua;
            lua:!script.lua;

        Negation:
            lua:!script.lua; - Alert if script returns false

        Use Case:
            Run custom Lua code for complex detection logic not expressible
            in standard rule syntax. Allows arbitrary packet inspection,
            protocol parsing, and stateful tracking.

        Security:
            Lua scripts have full access to packet data and system resources.
            Only use trusted scripts.
        """
        negated, script_name = _script_negation(items)
        return LuaOption(script_name=script_name, negated=negated)

    def luajit_option(self, items: Sequence[Any]) -> LuajitOption:
        """
        Transform luajit option (LuaJIT script execution).

        Args:
            items: List containing optional "!" and script name

        Returns:
            LuajitOption node with script name and negation flag

        Usage:
            luajit:script.lua;
            luajit:!script.lua;

        LuaJIT vs Lua:
            LuaJIT is a Just-In-Time compiler for Lua providing:
            - Significantly faster execution (5-50x speedup)
            - Lower memory usage
            - Same Lua 5.1 syntax

        Use Case:
            Performance-critical custom detection logic. Prefer luajit over
            lua when script performance matters (high traffic environments).
        """
        negated, script_name = _script_negation(items)
        return LuajitOption(script_name=script_name, negated=negated)

    def lua_script_name(self, items: Sequence[Token]) -> str:
        """
        Extract Lua script name from tokens.

        Args:
            items: Tokens forming script name (may include path)

        Returns:
            Script name string

        Formats:
            - Simple: script.lua
            - Path: scripts/file.lua
            - Complex: WORD "." WORD format (e.g., "script" "." "lua")
        """
        # A single REFERENCE_ID token, a ``WORD "." WORD`` sequence and any other
        # token run all join to the same string, so concatenate uniformly.
        return "".join(token_to_str(item) for item in items)
