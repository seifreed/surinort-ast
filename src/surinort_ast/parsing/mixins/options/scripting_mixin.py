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

from lark import Token

from ....core.nodes import LuajitOption, LuaOption


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
        negated = False
        script_name = ""

        for item in items:
            if isinstance(item, Token):
                if item.type == "LPAR" or str(item.value) == "!":
                    negated = True
                else:
                    # Extract script name from token
                    script_name = str(item.value)
            elif isinstance(item, str):
                if item == "!":
                    negated = True
                else:
                    script_name = item

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
        negated = False
        script_name = ""

        for item in items:
            if isinstance(item, Token):
                if item.type == "LPAR" or str(item.value) == "!":
                    negated = True
                else:
                    # Extract script name from token
                    script_name = str(item.value)
            elif isinstance(item, str):
                if item == "!":
                    negated = True
                else:
                    script_name = item

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
        if len(items) == 1:
            # Single token (REFERENCE_ID with path)
            return str(items[0].value)
        if len(items) >= 3:
            # WORD "." WORD format (e.g., "script" "." "lua")
            return "".join(
                str(item.value) if isinstance(item, Token) else str(item) for item in items
            )
        # Fallback: join all tokens
        return "".join(str(item.value) if isinstance(item, Token) else str(item) for item in items)
