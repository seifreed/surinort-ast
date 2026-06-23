"""
Shared option-type categories for analysis.

Centralises which option node types are position-significant so cost
estimation and optimization strategies share one source of truth and never
drift apart.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

# Sticky content modifiers that attach to the preceding content option: they
# adjust its cost and a non-modifier option between them breaks the chain.
CONTENT_MODIFIER_OPTIONS: frozenset[str] = frozenset(
    {
        "DepthOption",
        "OffsetOption",
        "DistanceOption",
        "WithinOption",
        "NocaseOption",
        "RawbytesOption",
        "StartswithOption",
        "EndswithOption",
        "FastPatternOption",
    }
)

# Options whose meaning depends on their position in the option sequence:
# the content modifiers above plus sticky-buffer selection and Lua/LuaJIT
# scripts. Reordering them, or removing a "duplicate", detaches them from the
# content they qualify and silently changes detection semantics, so strategies
# must treat their presence as order-significant.
POSITIONAL_OPTIONS: frozenset[str] = CONTENT_MODIFIER_OPTIONS | frozenset(
    {
        "BufferSelectOption",
        "LuaOption",
        "LuajitOption",
    }
)
