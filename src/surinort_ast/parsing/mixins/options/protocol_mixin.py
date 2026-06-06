"""
Protocol-specific options transformer mixin.

Handles transformation of protocol-specific inspection options including:
- urilen: HTTP URI length checks
- isdataat: Data availability checks at specific offsets

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token, Tree

from ....core.nodes import GenericOption
from ...helpers import token_to_str
from ._helpers import generic_kv


class ProtocolSpecificOptionsMixin:
    """
    Mixin for transforming protocol-specific options.

    This mixin handles options tied to specific protocols or payload inspection:
    - urilen: HTTP URI length validation (detect abnormal URIs)
    - isdataat: Verify data availability at offset (prevent truncation issues)

    Use Cases:
        - Detect abnormally long URIs (SQLi, XSS attacks)
        - Verify sufficient data before pattern matching
        - Protocol anomaly detection
    """

    # ========================================================================
    # HTTP Protocol Options
    # ========================================================================

    def urilen_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform urilen option (HTTP URI length check).

        Args:
            items: List containing urilen value (may include operator)

        Returns:
            GenericOption with keyword="urilen" and value string

        Usage:
            urilen:21;
            urilen:<100;
            urilen:>500;

        Operators:
            - N: Exact length
            - <N: Less than N
            - >N: Greater than N

        Use Case:
            Detect abnormally long URIs (often used in attacks like SQLi, XSS).

        Note:
            The grammar matches operators but Lark discards literal string matches,
            so only the INT token is preserved. Full operator support would require
            defining operator terminals in the grammar.
        """
        # items[0] is the transformed urilen_value (which is a string like "21" or "<100")
        value_str = str(items[0]) if items else ""
        return generic_kv("urilen", value_str)

    def urilen_value(self, items: Sequence[Token]) -> str:
        """
        Extract urilen value with optional comparison operator.

        Args:
            items: Sequence containing optional URILEN_OP token and INT token

        Returns:
            Value string including operator (e.g., "<100", ">500", "21")
        """
        if not items:
            return ""

        # Items may be [URILEN_OP, INT] or [INT]
        parts = [str(token.value) for token in items]
        return "".join(parts)

    # ========================================================================
    # Data Availability Options
    # ========================================================================

    def isdataat_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform isdataat option (data availability check).

        Args:
            items: Sequence of isdataat parameter tokens

        Returns:
            GenericOption with keyword="isdataat" and comma-separated value

        Usage:
            isdataat:10;
            isdataat:10,relative;

        Parameters:
            - N: Offset to check
            - relative: Relative to previous match
            - rawbytes: Use raw payload (ignore decoding)

        Use Case:
            Verify sufficient data exists before matching subsequent patterns.
            Prevents false positives from truncated payloads.
        """
        negated = bool(items) and isinstance(items[0], Tree) and items[0].data == "neg_bang"
        rest = items[1:] if negated else items
        value_str = ",".join(token_to_str(item) for item in rest)
        prefix = "!" if negated else ""
        return generic_kv("isdataat", f"{prefix}{value_str}")
