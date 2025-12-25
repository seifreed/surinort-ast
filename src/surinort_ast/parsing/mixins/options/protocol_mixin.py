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

from lark import Token

from ....core.nodes import GenericOption


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
        return GenericOption(keyword="urilen", value=value_str, raw=f"urilen:{value_str}")

    def urilen_value(self, items: Sequence[Token]) -> str:
        """
        Extract urilen value with optional comparison operator.

        Args:
            items: Sequence containing INT token

        Returns:
            Value string

        Note:
            Operator information is lost during parsing (see urilen_option note).
        """
        if items:
            return str(items[0].value)
        return ""

    # ========================================================================
    # Data Availability Options
    # ========================================================================

    def isdataat_option(self, items: Sequence[Token]) -> GenericOption:
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
        value_str = ",".join(str(item.value) for item in items)
        return GenericOption(keyword="isdataat", value=value_str, raw=f"isdataat:{value_str}")
