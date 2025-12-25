"""
Threshold and detection filter options transformer mixin.

Handles transformation of rate limiting options including:
- threshold: Alert rate limiting (limit, threshold, both)
- detection_filter: Alert suppression (require N matches before alerting)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token

from ....core.nodes import GenericOption


class ThresholdOptionsMixin:
    """
    Mixin for transforming threshold and detection filter options.

    This mixin handles rate limiting and alert suppression:
    - threshold: Limit alert rate after first match
    - detection_filter: Require N matches before first alert

    Use Cases:
        - Prevent alert flooding from repeated events
        - Reduce false positives by requiring multiple occurrences
        - Control alert volume in high-traffic environments

    Threshold Types:
        - limit: Alert once per interval
        - threshold: Alert every N matches in interval
        - both: Combine limit and threshold

    Track By:
        - by_src: Track per source IP
        - by_dst: Track per destination IP
    """

    # ========================================================================
    # Threshold Options
    # ========================================================================

    def threshold_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform threshold option (rate limiting).

        Args:
            items: List containing threshold parameters

        Returns:
            GenericOption with keyword="threshold" and formatted parameters

        Usage:
            threshold:type threshold, track by_src, count 10, seconds 60;

        Threshold Types:
            - limit: Alert once per interval
            - threshold: Alert every N matches in interval
            - both: Combine limit and threshold

        Track By:
            - by_src: Track per source IP
            - by_dst: Track per destination IP

        Parameters:
            - count: Number of matches
            - seconds: Time interval

        Use Case:
            Prevent alert flooding from repeated events.
        """
        # items[0] should be threshold_params which is a list of tuples
        params = items[0] if items else []

        # Build params string
        param_strs = []
        for item in params:
            if isinstance(item, tuple) and len(item) == 2:
                param_strs.append(f"{item[0]} {item[1]}")
            elif isinstance(item, Token):
                param_strs.append(str(item.value))
            else:
                param_strs.append(str(item))

        params_str = ", ".join(param_strs)
        return GenericOption(keyword="threshold", value=params_str, raw=f"threshold:{params_str}")

    def threshold_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through threshold params."""
        return items

    def threshold_param(self, items: Sequence[Token]) -> tuple[str, str]:
        """
        Parse threshold parameter (key value pair).

        Args:
            items: [key, value] tokens

        Returns:
            Tuple of (key, value) strings
        """
        if len(items) >= 2:
            key = str(items[0].value)
            value = str(items[1].value)
            return (key, value)
        if len(items) == 1:
            return (str(items[0].value), "")
        return ("", "")

    # ========================================================================
    # Detection Filter Options
    # ========================================================================

    def detection_filter_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform detection_filter option (alert suppression).

        Args:
            items: List containing detection_filter parameters

        Returns:
            GenericOption with keyword="detection_filter" and formatted parameters

        Usage:
            detection_filter:track by_src, count 10, seconds 60;

        Parameters:
            - track: by_src or by_dst
            - count: Minimum match count before alerting
            - seconds: Time window

        Difference from threshold:
            - threshold: Limits alerts after first match
            - detection_filter: Requires N matches before first alert

        Use Case:
            Reduce false positives by requiring repeated events.
        """
        # items[0] is the list of tuples from detection_params
        params = items[0] if items else []

        param_strs = []
        for item in params:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                # item is a tuple from detection_param: (key, value)
                key = str(item[0].value if isinstance(item[0], Token) else item[0])
                value = str(item[1].value if isinstance(item[1], Token) else item[1])
                param_strs.append(f"{key} {value}")
            elif isinstance(item, Token):
                param_strs.append(str(item.value))
            else:
                param_strs.append(str(item))

        params_str = ", ".join(param_strs)
        return GenericOption(
            keyword="detection_filter",
            value=params_str,
            raw=f"detection_filter:{params_str}",
        )

    def detection_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through detection params."""
        return items

    def detection_param(self, items: Sequence[Token]) -> tuple[str, str]:
        """
        Parse detection_filter parameter (key value pair).

        Args:
            items: [key, value] tokens

        Returns:
            Tuple of (key, value) strings
        """
        if len(items) >= 2:
            return (str(items[0].value), str(items[1].value))
        return ("", "")
