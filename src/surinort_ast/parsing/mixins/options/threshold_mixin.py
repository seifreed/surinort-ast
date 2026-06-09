"""
Threshold and detection filter options transformer mixin.

Handles transformation of rate limiting options including:
- threshold: Alert rate limiting (limit, threshold, both)
- detection_filter: Alert suppression (require N matches before alerting)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from lark import Token

from ...helpers import token_to_str
from ._helpers import generic_kv

if TYPE_CHECKING:
    from .. import DiagnosticReporter

from ....core.diagnostics import DiagnosticLevel
from ....core.nodes import DetectionFilterOption, GenericOption, ThresholdOption

logger = logging.getLogger(__name__)


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

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - add_diagnostic(level, message, location) - Diagnostic reporting method
    """

    # Declare expected attributes for type checking
    add_diagnostic: DiagnosticReporter

    # ========================================================================
    # Threshold Options
    # ========================================================================

    def threshold_option(self, items: Sequence[Any]) -> ThresholdOption | GenericOption:
        """
        Transform threshold option (rate limiting).

        Args:
            items: List containing threshold parameters

        Returns:
            ThresholdOption with structured fields, or GenericOption as fallback

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

        # Try to extract structured fields for ThresholdOption
        param_dict: dict[str, str] = {}
        param_strs = []
        for item in params:
            if isinstance(item, tuple) and len(item) == 2:
                key = str(item[0])
                value = str(item[1])
                if key in param_dict:
                    self.add_diagnostic(
                        DiagnosticLevel.WARNING,
                        f"Duplicate threshold parameter '{key}' "
                        f"(was '{param_dict[key]}', now '{value}')",
                    )
                param_dict[key] = value
                param_strs.append(f"{key} {value}")
            else:
                param_strs.append(token_to_str(item))

        # Build ThresholdOption if all required fields are present
        if all(k in param_dict for k in ("type", "track", "count", "seconds")):
            try:
                return ThresholdOption(
                    threshold_type=param_dict["type"],
                    track=param_dict["track"],
                    count=int(param_dict["count"]),
                    seconds=int(param_dict["seconds"]),
                )
            except (ValueError, TypeError) as e:
                logger.debug(f"Threshold structured parse failed: {e}")
                self.add_diagnostic(
                    DiagnosticLevel.WARNING,
                    f"Could not parse threshold as structured option: {e}. "
                    "Falling back to generic representation.",
                )

        # Fallback to GenericOption for non-standard threshold syntax
        if not all(k in param_dict for k in ("type", "track", "count", "seconds")):
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                "Threshold option missing required fields (type, track, count, seconds). "
                "Using generic representation.",
            )
        params_str = ", ".join(param_strs)
        return generic_kv("threshold", params_str)

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

    def detection_filter_option(
        self, items: Sequence[Any]
    ) -> DetectionFilterOption | GenericOption:
        """
        Transform detection_filter option (alert suppression).

        Args:
            items: List containing detection_filter parameters

        Returns:
            DetectionFilterOption with structured fields, or GenericOption as fallback

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

        param_dict: dict[str, str] = {}
        param_strs = []
        for item in params:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                # item is a tuple from detection_param: (key, value)
                key = token_to_str(item[0])
                value = token_to_str(item[1])
                param_dict[key] = value
                param_strs.append(f"{key} {value}")
            else:
                param_strs.append(token_to_str(item))

        # Build DetectionFilterOption if all required fields are present
        if all(k in param_dict for k in ("track", "count", "seconds")):
            try:
                return DetectionFilterOption(
                    track=param_dict["track"],
                    count=int(param_dict["count"]),
                    seconds=int(param_dict["seconds"]),
                )
            except (ValueError, TypeError) as e:
                logger.debug(f"detection_filter structured parse failed: {e}")
                self.add_diagnostic(
                    DiagnosticLevel.WARNING,
                    f"Could not parse detection_filter as structured option: {e}. "
                    "Falling back to generic representation.",
                )

        # Fallback to GenericOption for non-standard syntax
        if not all(k in param_dict for k in ("track", "count", "seconds")):
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                "detection_filter option missing required fields (track, count, seconds). "
                "Using generic representation.",
            )
        params_str = ", ".join(param_strs)
        return generic_kv("detection_filter", params_str)

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
