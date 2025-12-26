"""
Option transformer sub-mixins and helpers.

This package contains specialized mixins for different categories of IDS rule options.
Each mixin handles a specific domain of option transformation.

Mixins:
    - MetadataOptionsMixin: msg, sid, rev, gid, classtype, priority, reference, metadata
    - FlowTrackingOptionsMixin: flow, flowbits, flowint
    - ThresholdOptionsMixin: threshold, detection_filter
    - BufferSelectionOptionsMixin: Sticky buffers (http.uri, dns_query, etc.)
    - PatternMatchingOptionsMixin: pcre
    - ProtocolSpecificOptionsMixin: urilen, isdataat
    - FileOperationsOptionsMixin: filestore, tag, flags
    - ScriptingOptionsMixin: lua, luajit
    - GenericOptionsMixin: generic_option, options list, terminals

Helpers:
    - parse_quoted_string: Parse and unescape quoted strings
    - parse_pcre_pattern: Parse PCRE pattern into pattern and flags

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ._helpers import (
    parse_pcre_pattern,
    parse_pcre_pattern_cached,
    parse_quoted_string,
    parse_quoted_string_cached,
)
from .buffer_mixin import BufferSelectionOptionsMixin
from .fileops_mixin import FileOperationsOptionsMixin
from .flow_mixin import FlowTrackingOptionsMixin
from .generic_mixin import GenericOptionsMixin
from .metadata_mixin import MetadataOptionsMixin
from .pattern_mixin import PatternMatchingOptionsMixin
from .protocol_mixin import ProtocolSpecificOptionsMixin
from .scripting_mixin import ScriptingOptionsMixin
from .threshold_mixin import ThresholdOptionsMixin

__all__ = [
    "BufferSelectionOptionsMixin",
    "FileOperationsOptionsMixin",
    "FlowTrackingOptionsMixin",
    "GenericOptionsMixin",
    # Mixins
    "MetadataOptionsMixin",
    "PatternMatchingOptionsMixin",
    "ProtocolSpecificOptionsMixin",
    "ScriptingOptionsMixin",
    "ThresholdOptionsMixin",
    "parse_pcre_pattern",
    "parse_pcre_pattern_cached",
    # Helpers (re-exported for backward compatibility)
    "parse_quoted_string",
    "parse_quoted_string_cached",
]
