"""
Option transformation mixin for IDS rule parser.

This mixin is a compositor that combines specialized option transformation mixins.
It delegates to sub-mixins for different categories of rule options:

- MetadataOptionsMixin: msg, sid, rev, gid, classtype, priority, reference, metadata
- FlowTrackingOptionsMixin: flow, flowbits, flowint
- ThresholdOptionsMixin: threshold, detection_filter
- BufferSelectionOptionsMixin: Sticky buffers (http.uri, dns_query, tls.sni, etc.)
- PatternMatchingOptionsMixin: pcre
- ProtocolSpecificOptionsMixin: urilen, isdataat
- FileOperationsOptionsMixin: filestore, tag, flags
- ScriptingOptionsMixin: lua, luajit
- GenericOptionsMixin: generic_option, options list, terminals

The mixin is designed to be composed with other transformer mixins in RuleTransformer.

Architecture:
    This file serves as the public API for option transformation. All sub-mixins
    are composed through multiple inheritance, providing a single OptionTransformerMixin
    class that maintains backward compatibility while delegating implementation to
    specialized, maintainable sub-mixins.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

# Re-export helper functions for backward compatibility
from .options import (
    parse_pcre_pattern,
    parse_pcre_pattern_cached,
    parse_quoted_string,
    parse_quoted_string_cached,
)

# Import all specialized sub-mixins
from .options.buffer_mixin import BufferSelectionOptionsMixin
from .options.fileops_mixin import FileOperationsOptionsMixin
from .options.flow_mixin import FlowTrackingOptionsMixin
from .options.generic_mixin import GenericOptionsMixin
from .options.metadata_mixin import MetadataOptionsMixin
from .options.pattern_mixin import PatternMatchingOptionsMixin
from .options.protocol_mixin import ProtocolSpecificOptionsMixin
from .options.scripting_mixin import ScriptingOptionsMixin
from .options.threshold_mixin import ThresholdOptionsMixin

# Re-export helpers for backward compatibility
__all__ = [
    "OptionTransformerMixin",
    "parse_pcre_pattern",
    "parse_pcre_pattern_cached",
    "parse_quoted_string",
    "parse_quoted_string_cached",
]


class OptionTransformerMixin(
    MetadataOptionsMixin,
    FlowTrackingOptionsMixin,
    ThresholdOptionsMixin,
    BufferSelectionOptionsMixin,
    PatternMatchingOptionsMixin,
    ProtocolSpecificOptionsMixin,
    FileOperationsOptionsMixin,
    ScriptingOptionsMixin,
    GenericOptionsMixin,
):
    """
    Mixin for transforming rule option AST nodes.

    This compositor combines specialized mixins for different option categories,
    providing a complete option transformation interface through composition.

    Sub-Mixins (in MRO order):
        1. MetadataOptionsMixin: Basic metadata (msg, sid, rev, gid, classtype, priority)
                                 and references (reference, metadata)
        2. FlowTrackingOptionsMixin: Flow tracking (flow, flowbits, flowint)
        3. ThresholdOptionsMixin: Rate limiting (threshold, detection_filter)
        4. BufferSelectionOptionsMixin: Sticky buffers (http.uri, dns_query, etc.)
        5. PatternMatchingOptionsMixin: Pattern matching (pcre)
        6. ProtocolSpecificOptionsMixin: Protocol options (urilen, isdataat)
        7. FileOperationsOptionsMixin: File/tag operations (filestore, tag, flags)
        8. ScriptingOptionsMixin: Scripting (lua, luajit)
        9. GenericOptionsMixin: Generic fallback and core list processing

    Option Categories:
        1. Required: msg, sid, rev (every rule should have these)
        2. Classification: classtype, priority, reference (rule categorization)
        3. Metadata: metadata (key-value pairs for rule management)
        4. Detection: pcre, flow, flowbits (pattern and state matching)
        5. Performance: threshold, detection_filter (rate limiting)
        6. Protocol: urilen, isdataat, buffer selection (protocol-specific)
        7. Actions: filestore, tag (packet processing actions)
        8. Advanced: lua, luajit (custom scripting)

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method

    Architecture Benefits:
        - Modularity: Each sub-mixin handles a specific domain
        - Maintainability: Smaller files (~100-300 lines vs 1290)
        - Testability: Isolated testing of option categories
        - Extensibility: Easy to add new option categories
        - Clarity: Clear separation of responsibilities
    """

    # All methods are inherited from sub-mixins.
    # This class exists purely for composition and API compatibility.
