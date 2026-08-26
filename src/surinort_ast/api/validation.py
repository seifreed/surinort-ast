"""
Validation functions for surinort-ast.

This module provides functions for validating Rule ASTs and generating
diagnostics for errors, warnings, and informational messages.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..analysis.targets import EngineTarget
from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.location import Location
from ..core.nodes import (
    ContentModifier,
    ContentOption,
    FlowbitsOption,
    Rule,
    RuleOption,
    extract_sid,
)

_SINGLETON_OPTIONS = {
    "SidOption": "sid",
    "GidOption": "gid",
    "RevOption": "rev",
    "PriorityOption": "priority",
    "DetectionFilterOption": "detection_filter",
    "ThresholdOption": "threshold",
}
_CONTENT_MODIFIERS = {
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
_BYTE_REFERENCE_FIELDS = {
    "DepthOption": ("value",),
    "OffsetOption": ("value",),
    "DistanceOption": ("value",),
    "WithinOption": ("value",),
    "ByteTestOption": ("bytes_to_extract", "value", "offset"),
    "ByteJumpOption": ("bytes_to_extract", "offset"),
    "ByteExtractOption": ("bytes_to_extract", "offset"),
}
_BYTE_COUNT_OPTIONS = {"ByteTestOption", "ByteJumpOption", "ByteExtractOption"}
_RELATIVE_LIMIT = 1_048_576
_BYTE_TEST_OPERATORS = {
    "!",
    "!=",
    "!&",
    "!<",
    "!<=",
    "!^",
    "!>",
    "!>=",
    "&",
    "<",
    "<=",
    "=",
    ">",
    ">=",
    "^",
}
_OPTION_FEATURES = {
    "BufferSelectOption": "sticky-buffer",
    "FlowbitsOption": "flowbits",
    "ByteTestOption": "byte-ops",
    "ByteJumpOption": "byte-ops",
    "ByteExtractOption": "byte-ops",
    "PcreOption": "pcre",
}
_SURICATA_PRIORITY_MAX = 255
_SNORT2_PRIORITY_MAX = 255
_SNORT3_PRIORITY_MAX = 2_147_483_647
_FLOWBIT_ACTIONS = {"set", "isset", "isnotset", "toggle", "unset", "noalert"}
_FLOWBIT_NAME_REQUIRED = {"set", "isset", "isnotset", "toggle", "unset"}
_FLOWBIT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _option_keyword(option: object) -> str:
    keyword = getattr(option, "keyword", None)
    if isinstance(keyword, str) and keyword:
        return keyword.lower()
    node_name = getattr(option, "node_type", "").removesuffix("Option")
    return re.sub(r"(?<!^)(?=[A-Z])", "_", node_name).lower()


def _modifier_signature(modifier: ContentModifier) -> tuple[str, int | str | None]:
    return modifier.name_str, modifier.value


def _variable_reference(value: object) -> str | None:
    """Return a referenced variable name, or ``None`` for a numeric value."""
    if not isinstance(value, str):
        return None
    candidate = value[1:] if value.startswith("-") else value
    try:
        int(candidate, 0)
    except ValueError:
        return candidate
    return None


def _validate_relative_value(
    name: str, value: object, location: Location | None
) -> list[Diagnostic]:
    if not isinstance(value, int):
        return []
    if name == "distance":
        valid = abs(value) <= _RELATIVE_LIMIT
    elif name == "offset":
        valid = 0 <= value <= _RELATIVE_LIMIT
    else:
        valid = 0 < value <= _RELATIVE_LIMIT
    if valid:
        return []
    minimum = "any value" if name == "distance" else "a value greater than zero"
    return [
        Diagnostic(
            level=DiagnosticLevel.ERROR,
            message=f"{name} must be {minimum} and no more than {_RELATIVE_LIMIT} bytes",
            location=location,
            code="invalid_relative_modifier_range",
            phase="option-chain",
        )
    ]


def _validate_content_modifier_combination(
    names: set[str], location: Location | None
) -> list[Diagnostic]:
    conflicts: set[str] = set()
    for left, right in (
        ("offset", "distance"),
        ("offset", "within"),
        ("depth", "distance"),
        ("depth", "within"),
    ):
        if left in names and right in names:
            conflicts.update({left, right})
    if "startswith" in names:
        conflicts.update(names & {"depth", "offset", "distance", "within"})
    if "endswith" in names:
        conflicts.update(names & {"offset", "distance", "within"})
    if "startswith" in names and "endswith" in names:
        conflicts.update({"startswith", "endswith"})
    if not conflicts:
        return []
    return [
        Diagnostic(
            level=DiagnosticLevel.ERROR,
            message="Incompatible content modifiers: " + ", ".join(sorted(names)),
            location=location,
            code="incompatible_content_modifiers",
            hint="Use startswith/endswith without conflicting position modifiers.",
            phase="option-chain",
        )
    ]


def _byte_math_fields(value: object) -> dict[str, str]:
    """Extract the simple ``key value`` fields from a byte_math tail."""
    if not isinstance(value, str):
        return {}
    fields: dict[str, str] = {}
    for part in value.split(","):
        pieces = part.strip().split(maxsplit=1)
        if len(pieces) == 2:
            fields[pieces[0].lower()] = pieces[1].strip()
        elif pieces:
            fields[pieces[0].lower()] = ""
    return fields


def _validate_byte_operations(rule: Rule) -> list[Diagnostic]:  # noqa: PLR0912
    diagnostics: list[Diagnostic] = []
    defined: set[str] = set()
    for option in rule.options:
        option_type = option.node_type
        if (
            option_type == "GenericOption"
            and str(getattr(option, "keyword", "")).lower() == "byte_math"
        ):
            fields = _byte_math_fields(getattr(option, "value", None))
            for field_name in ("bytes", "offset", "rvalue"):
                variable = _variable_reference(fields.get(field_name))
                if variable is not None and variable not in defined:
                    diagnostics.append(
                        Diagnostic(
                            level=DiagnosticLevel.WARNING,
                            message=f"Byte-operation variable '{variable}' is not defined earlier in the rule",
                            location=getattr(option, "location", None),
                            code="undefined_byte_variable",
                            hint="Add byte_extract or byte_math before using the variable.",
                            phase="option-chain",
                            confidence="medium",
                        )
                    )
            result = fields.get("result", "")
            if result and not _FLOWBIT_NAME_RE.fullmatch(result):
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Invalid byte_math result variable '{result}'",
                        location=getattr(option, "location", None),
                        code="invalid_byte_variable",
                        phase="option-chain",
                    )
                )
            elif result:
                if result in defined:
                    diagnostics.append(
                        Diagnostic(
                            level=DiagnosticLevel.ERROR,
                            message=f"Byte-operation variable '{result}' is extracted more than once",
                            location=getattr(option, "location", None),
                            code="duplicate_byte_variable",
                            phase="option-chain",
                        )
                    )
                defined.add(result)
        if option_type in _BYTE_COUNT_OPTIONS:
            count = getattr(option, "bytes_to_extract", None)
            if isinstance(count, int) and count < 1:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message="Byte operation length must be greater than zero",
                        location=getattr(option, "location", None),
                        code="invalid_byte_length",
                        phase="option-chain",
                    )
                )

        if option_type == "ByteTestOption":
            operator = getattr(option, "operator", None)
            if operator not in _BYTE_TEST_OPERATORS:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Unsupported byte_test operator '{operator}'",
                        location=getattr(option, "location", None),
                        code="invalid_byte_test_operator",
                        phase="option-chain",
                    )
                )

        for field_name in _BYTE_REFERENCE_FIELDS.get(option_type, ()):
            value = getattr(option, field_name, None)
            variable = _variable_reference(value)
            if variable is not None and variable not in defined:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        message=f"Byte-operation variable '{variable}' is not defined earlier in the rule",
                        location=getattr(option, "location", None),
                        code="undefined_byte_variable",
                        hint="Add byte_extract before using the variable, or verify the engine context.",
                        phase="option-chain",
                        confidence="medium",
                    )
                )

        if option_type == "ByteExtractOption":
            name = getattr(option, "var_name", None)
            if isinstance(name, str):
                if name in defined:
                    diagnostics.append(
                        Diagnostic(
                            level=DiagnosticLevel.ERROR,
                            message=f"Byte-operation variable '{name}' is extracted more than once",
                            location=getattr(option, "location", None),
                            code="duplicate_byte_variable",
                            phase="option-chain",
                        )
                    )
                defined.add(name)
    return diagnostics


def _validate_fast_pattern(option: object, has_content: bool) -> list[Diagnostic]:
    if not has_content:
        return [
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                message="Option 'fast_pattern' requires a preceding content option",
                location=getattr(option, "location", None),
                code="fast_pattern_without_content",
                hint="Place fast_pattern immediately after content.",
                phase="option-chain",
                fix={"action": "move_after_content"},
            )
        ]
    diagnostics: list[Diagnostic] = []
    offset = getattr(option, "offset", None)
    length = getattr(option, "length", None)
    if getattr(option, "only", False) and (offset is not None or length is not None):
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                message="fast_pattern:only cannot include an offset or length",
                location=getattr(option, "location", None),
                code="fast_pattern_only_with_range",
                phase="option-chain",
            )
        )
    if (offset is None) != (length is None) or (length is not None and length < 1):
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                message="fast_pattern offset and length must be supplied together with a positive length",
                location=getattr(option, "location", None),
                code="invalid_fast_pattern_range",
                phase="option-chain",
            )
        )
    return diagnostics


def _validate_target_priority(rule: Rule, target: EngineTarget) -> list[Diagnostic]:
    engine = target.engine.lower()
    version = _version_tuple(target.version)
    if engine == "suricata":
        maximum = _SURICATA_PRIORITY_MAX
    elif engine.startswith("snort"):
        maximum = (
            _SNORT3_PRIORITY_MAX
            if version is not None and version[0] >= 3
            else _SNORT2_PRIORITY_MAX
        )
    else:
        return []
    diagnostics: list[Diagnostic] = []
    for option in rule.options:
        if option.node_type != "PriorityOption":
            continue
        priority = getattr(option, "value", None)
        if isinstance(priority, int) and priority > maximum:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=(
                        f"Priority {priority} is outside the {target.engine} range 1-{maximum}"
                    ),
                    location=option.location,
                    code="engine_priority_out_of_range",
                    phase="version",
                )
            )
    return diagnostics


def _validate_target_options(rule: Rule, target: EngineTarget) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if target.supports_action(rule.action.value) is False:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                message=f"Action '{rule.action.value}' is not listed for {target.engine} {target.version}",
                location=rule.location,
                code="unsupported_engine_action",
                hint="Use a compatible engine target or replace the action.",
                phase="version",
            )
        )
    protocol = rule.header.protocol if rule.header is not None else rule.protocol
    if protocol is not None and target.supports_protocol(protocol.value) is False:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.ERROR,
                message=f"Protocol '{protocol.value}' is not listed for {target.engine} {target.version}",
                location=rule.header.location if rule.header is not None else rule.location,
                code="unsupported_engine_protocol",
                hint="Use a compatible engine target or replace the protocol.",
                phase="version",
            )
        )
    diagnostics.extend(_validate_target_priority(rule, target))
    for option in rule.options:
        keyword = _option_keyword(option)
        support = target.supports(keyword)
        feature = _OPTION_FEATURES.get(option.node_type)
        if feature is not None and target.supports_feature(feature) is False:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Feature '{feature}' is not listed for {target.engine} {target.version}",
                    location=option.location,
                    code="unsupported_engine_feature",
                    hint="Use a compatible engine target or remove the dependent option.",
                    phase="version",
                )
            )
        if option.node_type == "BufferSelectOption":
            buffer_name = str(getattr(option, "buffer_name", "")).lower()
            buffer_support = target.supports(buffer_name)
            if buffer_support is True or support is True:
                support = True
            elif buffer_support is None and support is None:
                support = None
            else:
                support = False
        if support is False:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Keyword '{keyword}' is not listed for {target.engine} {target.version}",
                    location=option.location,
                    code="unsupported_engine_keyword",
                    hint="Use a compatible engine target or replace the keyword.",
                    phase="version",
                )
            )
        elif target.is_deprecated(keyword):
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    message=f"Keyword '{keyword}' is deprecated for {target.engine} {target.version}",
                    location=option.location,
                    code="deprecated_engine_keyword",
                    phase="version",
                    confidence="medium",
                )
            )
    return diagnostics


def _validate_option_chain(rule: Rule) -> list[Diagnostic]:  # noqa: PLR0912
    diagnostics: list[Diagnostic] = []
    counts: dict[str, int] = {}
    previous_content = False
    previous_content_negated = False
    seen_content = False
    current_modifiers: set[str] = set()
    for option in rule.options:
        option_type = option.node_type
        if option_type in _SINGLETON_OPTIONS:
            counts[option_type] = counts.get(option_type, 0) + 1
        if option_type == "ContentOption":
            modifiers = tuple(getattr(option, "modifiers", ()))
            modifier_names = [modifier.name_str for modifier in modifiers]
            current_modifiers = set(modifier_names)
            diagnostics.extend(
                _validate_content_modifier_combination(current_modifiers, option.location)
            )
            for modifier in modifiers:
                diagnostics.extend(
                    _validate_relative_value(
                        modifier.name_str, modifier.value, getattr(option, "location", None)
                    )
                )
            duplicate_modifiers = {
                name for name in modifier_names if name and modifier_names.count(name) > 1
            }
            for name in sorted(duplicate_modifiers):
                same_name = tuple(modifier for modifier in modifiers if modifier.name_str == name)
                safe = len({_modifier_signature(modifier) for modifier in same_name}) == 1
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Content modifier '{name}' may appear only once per content option",
                        location=option.location,
                        code="duplicate_content_modifier",
                        phase="option-chain",
                        fix=(
                            {"action": "remove_duplicate_content_modifier", "name": name}
                            if safe
                            else None
                        ),
                        safe_fix=safe,
                    )
                )
            for modifier in modifiers:
                if getattr(modifier, "name_str", "") in {"distance", "within"} and not seen_content:
                    diagnostics.append(
                        Diagnostic(
                            level=DiagnosticLevel.ERROR,
                            message="Inline distance/within requires a preceding content option",
                            location=option.location,
                            code="relative_modifier_without_content",
                            phase="option-chain",
                        )
                    )
            previous_content = True
            previous_content_negated = bool(getattr(option, "negated", False))
            seen_content = True
            continue
        if option_type == "FastPatternOption":
            diagnostics.extend(_validate_fast_pattern(option, previous_content))
            if previous_content_negated:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        message="fast_pattern follows negated content and may not be usable by the engine",
                        location=option.location,
                        code="fast_pattern_on_negated_content",
                        phase="option-chain",
                        confidence="medium",
                    )
                )
        if option_type in _CONTENT_MODIFIERS:
            if not previous_content:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Option '{option_type.removesuffix('Option').lower()}' requires a preceding content option",
                        location=option.location,
                        code="content_modifier_without_content",
                        hint="Place the modifier immediately after content or use an inline modifier.",
                        phase="option-chain",
                        fix={"action": "move_after_content"},
                    )
                )
            modifier_name = option_type.removesuffix("Option").lower()
            current_modifiers.add(modifier_name)
            diagnostics.extend(
                _validate_content_modifier_combination(current_modifiers, option.location)
            )
            diagnostics.extend(
                _validate_relative_value(
                    modifier_name, getattr(option, "value", None), getattr(option, "location", None)
                )
            )
            continue
        previous_content = False
        current_modifiers.clear()

    for option_type, count in counts.items():
        if count > 1:
            keyword = _SINGLETON_OPTIONS[option_type]
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Option '{keyword}' may appear only once",
                    code="duplicate_singleton_option",
                    hint=f"Keep one {keyword} option in the rule.",
                    phase="option-chain",
                )
            )
    return diagnostics


def _flowbit_names(value: str) -> tuple[str, ...]:
    """Return the individual names in a valid flowbit expression."""
    if not value or ("&" in value and "|" in value):
        return ()
    names = tuple(re.split(r"[&|]", value))
    return names if all(_FLOWBIT_NAME_RE.fullmatch(name) for name in names) else ()


def _version_tuple(version: str) -> tuple[int, ...] | None:
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups(default="0"))


def _validate_flowbits(rule: Rule, target: EngineTarget | None = None) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for option in rule.options:
        if not isinstance(option, FlowbitsOption):
            continue
        action = option.action.lower()
        name = option.name
        if action in _FLOWBIT_NAME_REQUIRED and not name:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"flowbits:{action} requires a flowbit name",
                    location=option.location,
                    code="missing_flowbit_name",
                    hint="Add the flowbit name after the action.",
                    phase="option-chain",
                )
            )
        if action == "noalert" and name:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message="flowbits:noalert does not accept a flowbit name",
                    location=option.location,
                    code="unexpected_flowbit_name",
                    hint="Use flowbits:noalert without a name.",
                    phase="option-chain",
                )
            )
        names = _flowbit_names(name)
        if name and not names:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Invalid flowbit name expression '{name}'",
                    location=option.location,
                    code="invalid_flowbit_name",
                    hint="Use alphanumeric names with periods, dashes, or underscores.",
                    phase="option-chain",
                )
            )
        if action in {"set", "toggle", "unset"} and "|" in name:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"flowbits:{action} only supports '&' between multiple names",
                    location=option.location,
                    code="invalid_flowbit_operator",
                    hint="Use '&' for a mutating flowbits expression.",
                    phase="option-chain",
                )
            )
        if action and action not in _FLOWBIT_ACTIONS:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"Unsupported flowbits action '{option.action}'",
                    location=option.location,
                    code="invalid_flowbits_action",
                    phase="option-chain",
                )
            )
        if target is not None and action == "toggle":
            engine = target.engine.lower()
            version = _version_tuple(target.version)
            if engine.startswith("snort") and version is not None and version[0] >= 3:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"flowbits:toggle is not supported by {target.engine} {target.version}",
                        location=option.location,
                        code="unsupported_engine_flowbit_action",
                        phase="version",
                    )
                )
            elif engine == "suricata" and version is not None and version >= (8, 0, 6):
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        message=f"flowbits:toggle is deprecated in Suricata {target.version}",
                        location=option.location,
                        code="deprecated_engine_flowbit_action",
                        phase="version",
                        confidence="high",
                    )
                )
    return diagnostics


def apply_safe_fixes(rule: Rule) -> Rule:
    """Return ``rule`` with only explicitly safe, idempotent fixes applied.

    Currently this removes exact duplicate inline content modifiers. Duplicate
    modifiers with different values are intentionally left unchanged because
    choosing which value to keep would require engine-specific semantics.
    """
    safe_names = {
        str(diagnostic.fix["name"])
        for diagnostic in validate_rule(rule)
        if diagnostic.safe_fix
        and diagnostic.code == "duplicate_content_modifier"
        and diagnostic.fix is not None
        and diagnostic.fix.get("action") == "remove_duplicate_content_modifier"
    }
    if not safe_names:
        return rule

    changed = False
    options: list[RuleOption] = []
    for option in rule.options:
        if not isinstance(option, ContentOption):
            options.append(option)
            continue
        seen: set[tuple[str, int | str | None]] = set()
        modifiers: list[ContentModifier] = []
        for modifier in option.modifiers:
            signature = _modifier_signature(modifier)
            if modifier.name_str in safe_names and signature in seen:
                changed = True
                continue
            seen.add(signature)
            modifiers.append(modifier)
        options.append(option.model_copy(update={"modifiers": tuple(modifiers)}))

    return rule.model_copy(update={"options": tuple(options)}) if changed else rule


def _validate_buffer_semantics(rule: Rule) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    protocol = (
        rule.header.protocol.value
        if rule.header is not None
        else rule.protocol.value
        if rule.protocol is not None
        else None
    )
    selected_buffer: str | None = None
    has_match = False
    for option in rule.options:
        option_type = option.node_type
        if option_type == "BufferSelectOption":
            if selected_buffer is not None and not has_match:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.WARNING,
                        message=f"Sticky buffer '{selected_buffer}' is replaced without a content or pcre match",
                        location=option.location,
                        code="sticky_buffer_without_match",
                        phase="option-chain",
                        confidence="medium",
                    )
                )
            selected_buffer = str(getattr(option, "buffer_name", "")).lower()
            has_match = False
            if protocol in {"udp", "icmp", "ip", "ipv6"} and selected_buffer.startswith(
                ("http", "tls", "ssh", "ftp", "smtp", "imap", "smb")
            ):
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message=f"Buffer '{selected_buffer}' is incompatible with {protocol} header protocol",
                        location=option.location,
                        code="buffer_protocol_mismatch",
                        phase="structure",
                    )
                )
            continue
        if option_type in {"ContentOption", "PcreOption"}:
            has_match = True
    if selected_buffer is not None and not has_match:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message=f"Sticky buffer '{selected_buffer}' has no content or pcre match",
                code="sticky_buffer_without_match",
                phase="option-chain",
                confidence="medium",
            )
        )
    return diagnostics


def _validate_relative_patterns(rule: Rule) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    has_anchor = False
    for option in rule.options:
        flags = {str(flag).lower() for flag in getattr(option, "flags", ())}
        if (
            option.node_type == "GenericOption"
            and str(getattr(option, "keyword", "")).lower() == "byte_math"
        ):
            math_fields = _byte_math_fields(getattr(option, "value", None))
            if "relative" in math_fields and not has_anchor:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message="Relative byte_math requires a preceding content or byte match",
                        location=option.location,
                        code="relative_byte_operation_without_anchor",
                        phase="option-chain",
                    )
                )
        if (
            option.node_type in {"ByteTestOption", "ByteJumpOption", "ByteExtractOption"}
            and "relative" in flags
            and not has_anchor
        ):
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message="Relative byte operation requires a preceding content or byte match",
                    location=option.location,
                    code="relative_byte_operation_without_anchor",
                    phase="option-chain",
                )
            )
        if option.node_type in {"ContentOption", "ByteTestOption", "ByteJumpOption"}:
            has_anchor = True
        if option.node_type == "PcreOption" and "r" in str(getattr(option, "flags", "")).lower():
            if not has_anchor:
                diagnostics.append(
                    Diagnostic(
                        level=DiagnosticLevel.ERROR,
                        message="Relative PCRE flag 'R' requires a preceding content or byte match",
                        location=option.location,
                        code="relative_pcre_without_anchor",
                        phase="option-chain",
                    )
                )
            has_anchor = True
    return diagnostics


def validate_rule(rule: Rule, target: EngineTarget | None = None) -> list[Diagnostic]:
    """
    Validate a Rule AST and return diagnostics.

    Args:
        rule: Rule to validate

    Returns:
        List of diagnostics (errors, warnings, info)

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test";)')
        >>> diagnostics = validate_rule(rule)
        >>> for diag in diagnostics:
        ...     print(f"{diag.level}: {diag.message}")
        WARNING: Missing required option 'sid'
    """
    diagnostics: list[Diagnostic] = []

    # Structure and option-chain checks.
    has_sid = any(opt.node_type == "SidOption" for opt in rule.options)
    has_msg = any(opt.node_type == "MsgOption" for opt in rule.options)
    has_rev = any(opt.node_type == "RevOption" for opt in rule.options)

    if not has_sid:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message="Missing required option 'sid'",
                code="missing_sid",
                phase="structure",
            )
        )

    if not has_msg:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.WARNING,
                message="Missing required option 'msg'",
                code="missing_msg",
                phase="structure",
            )
        )

    if has_sid and not has_rev:
        diagnostics.append(
            Diagnostic(
                level=DiagnosticLevel.INFO,
                message="Missing recommended option 'rev'",
                code="missing_rev",
                phase="policy",
            )
        )

    diagnostics.extend(_validate_option_chain(rule))
    diagnostics.extend(_validate_flowbits(rule, target=target))

    if target is not None:
        diagnostics.extend(_validate_target_options(rule, target))

    diagnostics.extend(_validate_byte_operations(rule))
    diagnostics.extend(_validate_buffer_semantics(rule))
    diagnostics.extend(_validate_relative_patterns(rule))

    # Cross-rule checks (duplicate SIDs, shadowing, conflicting actions) require a
    # whole rule set and live in surinort_ast.analysis.conflicts and the streaming
    # ValidateProcessor, not in this single-rule validator.

    # Include any diagnostics from parsing
    if rule.diagnostics:
        diagnostics.extend(rule.diagnostics)

    return diagnostics


def validate_rules(rules: Sequence[Rule], target: EngineTarget | None = None) -> list[Diagnostic]:
    """Validate individual rules and cross-rule SID uniqueness."""
    diagnostics: list[Diagnostic] = []
    seen_sids: dict[int, int] = {}
    flowbit_definitions: set[str] = set()
    flowbit_uses: list[tuple[str, FlowbitsOption]] = []
    for index, rule in enumerate(rules, start=1):
        diagnostics.extend(validate_rule(rule, target=target))
        sid = extract_sid(rule)
        if sid is None:
            continue
        previous = seen_sids.get(sid)
        if previous is not None:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.ERROR,
                    message=f"SID {sid} is duplicated by rules {previous} and {index}",
                    code="duplicate_sid",
                    hint="Assign a unique SID to each rule.",
                    phase="cross-rule",
                )
            )
        else:
            seen_sids[sid] = index
        for option in rule.options:
            if not isinstance(option, FlowbitsOption):
                continue
            action = option.action.lower()
            name = option.name
            names = _flowbit_names(name)
            if action in {"set", "toggle"}:
                flowbit_definitions.update(names)
            elif action in {"isset", "isnotset", "unset"}:
                flowbit_uses.extend((flowbit_name, option) for flowbit_name in names)
    for name, option in flowbit_uses:
        if name not in flowbit_definitions:
            diagnostics.append(
                Diagnostic(
                    level=DiagnosticLevel.WARNING,
                    message=f"Flowbit '{name}' is used without a set/toggle in this ruleset",
                    location=option.location,
                    code="flowbit_without_definition",
                    hint="Check included rules and engine configuration; the definition may be external.",
                    phase="cross-rule",
                    confidence="medium",
                )
            )
    return diagnostics


__all__ = [
    "apply_safe_fixes",
    "validate_rule",
    "validate_rules",
]
