"""
Sub-builders for complex option configuration.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.enums import FlowDirection, FlowState
from ..core.nodes import (
    ContentModifier,
    ContentOption,
    DepthOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    FlowOption,
    NocaseOption,
    OffsetOption,
    Option,
    RawbytesOption,
    StartswithOption,
    ThresholdOption,
    WithinOption,
)

if TYPE_CHECKING:
    from .rule_builder import RuleBuilder


class ContentBuilder:
    """
    Fluent builder for content options with modifiers.

    Provides a chainable API for building content patterns with
    sticky buffers, offsets, and other modifiers.

    Example:
        >>> rule = (
        ...     RuleBuilder()
        ...     .alert().protocol("tcp")
        ...     .source_ip("any").source_port("any")
        ...     .dest_ip("any").dest_port("80")
        ...     .msg("Example with content")
        ...     .sid(1000001)
        ...     .content_builder()
        ...         .pattern(b"GET")
        ...         .http_uri()
        ...         .nocase()
        ...         .depth(10)
        ...         .done()
        ...     .build()
        ... )
    """

    def __init__(self, parent: RuleBuilder) -> None:
        """
        Initialize ContentBuilder.

        Args:
            parent: Parent RuleBuilder to return to after done()
        """
        self._parent = parent
        self._pattern: bytes | None = None
        self._modifiers: list[ContentModifier] = []
        self._pending_modifiers: list[Option] = []
        self._pending_buffers: list[Option] = []

    def pattern(self, pattern: bytes) -> ContentBuilder:
        """
        Set content pattern to match.

        Args:
            pattern: Bytes pattern to search for

        Returns:
            Self for chaining
        """
        self._pattern = pattern
        return self

    def _add_modifier(self, modifier: Option) -> ContentBuilder:
        """Append a pending content modifier and return self for chaining."""
        self._pending_modifiers.append(modifier)
        return self

    def nocase(self) -> ContentBuilder:
        """Add nocase modifier (case-insensitive matching)."""
        return self._add_modifier(NocaseOption())

    def rawbytes(self) -> ContentBuilder:
        """Add rawbytes modifier (match raw packet data)."""
        return self._add_modifier(RawbytesOption())

    def depth(self, depth: int) -> ContentBuilder:
        """Add depth modifier (search within first N bytes)."""
        return self._add_modifier(DepthOption(value=depth))

    def offset(self, offset: int) -> ContentBuilder:
        """Add offset modifier (start search at byte position)."""
        return self._add_modifier(OffsetOption(value=offset))

    def distance(self, distance: int) -> ContentBuilder:
        """Add distance modifier (relative to previous match)."""
        return self._add_modifier(DistanceOption(value=distance))

    def within(self, within: int) -> ContentBuilder:
        """Add within modifier (match within N bytes of previous)."""
        return self._add_modifier(WithinOption(value=within))

    def fast_pattern(self) -> ContentBuilder:
        """Add fast_pattern modifier (use for fast pattern matching)."""
        return self._add_modifier(FastPatternOption())

    def startswith(self) -> ContentBuilder:
        """Add startswith modifier (match at start of buffer)."""
        return self._add_modifier(StartswithOption())

    def endswith(self) -> ContentBuilder:
        """Add endswith modifier (match at end of buffer)."""
        return self._add_modifier(EndswithOption())

    def _add_buffer(self, buffer_name: str) -> ContentBuilder:
        """Queue a sticky-buffer selection and return self for chaining.

        The selection is deferred (not pushed to the parent immediately) so a
        ``done()`` that fails its pattern precondition leaves the parent builder
        untouched instead of leaking a dangling buffer with no content attached.
        """
        from ..core.nodes import BufferSelectOption

        self._pending_buffers.append(BufferSelectOption(buffer_name=buffer_name))
        return self

    def http_uri(self) -> ContentBuilder:
        """Add http_uri sticky buffer (use before pattern)."""
        return self._add_buffer("http_uri")

    def http_header(self) -> ContentBuilder:
        """Add http_header sticky buffer (use before pattern)."""
        return self._add_buffer("http_header")

    def http_method(self) -> ContentBuilder:
        """Add http_method sticky buffer (use before pattern)."""
        return self._add_buffer("http_method")

    def http_cookie(self) -> ContentBuilder:
        """Add http_cookie sticky buffer (use before pattern)."""
        return self._add_buffer("http_cookie")

    def dns_query(self) -> ContentBuilder:
        """Add dns_query sticky buffer (use before pattern)."""
        return self._add_buffer("dns_query")

    def tls_sni(self) -> ContentBuilder:
        """Add tls.sni sticky buffer (use before pattern)."""
        return self._add_buffer("tls.sni")

    def file_data(self) -> ContentBuilder:
        """Add file_data sticky buffer (use before pattern)."""
        return self._add_buffer("file_data")

    def done(self) -> RuleBuilder:
        """
        Finish content configuration and return to parent builder.

        Returns:
            Parent RuleBuilder for continued chaining

        Raises:
            BuilderError: If pattern was not set
        """
        from .rule_builder import BuilderError

        if self._pattern is None:
            raise BuilderError("Content pattern must be set before calling done()")

        # Sticky buffers select the buffer the following content binds to, so
        # they precede it (IDS rule ordering); flush them first.
        self._parent._options.extend(self._pending_buffers)

        # Add content option with inline modifiers, then standalone modifiers after
        content_opt = ContentOption(pattern=self._pattern, modifiers=self._modifiers)
        self._parent._options.append(content_opt)

        # Append standalone modifiers AFTER content (IDS rule ordering)
        self._parent._options.extend(self._pending_modifiers)

        return self._parent


class FlowBuilder:
    """
    Fluent builder for flow options.

    Provides a chainable API for configuring flow direction and state.

    Example:
        >>> rule = (
        ...     RuleBuilder()
        ...     .alert().protocol("tcp")
        ...     .source_ip("any").source_port("any")
        ...     .dest_ip("any").dest_port("80")
        ...     .msg("Example with flow")
        ...     .sid(1000001)
        ...     .flow_builder()
        ...         .to_server()
        ...         .established()
        ...         .done()
        ...     .build()
        ... )
    """

    def __init__(self, parent: RuleBuilder) -> None:
        """
        Initialize FlowBuilder.

        Args:
            parent: Parent RuleBuilder to return to after done()
        """
        self._parent = parent
        self._directions: list[FlowDirection] = []
        self._states: list[FlowState] = []

    def _add_direction(self, direction: FlowDirection) -> FlowBuilder:
        """Append a flow direction and return self for chaining."""
        self._directions.append(direction)
        return self

    def _add_state(self, state: FlowState) -> FlowBuilder:
        """Append a flow state and return self for chaining."""
        self._states.append(state)
        return self

    def to_server(self) -> FlowBuilder:
        """Set flow direction to server."""
        return self._add_direction(FlowDirection.TO_SERVER)

    def to_client(self) -> FlowBuilder:
        """Set flow direction to client."""
        return self._add_direction(FlowDirection.TO_CLIENT)

    def from_server(self) -> FlowBuilder:
        """Set flow direction from server."""
        return self._add_direction(FlowDirection.FROM_SERVER)

    def from_client(self) -> FlowBuilder:
        """Set flow direction from client."""
        return self._add_direction(FlowDirection.FROM_CLIENT)

    def established(self) -> FlowBuilder:
        """Set flow state to established."""
        return self._add_state(FlowState.ESTABLISHED)

    def stateless(self) -> FlowBuilder:
        """Set flow state to stateless."""
        return self._add_state(FlowState.STATELESS)

    def not_established(self) -> FlowBuilder:
        """Set flow state to not established."""
        return self._add_state(FlowState.NOT_ESTABLISHED)

    def done(self) -> RuleBuilder:
        """
        Finish flow configuration and return to parent builder.

        Returns:
            Parent RuleBuilder for continued chaining

        Raises:
            BuilderError: If neither direction nor state was set
        """
        from .rule_builder import BuilderError

        if not self._directions and not self._states:
            raise BuilderError("Flow must have at least one direction or state")

        # Add flow option
        flow_opt = FlowOption(directions=self._directions, states=self._states)
        self._parent._options.append(flow_opt)

        return self._parent


class ThresholdBuilder:
    """
    Fluent builder for threshold options.

    Provides a chainable API for configuring thresholding behavior.

    Example:
        >>> rule = (
        ...     RuleBuilder()
        ...     .alert().protocol("tcp")
        ...     .source_ip("any").source_port("any")
        ...     .dest_ip("any").dest_port("80")
        ...     .msg("Example with threshold")
        ...     .sid(1000001)
        ...     .threshold_builder()
        ...         .threshold_type("limit")
        ...         .track("by_src")
        ...         .count(5)
        ...         .seconds(60)
        ...         .done()
        ...     .build()
        ... )
    """

    def __init__(self, parent: RuleBuilder) -> None:
        """
        Initialize ThresholdBuilder.

        Args:
            parent: Parent RuleBuilder to return to after done()
        """
        self._parent = parent
        self._type: str | None = None
        self._track: str | None = None
        self._count: int | None = None
        self._seconds: int | None = None

    def threshold_type(self, threshold_type: str) -> ThresholdBuilder:
        """
        Set threshold type.

        Args:
            threshold_type: Type (limit, threshold, both)

        Returns:
            Self for chaining
        """
        self._type = threshold_type
        return self

    def track(self, track: str) -> ThresholdBuilder:
        """
        Set tracking method.

        Args:
            track: Tracking method (by_src, by_dst)

        Returns:
            Self for chaining
        """
        self._track = track
        return self

    def count(self, count: int) -> ThresholdBuilder:
        """
        Set event count threshold.

        Args:
            count: Number of events

        Returns:
            Self for chaining
        """
        self._count = count
        return self

    def seconds(self, seconds: int) -> ThresholdBuilder:
        """
        Set time window.

        Args:
            seconds: Time window in seconds

        Returns:
            Self for chaining
        """
        self._seconds = seconds
        return self

    def done(self) -> RuleBuilder:
        """
        Finish threshold configuration and return to parent builder.

        Returns:
            Parent RuleBuilder for continued chaining

        Raises:
            BuilderError: If required fields are missing
        """
        from .rule_builder import BuilderError

        if self._type is None:
            raise BuilderError("Threshold type must be set")
        if self._track is None:
            raise BuilderError("Threshold track must be set")
        if self._count is None:
            raise BuilderError("Threshold count must be set")
        if self._seconds is None:
            raise BuilderError("Threshold seconds must be set")

        # Add threshold option
        threshold_opt = ThresholdOption(
            threshold_type=self._type, track=self._track, count=self._count, seconds=self._seconds
        )
        self._parent._options.append(threshold_opt)

        return self._parent


__all__ = ["ContentBuilder", "FlowBuilder", "ThresholdBuilder"]
