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

    def nocase(self) -> ContentBuilder:
        """
        Add nocase modifier (case-insensitive matching).

        Returns:
            Self for chaining
        """
        self._parent._options.append(NocaseOption())
        return self

    def rawbytes(self) -> ContentBuilder:
        """
        Add rawbytes modifier (match raw packet data).

        Returns:
            Self for chaining
        """
        self._parent._options.append(RawbytesOption())
        return self

    def depth(self, depth: int) -> ContentBuilder:
        """
        Add depth modifier (search within first N bytes).

        Args:
            depth: Maximum depth in bytes

        Returns:
            Self for chaining
        """
        self._parent._options.append(DepthOption(value=depth))
        return self

    def offset(self, offset: int) -> ContentBuilder:
        """
        Add offset modifier (start search at byte position).

        Args:
            offset: Start offset in bytes

        Returns:
            Self for chaining
        """
        self._parent._options.append(OffsetOption(value=offset))
        return self

    def distance(self, distance: int) -> ContentBuilder:
        """
        Add distance modifier (relative to previous match).

        Args:
            distance: Distance in bytes from previous match

        Returns:
            Self for chaining
        """
        self._parent._options.append(DistanceOption(value=distance))
        return self

    def within(self, within: int) -> ContentBuilder:
        """
        Add within modifier (match within N bytes of previous).

        Args:
            within: Maximum bytes from previous match

        Returns:
            Self for chaining
        """
        self._parent._options.append(WithinOption(value=within))
        return self

    def fast_pattern(self) -> ContentBuilder:
        """
        Add fast_pattern modifier (use for fast pattern matching).

        Returns:
            Self for chaining
        """
        self._parent._options.append(FastPatternOption())
        return self

    def startswith(self) -> ContentBuilder:
        """
        Add startswith modifier (match at start of buffer).

        Returns:
            Self for chaining
        """
        self._parent._options.append(StartswithOption())
        return self

    def endswith(self) -> ContentBuilder:
        """
        Add endswith modifier (match at end of buffer).

        Returns:
            Self for chaining
        """
        self._parent._options.append(EndswithOption())
        return self

    def http_uri(self) -> ContentBuilder:
        """
        Add http_uri sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="http_uri"))
        return self

    def http_header(self) -> ContentBuilder:
        """
        Add http_header sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="http_header"))
        return self

    def http_method(self) -> ContentBuilder:
        """
        Add http_method sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="http_method"))
        return self

    def http_cookie(self) -> ContentBuilder:
        """
        Add http_cookie sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="http_cookie"))
        return self

    def dns_query(self) -> ContentBuilder:
        """
        Add dns_query sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="dns_query"))
        return self

    def tls_sni(self) -> ContentBuilder:
        """
        Add tls.sni sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="tls.sni"))
        return self

    def file_data(self) -> ContentBuilder:
        """
        Add file_data sticky buffer (use before pattern).

        Returns:
            Self for chaining
        """
        from ..core.nodes import BufferSelectOption

        self._parent._options.append(BufferSelectOption(buffer_name="file_data"))
        return self

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

        # Add content option with modifiers
        content_opt = ContentOption(pattern=self._pattern, modifiers=self._modifiers)
        self._parent._options.append(content_opt)

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

    def to_server(self) -> FlowBuilder:
        """
        Set flow direction to server.

        Returns:
            Self for chaining
        """
        self._directions.append(FlowDirection.TO_SERVER)
        return self

    def to_client(self) -> FlowBuilder:
        """
        Set flow direction to client.

        Returns:
            Self for chaining
        """
        self._directions.append(FlowDirection.TO_CLIENT)
        return self

    def from_server(self) -> FlowBuilder:
        """
        Set flow direction from server.

        Returns:
            Self for chaining
        """
        self._directions.append(FlowDirection.FROM_SERVER)
        return self

    def from_client(self) -> FlowBuilder:
        """
        Set flow direction from client.

        Returns:
            Self for chaining
        """
        self._directions.append(FlowDirection.FROM_CLIENT)
        return self

    def established(self) -> FlowBuilder:
        """
        Set flow state to established.

        Returns:
            Self for chaining
        """
        self._states.append(FlowState.ESTABLISHED)
        return self

    def stateless(self) -> FlowBuilder:
        """
        Set flow state to stateless.

        Returns:
            Self for chaining
        """
        self._states.append(FlowState.STATELESS)
        return self

    def not_established(self) -> FlowBuilder:
        """
        Set flow state to not established.

        Returns:
            Self for chaining
        """
        self._states.append(FlowState.NOT_ESTABLISHED)
        return self

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
