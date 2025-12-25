"""
Flow tracking options transformer mixin.

Handles transformation of flow-related options including:
- flow: Stateful flow tracking (directions and states)
- flowbits: Flow state variables (set, isset, toggle, etc.)
- flowint: Flow integer variables (counters and comparisons)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token

from ....core.diagnostics import DiagnosticLevel
from ....core.enums import FlowDirection, FlowState
from ....core.nodes import FlowbitsOption, FlowOption, GenericOption
from ...helpers import token_to_location


class FlowTrackingOptionsMixin:
    """
    Mixin for transforming flow tracking options.

    This mixin handles stateful flow inspection:
    - flow: Match packets based on flow direction and state
    - flowbits: Set/check flow state variables (boolean flags)
    - flowint: Set/check flow integer variables (counters)

    Use Cases:
        - Track multi-packet attack sequences
        - Maintain state across flow lifetime
        - Correlate related events in same session

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method
    """

    # Declare expected attributes for type checking
    file_path: str | None
    add_diagnostic: Any  # Method signature varies by parent class

    # ========================================================================
    # Flow Direction and State
    # ========================================================================

    def flow_option(self, items: Sequence[Token]) -> FlowOption:
        """
        Transform flow option (stateful flow tracking).

        Args:
            items: Sequence of flow value tokens

        Returns:
            FlowOption node with directions and states

        Usage:
            flow:established,to_server;
            flow:to_client,only_stream;

        Flow Directions:
            - to_server: Client to server
            - to_client: Server to client
            - from_server: Same as to_client
            - from_client: Same as to_server

        Flow States:
            - established: Connection established (after handshake)
            - stateless: No state tracking
            - only_stream: Only match reassembled streams
            - no_stream: Only match raw packets
            - only_frag: Only match fragmented packets
            - no_frag: Only match unfragmented packets

        Diagnostic:
            Unknown flow values generate warnings but don't fail parsing.
        """
        directions: list[FlowDirection] = []
        states: list[FlowState] = []

        for item in items:
            value = str(item.value)

            # Check if it's a direction
            try:
                directions.append(FlowDirection(value))
                continue
            except ValueError:
                pass

            # Check if it's a state
            try:
                states.append(FlowState(value))
                continue
            except ValueError:
                pass

            # Unknown flow value
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"Unknown flow value: {value}",
                token_to_location(item, self.file_path),
            )

        return FlowOption(directions=directions, states=states)

    def flow_value(self, items: Sequence[Token]) -> Token:
        """
        Extract flow value token.

        Args:
            items: Sequence containing single flow value token

        Returns:
            Flow value token or empty WORD token
        """
        return items[0] if items else Token("WORD", "")

    # ========================================================================
    # Flowbits (Boolean State Variables)
    # ========================================================================

    def flowbits_option(self, items: Sequence[Any]) -> FlowbitsOption:
        """
        Transform flowbits option (flow state variables).

        Args:
            items: List containing flowbits action and name

        Returns:
            FlowbitsOption node with action and name

        Usage:
            flowbits:set,name;
            flowbits:isset,name;
            flowbits:toggle,name;
            flowbits:unset,name;
            flowbits:noalert;

        Flowbits Actions:
            - set: Set a flowbit (mark flow state)
            - isset: Check if flowbit is set
            - isnotset: Check if flowbit is not set
            - toggle: Toggle flowbit state
            - unset: Clear flowbit
            - noalert: Don't generate alert (used with set)

        Use Case:
            Track multi-packet attack sequences across flow lifetime.
            Example: Rule 1 detects attack start (sets flowbit),
                     Rule 2 detects completion (checks isset).
        """
        # items[0] is the result from flowbits_action, which is a list of tokens
        action_items = items[0] if items else []

        action = ""
        name = ""

        if len(action_items) >= 1:
            action = str(
                action_items[0].value if isinstance(action_items[0], Token) else action_items[0]
            )
        if len(action_items) >= 2:
            name = str(
                action_items[1].value if isinstance(action_items[1], Token) else action_items[1]
            )

        return FlowbitsOption(action=action, name=name)

    def flowbits_action(self, items: Sequence[Token]) -> Sequence[Token]:
        """
        Pass through flowbits action tokens.

        Args:
            items: Sequence of tokens (action, optional name)

        Returns:
            Same sequence of tokens
        """
        return items

    def flowbits_name(self, items: Sequence[Token]) -> Token:
        """
        Join multiple flowbit names with & separator.

        Args:
            items: Sequence of WORD tokens

        Returns:
            Single Token with & separated names

        Composite Names:
            Multiple flowbit names can be combined with &:
            flowbits:isset,name1&name2; (both must be set)
        """
        name = "&".join(str(token.value) for token in items)
        return Token("WORD", name)

    # ========================================================================
    # Flowint (Integer State Variables)
    # ========================================================================

    def flowint_option(self, items: Sequence[Token]) -> GenericOption:
        """
        Transform flowint option (flow integer variables).

        Args:
            items: Sequence of flowint parameter tokens

        Returns:
            GenericOption with keyword="flowint" and comma-separated value

        Usage:
            flowint:name,+,1;
            flowint:name,>,10;

        Flowint Operations:
            - Set: flowint:name,=,value;
            - Increment: flowint:name,+,value;
            - Decrement: flowint:name,-,value;
            - Compare: flowint:name,>,value;

        Use Case:
            Track numeric state across flow lifetime (packet counts, thresholds).
        """
        value_str = ",".join(str(item.value) for item in items)
        return GenericOption(keyword="flowint", value=value_str, raw=f"flowint:{value_str}")
