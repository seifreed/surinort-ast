"""Shared location-building for transformer mixins.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from lark import Token

from ...core.location import Location
from ..helpers import token_to_location


class LocationAwareMixin:
    """Builds node locations from tokens, honouring the ``track_locations`` flag.

    Transformer mixins share two instance attributes set by ``RuleTransformer``:
    the source ``file_path`` and the ``track_locations`` toggle. ``_location_for``
    is the single place that turns a token into a :class:`Location`, returning
    ``None`` when tracking is disabled so ``track_locations=False`` genuinely
    omits positions (saving the per-token work and the AST memory they occupy).
    """

    file_path: str | None
    # Default for mixin users that don't set it (e.g. test doubles); the concrete
    # RuleTransformer always assigns it from its constructor.
    track_locations: bool = True

    def _location_for(self, token: Token) -> Location | None:
        if not self.track_locations:
            return None
        return token_to_location(token, self.file_path)
