"""
Transformer mixins for modular AST transformation.

This package contains focused mixin classes that compose the main RuleTransformer.
Each mixin handles a specific aspect of IDS rule transformation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import Protocol

from ...core.diagnostics import DiagnosticLevel
from ...core.location import Location


class DiagnosticReporter(Protocol):
    """Type contract for the add_diagnostic method required by transformer mixins.

    Matches RuleTransformer.add_diagnostic(level, message, location?, code?, hint?).
    Using Protocol instead of Callable[..., None] to express optional kwargs.
    """

    def __call__(
        self,
        level: DiagnosticLevel,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None: ...


from .address_transformer import AddressTransformerMixin
from .content_transformer import ContentTransformerMixin
from .header_transformer import HeaderTransformerMixin
from .option_transformer import OptionTransformerMixin
from .port_transformer import PortTransformerMixin

__all__ = [
    "AddressTransformerMixin",
    "ContentTransformerMixin",
    "HeaderTransformerMixin",
    "OptionTransformerMixin",
    "PortTransformerMixin",
]
