"""Miscellaneous shared helpers for unit tests."""

from __future__ import annotations

import json

from surinort_ast.core.enums import Direction, Protocol
from surinort_ast.core.nodes import AnyAddress, AnyPort, Header, PortExpr


def any_header(
    *,
    src_port: PortExpr | None = None,
    dst_port: PortExpr | None = None,
) -> Header:
    """Build the permissive ``tcp any any -> any any`` header used across tests.

    Ports default to ``AnyPort()``; pass ``src_port``/``dst_port`` to pin a
    specific port for the cases that need one.
    """
    return Header(
        protocol=Protocol.TCP,
        src_addr=AnyAddress(),
        src_port=src_port if src_port is not None else AnyPort(),
        direction=Direction.TO,
        dst_addr=AnyAddress(),
        dst_port=dst_port if dst_port is not None else AnyPort(),
    )


def extract_json(text: str) -> dict[str, object]:
    """Parse the outermost ``{...}`` JSON object embedded in ``text``.

    Used by the SARIF tests to pull a JSON payload out of mixed CLI/console
    output that may contain surrounding text.
    """
    start = text.find("{")
    end = text.rfind("}")
    return json.loads(text[start : end + 1])
