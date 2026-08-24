"""Small stdlib-only Language Server Protocol endpoint for rule files."""

from __future__ import annotations

import json
import sys
from typing import Any, BinaryIO, cast

from ..api import parse_rule, validate_rule, validate_rules
from ..core.enums import DiagnosticLevel, Dialect
from ..core.nodes import Rule, extract_sid
from ..exceptions import ParseError
from ..streaming.parser import _iter_rule_blocks


def _diagnostic(
    level: DiagnosticLevel, message: str, line: int, code: str | None
) -> dict[str, Any]:
    return {
        "range": {"start": {"line": line, "character": 0}, "end": {"line": line, "character": 999}},
        "severity": {DiagnosticLevel.ERROR: 1, DiagnosticLevel.WARNING: 2}.get(level, 3),
        "message": message,
        "code": code,
        "source": "surinort-ast",
    }


def _parse_document(text: str, dialect: Dialect) -> tuple[list[Rule], list[dict[str, Any]]]:
    rules: list[Rule] = []
    diagnostics: list[dict[str, Any]] = []
    for line, raw in _iter_rule_blocks(enumerate(text.splitlines(), start=0)):
        try:
            rule = parse_rule(raw, dialect=dialect)
        except ParseError as exc:
            diagnostics.append(_diagnostic(DiagnosticLevel.ERROR, str(exc), line, "parse_error"))
            continue
        rules.append(rule)
        for diagnostic in validate_rule(rule):
            diagnostics.append(
                _diagnostic(diagnostic.level, diagnostic.message, line, diagnostic.code)
            )
    for diagnostic in validate_rules(rules):
        if diagnostic.code in {"duplicate_sid", "flowbit_without_definition"}:
            diagnostics.append(
                _diagnostic(diagnostic.level, diagnostic.message, 0, diagnostic.code)
            )
    return rules, diagnostics


def diagnostics_for_text(text: str, dialect: Dialect = Dialect.SURICATA) -> list[dict[str, Any]]:
    """Return LSP diagnostics for a document."""
    return _parse_document(text, dialect)[1]


def hover_for_text(
    text: str, line: int, dialect: Dialect = Dialect.SURICATA
) -> dict[str, Any] | None:
    """Return a compact rule summary for an LSP hover request."""
    lines = text.splitlines()
    if line < 0 or line >= len(lines) or not lines[line].strip():
        return None
    try:
        rule = parse_rule(lines[line], dialect=dialect)
    except ParseError:
        return None
    sid = extract_sid(rule)
    protocol = rule.header.protocol if rule.header is not None else rule.protocol
    protocol_text = protocol.value if protocol is not None else "headerless"
    value = f"**{rule.action.value}** `{protocol_text}`"
    if sid is not None:
        value += f"\n\nSID: `{sid}`"
    return {"contents": {"kind": "markdown", "value": value}}


def _read_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, _, value = line.decode("ascii").partition(":")
        headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    return cast(dict[str, Any], json.loads(stream.read(length).decode("utf-8")))


def _write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    stream.flush()


def serve(reader: BinaryIO, writer: BinaryIO) -> None:
    """Serve LSP messages until EOF or an ``exit`` notification."""
    documents: dict[str, str] = {}
    while True:
        message = _read_message(reader)
        if message is None:
            return
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            _write_message(
                writer,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"capabilities": {"hoverProvider": True, "textDocumentSync": 1}},
                },
            )
        elif method in {"textDocument/didOpen", "textDocument/didChange"}:
            params = message.get("params", {})
            document = params.get("textDocument", {})
            uri = document.get("uri", "")
            text = document.get("text")
            if text is None:
                text = params.get("contentChanges", [{}])[-1].get("text", "")
            documents[uri] = text
            _write_message(
                writer,
                {
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {"uri": uri, "diagnostics": diagnostics_for_text(text)},
                },
            )
        elif method == "textDocument/hover":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            position = params.get("position", {})
            result = hover_for_text(
                documents.get(document.get("uri", ""), ""), position.get("line", 0)
            )
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": result})
        elif method == "shutdown":
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": None})
        elif method == "exit":
            return


def main() -> None:
    """Run the LSP endpoint over stdio."""
    serve(sys.stdin.buffer, sys.stdout.buffer)


__all__ = ["diagnostics_for_text", "hover_for_text", "main", "serve"]
