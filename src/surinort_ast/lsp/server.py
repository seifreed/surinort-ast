"""Small stdlib-only Language Server Protocol endpoint for rule files."""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, BinaryIO, cast

from ..analysis import CapabilityRegistry, CoverageAnalyzer, EngineTarget, EngineVerifier
from ..api import apply_safe_fixes, parse_rule, validate_rule, validate_rules
from ..core.enums import Action, DiagnosticLevel, Dialect, Protocol
from ..core.nodes import FlowbitsOption, Rule, extract_sid
from ..exceptions import ParseError
from ..printer import CanonicalPrinter
from ..streaming.parser import _iter_rule_blocks

_OPTION_COMPLETIONS = (
    "msg",
    "sid",
    "gid",
    "rev",
    "classtype",
    "priority",
    "reference",
    "metadata",
    "content",
    "uricontent",
    "pcre",
    "flow",
    "flowbits",
    "flowint",
    "byte_test",
    "byte_jump",
    "byte_extract",
    "detection_filter",
    "threshold",
    "nocase",
    "offset",
    "depth",
    "distance",
    "within",
    "fast_pattern",
    "startswith",
    "endswith",
    "rawbytes",
    "http_uri",
    "http_header",
    "dns_query",
    "tls_sni",
)

_KEYWORD_DOCUMENTATION = {
    "content": "Matches bytes in the current detection buffer. Position modifiers attach to this match.",
    "pcre": "Evaluates a PCRE pattern against the current detection buffer.",
    "flowbits": "Sets, tests, or clears state shared by rules on the same flow.",
    "byte_extract": "Extracts bytes into a named variable for later rule options.",
    "byte_test": "Reads bytes and compares the value with an operator.",
    "byte_jump": "Reads bytes and advances the detection cursor by the decoded value.",
    "detection_filter": "Limits alert generation by tracking a count over a time window.",
    "http_uri": "Selects the normalized HTTP URI sticky buffer.",
    "http_header": "Selects the normalized HTTP header sticky buffer.",
    "sid": "The rule signature identifier; it must be unique within a ruleset.",
    "gid": "The generator identifier associated with the rule source.",
    "rev": "The revision number of the rule definition.",
}


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


def _keyword_documentation(
    keyword: str, dialect: Dialect, target: EngineTarget | None = None
) -> str | None:
    documentation = _KEYWORD_DOCUMENTATION.get(keyword.lower())
    if documentation is None:
        return None
    if target is None:
        return f"**{keyword}** ({dialect.value})\n\n{documentation}"
    support = target.supports(keyword)
    status = "supported" if support is True else "not listed" if support is False else "unknown"
    return (
        f"**{keyword}** ({dialect.value}; {target.engine} {target.version})\n\n"
        f"{documentation}\n\nEngine status: {status}."
    )


def _parse_document(
    text: str, dialect: Dialect, target: EngineTarget | None = None
) -> tuple[list[Rule], list[dict[str, Any]]]:
    rules: list[Rule] = []
    diagnostics: list[dict[str, Any]] = []
    for line, raw in _iter_rule_blocks(enumerate(text.splitlines(), start=0)):
        try:
            rule = parse_rule(raw, dialect=dialect)
        except ParseError as exc:
            diagnostics.append(_diagnostic(DiagnosticLevel.ERROR, str(exc), line, "parse_error"))
            continue
        rules.append(rule)
        for diagnostic in validate_rule(rule, target=target):
            diagnostics.append(
                _diagnostic(diagnostic.level, diagnostic.message, line, diagnostic.code)
            )
    for diagnostic in validate_rules(rules, target=target):
        if diagnostic.code in {"duplicate_sid", "flowbit_without_definition"}:
            diagnostics.append(
                _diagnostic(diagnostic.level, diagnostic.message, 0, diagnostic.code)
            )
    return rules, diagnostics


def diagnostics_for_text(
    text: str, dialect: Dialect = Dialect.SURICATA, target: EngineTarget | None = None
) -> list[dict[str, Any]]:
    """Return LSP diagnostics for a document."""
    return _parse_document(text, dialect, target)[1]


def hover_for_text(
    text: str,
    line: int,
    dialect: Dialect = Dialect.SURICATA,
    character: int | None = None,
    target: EngineTarget | None = None,
) -> dict[str, Any] | None:
    """Return keyword documentation or a compact rule summary for hover."""
    lines = text.splitlines()
    if line < 0 or line >= len(lines) or not lines[line].strip():
        return None
    if character is not None:
        keyword = _word_at(text, line, character)
        documentation = _keyword_documentation(keyword or "", dialect, target)
        if documentation is not None:
            return {
                "contents": {
                    "kind": "markdown",
                    "value": documentation,
                }
            }
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


def completion_items(
    text: str,
    line: int,
    character: int,
    dialect: Dialect = Dialect.SURICATA,
    target: EngineTarget | None = None,
) -> list[dict[str, Any]]:
    """Return keyword completions for the current rule context."""
    lines = text.splitlines()
    if line < 0 or line >= len(lines):
        return []
    current = lines[line][: max(0, character)]
    match = re.search(r"[A-Za-z_][A-Za-z0-9_.-]*$", current)
    prefix = match.group(0).lower() if match else ""
    option_context = current.rfind("(") > current.rfind(")")
    candidates = (
        _OPTION_COMPLETIONS
        if option_context
        else (
            *(action.value for action in Action),
            *(protocol.value for protocol in Protocol),
        )
    )
    items: list[dict[str, Any]] = []
    for value in candidates:
        if not value.startswith(prefix):
            continue
        item: dict[str, Any] = {
            "label": value,
            "kind": 14,
            "detail": f"Surinort {dialect.value} keyword",
        }
        documentation = _keyword_documentation(value, dialect, target)
        if documentation is not None:
            item["documentation"] = {"kind": "markdown", "value": documentation}
        if target is not None:
            item["detail"] = f"Surinort {dialect.value} keyword ({target.engine} {target.version})"
        items.append(item)
    return items


def format_document(text: str, dialect: Dialect = Dialect.SURICATA) -> str:
    """Format parsed rules while retaining comments and non-rule text."""
    printer = CanonicalPrinter()
    cursor = 0
    chunks: list[str] = []
    for _, raw in _iter_rule_blocks(enumerate(text.splitlines(), start=0)):
        start = text.find(raw, cursor)
        if start < 0:
            continue
        chunks.append(text[cursor:start])
        chunks.append(printer.print_rule(parse_rule(raw, dialect=dialect)))
        cursor = start + len(raw)
    chunks.append(text[cursor:])
    return "".join(chunks)


def formatting_edits_for_text(
    text: str, dialect: Dialect = Dialect.SURICATA
) -> list[dict[str, Any]]:
    """Return one full-document formatting edit, or no edit on parse failure."""
    try:
        formatted = format_document(text, dialect)
    except ParseError:
        return []
    if formatted == text:
        return []
    lines = text.splitlines()
    end_line = len(lines) - 1 if lines else 0
    end_character = len(lines[-1]) if lines else 0
    return [
        {
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": end_line, "character": end_character},
            },
            "newText": formatted,
        }
    ]


def code_actions_for_text(
    text: str,
    line: int,
    dialect: Dialect = Dialect.SURICATA,
) -> list[dict[str, Any]]:
    """Return safe quick-fixes for the rule containing ``line``."""
    for start_line, raw in _iter_rule_blocks(enumerate(text.splitlines(), start=0)):
        end_line = start_line + raw.count("\n")
        if not start_line <= line <= end_line:
            continue
        try:
            rule = parse_rule(raw, dialect=dialect)
        except ParseError:
            return []
        fixed = apply_safe_fixes(rule)
        if fixed == rule:
            return []
        return [
            {
                "title": "Remove duplicate content modifiers",
                "kind": "quickfix",
                "edit": {
                    "range": {
                        "start": {"line": start_line, "character": 0},
                        "end": {"line": end_line, "character": len(raw.splitlines()[-1])},
                    },
                    "newText": CanonicalPrinter().print_rule(fixed),
                },
            }
        ]
    return []


def _word_at(text: str, line: int, character: int) -> str | None:
    lines = text.splitlines()
    if line < 0 or line >= len(lines):
        return None
    for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_.-]*", lines[line]):
        if match.start() <= character <= match.end():
            return match.group(0)
    return None


def _flowbit_occurrences(text: str, dialect: Dialect) -> list[dict[str, Any]]:
    occurrences: list[dict[str, Any]] = []
    for line, raw in _iter_rule_blocks(enumerate(text.splitlines(), start=0)):
        try:
            rule = parse_rule(raw, dialect=dialect)
        except ParseError:
            continue
        for option in rule.options:
            if not isinstance(option, FlowbitsOption):
                continue
            names = tuple(filter(None, re.split(r"[&|]", option.name)))
            for name in names:
                occurrences.append({"line": line, "name": name, "action": option.action})
    return occurrences


def flowbit_locations(
    text: str,
    line: int,
    character: int,
    definitions_only: bool = False,
    dialect: Dialect = Dialect.SURICATA,
) -> list[dict[str, Any]]:
    """Return flowbit rule locations matching the symbol under the cursor."""
    name = _word_at(text, line, character)
    if name is None:
        return []
    return [
        occurrence
        for occurrence in _flowbit_occurrences(text, dialect)
        if occurrence["name"] == name
        and (not definitions_only or occurrence["action"].lower() in {"set", "toggle"})
    ]


def match_space_preview(text: str, dialect: Dialect = Dialect.SURICATA) -> dict[str, Any]:
    """Return a coverage-backed, explicitly heuristic match-space preview."""
    rules, diagnostics = _parse_document(text, dialect)
    report = CoverageAnalyzer().analyze(rules)
    return {"heuristic": True, "coverage": report.to_dict(), "diagnostics": diagnostics}


def engine_validation_for_text(text: str, command: str, timeout: float = 30.0) -> dict[str, Any]:
    """Validate the current document with a configured local engine command."""
    try:
        verifier = EngineVerifier(command, timeout)
        with tempfile.TemporaryDirectory(prefix="surinort-lsp-") as directory:
            path = Path(directory) / "document.rules"
            path.write_text(text, encoding="utf-8")
            return verifier.verify(path).to_dict()
    except (OSError, ValueError) as exc:
        return {"status": "error", "returncode": None, "stdout": "", "stderr": str(exc)}


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


def _document_dialect(language_id: object) -> Dialect:
    try:
        return Dialect(str(language_id))
    except ValueError:
        return Dialect.SURICATA


def _document_state(
    documents: dict[str, tuple[str, Dialect, EngineTarget | None]], uri: str
) -> tuple[str, Dialect, EngineTarget | None]:
    return documents.get(uri, ("", Dialect.SURICATA, None))


def _initialization_target(params: object) -> EngineTarget | None:
    if not isinstance(params, dict):
        return None
    options = params.get("initializationOptions")
    if not isinstance(options, dict):
        return None
    engine = options.get("engine")
    version = options.get("engineVersion")
    if not isinstance(engine, str) or not engine or not isinstance(version, str) or not version:
        return None
    target = EngineTarget(engine, version)
    capability_file = options.get("capabilityFile")
    if not isinstance(capability_file, str) or not capability_file:
        return target
    try:
        resolved = CapabilityRegistry.from_json(Path(capability_file)).resolve(engine, version)
    except (OSError, ValueError, json.JSONDecodeError):
        return target
    return resolved or target


def _write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    stream.flush()


def serve(reader: BinaryIO, writer: BinaryIO) -> None:  # noqa: PLR0912, PLR0915
    """Serve LSP messages until EOF or an ``exit`` notification."""
    documents: dict[str, tuple[str, Dialect, EngineTarget | None]] = {}
    configured_target: EngineTarget | None = None
    while True:
        message = _read_message(reader)
        if message is None:
            return
        method = message.get("method")
        request_id = message.get("id")
        if method == "initialize":
            configured_target = _initialization_target(message.get("params", {}))
            _write_message(
                writer,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "capabilities": {
                            "hoverProvider": True,
                            "completionProvider": {"triggerCharacters": [":", ";", " "]},
                            "documentFormattingProvider": True,
                            "codeActionProvider": True,
                            "definitionProvider": True,
                            "referencesProvider": True,
                            "textDocumentSync": 1,
                        }
                    },
                },
            )
        elif method in {"textDocument/didOpen", "textDocument/didChange"}:
            params = message.get("params", {})
            document = params.get("textDocument", {})
            uri = document.get("uri", "")
            text = document.get("text")
            if text is None:
                text = params.get("contentChanges", [{}])[-1].get("text", "")
            _, previous_dialect, previous_target = _document_state(documents, uri)
            dialect = (
                _document_dialect(document.get("languageId"))
                if method == "textDocument/didOpen"
                else previous_dialect
            )
            target = configured_target if method == "textDocument/didOpen" else previous_target
            documents[uri] = (str(text), dialect, target)
            _write_message(
                writer,
                {
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {
                        "uri": uri,
                        "diagnostics": diagnostics_for_text(str(text), dialect, target),
                    },
                },
            )
        elif method == "textDocument/hover":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            position = params.get("position", {})
            text, dialect, target = _document_state(documents, document.get("uri", ""))
            result = hover_for_text(
                text,
                position.get("line", 0),
                dialect,
                position.get("character", 0),
                target,
            )
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": result})
        elif method == "textDocument/completion":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            position = params.get("position", {})
            text, dialect, target = _document_state(documents, document.get("uri", ""))
            completion_result = completion_items(
                text,
                position.get("line", 0),
                position.get("character", 0),
                dialect,
                target,
            )
            _write_message(
                writer, {"jsonrpc": "2.0", "id": request_id, "result": completion_result}
            )
        elif method == "textDocument/formatting":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            text, dialect, _ = _document_state(documents, document.get("uri", ""))
            formatting_result = formatting_edits_for_text(text, dialect)
            _write_message(
                writer, {"jsonrpc": "2.0", "id": request_id, "result": formatting_result}
            )
        elif method == "textDocument/codeAction":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            start = params.get("range", {}).get("start", {})
            text, dialect, _ = _document_state(documents, document.get("uri", ""))
            code_action_result = code_actions_for_text(text, start.get("line", 0), dialect)
            _write_message(
                writer, {"jsonrpc": "2.0", "id": request_id, "result": code_action_result}
            )
        elif method in {"textDocument/definition", "textDocument/references"}:
            params = message.get("params", {})
            document = params.get("textDocument", {})
            position = params.get("position", params.get("range", {}).get("start", {}))
            text, dialect, _ = _document_state(documents, document.get("uri", ""))
            locations = flowbit_locations(
                text,
                position.get("line", 0),
                position.get("character", 0),
                definitions_only=method.endswith("definition"),
                dialect=dialect,
            )
            locations_result = [
                {
                    "uri": document.get("uri", ""),
                    "range": {
                        "start": {"line": item["line"], "character": 0},
                        "end": {"line": item["line"], "character": 999},
                    },
                }
                for item in locations
            ]
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": locations_result})
        elif method == "surinort/matchSpacePreview":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            text, dialect, _ = _document_state(documents, document.get("uri", ""))
            preview_result = match_space_preview(text, dialect)
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": preview_result})
        elif method == "surinort/engineValidate":
            params = message.get("params", {})
            document = params.get("textDocument", {})
            text, _, _ = _document_state(documents, document.get("uri", ""))
            engine_result = engine_validation_for_text(
                text,
                str(params.get("command", "")),
                float(params.get("timeout", 30.0)),
            )
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": engine_result})
        elif method == "shutdown":
            _write_message(writer, {"jsonrpc": "2.0", "id": request_id, "result": None})
        elif method == "exit":
            return


def main() -> None:
    """Run the LSP endpoint over stdio."""
    serve(sys.stdin.buffer, sys.stdout.buffer)


__all__ = [
    "code_actions_for_text",
    "completion_items",
    "diagnostics_for_text",
    "engine_validation_for_text",
    "flowbit_locations",
    "format_document",
    "formatting_edits_for_text",
    "hover_for_text",
    "main",
    "match_space_preview",
    "serve",
]
