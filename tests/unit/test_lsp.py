import io
import json

import surinort_ast.lsp.server as lsp_server
from surinort_ast.core.enums import Dialect
from surinort_ast.lsp import (
    code_actions_for_text,
    completion_items,
    diagnostics_for_text,
    engine_validation_for_text,
    flowbit_locations,
    formatting_edits_for_text,
    hover_for_text,
    match_space_preview,
)
from surinort_ast.lsp.server import serve


def test_lsp_reports_rule_diagnostics_and_hover() -> None:
    text = 'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n'

    diagnostics = diagnostics_for_text(text)
    hover = hover_for_text(text, 0)

    assert any(item["code"] == "missing_rev" for item in diagnostics)
    assert hover is not None
    assert "tcp" in hover["contents"]["value"]


def test_lsp_groups_multiline_rules_before_parsing() -> None:
    text = 'alert tcp any any -> any 80 (\n  msg:"x";\n  sid:1;\n)\n'

    diagnostics = diagnostics_for_text(text)

    assert any(item["code"] == "missing_rev" for item in diagnostics)
    assert not any(item["code"] == "parse_error" for item in diagnostics)


def test_lsp_completes_rule_keywords_by_context() -> None:
    options = completion_items("alert tcp any any -> any 80 (flow", 0, 43)
    header = completion_items("alert tc", 0, 9)

    assert any(item["label"] == "flowbits" for item in options)
    assert any(item["label"] == "tcp" for item in header)


def test_lsp_formats_rules_and_offers_safe_quick_fix() -> None:
    text = 'alert tcp any any -> any 80 (content:"x",nocase,nocase;sid:1;)\n'

    edits = formatting_edits_for_text(text)
    actions = code_actions_for_text(text, 0)

    assert edits
    assert 'content:"x"' in edits[0]["newText"]
    assert actions[0]["kind"] == "quickfix"
    assert actions[0]["edit"]["newText"].count("nocase") == 1


def test_lsp_navigates_flowbits_and_previews_match_space() -> None:
    text = (
        "alert tcp any any -> any 80 (flowbits:set,stage1; sid:1;)\n"
        "alert tcp any any -> any 80 (flowbits:isset,stage1; sid:2;)\n"
    )

    definitions = flowbit_locations(text, 1, 48, definitions_only=True)
    references = flowbit_locations(text, 1, 48)
    preview = match_space_preview(text)

    assert [item["line"] for item in definitions] == [0]
    assert [item["line"] for item in references] == [0, 1]
    assert preview["heuristic"] is True
    assert preview["coverage"]["total_rules"] == 2


def test_lsp_can_validate_document_with_configured_engine() -> None:
    import sys

    result = engine_validation_for_text(
        "alert tcp any any -> any 80 (sid:1;)\n",
        f"{sys.executable} -c 'pass' {{file}}",
    )

    assert result["status"] == "passed"


def test_lsp_transport_exposes_navigation_and_preview() -> None:
    text = "alert tcp any any -> any 80 (flowbits:set,stage1; sid:1;)\n"

    def message(payload: dict[str, object]) -> bytes:
        body = json.dumps(payload, separators=(",", ":")).encode()
        return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

    reader = io.BytesIO(
        b"".join(
            [
                message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                message(
                    {
                        "jsonrpc": "2.0",
                        "method": "textDocument/didOpen",
                        "params": {"textDocument": {"uri": "file:///rule.rules", "text": text}},
                    }
                ),
                message(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "textDocument/definition",
                        "params": {
                            "textDocument": {"uri": "file:///rule.rules"},
                            "position": {"line": 0, "character": 48},
                        },
                    }
                ),
                message(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "surinort/matchSpacePreview",
                        "params": {"textDocument": {"uri": "file:///rule.rules"}},
                    }
                ),
                message({"jsonrpc": "2.0", "id": 4, "method": "shutdown", "params": None}),
            ]
        )
    )
    writer = io.BytesIO()

    serve(reader, writer)

    output = writer.getvalue()
    assert b'"id":1' in output
    assert b'"id":2' in output and b'"line":0' in output
    assert b'"id":3' in output and b'"heuristic":true' in output


def test_lsp_transport_retains_document_dialect(monkeypatch) -> None:
    seen: list[Dialect] = []

    def fake_diagnostics(text: str, dialect: Dialect = Dialect.SURICATA) -> list[dict[str, object]]:
        del text
        seen.append(dialect)
        return []

    monkeypatch.setattr(lsp_server, "diagnostics_for_text", fake_diagnostics)

    def message(payload: dict[str, object]) -> bytes:
        body = json.dumps(payload, separators=(",", ":")).encode()
        return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

    reader = io.BytesIO(
        b"".join(
            [
                message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                message(
                    {
                        "jsonrpc": "2.0",
                        "method": "textDocument/didOpen",
                        "params": {
                            "textDocument": {
                                "uri": "file:///rule.snort3.rules",
                                "languageId": "snort3",
                                "text": "alert tcp (sid:1;)\n",
                            }
                        },
                    }
                ),
                message(
                    {
                        "jsonrpc": "2.0",
                        "method": "textDocument/didChange",
                        "params": {
                            "textDocument": {"uri": "file:///rule.snort3.rules"},
                            "contentChanges": [{"text": "alert tcp (sid:2;)\n"}],
                        },
                    }
                ),
            ]
        )
    )

    serve(reader, io.BytesIO())

    assert seen == [Dialect.SNORT3, Dialect.SNORT3]
