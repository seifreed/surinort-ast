from surinort_ast.lsp import (
    code_actions_for_text,
    completion_items,
    diagnostics_for_text,
    formatting_edits_for_text,
    hover_for_text,
)


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
