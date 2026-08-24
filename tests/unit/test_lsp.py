from surinort_ast.lsp import diagnostics_for_text, hover_for_text


def test_lsp_reports_rule_diagnostics_and_hover() -> None:
    text = 'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n'

    diagnostics = diagnostics_for_text(text)
    hover = hover_for_text(text, 0)

    assert any(item["code"] == "missing_rev" for item in diagnostics)
    assert hover is not None
    assert "tcp" in hover["contents"]["value"]
