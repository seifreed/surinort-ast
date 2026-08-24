from surinort_ast import parse_rule, validate_rule
from surinort_ast.parsing.lark_parser import LarkRuleParser


def test_parse_and_semantic_diagnostics_expose_phases() -> None:
    parsed = LarkRuleParser(strict=False).parse("not a rule")
    semantic = validate_rule(parse_rule("alert tcp any any -> any 80 (nocase; sid:1;)"))

    assert parsed.diagnostics[0].phase == "syntax"
    assert next(
        item for item in semantic if item.code == "content_modifier_without_content"
    ).phase == ("option-chain")
