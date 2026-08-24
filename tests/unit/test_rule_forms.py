import pytest

from surinort_ast import parse_rule, print_rule
from surinort_ast.core.enums import Dialect, RuleForm


@pytest.mark.parametrize(
    ("text", "form", "printed"),
    [
        (
            'alert tcp any any -> any 80 (msg:"full"; sid:1;)',
            RuleForm.FULL,
            'alert tcp any any -> any 80 (msg:"full"; sid:1;)',
        ),
        (
            'alert tcp (msg:"protocol"; sid:2;)',
            RuleForm.PROTOCOL_ONLY,
            'alert tcp (msg:"protocol"; sid:2;)',
        ),
        (
            'alert (msg:"headerless"; sid:3;)',
            RuleForm.HEADERLESS,
            'alert (msg:"headerless"; sid:3;)',
        ),
    ],
)
def test_rule_form_survives_print_round_trip(text: str, form: RuleForm, printed: str) -> None:
    rule = parse_rule(text, dialect=Dialect.SNORT3)

    assert rule.form is form
    assert print_rule(rule) == printed
    assert parse_rule(print_rule(rule), dialect=Dialect.SNORT3).form is form
