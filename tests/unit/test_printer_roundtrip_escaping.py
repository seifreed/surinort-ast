"""
Regression tests for printer output that failed to re-parse.

print_rule must emit text that parses back to an equivalent rule. These cover
cases where it previously produced unparseable output:

- ``flowbits:noalert;`` (no bit name) was printed as ``flowbits:noalert,;``.
- ``msg`` text containing quotes/backslashes was printed unescaped.
- ``content`` patterns containing the ``"`` or ``;`` byte were printed literally.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.api import print_rule


@pytest.mark.parametrize(
    "rule_text",
    [
        "alert tcp any any -> any any (flowbits:noalert; sid:1;)",
        "alert tcp any any -> any any (flowbits:set,evil_bit; sid:1;)",
        'alert tcp any any -> any any (msg:"say \\"hi\\""; sid:1;)',
        'alert tcp any any -> any any (msg:"back\\\\slash"; sid:1;)',
        'alert tcp any any -> any any (content:"a|22|b"; sid:1;)',
        'alert tcp any any -> any any (content:"a|3b|b"; sid:1;)',
        'alert tcp any any -> any any (content:"GET"; sid:1;)',
    ],
)
def test_print_output_reparses(rule_text):
    rule = parse_rule(rule_text)
    # Must not raise: printed output is valid rule text.
    parse_rule(print_rule(rule))


def test_content_quote_byte_value_preserved():
    rule = parse_rule('alert tcp any any -> any any (content:"a|22|b"; sid:1;)')
    reparsed = parse_rule(print_rule(rule))
    pattern = next(o.pattern for o in reparsed.options if o.node_type == "ContentOption")
    assert pattern == b'a"b'


def test_msg_quotes_value_preserved():
    rule = parse_rule('alert tcp any any -> any any (msg:"say \\"hi\\""; sid:1;)')
    reparsed = parse_rule(print_rule(rule))
    text = next(o.text for o in reparsed.options if o.node_type == "MsgOption")
    assert text == 'say "hi"'
