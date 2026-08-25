"""Regression coverage for public corpus grammar gaps from issue #166."""

from __future__ import annotations

import pytest

from surinort_ast import Dialect, parse_rule
from surinort_ast.core.enums import Action
from surinort_ast.core.nodes import (
    BufferSelectOption,
    ByteJumpOption,
    ByteTestOption,
    MetadataOption,
)


@pytest.mark.parametrize(
    ("dialect", "rule_text"),
    [
        (
            Dialect.SNORT2,
            "alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS "
            '(msg:"x"; sid:52528; gid:3; rev:1; metadata: engine shared, soid 3|52528, service http;)',
        ),
        (
            Dialect.SNORT2,
            'alert ( msg:"SMTP_COMMAND_OVERFLOW"; sid:1; gid:124; rev:2; '
            "metadata: rule-type preproc; classtype:attempted-admin; )",
        ),
        (
            Dialect.SURICATA,
            "alert http $HOME_NET any -> $EXTERNAL_NET any "
            '(msg:"x"; http.header.raw; content:"a"; sid:2031579; rev:5;)',
        ),
        (
            Dialect.SNORT3,
            "alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any "
            '(msg:"x"; reference:url,support.microsoft.com/default.aspx?scid=kb\\;en-us\\;KB837253; '
            "sid:4146; rev:10;)",
        ),
        (
            Dialect.SURICATA,
            "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS "
            '(msg:"x"; pcre:"/\\"id\\"\\;\\x0d\\x0a/"; sid:2038766; rev:2;)',
        ),
        (
            Dialect.SNORT3,
            "rewrite tcp $EXTERNAL_NET any -> $HOME_NET any "
            '(msg:"x"; replace:"AAAAAAAAAA"; sid:12031; rev:6;)',
        ),
        (
            Dialect.SNORT3,
            'alert http ( msg:"x"; http_header:field content-type,with_body; '
            'content:"application/http-index-format"; sid:300019; rev:1; )',
        ),
        (
            Dialect.SNORT3,
            "alert http $HOME_NET any -> $EXTERNAL_NET any "
            '(msg:"x"; http_header_test:field user-agent,absent; sid:66173; rev:1;)',
        ),
        (
            Dialect.SURICATA,
            'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"x"; flags:SFU12; sid:2100627; rev:9;)',
        ),
        (
            Dialect.SNORT2,
            "alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 "
            '(msg:"x"; byte_test:2,!,0,7; sid:2528; rev:25;)',
        ),
        (
            Dialect.SNORT2,
            "alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 "
            '(msg:"x"; byte_extract:2,-6,file_name_len,relative,little; '
            "byte_jump:2,0,relative,little,post_offset file_name_len; sid:59461; rev:1;)",
        ),
        (Dialect.SURICATA, 'alert ipv6 any any -> any any (msg:"x"; sid:2030386; rev:1;)'),
        (
            Dialect.SURICATA,
            'alert tcp-stream $EXTERNAL_NET 1024: -> $HOME_NET any (msg:"x"; sid:2034219; rev:3;)',
        ),
        (
            Dialect.SURICATA,
            'alert telnet any any -> $HOME_NET any (msg:"x"; sid:2068415; rev:1;)',
        ),
        (
            Dialect.SNORT2,
            'alert tcp $EXTERNAL_NET 445 -> $HOME_NET ANY (msg:"x"; sid:18677; rev:3;)',
        ),
    ],
)
def test_issue_166_corpus_gaps_parse(dialect: Dialect, rule_text: str) -> None:
    assert parse_rule(rule_text, dialect=dialect).dialect is dialect


def test_issue_166_preserves_new_structured_values() -> None:
    metadata_rule = parse_rule(
        "alert tcp any any -> any any (metadata: engine shared, soid 3|52528; sid:1;)",
        dialect=Dialect.SNORT2,
    )
    metadata = next(
        option for option in metadata_rule.options if isinstance(option, MetadataOption)
    )
    assert ("soid", "3|52528") in metadata.entries

    headerless_rule = parse_rule("alert (gid:2; sid:1;)", dialect=Dialect.SNORT3)
    assert headerless_rule.header is None
    assert headerless_rule.protocol is None

    rewrite_rule = parse_rule(
        'rewrite tcp any any -> any any (replace:"AAAAAAAAAA"; sid:2;)',
        dialect=Dialect.SNORT3,
    )
    assert rewrite_rule.action is Action.REWRITE

    buffer_rule = parse_rule(
        "alert http any any -> any any (http_header_test:field user-agent,absent; sid:3;)",
        dialect=Dialect.SNORT3,
    )
    buffer = next(
        option for option in buffer_rule.options if isinstance(option, BufferSelectOption)
    )
    assert buffer.buffer_name == "http_header_test:field user-agent,absent"

    byte_test_rule = parse_rule(
        "alert tcp any any -> any any (byte_test:2,!,0,7; sid:4;)",
        dialect=Dialect.SNORT2,
    )
    byte_test = next(
        option for option in byte_test_rule.options if isinstance(option, ByteTestOption)
    )
    assert byte_test.operator == "!"

    byte_jump_rule = parse_rule(
        "alert tcp any any -> any any "
        "(byte_extract:2,-6,file_name_len,relative,little; "
        "byte_jump:2,0,relative,little,post_offset file_name_len; sid:5;)",
        dialect=Dialect.SNORT2,
    )
    byte_jump = next(
        option for option in byte_jump_rule.options if isinstance(option, ByteJumpOption)
    )
    assert "post_offset file_name_len" in byte_jump.flags
