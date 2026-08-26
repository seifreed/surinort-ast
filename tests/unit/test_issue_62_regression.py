import json
from pathlib import Path

from surinort_ast.api.parsing import parse_rule
from surinort_ast.core.enums import Dialect
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.printer.text_printer import print_rule

FIXTURE_PATH = Path(__file__).parent.parent / "fixtures" / "issue_62_parse_error.jsonl"
DIALECT_BY_ENGINE = {
    "suricata": Dialect.SURICATA,
    "snort2": Dialect.SNORT2,
    "snort3": Dialect.SNORT3,
}


def _load_issue_62_cases() -> list[dict[str, str]]:
    return [json.loads(line) for line in FIXTURE_PATH.read_text().splitlines() if line.strip()]


def test_issue_62_fixture_is_complete():
    cases = _load_issue_62_cases()
    assert len(cases) == 31
    assert {case["engine"] for case in cases} == {"suricata", "snort2", "snort3"}


def test_issue_62_rules_parse_without_errors():
    for case in _load_issue_62_cases():
        rule = parse_rule(case["raw_text"], dialect=DIALECT_BY_ENGINE[case["engine"]])
        assert rule is not None


def test_issue_62_preserves_protocol_names_in_ast_and_printed_text():
    for case in _load_issue_62_cases():
        expected_protocol = case["raw_text"].split(maxsplit=2)[1]
        if expected_protocol not in {"tcp-pkt", "http1", "bittorrent-dht"}:
            continue

        rule = parse_rule(case["raw_text"], dialect=DIALECT_BY_ENGINE[case["engine"]])
        assert rule.header.protocol.value == expected_protocol
        assert print_rule(rule).split(maxsplit=2)[1] == expected_protocol


def test_issue_62_wrapper_parser_handles_escaped_content_terminator():
    case = _load_issue_62_cases()[16]
    parser = LarkRuleParser(dialect=DIALECT_BY_ENGINE[case["engine"]])
    rule = parser.parse(case["raw_text"])
    assert rule is not None


def test_normalize_does_not_corrupt_midpayload_escaped_quote():
    """The content-closer repair must only fire when ``\\";`` is the actual
    terminator. A properly closed content whose payload contains ``\\";`` in the
    middle (e.g. content:"GET \\"; HTTP") must be left intact, not split."""
    rule = parse_rule('alert tcp any any -> any any (content:"GET \\"; HTTP"; sid:1;)')
    contents = [opt for opt in rule.options if opt.node_type == "ContentOption"]
    assert len(contents) == 1
    assert contents[0].pattern == b'GET "; HTTP'


def test_normalize_still_repairs_missing_content_closer():
    """The quirk form (content closed only by ``\\";``) is still repaired."""
    rule = parse_rule('alert tcp any any -> any any (content:"abc\\"; sid:1;)')
    contents = [opt for opt in rule.options if opt.node_type == "ContentOption"]
    assert len(contents) == 1
    # The repair appends a closing quote, so the escaped quote stays a literal
    # ``"`` in the payload rather than dropping the content.
    assert contents[0].pattern == b'abc"'


def test_suricata_threshold_can_be_followed_by_option_without_separator():
    """Suricata accepts the ET Open threshold/reference separator omission."""
    rule = parse_rule(
        'alert dns any any -> any any (msg:"x"; '
        "threshold: type limit, count 1, seconds 120, track by_src "
        "reference:url,https://example.test/; sid:1;)"
    )

    assert [option.node_type for option in rule.options] == [
        "MsgOption",
        "ThresholdOption",
        "ReferenceOption",
        "SidOption",
    ]


def test_content_keyword_is_case_insensitive_for_engine_compatibility():
    rule = parse_rule('alert http any any -> any any (Content:"UserInformation.txt"; sid:1;)')

    assert rule.options[0].node_type == "ContentOption"
    assert 'content:"UserInformation.txt";' in print_rule(rule)
