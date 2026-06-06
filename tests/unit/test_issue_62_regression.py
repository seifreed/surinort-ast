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
