from surinort_ast import parse_rule
from surinort_ast.analysis import semantic_diff


def test_semantic_diff_reports_header_and_detection_changes() -> None:
    before = parse_rule('alert tcp any any -> any 80 (content:"GET"; sid:1;)')
    after = parse_rule('alert tcp any any -> any 443 (content:"POST"; sid:1;)')

    diff = semantic_diff(before, after)

    assert diff.changed is True
    assert "dst_port: changed" in diff.header_changes
    assert "option #1: changed" in diff.detection_changes
    assert "behavioral equivalence is unverified" in diff.risk
    assert diff.to_dict()["sid"] == 1


def test_semantic_diff_ignores_source_metadata() -> None:
    before = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
    after = before.model_copy(update={"raw_text": "different source spelling"})

    assert semantic_diff(before, after).changed is False
