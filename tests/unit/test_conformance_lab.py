import sys
from pathlib import Path

from tools.conformance_lab import run


def test_checked_in_conformance_corpus_round_trips() -> None:
    report = run(Path("conformance/corpus"))

    assert report["total_rules"] == 7
    assert report["parsed"] == 6
    assert report["parse_rate"] == 6 / 7
    assert report["round_trip_rate"] == 1.0
    assert report["unexpected_failures"] == 0


def test_conformance_engine_checks_original_and_printed_rule(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "basic.rules").write_text(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8"
    )
    command = f"{sys.executable} -c pass {{file}}"

    report = run(corpus.parent.parent, engine_command=command)

    assert report["engine_validation_passed"] == 1
    assert report["engine_validation_after_print_passed"] == 1
    assert report["cases"][0]["engine_validation_after_print"] == "passed"
