from pathlib import Path

from tools.conformance_lab import run


def test_checked_in_conformance_corpus_round_trips() -> None:
    report = run(Path("conformance/corpus"))

    assert report["total_rules"] == 7
    assert report["parsed"] == 6
    assert report["parse_rate"] == 6 / 7
    assert report["round_trip_rate"] == 1.0
    assert report["unexpected_failures"] == 0
