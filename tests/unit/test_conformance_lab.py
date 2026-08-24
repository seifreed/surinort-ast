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
    assert report["printed"] == 6
    assert report["parse_exceptions"] == 1
    assert report["rules_per_second"] > 0
    assert report["peak_memory_mb"] > 0


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


def test_conformance_engine_rejection_is_unexpected_failure(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "basic.rules").write_text(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8"
    )
    command = f'{sys.executable} -c "import sys; sys.exit(2)" {{file}}'

    report = run(corpus.parent.parent, engine_command=command)

    assert report["engine_validation_failures"] == 1
    assert report["engine_validation_after_print_failures"] == 1
    assert report["unexpected_failures"] == 1


def test_manifest_controls_dialect_expectation_and_limits(tmp_path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    rule_file = corpus / "rules.rules"
    rule_file.write_text('alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        '{"files": [{"path": "corpus/rules.rules", "dialect": "snort3", '
        '"expected_parse": true}], "unsupported": [{"id": "engine_config", '
        '"description": "Engine configuration directives are outside rule AST."}]}\n',
        encoding="utf-8",
    )

    report = run(corpus, manifest=manifest)

    assert report["manifest"] == str(manifest)
    assert report["cases"][0]["dialect"] == "snort3"
    assert report["unsupported_constructions"][0]["id"] == "engine_config"


def test_conformance_reports_printed_rule_parse_failure(tmp_path, monkeypatch) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "basic.rules").write_text(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8"
    )
    monkeypatch.setattr("tools.conformance_lab.print_rule", lambda _rule: "invalid rule")

    report = run(corpus.parent.parent)

    assert report["round_trip_passed"] == 0
    assert report["round_trip_rate"] == 0.0
    assert report["parse_exceptions"] == 1
    assert report["unexpected_failures"] == 1
    assert "Printed rule failed to parse" in report["cases"][0]["error"]
