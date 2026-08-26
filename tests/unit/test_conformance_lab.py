import json
import sys
from pathlib import Path

import pytest
from tools.conformance_lab import run
from tools.engine_matrix import load_matrix, run_matrix


def test_checked_in_conformance_corpus_round_trips() -> None:
    report = run(Path("conformance/corpus"))

    assert report["total_rules"] == 7
    assert report["parsed"] == 6
    assert report["parse_rate"] == 6 / 7
    assert report["round_trip_rate"] == 1.0
    assert report["unexpected_failures"] == 0
    assert report["printed"] == 6
    assert report["parse_exceptions"] == 1
    assert sum(report["errors_by_keyword"].values()) == 1
    assert report["dialect_metrics"]["suricata"]["total_rules"] == 3
    assert report["rules_per_second"] > 0
    assert report["peak_memory_mb"] > 0


def test_bundled_manifest_points_to_tracked_corpora() -> None:
    manifest = json.loads(Path("conformance/manifest.bundled.json").read_text(encoding="utf-8"))

    assert [entry["dialect"] for entry in manifest["files"]] == [
        "suricata",
        "snort2",
        "snort3",
    ]
    assert all(
        (Path("conformance") / entry["path"]).resolve().is_file() for entry in manifest["files"]
    )


def test_engine_matrix_runs_declared_entries(tmp_path) -> None:
    matrix = tmp_path / "matrix.json"
    manifest = tmp_path / "manifest.json"
    corpus = tmp_path / "rules.rules"
    corpus.write_text('alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8")
    manifest.write_text(
        json.dumps({"files": [{"path": "rules.rules", "dialect": "suricata"}]}),
        encoding="utf-8",
    )
    matrix.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": [
                    {
                        "id": "fake-suricata",
                        "engine": "suricata",
                        "version": "1.2.3",
                        "dialect": "suricata",
                        "manifest": "manifest.json",
                        "command": f"{sys.executable} -c pass {{file}}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    entries = load_matrix(matrix)
    report = run_matrix(matrix)

    assert entries[0].version == "1.2.3"
    assert report["total_rules"] == 1
    assert report["unexpected_failures"] == 0
    assert report["engines"][0]["report"]["engine_validation_passed"] == 1


def test_engine_matrix_rejects_wildcard_versions(tmp_path) -> None:
    matrix = tmp_path / "matrix.json"
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"files": []}', encoding="utf-8")
    matrix.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": [
                    {
                        "id": "suricata-template",
                        "engine": "suricata",
                        "version": "8.x",
                        "dialect": "suricata",
                        "manifest": "manifest.json",
                        "command": f"{sys.executable} -c pass {{file}}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="concrete numeric version"):
        load_matrix(matrix)


def test_engine_matrix_rejects_invalid_dialect_and_missing_manifest(tmp_path) -> None:
    matrix = tmp_path / "matrix.json"
    matrix.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": [
                    {
                        "id": "invalid-dialect",
                        "engine": "suricata",
                        "version": "8.0.0",
                        "dialect": "unknown",
                        "manifest": "missing.json",
                        "command": "engine -S {file}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="dialect"):
        load_matrix(matrix)

    payload = json.loads(matrix.read_text(encoding="utf-8"))
    payload["engines"][0]["dialect"] = "suricata"
    matrix.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest does not exist"):
        load_matrix(matrix)


def test_engine_matrix_requires_matching_pcap_placeholder(tmp_path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"files": []}', encoding="utf-8")
    pcap = tmp_path / "traffic.pcap"
    pcap.write_bytes(b"pcap")
    matrix = tmp_path / "matrix.json"
    matrix.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "engines": [
                    {
                        "id": "missing-pcap-placeholder",
                        "engine": "suricata",
                        "version": "8.0.0",
                        "dialect": "suricata",
                        "manifest": "manifest.json",
                        "pcap": "traffic.pcap",
                        "command": "engine -S {file}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must contain \\{pcap\\}"):
        load_matrix(matrix)


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
    assert report["dialect_metrics"]["suricata"]["unexpected_failures"] == 1


def test_conformance_behavior_verification_compares_original_and_printed(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "basic.rules").write_text(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8"
    )
    pcap = tmp_path / "traffic.pcap"
    pcap.write_bytes(b"pcap")
    command = f"{sys.executable} -c 'print(\"same\")' {{file}} {{pcap}}"

    report = run(corpus.parent.parent, engine_command=command, behavior_pcap=pcap)

    assert report["behavior_validation_passed"] == 1
    assert report["behavior_validation_failures"] == 0
    assert report["unexpected_failures"] == 0


def test_conformance_behavior_mismatch_is_unexpected_failure(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "basic.rules").write_text(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n', encoding="utf-8"
    )
    pcap = tmp_path / "traffic.pcap"
    pcap.write_bytes(b"pcap")
    command = f"{sys.executable} -c 'import sys; print(sys.argv[1])' {{file}} {{pcap}}"

    report = run(corpus.parent.parent, engine_command=command, behavior_pcap=pcap)

    assert report["cases"][0]["behavior_validation"] == "mismatch"
    assert report["behavior_validation_failures"] == 1
    assert report["unexpected_failures"] == 1


def test_conformance_behavior_skips_expected_parse_failures(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "invalid.rules").write_text("not a rule\n", encoding="utf-8")
    pcap = tmp_path / "traffic.pcap"
    pcap.write_bytes(b"pcap")
    command = f"{sys.executable} -c 'print(\"same\")' {{file}} {{pcap}}"

    report = run(corpus.parent.parent, engine_command=command, behavior_pcap=pcap)

    assert report["parsed"] == 0
    assert report["behavior_validation_passed"] == 0
    assert report["behavior_validation_failures"] == 0
    assert report["unexpected_failures"] == 0


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
    assert report["dialect_metrics"]["snort3"]["parsed"] == 1


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


def test_conformance_error_keyword_ignores_quoted_colons(tmp_path) -> None:
    corpus = tmp_path / "corpus" / "suricata"
    corpus.mkdir(parents=True)
    (corpus / "invalid.rules").write_text(
        'alert tcp any any -> any 80 (content:"http:"; broken\n', encoding="utf-8"
    )

    report = run(corpus.parent.parent)

    assert report["errors_by_keyword"] == {"content": 1}
