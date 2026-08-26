import sys

import pytest

from surinort_ast.analysis import EngineVerifier


def test_engine_verifier_reports_pass_and_failure(tmp_path) -> None:
    path = tmp_path / "rule.rules"
    path.write_text("alert tcp any any -> any 80 (sid:1;)\n", encoding="utf-8")

    passed = EngineVerifier(f'{sys.executable} -c "import sys; sys.exit(0)" {{file}}').verify(path)
    failed = EngineVerifier(f'{sys.executable} -c "import sys; sys.exit(3)" {{file}}').verify(path)

    assert passed.passed
    assert passed.returncode == 0
    assert failed.status == "failed"
    assert failed.returncode == 3


def test_engine_verifier_reports_unavailable_and_validates_command(tmp_path) -> None:
    path = tmp_path / "rule.rules"
    path.write_text("", encoding="utf-8")

    result = EngineVerifier("missing-surinort-engine --check {file}").verify(path)

    assert result.status == "unavailable"
    with pytest.raises(ValueError, match="placeholder"):
        EngineVerifier("suricata -T")


def test_engine_verifier_compares_behavior_output(tmp_path) -> None:
    original = tmp_path / "original.rules"
    candidate = tmp_path / "candidate.rules"
    pcap = tmp_path / "traffic.pcap"
    original.write_text("original", encoding="utf-8")
    candidate.write_text("original", encoding="utf-8")
    pcap.write_bytes(b"pcap")
    command = (
        f'{sys.executable} -c "import pathlib,sys; '
        f'print(pathlib.Path(sys.argv[1]).read_text())" {{file}} {{pcap}}'
    )
    verifier = EngineVerifier(command)

    passed = verifier.verify_behavior(original, candidate, pcap)
    candidate.write_text("changed", encoding="utf-8")
    mismatch = verifier.verify_behavior(original, candidate, pcap)

    assert passed.passed
    assert mismatch.status == "mismatch"


def test_engine_verifier_compares_json_alert_projections(tmp_path) -> None:
    original = tmp_path / "original.rules"
    candidate = tmp_path / "candidate.rules"
    pcap = tmp_path / "traffic.pcap"
    original.write_text("original", encoding="utf-8")
    candidate.write_text("candidate", encoding="utf-8")
    pcap.write_bytes(b"pcap")
    command = f"{sys.executable} -c \"print('[1]')\" {{file}} {{pcap}}"

    result = EngineVerifier(command).verify_behavior(original, candidate, pcap)

    assert result.passed
    assert result.alert_output_equal is True
