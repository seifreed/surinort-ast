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
