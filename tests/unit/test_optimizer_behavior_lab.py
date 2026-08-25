import sys

from tools.optimizer_behavior_lab import run


def test_optimizer_behavior_lab_compares_every_pcap(tmp_path) -> None:
    original = tmp_path / "original.rules"
    candidate = tmp_path / "candidate.rules"
    pcaps = [tmp_path / "one.pcap", tmp_path / "two.pcap"]
    original.write_text("same", encoding="utf-8")
    candidate.write_text("same", encoding="utf-8")
    for pcap in pcaps:
        pcap.write_bytes(b"pcap")
    command = f"{sys.executable} -c 'print(\"same\")' {{file}} {{pcap}}"

    report = run(original, candidate, pcaps, command)

    assert report["pcap_count"] == 2
    assert report["passed"] == 2
    assert report["failures"] == 0
    assert report["behaviorally_equivalent"] is True
