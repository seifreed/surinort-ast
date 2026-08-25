"""Compare an original and optimized ruleset across a PCAP battery."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from surinort_ast.analysis import EngineVerifier


def run(
    original: Path,
    candidate: Path,
    pcaps: list[Path],
    engine_command: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run both rulesets against every PCAP and compare engine output."""
    for path in (original, candidate, *pcaps):
        if not path.is_file():
            raise FileNotFoundError(path)
    if not pcaps:
        raise ValueError("at least one PCAP is required")

    verifier = EngineVerifier(engine_command, timeout)
    cases: list[dict[str, Any]] = []
    for pcap in pcaps:
        behavior = verifier.verify_behavior(original, candidate, pcap)
        cases.append({"pcap": str(pcap), **asdict(behavior)})
    failures = [case for case in cases if case["status"] != "passed"]
    return {
        "original": str(original),
        "candidate": str(candidate),
        "engine_command": engine_command,
        "pcap_count": len(cases),
        "passed": len(cases) - len(failures),
        "failures": len(failures),
        "behaviorally_equivalent": not failures,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, action="append", required=True)
    parser.add_argument("--engine-command", required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.original, args.candidate, args.pcap, args.engine_command, args.timeout)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["behaviorally_equivalent"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
