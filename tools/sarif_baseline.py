"""Compare SARIF findings against a stored baseline."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def findings(path: Path) -> set[tuple[str, str, str]]:
    """Return stable finding keys, excluding line numbers that move in edits."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    result: set[tuple[str, str, str]] = set()
    for run in payload.get("runs", []):
        for item in run.get("results", []):
            locations = item.get("locations", [])
            uri = ""
            if locations:
                uri = (
                    locations[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
            result.add(
                (
                    item.get("ruleId", ""),
                    item.get("message", {}).get("text", ""),
                    uri,
                )
            )
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} CURRENT BASELINE", file=sys.stderr)
        return 2
    current = findings(Path(sys.argv[1]))
    baseline = findings(Path(sys.argv[2]))
    new = current - baseline
    print(f"Baseline findings: {len(baseline)}; current: {len(current)}; new: {len(new)}")
    return 1 if new else 0


if __name__ == "__main__":
    raise SystemExit(main())
