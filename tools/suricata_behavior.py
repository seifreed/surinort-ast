"""Run Suricata on a PCAP and print a stable alert projection."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_ALERT_FIELDS = ("action", "category", "gid", "rev", "severity", "signature", "signature_id")


def alert_projection(eve_path: Path) -> tuple[dict[str, Any], ...]:
    """Extract stable alert fields from a Suricata EVE JSON log."""
    alerts: list[dict[str, Any]] = []
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        event = json.loads(line)
        if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
            continue
        alert = event["alert"]
        alerts.append({field: alert.get(field) for field in _ALERT_FIELDS})
    return tuple(sorted(alerts, key=lambda item: json.dumps(item, sort_keys=True)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--engine", default="suricata")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="surinort-suricata-") as directory:
        try:
            completed = subprocess.run(
                [
                    args.engine,
                    "-k",
                    "none",
                    "-r",
                    str(args.pcap),
                    "-S",
                    str(args.rules),
                    "-l",
                    directory,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
        except FileNotFoundError:
            print(f"engine not found: {args.engine}", file=sys.stderr)
            return 127
        except subprocess.TimeoutExpired:
            print(f"engine timed out after {args.timeout}s", file=sys.stderr)
            return 124
        if completed.returncode != 0:
            print(completed.stderr, file=sys.stderr, end="")
            return completed.returncode

        eve_path = Path(directory) / "eve.json"
        if not eve_path.exists():
            print("Suricata did not produce eve.json", file=sys.stderr)
            return 1
        print(json.dumps(alert_projection(eve_path), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
