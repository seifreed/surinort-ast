"""Run the conformance lab against a declared engine/version matrix."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools.conformance_lab import run

from surinort_ast.core.enums import Dialect


@dataclass(frozen=True)
class MatrixEntry:
    """One concrete engine invocation in a conformance matrix."""

    id: str
    engine: str
    version: str
    dialect: str
    manifest: Path
    command: str
    pcap: Path | None = None


def load_matrix(path: Path) -> list[MatrixEntry]:
    """Load and validate a versioned engine matrix."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("engine matrix schema_version must be 1")
    entries = payload.get("engines")
    if not isinstance(entries, list) or not entries:
        raise ValueError("engine matrix must contain a non-empty 'engines' list")

    loaded: list[MatrixEntry] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each engine matrix entry must be an object")
        required = ("id", "engine", "version", "dialect", "manifest", "command")
        if any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
            raise ValueError(f"engine matrix entries require string fields: {', '.join(required)}")
        if "{file}" not in entry["command"]:
            raise ValueError(f"engine matrix command for {entry['id']} must contain {{file}}")
        pcap = entry.get("pcap")
        if pcap is not None and not isinstance(pcap, str):
            raise ValueError(f"engine matrix pcap for {entry['id']} must be a string")
        loaded.append(
            MatrixEntry(
                id=entry["id"],
                engine=entry["engine"],
                version=entry["version"],
                dialect=entry["dialect"],
                manifest=(path.parent / entry["manifest"]).resolve(),
                command=entry["command"],
                pcap=(path.parent / pcap).resolve() if pcap else None,
            )
        )
    return loaded


def run_matrix(path: Path) -> dict[str, Any]:
    """Run every declared engine and return one aggregate JSON report."""
    entries = load_matrix(path)
    reports: list[dict[str, Any]] = []
    for entry in entries:
        report = run(
            path.parent,
            engine_command=entry.command,
            manifest=entry.manifest,
            behavior_pcap=entry.pcap,
            dialect_filter=Dialect(entry.dialect),
        )
        reports.append(
            {
                **asdict(entry),
                "manifest": str(entry.manifest),
                "pcap": str(entry.pcap) if entry.pcap else None,
                "report": report,
            }
        )
    return {
        "schema_version": 1,
        "matrix": str(path),
        "engines": reports,
        "total_rules": sum(item["report"]["total_rules"] for item in reports),
        "unexpected_failures": sum(item["report"]["unexpected_failures"] for item in reports),
        "engine_validation_failures": sum(
            item["report"]["engine_validation_failures"] for item in reports
        ),
        "behavior_validation_failures": sum(
            item["report"]["behavior_validation_failures"] for item in reports
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_matrix(args.matrix)
    rendered = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if report["unexpected_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
