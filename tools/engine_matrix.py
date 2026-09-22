"""Run the conformance lab against a declared engine/version matrix."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools.conformance_lab import run

from surinort_ast.core.enums import Dialect

_CONCRETE_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")


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


def _resolve_pcap(path: Path, entry_id: str, value: object, command: str) -> Path | None:
    if value is None or value == "":
        if "{pcap}" in command:
            raise ValueError(f"engine matrix command for {entry_id} requires a pcap path")
        return None
    if not isinstance(value, str):
        raise ValueError(f"engine matrix pcap for {entry_id} must be a string")
    pcap_path = (path.parent / value).resolve()
    if not pcap_path.is_file():
        raise ValueError(f"engine matrix pcap does not exist for {entry_id}: {pcap_path}")
    if "{pcap}" not in command:
        raise ValueError(f"engine matrix command for {entry_id} must contain {{pcap}}")
    return pcap_path


def load_matrix(path: Path) -> list[MatrixEntry]:
    """Load and validate a versioned engine matrix."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("engine matrix schema_version must be 1")
    entries = payload.get("engines")
    if not isinstance(entries, list) or not entries:
        raise ValueError("engine matrix must contain a non-empty 'engines' list")

    loaded: list[MatrixEntry] = []
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each engine matrix entry must be an object")
        required = ("id", "engine", "version", "dialect", "manifest", "command")
        if any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
            raise ValueError(f"engine matrix entries require string fields: {', '.join(required)}")
        entry_id = entry["id"]
        if entry_id in seen_ids:
            raise ValueError(f"engine matrix entry id is duplicated: {entry_id}")
        seen_ids.add(entry_id)
        if not _CONCRETE_VERSION.fullmatch(entry["version"]):
            raise ValueError(
                f"engine matrix version for {entry_id} must be a concrete numeric version"
            )
        try:
            dialect = Dialect(entry["dialect"])
        except ValueError as exc:
            raise ValueError(f"engine matrix dialect is invalid for {entry_id}") from exc
        if "{file}" not in entry["command"]:
            raise ValueError(f"engine matrix command for {entry_id} must contain {{file}}")
        manifest = (path.parent / entry["manifest"]).resolve()
        if not manifest.is_file():
            raise ValueError(f"engine matrix manifest does not exist for {entry_id}: {manifest}")
        pcap_path = _resolve_pcap(path, entry_id, entry.get("pcap"), entry["command"])
        loaded.append(
            MatrixEntry(
                id=entry_id,
                engine=entry["engine"],
                version=entry["version"],
                dialect=dialect.value,
                manifest=manifest,
                command=entry["command"],
                pcap=pcap_path,
            )
        )
    return loaded


def _completeness_failures(entry: MatrixEntry, report: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report["parse_rate"] != 1.0:
        failures.append("parse rate is below 1")
    if report["round_trip_rate"] != 1.0:
        failures.append("round-trip rate is below 1")
    if report["engine_validation_failures"]:
        failures.append("original rules rejected by engine")
    if report["engine_validation_after_print_failures"]:
        failures.append("printed rules rejected by engine")
    if entry.pcap and report["behavior_validation_failures"]:
        failures.append("behavior verification failed")
    return failures


def run_matrix(path: Path, require_complete: bool = False) -> dict[str, Any]:
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
        item = {
            **asdict(entry),
            "manifest": str(entry.manifest),
            "pcap": str(entry.pcap) if entry.pcap else None,
            "report": report,
        }
        if require_complete:
            item["completeness_failures"] = _completeness_failures(entry, report)
        reports.append(item)
    completeness_failures = sum(len(item.get("completeness_failures", ())) for item in reports)
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
        "completeness_failures": completeness_failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail unless every matrix entry parses, round-trips, and loads in its engine",
    )
    args = parser.parse_args()
    report = run_matrix(args.matrix, require_complete=args.require_complete)
    rendered = json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if report["unexpected_failures"] or report["completeness_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
