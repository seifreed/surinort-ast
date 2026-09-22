"""Validate one complete ruleset before and after parse -> print."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from typing import Any, cast

from tools.conformance_lab import _error_keyword, _same_ast

from surinort_ast import parse_rule, print_rule
from surinort_ast.analysis import EngineVerifier
from surinort_ast.api.parsing import _read_rule_lines
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError
from surinort_ast.version import __version__


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entries(manifest: Path) -> list[tuple[Path, Dialect]]:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    entries = payload.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("engine-scale manifest must contain a non-empty 'files' list")
    result: list[tuple[Path, Dialect]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("each engine-scale manifest file needs a path")
        path = (manifest.parent / entry["path"]).resolve()
        if not path.is_file():
            raise ValueError(f"engine-scale manifest file does not exist: {path}")
        try:
            dialect = Dialect(entry.get("dialect", Dialect.SURICATA.value))
        except ValueError as exc:
            raise ValueError(f"invalid dialect for {path}") from exc
        result.append((path, dialect))
    return result


def run(
    manifest: Path,
    engine_command: str,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Run one engine against complete original and printed rulesets."""
    if "{file}" not in engine_command:
        raise ValueError("engine command must contain a {file} placeholder")
    started = time.perf_counter()
    tracemalloc.start()
    original_rules: list[str] = []
    printed_rules: list[str] = []
    metrics: dict[str, dict[str, int]] = {}
    errors_by_keyword: Counter[str] = Counter()
    files: list[dict[str, Any]] = []

    for path, dialect in _entries(manifest):
        dialect_metrics = metrics.setdefault(
            dialect.value,
            {"total_rules": 0, "parsed": 0, "round_trip_passed": 0, "parse_exceptions": 0},
        )
        file_rules = 0
        file_parsed = 0
        file_round_trip = 0
        for _line, source in _read_rule_lines(path):
            file_rules += 1
            dialect_metrics["total_rules"] += 1
            try:
                rule = parse_rule(source, dialect=dialect, include_raw_text=False)
                printed = print_rule(rule)
                reparsed = parse_rule(printed, dialect=dialect, include_raw_text=False)
            except ParseError as exc:
                dialect_metrics["parse_exceptions"] += 1
                errors_by_keyword[_error_keyword(source, str(exc))] += 1
                continue
            file_parsed += 1
            dialect_metrics["parsed"] += 1
            round_trip_ok = _same_ast(rule, reparsed)
            file_round_trip += int(round_trip_ok)
            dialect_metrics["round_trip_passed"] += int(round_trip_ok)
            original_rules.append(source)
            printed_rules.append(printed)
        file_result = {
            "path": path.name,
            "dialect": dialect.value,
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "total_rules": file_rules,
            "parsed": file_parsed,
            "round_trip_passed": file_round_trip,
        }
        files.append(file_result)

    with tempfile.TemporaryDirectory(prefix="surinort-engine-scale-") as directory:
        original_path = Path(directory) / "original.rules"
        printed_path = Path(directory) / "printed.rules"
        original_path.write_text("\n".join(original_rules) + "\n", encoding="utf-8")
        printed_path.write_text("\n".join(printed_rules) + "\n", encoding="utf-8")
        verifier = EngineVerifier(engine_command, timeout)
        original_result = verifier.verify(original_path)
        printed_result = verifier.verify(printed_path)

    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    total_rules = sum(item["total_rules"] for item in metrics.values())
    parsed = sum(item["parsed"] for item in metrics.values())
    round_trip = sum(item["round_trip_passed"] for item in metrics.values())
    unexpected = (
        total_rules != parsed
        or parsed != round_trip
        or not original_result.passed
        or not printed_result.passed
    )
    elapsed = time.perf_counter() - started
    return {
        "schema_version": 1,
        "kind": "engine-scale-conformance",
        "package_version": __version__,
        "manifest": str(manifest),
        "engine_command": engine_command,
        "engine_validation_scope": "one full combined ruleset load for original and printed files",
        "engine_original": original_result.to_dict(),
        "engine_printed": printed_result.to_dict(),
        "engine_validation_passed": int(original_result.passed),
        "engine_validation_after_print_passed": int(printed_result.passed),
        "engine_validation_failures": int(not original_result.passed),
        "engine_validation_after_print_failures": int(not printed_result.passed),
        "files": files,
        "dialect_metrics": metrics,
        "errors_by_keyword": dict(sorted(errors_by_keyword.items())),
        "total_rules": total_rules,
        "parsed": parsed,
        "printed": parsed,
        "parse_rate": parsed / total_rules if total_rules else 1.0,
        "round_trip_passed": round_trip,
        "round_trip_rate": round_trip / parsed if parsed else 1.0,
        "parse_exceptions": total_rules - parsed,
        "peak_memory_mb": peak_memory / 1_000_000,
        "rules_per_second": total_rules / elapsed if elapsed else 0.0,
        "unexpected_failures": int(unexpected),
        "elapsed_seconds": round(elapsed, 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--engine-command", required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.manifest, args.engine_command, args.timeout)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return cast(int, report["unexpected_failures"])


if __name__ == "__main__":
    raise SystemExit(main())
