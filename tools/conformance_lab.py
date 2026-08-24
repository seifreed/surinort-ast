"""Reproducible parser and round-trip conformance checks."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from surinort_ast import parse_rule, print_rule
from surinort_ast.api.parsing import _read_rule_lines
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError


@dataclass
class CaseResult:
    file: str
    dialect: str
    line: int
    expected_parse: bool
    parsed: bool
    round_trip: bool | None
    error: str | None = None
    engine_validation: str = "not-run"


def _dialect(path: Path) -> Dialect:
    for dialect in Dialect:
        if dialect.value in path.parts:
            return dialect
    return Dialect.SURICATA


def _strip_runtime_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_runtime_metadata(item)
            for key, item in value.items()
            if key not in {"location", "origin", "raw_text", "diagnostics"}
        }
    if isinstance(value, list):
        return [_strip_runtime_metadata(item) for item in value]
    return value


def _same_ast(left: Any, right: Any) -> bool:
    return bool(
        _strip_runtime_metadata(left.model_dump(mode="json"))
        == _strip_runtime_metadata(right.model_dump(mode="json"))
    )


def _run_engine(command: str, path: Path, timeout: float) -> str:
    parts = shlex.split(command.replace("{file}", str(path)))
    if not parts or shutil.which(parts[0]) is None:
        return "unavailable"
    try:
        completed = subprocess.run(
            parts, check=False, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    return "passed" if completed.returncode == 0 else "failed"


def run(corpus: Path, engine_command: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
    """Run conformance checks for every ``*.rules`` file below ``corpus``."""
    results: list[CaseResult] = []
    started = time.perf_counter()

    for path in sorted(corpus.rglob("*.rules")):
        dialect = _dialect(path)
        expected_parse = "invalid" not in path.parts and not path.stem.startswith("invalid")
        for line_number, text in _read_rule_lines(path):
            try:
                rule = parse_rule(text, dialect=dialect, include_raw_text=False)
            except ParseError as exc:
                results.append(
                    CaseResult(
                        str(path), dialect.value, line_number, expected_parse, False, None, str(exc)
                    )
                )
                continue

            round_trip_rule = parse_rule(print_rule(rule), dialect=dialect, include_raw_text=False)
            result = CaseResult(
                str(path),
                dialect.value,
                line_number,
                expected_parse,
                True,
                _same_ast(rule, round_trip_rule),
            )
            if engine_command:
                result.engine_validation = _run_engine(engine_command, path, timeout)
            results.append(result)

    unexpected = [
        result
        for result in results
        if result.parsed != result.expected_parse or result.round_trip is False
    ]
    parsed = sum(result.parsed for result in results)
    return {
        "corpus": str(corpus),
        "total_rules": len(results),
        "parsed": parsed,
        "parse_rate": parsed / len(results) if results else 1.0,
        "round_trip_passed": sum(result.round_trip is True for result in results),
        "round_trip_rate": (
            sum(result.round_trip is True for result in results) / parsed if parsed else 1.0
        ),
        "unexpected_failures": len(unexpected),
        "engine_command": engine_command,
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "cases": [asdict(result) for result in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("conformance/corpus"))
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--engine-command",
        help="Optional command template, for example 'suricata -T -S {file}'",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    report = run(args.corpus, args.engine_command, args.timeout)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 1 if report["unexpected_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
