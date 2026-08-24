"""Reproducible parser and round-trip conformance checks."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from surinort_ast import parse_rule, print_rule
from surinort_ast.analysis import EngineVerifier
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
    engine_validation_after_print: str = "not-run"


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


def run(corpus: Path, engine_command: str | None = None, timeout: float = 30.0) -> dict[str, Any]:
    """Run conformance checks for every ``*.rules`` file below ``corpus``."""
    results: list[CaseResult] = []
    started = time.perf_counter()
    verifier = EngineVerifier(engine_command, timeout) if engine_command else None

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

            printed = print_rule(rule)
            round_trip_rule = parse_rule(printed, dialect=dialect, include_raw_text=False)
            result = CaseResult(
                str(path),
                dialect.value,
                line_number,
                expected_parse,
                True,
                _same_ast(rule, round_trip_rule),
            )
            if verifier:
                with tempfile.TemporaryDirectory(prefix="surinort-conformance-") as directory:
                    original_path = Path(directory) / "original.rules"
                    printed_path = Path(directory) / "printed.rules"
                    original_path.write_text(text + "\n", encoding="utf-8")
                    printed_path.write_text(printed + "\n", encoding="utf-8")
                    result.engine_validation = verifier.verify(original_path).status
                    result.engine_validation_after_print = verifier.verify(printed_path).status
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
        "engine_validation_passed": sum(result.engine_validation == "passed" for result in results),
        "engine_validation_after_print_passed": sum(
            result.engine_validation_after_print == "passed" for result in results
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
