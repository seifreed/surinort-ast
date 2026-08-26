"""Reproducible parser and round-trip conformance checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import time
import tracemalloc
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from surinort_ast import parse_rule, print_rule
from surinort_ast.analysis import EngineVerifier
from surinort_ast.api.parsing import _read_rule_lines
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError
from surinort_ast.version import __version__


@dataclass
class CaseResult:
    file: str
    dialect: str
    line: int
    expected_parse: bool
    parsed: bool
    round_trip: bool | None
    error: str | None = None
    error_keyword: str | None = None
    engine_validation: str = "not-run"
    engine_validation_after_print: str = "not-run"
    behavior_validation: str = "not-run"


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


_OPTION_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TOKEN_RE = re.compile(r"Token\('[A-Z_]+',\s*'([^']+)'")


def _error_keyword(source: str, error: str) -> str:
    """Best-effort keyword attribution for conformance error reports."""
    options: list[str] = []
    in_quote = False
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\" and in_quote:
            escaped = not escaped
            index += 1
            continue
        if char == '"' and not escaped:
            in_quote = not in_quote
            index += 1
            continue
        escaped = False
        if not in_quote:
            match = _OPTION_NAME_RE.match(source, index)
            if match:
                end = match.end()
                while end < len(source) and source[end].isspace():
                    end += 1
                if end < len(source) and source[end] == ":":
                    options.append(match.group(0))
                index = match.end()
                continue
        index += 1
    if options:
        return options[-1].lower()
    token = _TOKEN_RE.search(error)
    if token and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token.group(1)):
        return cast(str, token.group(1)).lower()
    return "<unknown>"


def _summarize_results(
    results: list[CaseResult],
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    dialect_metrics: dict[str, dict[str, int]] = {}
    errors_by_keyword: Counter[str] = Counter()
    for result in results:
        metrics = dialect_metrics.setdefault(
            result.dialect,
            {"total_rules": 0, "parsed": 0, "round_trip_passed": 0, "unexpected_failures": 0},
        )
        metrics["total_rules"] += 1
        metrics["parsed"] += int(result.parsed)
        metrics["round_trip_passed"] += int(result.round_trip is True)
        metrics["unexpected_failures"] += int(_result_is_unexpected(result))
        if result.error is not None and result.error_keyword is not None:
            errors_by_keyword[result.error_keyword] += 1
    return dialect_metrics, dict(sorted(errors_by_keyword.items()))


def _result_is_unexpected(result: CaseResult) -> bool:
    """Return whether a result violates its manifest or verification contract."""
    if result.parsed != result.expected_parse or result.round_trip is False:
        return True
    if result.parsed and result.engine_validation not in {"not-run", "passed"}:
        return True
    if result.parsed and result.engine_validation_after_print not in {"not-run", "passed"}:
        return True
    return result.parsed and result.behavior_validation not in {"not-run", "passed"}


def _manifest_files(
    manifest: Path,
    dialect_filter: Dialect | None = None,
) -> tuple[list[tuple[Path, Dialect, bool]], list[dict[str, Any]]]:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    entries = payload.get("files")
    if not isinstance(entries, list):
        raise ValueError("conformance manifest must contain a 'files' list")
    files: list[tuple[Path, Dialect, bool]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("each conformance manifest file needs a string path")
        path = (manifest.parent / entry["path"]).resolve()
        dialect = Dialect(entry.get("dialect", Dialect.SURICATA.value))
        if dialect_filter is not None and dialect is not dialect_filter:
            continue
        expected_parse = bool(entry.get("expected_parse", True))
        files.append((path, dialect, expected_parse))
    unsupported = payload.get("unsupported", [])
    if not isinstance(unsupported, list):
        raise ValueError("conformance manifest 'unsupported' must be a list")
    return files, unsupported


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path, corpus: Path) -> str:
    """Return a stable report path without leaking a machine-local prefix."""
    for base in (Path.cwd(), corpus):
        try:
            return str(path.relative_to(base))
        except ValueError:
            continue
    return path.name


def run(
    corpus: Path,
    engine_command: str | None = None,
    timeout: float = 30.0,
    manifest: Path | None = None,
    behavior_pcap: Path | None = None,
    dialect_filter: Dialect | None = None,
) -> dict[str, Any]:
    """Run checks for a corpus, optionally using a reproducible manifest."""
    if behavior_pcap is not None:
        if engine_command is None:
            raise ValueError("behavior verification requires an engine command")
        if "{pcap}" not in engine_command:
            raise ValueError("behavior verification command must include a {pcap} placeholder")
    results: list[CaseResult] = []
    started = time.perf_counter()
    tracemalloc.start()
    verifier = EngineVerifier(engine_command, timeout) if engine_command else None

    unsupported: list[dict[str, Any]] = []
    if manifest is not None:
        files, unsupported = _manifest_files(manifest, dialect_filter)
    else:
        files = [
            (
                path,
                _dialect(path),
                "invalid" not in path.parts and not path.stem.startswith("invalid"),
            )
            for path in sorted(corpus.rglob("*.rules"))
        ]

    corpus_files = [
        {
            "path": _display_path(path, corpus),
            "dialect": dialect.value,
            "expected_parse": expected_parse,
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path, dialect, expected_parse in files
    ]

    for path, dialect, expected_parse in files:
        for line_number, text in _read_rule_lines(path):
            try:
                rule = parse_rule(text, dialect=dialect, include_raw_text=False)
            except ParseError as exc:
                results.append(
                    CaseResult(
                        str(path),
                        dialect.value,
                        line_number,
                        expected_parse,
                        False,
                        None,
                        str(exc),
                        _error_keyword(text, str(exc)),
                    )
                )
                continue

            printed = print_rule(rule)
            try:
                round_trip_rule = parse_rule(printed, dialect=dialect, include_raw_text=False)
            except ParseError as exc:
                results.append(
                    CaseResult(
                        str(path),
                        dialect.value,
                        line_number,
                        expected_parse,
                        True,
                        False,
                        f"Printed rule failed to parse: {exc}",
                        _error_keyword(printed, str(exc)),
                    )
                )
                continue
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
                    if behavior_pcap is not None:
                        behavior = verifier.verify_behavior(
                            original_path, printed_path, behavior_pcap
                        )
                        result.engine_validation = behavior.original.status
                        result.engine_validation_after_print = behavior.candidate.status
                        result.behavior_validation = behavior.status
                    else:
                        result.engine_validation = verifier.verify(original_path).status
                        result.engine_validation_after_print = verifier.verify(printed_path).status
            results.append(result)

    elapsed_seconds = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    unexpected = [
        result
        for result in results
        if result.parsed != result.expected_parse
        or result.round_trip is False
        or (
            verifier is not None
            and result.parsed
            and (
                result.engine_validation != "passed"
                or result.engine_validation_after_print != "passed"
            )
        )
        or (behavior_pcap is not None and result.parsed and result.behavior_validation != "passed")
    ]
    parsed = sum(result.parsed for result in results)
    dialect_metrics, errors_by_keyword = _summarize_results(results)
    return {
        "package_version": __version__,
        "corpus": str(corpus),
        "manifest": str(manifest) if manifest else None,
        "corpus_files": corpus_files,
        "unsupported_constructions": unsupported,
        "dialect_metrics": dialect_metrics,
        "errors_by_keyword": errors_by_keyword,
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
        "engine_validation_failures": sum(
            verifier is not None and result.parsed and result.engine_validation != "passed"
            for result in results
        ),
        "engine_validation_after_print_failures": sum(
            verifier is not None
            and result.parsed
            and result.engine_validation_after_print != "passed"
            for result in results
        ),
        "behavior_validation_passed": sum(
            result.behavior_validation == "passed" for result in results
        ),
        "behavior_validation_failures": sum(
            behavior_pcap is not None and result.parsed and result.behavior_validation != "passed"
            for result in results
        ),
        "printed": parsed,
        "parse_exceptions": sum(result.error is not None for result in results),
        "engine_timeouts": sum(
            result.engine_validation == "timeout"
            or result.engine_validation_after_print == "timeout"
            for result in results
        ),
        "rules_per_second": len(results) / elapsed_seconds if elapsed_seconds else 0.0,
        "peak_memory_mb": peak_memory / 1_000_000,
        "unexpected_failures": len(unexpected),
        "engine_command": engine_command,
        "behavior_pcap": str(behavior_pcap) if behavior_pcap else None,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "cases": [asdict(result) for result in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=Path("conformance/corpus"))
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optional JSON manifest with per-file dialect/expectation metadata",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="omit per-rule cases from the JSON output while retaining aggregate metrics",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail unless every declared rule parses and round-trips without exceptions",
    )
    parser.add_argument(
        "--engine-command",
        help="Optional command template, for example 'suricata -T -S {file}'",
    )
    parser.add_argument(
        "--pcap",
        type=Path,
        help="Optional traffic fixture for differential behavior verification",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    report = run(args.corpus, args.engine_command, args.timeout, args.manifest, args.pcap)
    if args.summary_only:
        report.pop("cases", None)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    failures: list[str] = []
    if report["unexpected_failures"]:
        failures.append(f"{report['unexpected_failures']} unexpected failure(s)")
    if args.require_complete:
        if report["parse_rate"] != 1.0:
            failures.append(f"parse rate is {report['parse_rate']:.6g}, expected 1")
        if report["round_trip_rate"] != 1.0:
            failures.append(f"round-trip rate is {report['round_trip_rate']:.6g}, expected 1")
        if report["parse_exceptions"]:
            failures.append(f"{report['parse_exceptions']} parse exception(s)")
        for dialect, metrics in sorted(report["dialect_metrics"].items()):
            if metrics["parsed"] != metrics["total_rules"]:
                failures.append(f"{dialect} has unparsed rules")
            if metrics["round_trip_passed"] != metrics["parsed"]:
                failures.append(f"{dialect} has round-trip failures")
    if failures:
        print("Conformance gate failed: " + "; ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
