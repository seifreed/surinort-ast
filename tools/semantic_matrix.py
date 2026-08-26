"""Run versioned semantic validation cases against engine targets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from surinort_ast import parse_rule, validate_rule
from surinort_ast.analysis import EngineTarget
from surinort_ast.core.enums import Dialect
from surinort_ast.exceptions import ParseError
from surinort_ast.version import __version__


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a string list")
    return value


def _target(value: object) -> EngineTarget:
    if not isinstance(value, dict):
        raise ValueError("semantic matrix targets must be objects")
    return EngineTarget.from_dict(value)


def run(manifest: Path) -> dict[str, Any]:
    """Run every matrix case and return an auditable JSON report."""
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("semantic matrix schema_version must be 1")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("semantic matrix must contain a non-empty 'cases' list")

    results: list[dict[str, Any]] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("semantic matrix cases must be objects")
        case_id = raw_case.get("id")
        rule_text = raw_case.get("rule")
        category = raw_case.get("category")
        if (
            not isinstance(case_id, str)
            or not case_id
            or not isinstance(rule_text, str)
            or not rule_text
            or not isinstance(category, str)
            or not category
        ):
            raise ValueError("semantic matrix cases require id, category, and rule strings")
        try:
            case_dialect = Dialect(raw_case.get("dialect", Dialect.SURICATA.value))
        except ValueError as exc:
            raise ValueError(f"invalid dialect for semantic case {case_id}") from exc
        targets = raw_case.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"semantic case {case_id} requires targets")
        for raw_target in targets:
            if not isinstance(raw_target, dict):
                raise ValueError(f"semantic case {case_id} target must be an object")
            target = _target(raw_target)
            try:
                dialect = Dialect(raw_target.get("dialect", case_dialect.value))
            except ValueError as exc:
                raise ValueError(f"invalid dialect for semantic target {case_id}") from exc
            expected = set(
                _strings(raw_target.get("expected_diagnostics", []), "expected_diagnostics")
            )
            try:
                rule = parse_rule(rule_text, dialect=dialect, include_raw_text=False)
                actual = {
                    diagnostic.code
                    for diagnostic in validate_rule(rule, target=target)
                    if diagnostic.code is not None
                }
                error = None
            except ParseError as exc:
                actual = {"parse_error"}
                error = str(exc)
            passed = actual == expected
            results.append(
                {
                    "id": case_id,
                    "category": category,
                    "engine": target.engine,
                    "version": target.version,
                    "dialect": dialect.value,
                    "expected_diagnostics": sorted(expected),
                    "actual_diagnostics": sorted(actual),
                    "passed": passed,
                    "error": error,
                }
            )

    failures = [result for result in results if not result["passed"]]
    categories = sorted({str(result["category"]) for result in results})
    return {
        "schema_version": 1,
        "kind": "semantic-validation-matrix",
        "package_version": __version__,
        "manifest": str(manifest),
        "case_count": len(raw_cases),
        "target_case_count": len(results),
        "categories": categories,
        "passed": len(results) - len(failures),
        "failures": len(failures),
        "cases": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.manifest)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return int(report["failures"])


if __name__ == "__main__":
    raise SystemExit(main())
