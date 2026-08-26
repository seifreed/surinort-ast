"""Render conformance JSON reports as a public Markdown dashboard."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _report_rows(
    report: dict[str, Any], source: str, version: str | None = None
) -> list[dict[str, Any]]:
    error_keywords = report.get("errors_by_keyword")
    error_summary = (
        ", ".join(f"{key}:{value}" for key, value in sorted(error_keywords.items()))
        if isinstance(error_keywords, dict) and error_keywords
        else None
    )
    if isinstance(report.get("engines"), list):
        rows: list[dict[str, Any]] = []
        for entry in report["engines"]:
            nested = entry.get("report")
            if isinstance(nested, dict):
                rows.extend(
                    _report_rows(
                        nested,
                        f"{source}:{entry.get('id', 'engine')}",
                        version=entry.get("version"),
                    )
                )
        return rows
    dialect_metrics = report.get("dialect_metrics")
    if isinstance(dialect_metrics, dict):
        rows = []
        for dialect, metrics in sorted(dialect_metrics.items()):
            if not isinstance(metrics, dict):
                continue
            total_rules = int(metrics.get("total_rules", 0))
            parsed = int(metrics.get("parsed", 0))
            round_trip = int(metrics.get("round_trip_passed", 0))
            rows.append(
                {
                    "source": source,
                    "version": version or report.get("package_version"),
                    "dialect": dialect,
                    "total_rules": total_rules,
                    "parse_rate": parsed / total_rules if total_rules else 1.0,
                    "round_trip_rate": round_trip / parsed if parsed else 1.0,
                    "parse_exceptions": report.get("parse_exceptions"),
                    "errors_by_keyword": error_summary,
                    "unexpected_failures": metrics.get("unexpected_failures", 0),
                    "rules_per_second": report.get("rules_per_second"),
                    "peak_memory_mb": report.get("peak_memory_mb"),
                }
            )
        if rows:
            return rows
    return [
        {
            "source": source,
            "version": version or report.get("package_version"),
            "dialect": report.get("dialect", ", ".join(report.get("dialects", []))),
            "total_rules": report.get("total_rules", 0),
            "parse_rate": report.get("parse_rate"),
            "round_trip_rate": report.get("round_trip_rate"),
            "parse_exceptions": report.get("parse_exceptions"),
            "errors_by_keyword": error_summary,
            "unexpected_failures": report.get("unexpected_failures", 0),
            "rules_per_second": report.get("rules_per_second"),
            "peak_memory_mb": report.get("peak_memory_mb"),
        }
    ]


def _semantic_rows(report: dict[str, Any], source: str) -> list[dict[str, Any]]:
    cases = report.get("cases")
    if not isinstance(cases, list):
        return []
    grouped: dict[tuple[str, str, str], dict[str, int]] = {}
    for case in cases:
        if not isinstance(case, dict):
            continue
        key = (
            str(case.get("engine", "")),
            str(case.get("version", "")),
            str(case.get("dialect", "")),
        )
        metrics = grouped.setdefault(key, {"evaluations": 0, "passed": 0})
        metrics["evaluations"] += 1
        metrics["passed"] += int(case.get("passed") is True)
    return [
        {
            "source": source,
            "version": report.get("package_version"),
            "engine": engine,
            "dialect": dialect,
            "engine_version": engine_version,
            "evaluations": metrics["evaluations"],
            "passed": metrics["passed"],
            "failures": metrics["evaluations"] - metrics["passed"],
        }
        for (engine, engine_version, dialect), metrics in sorted(grouped.items())
    ]


def _load_reports(
    history_dir: Path, report: Path | None, semantic_matrix: Path | None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    paths = sorted(history_dir.glob("*.json")) if history_dir.is_dir() else []
    if report is not None and report not in paths:
        paths.append(report)
    rows: list[dict[str, Any]] = []
    semantic_rows: list[dict[str, Any]] = []
    if semantic_matrix is not None and semantic_matrix not in paths:
        paths.append(semantic_matrix)
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            if payload.get("kind") == "semantic-validation-matrix":
                semantic_rows.extend(_semantic_rows(payload, path.name))
                continue
            if payload.get("kind") in {
                "optimizer-behavior-conformance",
                "optimizer-behavior-engine-conformance",
            } or ("pcap_count" in payload and "cases" in payload):
                continue
            rows.extend(_report_rows(payload, path.name))
    return rows, semantic_rows


def render(
    history_dir: Path,
    output: Path,
    report: Path | None = None,
    semantic_matrix: Path | None = None,
) -> str:
    """Render reports and write the resulting Markdown page."""
    rows, semantic_rows = _load_reports(history_dir, report, semantic_matrix)
    lines = [
        "# Conformance Dashboard",
        "",
        "This page contains only reports generated by the conformance lab. "
        "Missing engine runs are not represented as passing results.",
        "",
        "| Snapshot | Version | Dialect | Rules | Parse rate | Round-trip rate | Parse exceptions | Errors by keyword | Unexpected failures | Rules/s | Peak MB |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: |",
    ]
    if rows:
        for row in rows:

            def number(value: Any) -> str:
                return "-" if value is None else str(value)

            lines.append(
                "| {source} | {version} | {dialect} | {total_rules} | {parse_rate} | "
                "{round_trip_rate} | {parse_exceptions} | {errors_by_keyword} | "
                "{unexpected_failures} | {rules_per_second} | "
                "{peak_memory_mb} |".format(**{key: number(value) for key, value in row.items()})
            )
    else:
        lines.append("| No reports | - | - | 0 | - | - | - | - | - | - | - |")
    lines.extend(
        [
            "",
            "Rates are fractions in the source JSON. Engine and PCAP behavior "
            "claims require a report from the corresponding real engine build.",
            "",
        ]
    )
    if semantic_rows:
        lines.extend(
            [
                "## Semantic Validation Matrix",
                "",
                "| Snapshot | Package | Engine | Version | Dialect | Evaluations | Passed | Failures |",
                "| --- | --- | --- | --- | --- | ---: | ---: | ---: |",
            ]
        )
        for row in semantic_rows:
            lines.append(
                "| {source} | {version} | {engine} | {engine_version} | {dialect} | "
                "{evaluations} | {passed} | {failures} |".format(**row)
            )
        lines.append("")
    rendered = "\n".join(lines)
    output.write_text(rendered, encoding="utf-8")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--semantic-matrix", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render(args.history_dir, args.output, args.report, args.semantic_matrix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
