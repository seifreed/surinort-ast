"""Parse the bundled Suricata/Snort rule corpus and report parse throughput.

Unlike ``benchmark_suite`` (which uses generated rules), this measures the real
``rules/`` corpus end-to-end through the public ``parse_file`` API, so it tracks
the performance of actual production rules.

Usage:
    python benchmarks/parse_corpus.py            # human-readable table
    python benchmarks/parse_corpus.py --json     # machine-readable result

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import NamedTuple, TypedDict

from surinort_ast import parse_file
from surinort_ast.api.parsing import parse_file_streaming

_CORPUS_ROOT = Path(__file__).resolve().parent.parent / "rules"


class FileStat(TypedDict):
    file: str
    rules: int
    seconds: float
    rules_per_second: int


class CorpusResult(TypedDict):
    files: list[FileStat]
    total_rules: int
    total_seconds: float
    rules_per_second: int
    microseconds_per_rule: float


class Config(NamedTuple):
    label: str
    track_locations: bool
    include_raw_text: bool
    workers: int


class ConfigStat(TypedDict):
    config: str
    seconds: float
    rules_per_second: int
    speedup: float


# Config matrix for --compare: the levers a caller can turn for bulk parsing.
_COMPARE_CONFIGS: tuple[Config, ...] = (
    Config("default (locations + raw_text)", True, True, 1),
    Config("no locations", False, True, 1),
    Config("lean (no locations, no raw_text)", False, False, 1),
    Config("lean + workers=4", False, False, 4),
)


def _rule_files() -> list[Path]:
    return sorted(_CORPUS_ROOT.rglob("*.rules"))


def _run_corpus(track_locations: bool, include_raw_text: bool, workers: int) -> tuple[int, float]:
    """Parse the whole corpus with one config; return (total_rules, seconds)."""
    total_rules = 0
    total_seconds = 0.0
    for path in _rule_files():
        start = time.perf_counter()
        rules = parse_file(
            path,
            track_locations=track_locations,
            include_raw_text=include_raw_text,
            workers=workers,
        )
        total_seconds += time.perf_counter() - start
        total_rules += len(rules)
    return total_rules, total_seconds


def compare() -> list[ConfigStat]:
    files = _rule_files()
    if not files:
        raise SystemExit(f"No .rules files found under {_CORPUS_ROOT}")

    parse_file(files[0])  # warm the parser cache

    stats: list[ConfigStat] = []
    baseline_rps = 0.0
    for cfg in _COMPARE_CONFIGS:
        rules, seconds = _run_corpus(cfg.track_locations, cfg.include_raw_text, cfg.workers)
        rps = rules / seconds if seconds else 0.0
        if cfg is _COMPARE_CONFIGS[0]:
            baseline_rps = rps
        stats.append(
            {
                "config": cfg.label,
                "seconds": round(seconds, 4),
                "rules_per_second": round(rps),
                "speedup": round(rps / baseline_rps, 2) if baseline_rps else 1.0,
            }
        )
    return stats


def measure() -> CorpusResult:
    files = _rule_files()
    if not files:
        raise SystemExit(f"No .rules files found under {_CORPUS_ROOT}")

    # Warm the grammar/parser cache so construction cost is excluded.
    parse_file(files[0])

    per_file: list[FileStat] = []
    total_rules = 0
    total_seconds = 0.0
    for path in files:
        start = time.perf_counter()
        rules = parse_file(path)
        elapsed = time.perf_counter() - start
        total_rules += len(rules)
        total_seconds += elapsed
        per_file.append(
            {
                "file": path.name,
                "rules": len(rules),
                "seconds": round(elapsed, 4),
                "rules_per_second": round(len(rules) / elapsed) if elapsed else 0,
            }
        )

    return {
        "files": per_file,
        "total_rules": total_rules,
        "total_seconds": round(total_seconds, 4),
        "rules_per_second": round(total_rules / total_seconds) if total_seconds else 0,
        "microseconds_per_rule": round(total_seconds / total_rules * 1e6, 1) if total_rules else 0,
    }


class MemoryStat(TypedDict):
    config: str
    rules: int
    peak_mb: float
    bytes_per_rule: int


def _peak_mb_full(track_locations: bool, include_raw_text: bool) -> tuple[int, float]:
    """Peak heap (MB) for holding the whole corpus as a list of Rule ASTs."""
    gc.collect()
    tracemalloc.start()
    rules = [
        rule
        for path in _rule_files()
        for rule in parse_file(
            path, track_locations=track_locations, include_raw_text=include_raw_text
        )
    ]
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    count = len(rules)
    del rules
    gc.collect()
    return count, peak / 1e6


def _peak_mb_streaming() -> tuple[int, float]:
    """Peak heap (MB) when streaming — only one rule is live at a time."""
    gc.collect()
    tracemalloc.start()
    count = 0
    for path in _rule_files():
        for _ in parse_file_streaming(path, track_locations=False, include_raw_text=False):
            count += 1
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    gc.collect()
    return count, peak / 1e6


def memory() -> list[MemoryStat]:
    if not _rule_files():
        raise SystemExit(f"No .rules files found under {_CORPUS_ROOT}")

    parse_file(_rule_files()[0])  # warm the parser cache

    measured: list[tuple[str, tuple[int, float]]] = [
        ("full (locations + raw_text)", _peak_mb_full(True, True)),
        ("full lean (no locations, no raw_text)", _peak_mb_full(False, False)),
        ("streaming lean", _peak_mb_streaming()),
    ]
    stats: list[MemoryStat] = []
    for label, (count, peak_mb) in measured:
        stats.append(
            {
                "config": label,
                "rules": count,
                "peak_mb": round(peak_mb, 1),
                "bytes_per_rule": round(peak_mb * 1e6 / count) if count else 0,
            }
        )
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument(
        "--compare",
        action="store_true",
        help="parse the corpus under several configs and report relative throughput",
    )
    ap.add_argument(
        "--memory",
        action="store_true",
        help="report peak heap memory per config (full vs lean vs streaming)",
    )
    args = ap.parse_args()

    if args.memory:
        mem = memory()
        if args.json:
            json.dump(mem, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0
        for m in mem:
            print(
                f"{m['config']:40s} {m['rules']:7d} rules  "
                f"peak {m['peak_mb']:8.1f} MB  {m['bytes_per_rule']:6d} B/rule"
            )
        return 0

    if args.compare:
        stats = compare()
        if args.json:
            json.dump(stats, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 0
        for stat in stats:
            print(
                f"{stat['config']:36s} {stat['seconds']:7.2f}s  "
                f"{stat['rules_per_second']:7d} rules/s  {stat['speedup']:.2f}x"
            )
        return 0

    result = measure()
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    for entry in result["files"]:
        print(
            f"{entry['file']:32s} {entry['rules']:7d} rules  "
            f"{entry['seconds']:8.3f}s  {entry['rules_per_second']:8d} rules/s"
        )
    print(
        f"\nTOTAL {result['total_rules']} rules in {result['total_seconds']}s "
        f"= {result['rules_per_second']} rules/s "
        f"({result['microseconds_per_rule']} us/rule)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
