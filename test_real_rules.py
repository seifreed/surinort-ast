#!/usr/bin/env python3
"""
Script para parsear todas las reglas reales de Snort y Suricata.
Genera estadísticas detalladas de éxito/fallo.
"""
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError

def parse_rules_file(filepath: Path, dialect: str = "suricata") -> Tuple[List[str], List[Tuple[int, str, str]]]:
    """Parsea un archivo de reglas y retorna (éxitos, fallos)."""
    successes = []
    failures = []

    with filepath.open('r', encoding='utf-8', errors='ignore') as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Check if it looks like a rule
            if not any(line.startswith(action) for action in ['alert', 'drop', 'pass', 'log', 'reject', 'sdrop']):
                continue

            try:
                rule = parse_rule(line, dialect=dialect)
                successes.append(line)
            except ParseError as e:
                error_msg = str(e)
                # Truncate error message
                if len(error_msg) > 100:
                    error_msg = error_msg[:100] + "..."
                failures.append((line_num, line[:80] + "..." if len(line) > 80 else line, error_msg))
            except Exception as e:
                failures.append((line_num, line[:80], f"Unexpected: {str(e)[:50]}"))

    return successes, failures


def analyze_failures(failures: List[Tuple[int, str, str]]) -> Dict[str, int]:
    """Analiza patrones comunes en los fallos."""
    patterns = defaultdict(int)

    for _, rule, error in failures:
        # Classify by error type
        if "UnexpectedToken" in error or "UnexpectedCharacters" in error:
            # Try to identify what's failing
            if "byte_test" in rule:
                patterns["byte_test syntax"] += 1
            elif "byte_jump" in rule:
                patterns["byte_jump syntax"] += 1
            elif "byte_extract" in rule:
                patterns["byte_extract syntax"] += 1
            elif "byte_math" in rule:
                patterns["byte_math syntax"] += 1
            elif "pcre:" in rule:
                patterns["pcre pattern"] += 1
            elif "threshold:" in rule:
                patterns["threshold syntax"] += 1
            elif "detection_filter:" in rule:
                patterns["detection_filter syntax"] += 1
            elif "flowbits:" in rule:
                patterns["flowbits syntax"] += 1
            else:
                patterns["grammar/syntax"] += 1
        elif "ValidationError" in error:
            patterns["validation error"] += 1
        else:
            patterns["other error"] += 1

    return dict(patterns)


def main():
    rule_files = [
        ("rules/suricata/suricata.rules", "suricata"),
        ("rules/snort/snort29-community-rules/community-rules/community.rules", "snort2"),
        ("rules/snort/snort3-community-rules/snort3-community-rules/snort3-community.rules", "snort3"),
    ]

    total_success = 0
    total_failures = 0
    all_failures = []

    print("=" * 80)
    print("PARSING REAL IDS RULES - COMPREHENSIVE TEST")
    print("=" * 80)
    print()

    for filepath, dialect in rule_files:
        path = Path(filepath)
        if not path.exists():
            print(f"⚠️  {filepath}: FILE NOT FOUND")
            continue

        print(f"📂 {filepath}")
        print(f"   Dialect: {dialect}")

        successes, failures = parse_rules_file(path, dialect)

        total_rules = len(successes) + len(failures)
        success_rate = (len(successes) / total_rules * 100) if total_rules > 0 else 0

        total_success += len(successes)
        total_failures += len(failures)
        all_failures.extend(failures)

        print(f"   Total rules: {total_rules}")
        print(f"   ✅ Success: {len(successes)} ({success_rate:.1f}%)")
        print(f"   ❌ Failed: {len(failures)} ({100-success_rate:.1f}%)")
        print()

        # Show first 5 failures
        if failures:
            print(f"   First failures:")
            for i, (line_num, rule, error) in enumerate(failures[:5], 1):
                print(f"     {i}. Line {line_num}: {error[:60]}")
            if len(failures) > 5:
                print(f"     ... and {len(failures) - 5} more")
            print()

    # Global statistics
    total_rules = total_success + total_failures
    global_success_rate = (total_success / total_rules * 100) if total_rules > 0 else 0

    print("=" * 80)
    print("GLOBAL STATISTICS")
    print("=" * 80)
    print(f"Total rules tested: {total_rules:,}")
    print(f"✅ Successfully parsed: {total_success:,} ({global_success_rate:.2f}%)")
    print(f"❌ Failed to parse: {total_failures:,} ({100-global_success_rate:.2f}%)")
    print()

    # Failure analysis
    if all_failures:
        print("=" * 80)
        print("FAILURE PATTERN ANALYSIS")
        print("=" * 80)
        patterns = analyze_failures(all_failures)
        for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_failures * 100)
            print(f"  {pattern:30s}: {count:5d} ({percentage:5.1f}%)")
        print()

    # Return exit code
    if total_failures == 0:
        print("🎉 ALL RULES PARSED SUCCESSFULLY!")
        return 0
    else:
        print(f"⚠️  {total_failures} rules failed to parse")
        return 1


if __name__ == "__main__":
    sys.exit(main())
