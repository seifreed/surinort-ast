# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Golden tests using 35,157 active IDS rules.

These tests parse ALL active rules from the rules/ directory:
- 30,579 Suricata rules
- 561 Snort 2.9 rules (3,468 commented/disabled)
- 4,017 Snort 3 rules

NO MOCKS - all tests use real parser execution with actual rule files.
"""

from pathlib import Path

import pytest
from lark import Lark
from lark.exceptions import LarkError

from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.transformer import RuleTransformer


def _parse_all_lines(
    rules_file: Path, lark_parser: Lark, transformer: RuleTransformer
) -> tuple[int, int, list[tuple[int, str, str]]]:
    """Parse every non-comment line of a rules file.

    Returns ``(total_rules, parsed_successfully, parse_errors)`` where each error
    is ``(line_number, truncated_rule_text, message)``.
    """
    total_rules = 0
    parsed_successfully = 0
    parse_errors: list[tuple[int, str, str]] = []
    with open(rules_file, encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total_rules += 1
            try:
                result = transformer.transform(lark_parser.parse(line))
                if isinstance(result, list) and len(result) > 0:
                    assert isinstance(result[0], Rule)
                    parsed_successfully += 1
                else:
                    parse_errors.append((line_num, line[:100], "No rule returned"))
            except LarkError as e:
                parse_errors.append((line_num, line[:100], str(e)[:200]))
            except Exception as e:
                parse_errors.append((line_num, line[:100], f"Unexpected: {str(e)[:200]}"))
    return total_rules, parsed_successfully, parse_errors


def _assert_file_parses(
    label: str,
    rules_file: Path,
    lark_parser: Lark,
    transformer: RuleTransformer,
    threshold: float = 95.0,
) -> None:
    """Parse a whole rules file and assert its success rate meets ``threshold``."""
    total_rules, parsed_successfully, parse_errors = _parse_all_lines(
        rules_file, lark_parser, transformer
    )
    success_rate = (parsed_successfully / total_rules * 100) if total_rules > 0 else 0

    print(f"\n{'=' * 80}")
    print(f"{label} Rules Parsing Summary")
    print(f"{'=' * 80}")
    print(f"Total rules:        {total_rules}")
    print(f"Parsed successfully: {parsed_successfully}")
    print(f"Parse errors:       {len(parse_errors)}")
    print(f"Success rate:       {success_rate:.2f}%")
    print(f"{'=' * 80}")

    if parse_errors:
        print("\nFirst 10 parse errors:")
        for line_num, rule_text, error in parse_errors[:10]:
            print(f"  Line {line_num}: {rule_text}")
            print(f"    Error: {error}")

    message = f"Success rate {success_rate:.2f}% below {threshold:g}% threshold"
    assert success_rate >= threshold, message


@pytest.mark.golden
@pytest.mark.slow
class TestSuricataGolden:
    """Test parsing all Suricata rules (30,588 rules)."""

    def test_parse_all_suricata_rules(self, lark_parser: Lark, suricata_rules_file: Path):
        """
        Parse ALL Suricata rules from rules/suricata/suricata.rules.

        Target: 95%+ success rate.
        """
        _assert_file_parses("Suricata", suricata_rules_file, lark_parser, RuleTransformer())

    def test_suricata_rules_roundtrip(
        self, lark_parser: Lark, suricata_rules_file: Path, text_printer
    ):
        """
        Test roundtrip for first 1000 Suricata rules: parse -> print -> parse.

        This verifies that printed output can be re-parsed.
        """
        transformer = RuleTransformer()

        tested = 0
        roundtrip_ok = 0
        roundtrip_errors = []

        with open(suricata_rules_file, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                if tested >= 1000:
                    break

                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    # First parse
                    parse_tree1 = lark_parser.parse(line)
                    rule1 = transformer.transform(parse_tree1)[0]

                    # Print
                    printed = text_printer.print_rule(rule1)

                    # Second parse
                    parse_tree2 = lark_parser.parse(printed)
                    rule2 = transformer.transform(parse_tree2)[0]

                    # Verify basic equality
                    if (
                        rule1.action == rule2.action
                        and rule1.header.protocol == rule2.header.protocol
                    ):
                        roundtrip_ok += 1
                    else:
                        roundtrip_errors.append((line_num, "Fields mismatch"))

                    tested += 1

                except Exception as e:
                    roundtrip_errors.append((line_num, str(e)[:200]))
                    tested += 1

        success_rate = (roundtrip_ok / tested * 100) if tested > 0 else 0

        print("\nSuricata Roundtrip Test (first 1000 rules):")
        print(f"  Tested: {tested}")
        print(f"  Roundtrip OK: {roundtrip_ok}")
        print(f"  Success rate: {success_rate:.2f}%")

        assert success_rate >= 90.0, f"Roundtrip success rate {success_rate:.2f}% below 90%"


@pytest.mark.golden
@pytest.mark.slow
class TestSnortGolden:
    """Test parsing all Snort rules (4,031 + 4,017 = 8,048 rules)."""

    def test_parse_all_snort29_rules(self, lark_parser: Lark, snort29_rules_file: Path):
        """
        Parse ALL Snort 2.9 community rules.

        Target: 95%+ success rate.
        """
        _assert_file_parses("Snort 2.9", snort29_rules_file, lark_parser, RuleTransformer())

    def test_parse_all_snort3_rules(self, lark_parser: Lark, snort3_rules_file: Path):
        """
        Parse ALL Snort 3 community rules.

        Target: 95%+ success rate.
        """
        _assert_file_parses("Snort 3", snort3_rules_file, lark_parser, RuleTransformer())


@pytest.mark.golden
@pytest.mark.slow
class TestAllRulesGolden:
    """Test parsing all 35,157 active rules combined (38,636 total lines, 3,479 commented)."""

    def test_parse_all_38k_rules(
        self,
        lark_parser: Lark,
        suricata_rules_file: Path,
        snort29_rules_file: Path,
        snort3_rules_file: Path,
    ):
        """
        Parse all 35,157 active rules from all rule files.

        Rule files contain 38,636 total lines, but 3,479 are commented/disabled.
        This test validates parsing of all ACTIVE rules (non-commented, non-empty).

        This is the comprehensive test of the entire parser.
        """
        transformer = RuleTransformer()

        rule_files = [
            ("Suricata", suricata_rules_file),
            ("Snort 2.9", snort29_rules_file),
            ("Snort 3", snort3_rules_file),
        ]

        grand_total = 0
        grand_success = 0
        all_errors = []

        for source_name, rule_file in rule_files:
            total_rules, parsed_successfully, errors = _parse_all_lines(
                rule_file, lark_parser, transformer
            )
            grand_total += total_rules
            grand_success += parsed_successfully
            all_errors.extend((source_name, line_num, msg) for line_num, _text, msg in errors)

            print(
                f"\n{source_name}: {parsed_successfully}/{total_rules} "
                f"({parsed_successfully / total_rules * 100:.2f}%)"
            )

        overall_success_rate = (grand_success / grand_total * 100) if grand_total > 0 else 0

        print(f"\n{'=' * 80}")
        print("OVERALL PARSING RESULTS - ALL 38,636 RULES")
        print(f"{'=' * 80}")
        print(f"Total rules:        {grand_total}")
        print(f"Parsed successfully: {grand_success}")
        print(f"Parse errors:       {len(all_errors)}")
        print(f"Success rate:       {overall_success_rate:.2f}%")
        print(f"{'=' * 80}")

        # Print error distribution
        if all_errors:
            print("\nFirst 20 errors across all files:")
            for source, line_num, error in all_errors[:20]:
                print(f"  {source} line {line_num}: {error}")

        # Assert 95% overall success
        overall_msg = f"Overall success rate {overall_success_rate:.2f}% below 95% threshold"
        assert overall_success_rate >= 95.0, overall_msg
        assert grand_total >= 35000, f"Expected at least 35,000 rules, found {grand_total}"


@pytest.mark.golden
class TestGoldenSubsets:
    """Test specific subsets of rules for detailed analysis."""

    @pytest.mark.parametrize("rule_count", [100, 500, 1000])
    def test_parse_first_n_rules(
        self, lark_parser: Lark, suricata_rules_file: Path, rule_count: int
    ):
        """Test parsing first N rules from Suricata."""
        transformer = RuleTransformer()

        parsed = 0
        errors = 0

        with open(suricata_rules_file, encoding="utf-8", errors="replace") as f:
            tested = 0
            for line in f:
                if tested >= rule_count:
                    break

                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    parse_tree = lark_parser.parse(line)
                    result = transformer.transform(parse_tree)
                    if isinstance(result, list) and len(result) > 0:
                        parsed += 1
                except Exception:
                    errors += 1

                tested += 1

        success_rate = (parsed / (parsed + errors) * 100) if (parsed + errors) > 0 else 0
        print(
            f"\nFirst {rule_count} rules: {parsed} parsed, {errors} errors ({success_rate:.2f}% success)"
        )

        assert success_rate >= 95.0


@pytest.mark.golden
class TestPerformance:
    """Test parsing performance with real rules."""

    def test_parsing_speed(self, lark_parser: Lark, suricata_rules_file: Path, benchmark):
        """Benchmark parsing speed (if pytest-benchmark available)."""
        transformer = RuleTransformer()

        # Load first 100 rules
        rules_text = []
        with open(suricata_rules_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules_text.append(line)
                    if len(rules_text) >= 100:
                        break

        def parse_rules():
            """Parse all loaded rules."""
            for rule_text in rules_text:
                try:
                    parse_tree = lark_parser.parse(rule_text)
                    transformer.transform(parse_tree)
                except Exception:
                    pass

        # Benchmark if available, otherwise just run
        try:
            benchmark(parse_rules)
        except Exception:
            # pytest-benchmark not installed, just run once
            parse_rules()
