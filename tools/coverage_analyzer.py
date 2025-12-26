#!/usr/bin/env python3
"""
Coverage Analyzer for Surinort-AST

Analyzes test coverage by module category and generates reports.
This tool parses pytest-cov XML output and categorizes modules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass
class ModuleCoverage:
    """Coverage data for a single module."""

    name: str
    line_rate: float
    lines_valid: int
    lines_covered: int
    lines_missing: int
    branch_rate: float = 0.0

    @property
    def coverage_percent(self) -> float:
        """Get coverage as percentage."""
        return self.line_rate * 100

    @property
    def status(self) -> str:
        """Get coverage status indicator."""
        if self.coverage_percent >= 90:
            return "✓ EXCELLENT"
        elif self.coverage_percent >= 80:
            return "✓ GOOD"
        elif self.coverage_percent >= 70:
            return "△ ACCEPTABLE"
        elif self.coverage_percent >= 50:
            return "△ LOW"
        else:
            return "⚠ NEEDS WORK"


class CoverageAnalyzer:
    """Analyze coverage data by module category."""

    # Module category definitions
    CATEGORIES = {
        "Core": ["core/", "exceptions.py", "version.py"],
        "Parsing": ["parsing/"],
        "Serialization": ["serialization/"],
        "Printer": ["printer/"],
        "Builder": ["builder/"],
        "Query": ["query/"],
        "Streaming": ["streaming/"],
        "Plugins": ["plugins/"],
        "CLI": ["cli/"],
        "Analysis": ["analysis/"],
        "API": ["api/"],
    }

    # Coverage targets by category
    TARGETS = {
        "Core": 90.0,
        "Parsing": 90.0,
        "Serialization": 80.0,
        "Printer": 80.0,
        "Builder": 70.0,
        "Query": 70.0,
        "Streaming": 70.0,
        "Plugins": 60.0,
        "CLI": 50.0,
        "Analysis": 60.0,
        "API": 80.0,
    }

    def __init__(self, coverage_xml_path: Path):
        """
        Initialize analyzer with coverage XML file.

        Args:
            coverage_xml_path: Path to coverage.xml file
        """
        self.coverage_xml_path = coverage_xml_path
        self.modules: List[ModuleCoverage] = []

    def parse_coverage_xml(self) -> None:
        """Parse coverage.xml file and extract module data."""
        tree = ET.parse(self.coverage_xml_path)
        root = tree.getroot()

        for package in root.findall(".//package"):
            package_name = package.get("name", "")

            for class_elem in package.findall("./classes/class"):
                filename = class_elem.get("filename", "")
                line_rate = float(class_elem.get("line-rate", 0))
                branch_rate = float(class_elem.get("branch-rate", 0))

                # Get line counts
                lines = class_elem.findall(".//line")
                lines_valid = len(lines)
                lines_covered = sum(1 for line in lines if line.get("hits", "0") != "0")
                lines_missing = lines_valid - lines_covered

                # Extract module name
                if "surinort_ast" in filename:
                    module_name = filename.replace("src/surinort_ast/", "").replace("src\\surinort_ast\\", "")

                    self.modules.append(
                        ModuleCoverage(
                            name=module_name,
                            line_rate=line_rate,
                            lines_valid=lines_valid,
                            lines_covered=lines_covered,
                            lines_missing=lines_missing,
                            branch_rate=branch_rate,
                        )
                    )

    def categorize_modules(self) -> Dict[str, List[ModuleCoverage]]:
        """Categorize modules by their directory structure."""
        categorized: Dict[str, List[ModuleCoverage]] = {cat: [] for cat in self.CATEGORIES}

        for module in self.modules:
            categorized_flag = False
            for category, patterns in self.CATEGORIES.items():
                for pattern in patterns:
                    if pattern in module.name:
                        categorized[category].append(module)
                        categorized_flag = True
                        break
                if categorized_flag:
                    break

        return categorized

    def calculate_category_coverage(self, modules: List[ModuleCoverage]) -> float:
        """Calculate average coverage for a category."""
        if not modules:
            return 0.0

        total_lines = sum(m.lines_valid for m in modules)
        covered_lines = sum(m.lines_covered for m in modules)

        if total_lines == 0:
            return 0.0

        return (covered_lines / total_lines) * 100

    def generate_report(self, output_path: Path | None = None) -> str:
        """
        Generate coverage report.

        Args:
            output_path: Optional path to write report to

        Returns:
            Report as string
        """
        self.parse_coverage_xml()
        categorized = self.categorize_modules()

        lines = []
        lines.append("=" * 80)
        lines.append("SURINORT-AST COVERAGE REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Overall statistics
        total_lines = sum(m.lines_valid for m in self.modules)
        covered_lines = sum(m.lines_covered for m in self.modules)
        overall_coverage = (covered_lines / total_lines * 100) if total_lines > 0 else 0

        lines.append(f"Overall Coverage: {overall_coverage:.2f}%")
        lines.append(f"Total Lines: {total_lines}")
        lines.append(f"Covered Lines: {covered_lines}")
        lines.append(f"Missing Lines: {total_lines - covered_lines}")
        lines.append("")

        # Category breakdown
        lines.append("-" * 80)
        lines.append("COVERAGE BY CATEGORY")
        lines.append("-" * 80)
        lines.append("")

        for category in sorted(self.CATEGORIES.keys()):
            modules = categorized[category]
            if not modules:
                continue

            cat_coverage = self.calculate_category_coverage(modules)
            target = self.TARGETS.get(category, 70.0)
            status = "✓" if cat_coverage >= target else "✗"

            lines.append(f"{category}: {cat_coverage:.2f}% (Target: {target:.0f}%) {status}")

            # Sort modules by coverage
            sorted_modules = sorted(modules, key=lambda m: m.coverage_percent, reverse=True)

            for module in sorted_modules:
                indent = "  "
                lines.append(
                    f"{indent}{module.name}: {module.coverage_percent:.2f}% "
                    f"({module.lines_missing} missing) {module.status}"
                )

            lines.append("")

        # Target achievement summary
        lines.append("-" * 80)
        lines.append("TARGET ACHIEVEMENT")
        lines.append("-" * 80)
        lines.append("")

        for category in sorted(self.CATEGORIES.keys()):
            modules = categorized[category]
            if not modules:
                continue

            cat_coverage = self.calculate_category_coverage(modules)
            target = self.TARGETS.get(category, 70.0)
            status = "MET ✓" if cat_coverage >= target else "BELOW TARGET ✗"
            diff = cat_coverage - target

            lines.append(f"{category:20s} {cat_coverage:6.2f}% / {target:5.1f}%  " f"({diff:+6.2f}%) {status}")

        lines.append("")
        lines.append("=" * 80)

        report = "\n".join(lines)

        if output_path:
            output_path.write_text(report)

        return report

    def get_priority_improvements(self, top_n: int = 10) -> List[tuple[ModuleCoverage, float]]:
        """
        Get modules that would benefit most from improved coverage.

        Returns modules below their category target, sorted by impact (lines * coverage gap).

        Args:
            top_n: Number of top priorities to return

        Returns:
            List of (module, impact_score) tuples
        """
        categorized = self.categorize_modules()
        priorities = []

        for category, modules in categorized.items():
            target = self.TARGETS.get(category, 70.0)

            for module in modules:
                if module.coverage_percent < target:
                    coverage_gap = target - module.coverage_percent
                    impact = module.lines_valid * (coverage_gap / 100)
                    priorities.append((module, impact))

        # Sort by impact (descending)
        priorities.sort(key=lambda x: x[1], reverse=True)

        return priorities[:top_n]


def main():
    """Main entry point for CLI usage."""
    import sys

    coverage_xml = Path("coverage.xml")

    if not coverage_xml.exists():
        print("ERROR: coverage.xml not found. Run tests with coverage first:")
        print("  pytest --cov=src/surinort_ast --cov-report=xml")
        sys.exit(1)

    analyzer = CoverageAnalyzer(coverage_xml)
    report = analyzer.generate_report()
    print(report)

    # Print priority improvements
    print("\n" + "=" * 80)
    print("TOP PRIORITY IMPROVEMENTS")
    print("=" * 80)
    print("")

    priorities = analyzer.get_priority_improvements()
    for i, (module, impact) in enumerate(priorities, 1):
        print(f"{i:2d}. {module.name:50s} {module.coverage_percent:6.2f}% " f"(Impact: {impact:6.1f} lines)")


if __name__ == "__main__":
    main()


# ============================================================================
# License Information
# ============================================================================

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
