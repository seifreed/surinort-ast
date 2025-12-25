#!/usr/bin/env python3
"""
Automated import migration tool for surinort-ast API restructuring.

This tool scans Python files and automatically migrates old import patterns
to the new modular API structure. Supports dry-run mode for safety.

Author: Marc Rivero López
License: GNU General Public License v3.0
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MigrationResult:
    """Result of migrating a single file."""

    file_path: Path
    original_content: str
    migrated_content: str
    changes_made: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        """Check if file was actually modified."""
        return self.original_content != self.migrated_content

    @property
    def change_count(self) -> int:
        """Number of changes made."""
        return len(self.changes_made)


@dataclass
class MigrationReport:
    """Aggregated report of migration across multiple files."""

    total_files: int = 0
    files_scanned: int = 0
    files_modified: int = 0
    files_unchanged: int = 0
    files_errored: int = 0
    total_changes: int = 0
    results: list[MigrationResult] = field(default_factory=list)

    def add_result(self, result: MigrationResult) -> None:
        """Add a file result to the report."""
        self.results.append(result)
        self.files_scanned += 1

        if result.errors:
            self.files_errored += 1
        elif result.was_modified:
            self.files_modified += 1
            self.total_changes += result.change_count
        else:
            self.files_unchanged += 1

    def print_summary(self) -> None:
        """Print a summary of the migration report."""
        print("\n" + "=" * 70)
        print("MIGRATION SUMMARY")
        print("=" * 70)
        print(f"Total files found:     {self.total_files}")
        print(f"Files scanned:         {self.files_scanned}")
        print(f"Files modified:        {self.files_modified}")
        print(f"Files unchanged:       {self.files_unchanged}")
        print(f"Files with errors:     {self.files_errored}")
        print(f"Total changes:         {self.total_changes}")
        print("=" * 70)

        if self.files_modified > 0:
            print("\nModified files:")
            for result in self.results:
                if result.was_modified:
                    print(f"  - {result.file_path} ({result.change_count} changes)")

        if self.files_errored > 0:
            print("\nFiles with errors:")
            for result in self.results:
                if result.errors:
                    print(f"  - {result.file_path}")
                    for error in result.errors:
                        print(f"      {error}")

    def write_detailed_report(self, output_path: Path) -> None:
        """Write detailed migration report to file."""
        with output_path.open("w") as f:
            f.write("DETAILED MIGRATION REPORT\n")
            f.write("=" * 70 + "\n\n")

            for result in self.results:
                f.write(f"File: {result.file_path}\n")
                f.write("-" * 70 + "\n")

                if result.errors:
                    f.write("ERRORS:\n")
                    for error in result.errors:
                        f.write(f"  - {error}\n")
                elif result.was_modified:
                    f.write(f"CHANGES: {result.change_count}\n")
                    for change in result.changes_made:
                        f.write(f"  - {change}\n")
                else:
                    f.write("No changes needed\n")

                f.write("\n")


class ImportMigrator:
    """Migrate old import patterns to new modular API structure."""

    # Mapping of old import patterns to new ones
    # Note: In surinort-ast, both patterns actually work, but we recommend the modular approach
    IMPORT_MIGRATIONS: dict[str, str] = {
        # Parse functions
        r"from surinort_ast import parse_rule": "from surinort_ast.api.parsing import parse_rule",
        r"from surinort_ast import parse_rules": "from surinort_ast.api.parsing import parse_rules",
        r"from surinort_ast import parse_file": "from surinort_ast.api.parsing import parse_file",
        r"from surinort_ast import parse_file_streaming": "from surinort_ast.api.parsing import parse_file_streaming",
        # Serialization functions
        r"from surinort_ast import to_json": "from surinort_ast.api.serialization import to_json",
        r"from surinort_ast import from_json": "from surinort_ast.api.serialization import from_json",
        r"from surinort_ast import to_json_schema": "from surinort_ast.api.serialization import to_json_schema",
        # Validation functions
        r"from surinort_ast import validate_rule": "from surinort_ast.api.validation import validate_rule",
        # Printing functions
        r"from surinort_ast import print_rule": "from surinort_ast.api.printing import print_rule",
    }

    # Multi-import pattern (e.g., from surinort_ast import parse_rule, to_json)
    MULTI_IMPORT_PATTERN = re.compile(r"from\s+surinort_ast\s+import\s+([\w\s,]+)")

    def __init__(self, aggressive: bool = False):
        """
        Initialize the migrator.

        Args:
            aggressive: If True, migrate all top-level imports to modular.
                       If False (default), only migrate if explicitly beneficial.
        """
        self.aggressive = aggressive

    def migrate_file(self, file_path: Path, backup: bool = True) -> MigrationResult:
        """
        Migrate imports in a single file.

        Args:
            file_path: Path to the Python file to migrate
            backup: If True, create a backup before modifying

        Returns:
            MigrationResult with details of changes made
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            return MigrationResult(
                file_path=file_path,
                original_content="",
                migrated_content="",
                errors=[f"Failed to read file: {e}"],
            )

        original_content = content
        migrated_content = content
        changes: list[str] = []

        # Handle multi-import statements
        migrated_content, multi_changes = self._migrate_multi_imports(migrated_content)
        changes.extend(multi_changes)

        # Handle single-import statements
        migrated_content, single_changes = self._migrate_single_imports(migrated_content)
        changes.extend(single_changes)

        return MigrationResult(
            file_path=file_path,
            original_content=original_content,
            migrated_content=migrated_content,
            changes_made=changes,
        )

    def _migrate_multi_imports(self, content: str) -> tuple[str, list[str]]:
        """
        Migrate multi-import statements like:
        from surinort_ast import parse_rule, to_json

        To individual modular imports:
        from surinort_ast.api.parsing import parse_rule
        from surinort_ast.api.serialization import to_json
        """
        changes = []

        # Function category mapping
        function_categories = {
            "parse_rule": "parsing",
            "parse_rules": "parsing",
            "parse_file": "parsing",
            "parse_file_streaming": "parsing",
            "to_json": "serialization",
            "from_json": "serialization",
            "to_json_schema": "serialization",
            "validate_rule": "validation",
            "print_rule": "printing",
        }

        def replace_multi_import(match: re.Match) -> str:
            imports_str = match.group(1)
            # Parse imported names
            imported_names = [name.strip() for name in imports_str.split(",")]

            # Group by category
            category_groups: dict[str, list[str]] = {}
            unknown_imports = []

            for name in imported_names:
                category = function_categories.get(name)
                if category:
                    category_groups.setdefault(category, []).append(name)
                else:
                    # Not an API function we recognize - keep original import
                    unknown_imports.append(name)

            # Build replacement imports
            new_imports = []

            # Add modular imports for recognized functions
            for category, names in sorted(category_groups.items()):
                names_str = ", ".join(names)
                new_imports.append(f"from surinort_ast.api.{category} import {names_str}")

            # Keep unknown imports as-is
            if unknown_imports:
                unknown_str = ", ".join(unknown_imports)
                new_imports.append(f"from surinort_ast import {unknown_str}")

            if len(new_imports) > 0:
                changes.append(
                    f"Split multi-import into modular imports: {', '.join(imported_names)}"
                )

            return "\n".join(new_imports)

        migrated = self.MULTI_IMPORT_PATTERN.sub(replace_multi_import, content)
        return migrated, changes

    def _migrate_single_imports(self, content: str) -> tuple[str, list[str]]:
        """Migrate single-function import statements."""
        changes = []

        for old_pattern, new_pattern in self.IMPORT_MIGRATIONS.items():
            if re.search(old_pattern, content):
                content = re.sub(old_pattern, new_pattern, content)
                changes.append(f"{old_pattern} → {new_pattern}")

        return content, changes

    def migrate_project(
        self,
        project_dir: Path,
        dry_run: bool = True,
        backup: bool = True,
        recursive: bool = True,
    ) -> MigrationReport:
        """
        Migrate all Python files in a project.

        Args:
            project_dir: Root directory of the project
            dry_run: If True, don't write changes to disk
            backup: If True, create .bak files before modifying
            recursive: If True, scan subdirectories

        Returns:
            MigrationReport with aggregated results
        """
        report = MigrationReport()

        # Find all Python files
        pattern = "**/*.py" if recursive else "*.py"
        python_files = list(project_dir.glob(pattern))
        report.total_files = len(python_files)

        for file_path in python_files:
            # Skip common directories
            if self._should_skip_file(file_path):
                continue

            result = self.migrate_file(file_path, backup=backup)
            report.add_result(result)

            # Write changes if not dry run
            if not dry_run and result.was_modified:
                try:
                    # Create backup if requested
                    if backup:
                        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
                        shutil.copy2(file_path, backup_path)

                    # Write migrated content
                    file_path.write_text(result.migrated_content, encoding="utf-8")

                except Exception as e:
                    result.errors.append(f"Failed to write file: {e}")

        return report

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if a file should be skipped during migration."""
        skip_dirs = {
            ".git",
            ".venv",
            "venv",
            "env",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "build",
            "dist",
            "*.egg-info",
            ".tox",
        }

        for part in file_path.parts:
            if part in skip_dirs or part.startswith("."):
                return True

        return False


def main() -> int:
    """Main entry point for the migration tool."""
    parser = argparse.ArgumentParser(
        description="Migrate surinort-ast imports to new modular API structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (preview changes without modifying files)
  python migrate_imports.py /path/to/project --dry-run

  # Apply migrations with backups
  python migrate_imports.py /path/to/project --backup

  # Apply migrations without backups (use with caution!)
  python migrate_imports.py /path/to/project --no-backup

  # Generate detailed report
  python migrate_imports.py /path/to/project --dry-run --report report.txt

  # Scan only current directory (non-recursive)
  python migrate_imports.py /path/to/project --no-recursive
        """,
    )

    parser.add_argument(
        "project_dir",
        type=Path,
        help="Path to project directory to migrate",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying files (recommended first step)",
    )

    parser.add_argument(
        "--backup",
        action="store_true",
        default=True,
        help="Create .bak backup files before modifying (default: True)",
    )

    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup files",
    )

    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't scan subdirectories",
    )

    parser.add_argument(
        "--report",
        type=Path,
        help="Write detailed report to file",
    )

    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Aggressively migrate all top-level imports (not recommended)",
    )

    args = parser.parse_args()

    # Validate project directory
    if not args.project_dir.exists():
        print(f"Error: Project directory does not exist: {args.project_dir}", file=sys.stderr)
        return 1

    if not args.project_dir.is_dir():
        print(f"Error: Not a directory: {args.project_dir}", file=sys.stderr)
        return 1

    # Handle backup flags
    backup = args.backup and not args.no_backup

    # Create migrator
    migrator = ImportMigrator(aggressive=args.aggressive)

    # Run migration
    print(f"Scanning: {args.project_dir}")
    print(
        f"Mode: {'DRY RUN (no changes will be made)' if args.dry_run else 'LIVE (files will be modified)'}"
    )
    print(f"Backup: {'Enabled' if backup else 'Disabled'}")
    print(f"Recursive: {'Yes' if not args.no_recursive else 'No'}")
    print()

    report = migrator.migrate_project(
        args.project_dir,
        dry_run=args.dry_run,
        backup=backup,
        recursive=not args.no_recursive,
    )

    # Print summary
    report.print_summary()

    # Write detailed report if requested
    if args.report:
        report.write_detailed_report(args.report)
        print(f"\nDetailed report written to: {args.report}")

    # Success message
    if not args.dry_run and report.files_modified > 0:
        print("\n✓ Migration complete!")
        if backup:
            print("  Backups created with .bak extension")
        print("  Review changes and test your code before committing")

    elif args.dry_run and report.files_modified > 0:
        print("\n⚠ Dry run complete. To apply changes, run without --dry-run flag")

    return 0


if __name__ == "__main__":
    sys.exit(main())
