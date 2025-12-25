#!/usr/bin/env python3
"""
Check for circular dependencies in the surinort-ast project.

This script verifies that the refactoring successfully eliminated
all circular import dependencies.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import ast
import sys
from pathlib import Path


class ImportChecker:
    """Check Python files for circular import dependencies."""

    def __init__(self, root_dir: Path):
        """Initialize the checker with the root directory."""
        self.root_dir = root_dir
        self.imports: dict[str, set[str]] = {}

    def extract_imports(self, file_path: Path) -> set[str]:
        """Extract all imports from a Python file."""
        imports = set()

        try:
            with open(file_path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(file_path))

            for node in ast.walk(tree):
                # Check for 'from X import Y'
                if isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("."):
                        # Relative import - resolve it
                        imports.add(node.module)
                # Check for 'import X'
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("surinort_ast"):
                            imports.add(alias.name)

        except Exception as e:
            print(f"Error parsing {file_path}: {e}", file=sys.stderr)

        return imports

    def get_module_name(self, file_path: Path) -> str:
        """Convert file path to module name."""
        rel_path = file_path.relative_to(self.root_dir)
        parts = list(rel_path.parts)

        # Remove .py extension
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]

        # Remove __init__
        if parts[-1] == "__init__":
            parts = parts[:-1]

        return ".".join(parts)

    def scan_directory(self, directory: Path, package_name: str = ""):
        """Recursively scan directory for Python files."""
        for file_path in directory.rglob("*.py"):
            module_name = self.get_module_name(file_path)
            imports = self.extract_imports(file_path)

            # Resolve relative imports
            resolved_imports = set()
            for imp in imports:
                if imp.startswith("."):
                    # Relative import - resolve based on current module
                    level = len(imp) - len(imp.lstrip("."))
                    module_parts = module_name.split(".")

                    # Go up 'level' directories
                    base_parts = module_parts[:-level] if level > 0 else module_parts

                    # Add the import part
                    import_part = imp.lstrip(".")
                    if import_part:
                        full_import = ".".join(base_parts + [import_part])
                    else:
                        full_import = ".".join(base_parts)

                    resolved_imports.add(full_import)
                else:
                    resolved_imports.add(imp)

            self.imports[module_name] = resolved_imports

    def find_cycles(self) -> set[frozenset]:
        """Find circular dependencies using depth-first search."""
        cycles = set()

        def dfs(node: str, path: list, visited: set):
            """Depth-first search to find cycles."""
            if node in path:
                # Found a cycle
                cycle_start = path.index(node)
                cycle = frozenset(path[cycle_start:])
                if len(cycle) > 1:  # Only report multi-node cycles
                    cycles.add(cycle)
                return

            if node in visited:
                return

            visited.add(node)
            path.append(node)

            # Get imports for this module
            imports = self.imports.get(node, set())
            for imported in imports:
                # Only check imports within our packages
                if imported in self.imports:
                    dfs(imported, path.copy(), visited)

        # Check each module
        for module in self.imports:
            if any(pkg in module for pkg in ["query", "builder", "analysis"]):
                dfs(module, [], set())

        return cycles

    def check_specific_packages(self) -> dict[str, set[frozenset]]:
        """Check specific packages for circular dependencies."""
        packages = {"query": set(), "builder": set(), "analysis": set()}

        for pkg_name in packages:
            # Get all modules in this package
            pkg_modules = {mod for mod in self.imports if pkg_name in mod}

            # Check for cycles within package
            def dfs(node: str, path: list, visited: set):
                if node in path:
                    cycle_start = path.index(node)
                    cycle = frozenset(path[cycle_start:])
                    if len(cycle) > 1:
                        packages[pkg_name].add(cycle)
                    return

                if node in visited:
                    return

                visited.add(node)
                path.append(node)

                imports = self.imports.get(node, set())
                for imported in imports:
                    # Only follow imports within the same package
                    if imported in pkg_modules:
                        dfs(imported, path.copy(), visited)

            for module in pkg_modules:
                dfs(module, [], set())

        return packages


def main():
    """Main entry point."""
    src_dir = Path(__file__).parent / "src" / "surinort_ast"

    if not src_dir.exists():
        print(f"Error: Source directory not found: {src_dir}", file=sys.stderr)
        sys.exit(1)

    print("Checking for circular dependencies...")
    print(f"Scanning: {src_dir}\n")

    checker = ImportChecker(src_dir)
    checker.scan_directory(src_dir)

    print(f"Found {len(checker.imports)} modules\n")

    # Check specific packages
    print("=" * 70)
    print("Checking specific packages for circular dependencies:")
    print("=" * 70)

    package_cycles = checker.check_specific_packages()

    total_cycles = 0
    for pkg_name, cycles in package_cycles.items():
        print(f"\n{pkg_name}/ package:")
        if cycles:
            print(f"  ❌ Found {len(cycles)} circular dependency pattern(s):")
            for cycle in cycles:
                cycle_list = sorted(cycle, key=lambda x: x.split(".")[-1])
                print(f"    - {' ↔ '.join(c.split('.')[-1] + '.py' for c in cycle_list)}")
            total_cycles += len(cycles)
        else:
            print("  ✅ No circular dependencies found!")

    print("\n" + "=" * 70)
    if total_cycles == 0:
        print("✅ SUCCESS: No circular dependencies detected!")
        print("=" * 70)
        return 0
    print(f"❌ FAILURE: Found {total_cycles} circular dependency pattern(s)")
    print("=" * 70)
    return 1


if __name__ == "__main__":
    sys.exit(main())
