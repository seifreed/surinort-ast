"""
LibCST-based codemod for surinort-ast API migration.

This codemod uses LibCST for AST-based transformations, providing
more robust refactoring than regex-based approaches.

Author: Marc Rivero López
License: GNU General Public License v3.0

Usage:
    python -m libcst.tool codemod api_migration.MigrateAPIImports /path/to/project

Requirements:
    pip install libcst
"""

from __future__ import annotations

from collections.abc import Sequence

try:
    import libcst as cst
    from libcst import matchers as m
    from libcst.codemod import CodemodContext, VisitorBasedCodemodCommand
    from libcst.codemod.visitors import AddImportsVisitor, RemoveImportsVisitor
except ImportError:
    print("Error: libcst is not installed. Install with: pip install libcst")
    raise


class MigrateAPIImports(VisitorBasedCodemodCommand):
    """
    Codemod to migrate surinort-ast API imports to modular structure.

    Transforms:
        from surinort_ast import parse_rule, to_json
    Into:
        from surinort_ast.api.parsing import parse_rule
        from surinort_ast.api.serialization import to_json

    This provides more reliable refactoring than regex-based approaches
    because it operates on the AST level.
    """

    DESCRIPTION: str = "Migrate surinort-ast imports to modular API structure"

    # Mapping of function names to their API categories
    FUNCTION_TO_CATEGORY: dict[str, str] = {
        # Parsing
        "parse_rule": "parsing",
        "parse_rules": "parsing",
        "parse_file": "parsing",
        "parse_file_streaming": "parsing",
        # Serialization
        "to_json": "serialization",
        "from_json": "serialization",
        "to_json_schema": "serialization",
        # Validation
        "validate_rule": "validation",
        # Printing
        "print_rule": "printing",
    }

    def __init__(self, context: CodemodContext) -> None:
        """Initialize the codemod."""
        super().__init__(context)
        self.imports_to_add: dict[str, list[str]] = {}
        self.imports_to_remove: list[str] = []

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        """
        Transform ImportFrom nodes.

        This handles:
        1. from surinort_ast import X
        2. from surinort_ast import X, Y, Z
        """
        # Check if this is a surinort_ast import
        if not self._is_surinort_ast_import(updated_node):
            return updated_node

        # Check if already using modular import (don't transform)
        if self._is_modular_import(updated_node):
            return updated_node

        # Extract imported names
        imported_names = self._extract_imported_names(updated_node)
        if not imported_names:
            return updated_node

        # Categorize imports
        api_imports: dict[str, list[str]] = {}
        other_imports: list[str] = []

        for name in imported_names:
            category = self.FUNCTION_TO_CATEGORY.get(name)
            if category:
                api_imports.setdefault(category, []).append(name)
            else:
                # Not a recognized API function - keep in original import
                other_imports.append(name)

        # Schedule new modular imports to be added
        for category, names in api_imports.items():
            for name in names:
                AddImportsVisitor.add_needed_import(
                    context=self.context,
                    module=f"surinort_ast.api.{category}",
                    obj=name,
                )

        # If there are other imports, keep them in the original surinort_ast import
        if other_imports:
            # Reconstruct import with only non-API items
            return updated_node.with_changes(names=self._build_import_names(other_imports))

        # If all imports were API functions, remove this import statement
        # (the new modular imports will be added by AddImportsVisitor)
        RemoveImportsVisitor.remove_unused_import(
            context=self.context,
            module="surinort_ast",
        )
        return cst.RemovalSentinel.REMOVE

    def _is_surinort_ast_import(self, node: cst.ImportFrom) -> bool:
        """Check if this is an import from surinort_ast."""
        if node.module is None:
            return False

        module_name = self._get_module_name(node.module)
        return module_name == "surinort_ast"

    def _is_modular_import(self, node: cst.ImportFrom) -> bool:
        """Check if this is already a modular import (surinort_ast.api.*)."""
        if node.module is None:
            return False

        module_name = self._get_module_name(node.module)
        return module_name.startswith("surinort_ast.api.")

    def _get_module_name(self, module: cst.Attribute | cst.Name) -> str:
        """Extract module name from ImportFrom node."""
        if isinstance(module, cst.Name):
            return module.value
        if isinstance(module, cst.Attribute):
            # Recursively build dotted name
            parts = []
            current = module
            while isinstance(current, cst.Attribute):
                parts.append(current.attr.value)
                current = current.value
            if isinstance(current, cst.Name):
                parts.append(current.value)
            return ".".join(reversed(parts))
        return ""

    def _extract_imported_names(self, node: cst.ImportFrom) -> list[str]:
        """Extract list of imported names from ImportFrom node."""
        names: list[str] = []

        if isinstance(node.names, cst.ImportStar):
            # from surinort_ast import * - don't transform
            return []

        if isinstance(node.names, Sequence):
            for import_alias in node.names:
                if isinstance(import_alias, cst.ImportAlias):
                    if isinstance(import_alias.name, cst.Name):
                        names.append(import_alias.name.value)

        return names

    def _build_import_names(self, names: list[str]) -> Sequence[cst.ImportAlias] | cst.ImportStar:
        """Build ImportAlias sequence from list of names."""
        return [cst.ImportAlias(name=cst.Name(value=name)) for name in names]


class MigrateToTopLevelImports(VisitorBasedCodemodCommand):
    """
    Codemod to migrate modular imports back to top-level (if needed).

    This is the reverse of MigrateAPIImports.

    Transforms:
        from surinort_ast.api.parsing import parse_rule
        from surinort_ast.api.serialization import to_json
    Into:
        from surinort_ast import parse_rule, to_json

    Note: This is not recommended for new code, but provided for completeness.
    """

    DESCRIPTION: str = "Migrate modular API imports to top-level (not recommended)"

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        """Transform modular imports to top-level."""
        if not self._is_modular_api_import(updated_node):
            return updated_node

        # Extract imported names
        imported_names = self._extract_imported_names(updated_node)
        if not imported_names:
            return updated_node

        # Schedule new top-level imports to be added
        for name in imported_names:
            AddImportsVisitor.add_needed_import(
                context=self.context,
                module="surinort_ast",
                obj=name,
            )

        # Remove the modular import
        return cst.RemovalSentinel.REMOVE

    def _is_modular_api_import(self, node: cst.ImportFrom) -> bool:
        """Check if this is a modular API import."""
        if node.module is None:
            return False

        module_name = self._get_module_name(node.module)
        return module_name.startswith("surinort_ast.api.")

    def _get_module_name(self, module: cst.Attribute | cst.Name) -> str:
        """Extract module name from ImportFrom node."""
        if isinstance(module, cst.Name):
            return module.value
        if isinstance(module, cst.Attribute):
            parts = []
            current = module
            while isinstance(current, cst.Attribute):
                parts.append(current.attr.value)
                current = current.value
            if isinstance(current, cst.Name):
                parts.append(current.value)
            return ".".join(reversed(parts))
        return ""

    def _extract_imported_names(self, node: cst.ImportFrom) -> list[str]:
        """Extract list of imported names."""
        names: list[str] = []

        if isinstance(node.names, cst.ImportStar):
            return []

        if isinstance(node.names, Sequence):
            for import_alias in node.names:
                if isinstance(import_alias, cst.ImportAlias):
                    if isinstance(import_alias.name, cst.Name):
                        names.append(import_alias.name.value)

        return names


# Additional helper codemod for cleaning up duplicate imports
class CleanupDuplicateImports(VisitorBasedCodemodCommand):
    """
    Remove duplicate imports that may result from migration.

    After running migration codemods, there may be duplicate import statements.
    This codemod cleans them up.
    """

    DESCRIPTION: str = "Clean up duplicate imports after migration"

    def __init__(self, context: CodemodContext) -> None:
        """Initialize the codemod."""
        super().__init__(context)
        self.seen_imports: set[str] = set()

    def visit_Module(self, node: cst.Module) -> bool:
        """Reset state at module level."""
        self.seen_imports.clear()
        return True

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom | cst.RemovalSentinel:
        """Remove duplicate import statements."""
        import_signature = self._get_import_signature(updated_node)

        if import_signature in self.seen_imports:
            # Duplicate - remove it
            return cst.RemovalSentinel.REMOVE

        self.seen_imports.add(import_signature)
        return updated_node

    def _get_import_signature(self, node: cst.ImportFrom) -> str:
        """Get a unique signature for an import statement."""
        module = self._get_module_name(node.module) if node.module else ""
        names = self._extract_imported_names(node)
        return f"{module}:{','.join(sorted(names))}"

    def _get_module_name(self, module: cst.Attribute | cst.Name) -> str:
        """Extract module name."""
        if isinstance(module, cst.Name):
            return module.value
        if isinstance(module, cst.Attribute):
            parts = []
            current = module
            while isinstance(current, cst.Attribute):
                parts.append(current.attr.value)
                current = current.value
            if isinstance(current, cst.Name):
                parts.append(current.value)
            return ".".join(reversed(parts))
        return ""

    def _extract_imported_names(self, node: cst.ImportFrom) -> list[str]:
        """Extract list of imported names."""
        names: list[str] = []

        if isinstance(node.names, cst.ImportStar):
            return ["*"]

        if isinstance(node.names, Sequence):
            for import_alias in node.names:
                if isinstance(import_alias, cst.ImportAlias):
                    if isinstance(import_alias.name, cst.Name):
                        names.append(import_alias.name.value)

        return names


if __name__ == "__main__":
    print("This module provides LibCST codemods for surinort-ast API migration.")
    print()
    print("Usage:")
    print("  1. Install libcst: pip install libcst")
    print("  2. Run codemod:")
    print("     python -m libcst.tool codemod api_migration.MigrateAPIImports /path/to/project")
    print()
    print("Available codemods:")
    print("  - MigrateAPIImports: Migrate to modular API structure (recommended)")
    print("  - MigrateToTopLevelImports: Migrate back to top-level (not recommended)")
    print("  - CleanupDuplicateImports: Remove duplicate imports after migration")
    print()
    print("For more information, see: https://libcst.readthedocs.io/")
