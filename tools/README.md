# Migration Tools

**Project:** surinort-ast
**Author:** Marc Rivero López
**License:** GNU General Public License v3.0

---

## Overview

This directory contains tools to help users migrate from the old top-level import pattern to the new modular API structure in surinort-ast.

---

## Available Tools

### 1. migrate_imports.py - Automated Import Migration

**Purpose:** Automatically rewrite import statements in Python files

**Features:**
- Scan entire projects for surinort-ast imports
- Automatically rewrite to modular structure
- Dry-run mode for safe previewing
- Automatic backup creation
- Detailed migration reports

**Usage:**

```bash
# Preview changes (recommended first step)
python tools/migrate_imports.py /path/to/project --dry-run

# Apply changes with backups (safe)
python tools/migrate_imports.py /path/to/project --backup

# Apply changes without backups (use with caution)
python tools/migrate_imports.py /path/to/project --no-backup

# Generate detailed report
python tools/migrate_imports.py /path/to/project --dry-run --report migration_report.txt

# Non-recursive (current directory only)
python tools/migrate_imports.py /path/to/project --no-recursive
```

**Examples:**

```bash
# Safe workflow: preview, apply, review
python tools/migrate_imports.py ~/my_project --dry-run
# Review output
python tools/migrate_imports.py ~/my_project --backup
git diff  # Review changes
git add . && git commit -m "Migrate to modular API imports"

# Quick migration for scripts
python tools/migrate_imports.py ~/scripts --no-recursive
```

**Output:**

```
Scanning: /Users/you/my_project
Mode: DRY RUN (no changes will be made)
Backup: Enabled
Recursive: Yes

======================================================================
MIGRATION SUMMARY
======================================================================
Total files found:     42
Files scanned:         38
Files modified:        15
Files unchanged:       23
Files with errors:     0
Total changes:         27
======================================================================

Modified files:
  - /Users/you/my_project/parser.py (3 changes)
  - /Users/you/my_project/utils/helpers.py (2 changes)
  ...
```

### 2. codemods/api_migration.py - LibCST-based Codemod

**Purpose:** AST-based refactoring using LibCST (more robust than regex)

**Requirements:**
```bash
pip install libcst
```

**Features:**
- AST-level transformations (more reliable than regex)
- Handles complex import patterns
- Preserves code formatting
- Multiple codemods available

**Available Codemods:**

1. **MigrateAPIImports** - Migrate to modular structure (recommended)
2. **MigrateToTopLevelImports** - Reverse migration (not recommended)
3. **CleanupDuplicateImports** - Remove duplicate imports after migration

**Usage:**

```bash
# Migrate to modular imports
python -m libcst.tool codemod \
    tools.codemods.api_migration.MigrateAPIImports \
    /path/to/project

# Clean up duplicates
python -m libcst.tool codemod \
    tools.codemods.api_migration.CleanupDuplicateImports \
    /path/to/project

# Reverse migration (if needed)
python -m libcst.tool codemod \
    tools.codemods.api_migration.MigrateToTopLevelImports \
    /path/to/project
```

**Advantages over migrate_imports.py:**
- More robust AST-based transformations
- Better handling of edge cases
- Preserves formatting and comments
- Part of a well-tested framework

**When to use:**
- Complex codebases with tricky import patterns
- When regex-based tool fails
- For high-confidence refactoring

---

## Migration Workflow

### Recommended Steps

1. **Backup your code**
   ```bash
   git commit -m "Pre-migration checkpoint"
   # Or create a branch
   git checkout -b migrate-surinort-ast
   ```

2. **Run dry-run migration**
   ```bash
   python tools/migrate_imports.py ~/project --dry-run
   ```

3. **Review proposed changes**
   - Check the summary output
   - Review file-by-file changes if needed

4. **Apply migration**
   ```bash
   python tools/migrate_imports.py ~/project --backup
   ```

5. **Review changes in version control**
   ```bash
   git diff
   ```

6. **Test your code**
   ```bash
   pytest  # or your test command
   ```

7. **Clean up backups (optional)**
   ```bash
   find . -name "*.bak" -delete
   ```

8. **Commit changes**
   ```bash
   git add .
   git commit -m "Migrate to surinort-ast modular API"
   ```

---

## Migration Patterns

### What Gets Migrated

**Single imports:**
```python
# Before
from surinort_ast import parse_rule

# After
from surinort_ast.api.parsing import parse_rule
```

**Multiple imports:**
```python
# Before
from surinort_ast import parse_rule, to_json, validate_rule

# After
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.validation import validate_rule
```

**Function categories:**
- `parse_rule`, `parse_rules`, `parse_file`, `parse_file_streaming` → `surinort_ast.api.parsing`
- `to_json`, `from_json`, `to_json_schema` → `surinort_ast.api.serialization`
- `validate_rule` → `surinort_ast.api.validation`
- `print_rule` → `surinort_ast.api.printing`

### What Doesn't Get Migrated

**Already modular:**
```python
# Already modular - no change needed
from surinort_ast.api.parsing import parse_rule
```

**Non-API imports:**
```python
# Core types - no change needed
from surinort_ast import Rule, Dialect, Protocol

# These stay as-is
```

**Star imports (not recommended):**
```python
# Not migrated (star imports discouraged)
from surinort_ast import *
```

---

## Troubleshooting

### Tool Reports Errors

**Problem:** Migration tool shows errors for some files

**Solutions:**
- Check file permissions
- Verify files are valid Python
- Review error messages for specifics
- Manually migrate problematic files

### Changes Look Wrong

**Problem:** Proposed changes don't look correct

**Solutions:**
- Use `--dry-run` to review without applying
- Check for complex import patterns
- Try LibCST codemod for better handling
- Manually migrate edge cases

### Tests Fail After Migration

**Problem:** Tests break after applying migration

**Solutions:**
1. Review the diff carefully
   ```bash
   git diff
   ```

2. Check for incorrectly transformed imports

3. Verify all imports are correct

4. Restore from backup if needed
   ```bash
   # Restore specific file
   cp file.py.bak file.py

   # Or restore all
   git checkout .
   ```

### Performance Issues with Large Projects

**Problem:** Tool is slow on large codebases

**Solutions:**
- Use `--no-recursive` for specific directories
- Exclude directories with large dependencies
- Run on specific subdirectories separately

---

## Advanced Usage

### Exclude Directories

```bash
# Migrate all except tests (manual approach)
python tools/migrate_imports.py ~/project/src
python tools/migrate_imports.py ~/project/lib
# Skip ~/project/tests
```

### Integration with pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: check-imports
        name: Check surinort-ast imports
        entry: python tools/check_imports.py
        language: python
        types: [python]
```

### Custom Migration Rules

Extend `migrate_imports.py` for custom patterns:

```python
# In ImportMigrator class
IMPORT_MIGRATIONS = {
    # Add your custom patterns
    r"from my_package import my_func": "from my_package.api import my_func",
}
```

---

## Getting Help

### Documentation

- **Migration Strategy:** `docs/API_MIGRATION_STRATEGY.md`
- **Migration Checklist:** `docs/MIGRATION_CHECKLIST.md`
- **Versioning:** `docs/VERSIONING.md`

### Support

- **GitHub Issues:** Report bugs or issues with migration tools
- **GitHub Discussions:** Ask questions about migration
- **Examples:** See `examples/migration_examples.py`

### Reporting Issues

When reporting tool issues, include:
1. Tool version / surinort-ast version
2. Python version
3. Command you ran
4. Error message or unexpected behavior
5. Minimal example if possible

---

## Contributing

Improvements to migration tools are welcome!

**Ideas for contribution:**
- Enhanced edge case handling
- Better error messages
- Performance optimizations
- Additional codemods
- Integration with IDEs

See `CONTRIBUTING.md` for guidelines.

---

## License

All migration tools are licensed under GNU General Public License v3.0

Copyright (c) 2025 Marc Rivero López

---

**Version:** 1.0
**Last Updated:** 2025-12-25
