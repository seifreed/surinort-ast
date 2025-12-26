# Linting Quick Reference

## Current Status

```
Ruff:  201 → 26 errors (87% reduction) ✅
MyPy:  183 → 0 errors (100% clean)  ✅
```

## What's Suppressed (By Design)

| Code | Count | Reason | Files |
|------|-------|--------|-------|
| ARG001/ARG002 | 123 | Singledispatch/visitor pattern | printer, analysis, parsing |
| PLC0415 | 33 | Circular import prevention | streaming, plugins, CLI |
| PLR0911/0912/0915 | 13 | Inherent parsing/query complexity | parser, selectors, CLI |

## What's NOT Suppressed (Should Fix)

| Code | Count | Issue | Action |
|------|-------|-------|--------|
| PLW1641 | 7 | Missing `__hash__` | Add hash methods to selectors |
| B904 | 4 | Missing exception chain | Add `from e` or `from None` |
| F821 | 4 | Undefined names | Add imports |
| PLW0603 | 3 | Global statements | Refactor to singletons |
| PLR0912 | 3 | CLI complexity | Already acceptable for CLI |
| ARG001 | 2 | Unused CLI args | Implement or remove |
| PTH123 | 1 | Use Path.open() | Replace builtin open() |
| SIM105 | 1 | Use contextlib.suppress | Simplify try/except |

## Configuration Locations

All configuration in `/Users/seifreed/tools/malware/surinort-ast/pyproject.toml`:

```toml
[tool.ruff.lint.per-file-ignores]
# Per-file suppressions for design patterns

[[tool.mypy.overrides]]
# Per-module suppressions for type system limitations
```

## Testing Commands

```bash
# Activate environment
source venv/bin/activate

# Check Ruff
ruff check src/ --statistics

# Check MyPy
mypy src/surinort_ast

# Auto-fix Ruff issues
ruff check src/ --fix
```

## Key Principles

✅ **Suppress:** Design patterns (singledispatch, circular import prevention)
✅ **Suppress:** Library limitations (Lark, Protobuf)
✅ **Suppress:** Type system limitations (discriminated unions)
❌ **Don't Suppress:** Actual bugs or code smells
❌ **Don't Suppress:** Easy-to-fix style issues

## Documentation

See `/Users/seifreed/tools/malware/surinort-ast/LINTING_CONFIGURATION.md` for full details.
