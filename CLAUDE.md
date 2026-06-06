# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**surinort-ast** is a Python library and CLI for parsing, validating, serializing, and analyzing IDS/IPS rules (Suricata, Snort2, Snort3) into a typed AST backed by Pydantic v2 models.

## Engineering Policies (MANDATORY)

These are hard requirements for every change. Do not commit, merge, or hand off work that violates them.

### Clean code & clean architecture
- All code must follow clean-code and clean-architecture principles: small single-responsibility units; descriptive names; dependencies pointing inward (the `core/` domain stays independent of infrastructure, CLI, and external frameworks); no leaking of implementation details across module boundaries; no dead, duplicated, or commented-out code; no premature abstractions.

### No legacy for backward compatibility
- This project keeps NO legacy code for backward-compatibility reasons. When new code replaces old code, delete the old code in the same change — do not keep both paths side by side.
- Forbidden: dead or superseded implementations, compatibility shims, deprecated aliases/wrappers kept "just in case", `@deprecated` paths retained for old callers, and duplicate old/new variants of the same function or class.
- When you replace something, update every call site and test to the new code and remove the old one. There is no external API stability guarantee that justifies retaining superseded code.

### Quality gates (all must pass with zero findings)
Before any commit or merge, every one of these must pass clean:
- `ruff check src/ tests/`
- `ruff format --check src/ tests/`
- `black --check src/ tests/`
- `mypy src/ --strict`
- `bandit -r src/`
- `pip-audit -r requirements.txt`
- the full non-slow test suite: `pytest tests/ -m "not slow"`

### No suppressions, no policy bypasses
- Do NOT silence findings instead of fixing them. Fix the root cause.
- Forbidden: adding `# noqa`, `# type: ignore`, `# nosec`, `# pragma: no cover`, or any *new* suppression in `pyproject.toml` / tool config — including entries under `[tool.ruff.lint] ignore`, `[tool.ruff.lint.per-file-ignores]`, or `[[tool.mypy.overrides]]` `disable_error_code`.
- Do NOT bypass hooks or CI (`--no-verify`, skipping pre-commit, disabling or weakening checks) to get a change through.

### Commits
- Do NOT add Claude or any assistant as a commit co-author. Do not add a `Co-Authored-By` trailer for the assistant.

## Common Commands

```bash
# Activate venv
source venv/bin/activate

# Install in dev mode
pip install -e .[dev]

# Run all tests (excluding slow golden tests)
pytest tests/ -v --tb=short --strict-markers -m "not slow"

# Run a single test file
pytest tests/unit/test_parser.py -v

# Run a single test
pytest tests/unit/test_parser.py::TestClassName::test_name -v

# Run slow/golden tests (require rules/ directory with real rule files)
pytest tests/ -m slow -v

# Lint + format
ruff check src/ tests/
ruff format --check src/ tests/
black --check src/ tests/

# Type check
mypy src/ --strict

# Security scan
bandit -r src/ -f screen

# Dependency vulnerability audit (against the committed lockfiles)
pip-audit -r requirements.txt

# Full test script (lint + type check + security + tests + coverage)
./scripts/test.sh

# Build package
python -m build --sdist --wheel --outdir dist/

# CLI usage
surinort parse rules/local.rules
surinort validate rules/local.rules --strict
surinort stats rules/local.rules --format sarif
```

## Architecture

### Pipeline: Text → Lark Parse Tree → AST → Output

1. **Grammar** (`src/surinort_ast/parsing/grammar.lark`): Lark EBNF grammar defining IDS rule syntax. Uses Earley parser for maximum compatibility.
2. **Transformer** (`src/surinort_ast/parsing/transformer.py`): Converts Lark parse tree into typed AST nodes. Composed of mixins in `parsing/mixins/` (header, address, port, content, options).
3. **AST Nodes** (`src/surinort_ast/core/nodes.py`): Immutable Pydantic v2 models. `Rule` is the top-level node containing `Header` + `Sequence[DiscriminatedOption]`. Options use a discriminated union on the `type` field for JSON round-tripping.
4. **Output**: JSON serialization, text printing, protobuf, SARIF 2.1.0.

### Key Subsystems

- **`api/`**: Public API facade — `parse_rule()`, `validate_rule()`, `to_json()`, etc. All top-level imports come through here.
- **`parsing/`**: Lark-based parser with factory pattern (`ParserFactory`), protocol-based interface (`IParser`), and mixin-based transformer. Option parsing split across `parsing/mixins/options/` (flow, threshold, fileops, pattern, metadata, buffer, protocol, scripting, generic).
- **`core/`**: AST node definitions, enums (`Action`, `Protocol`, `Direction`, `Dialect`), diagnostics, location tracking, visitor pattern (`ASTVisitor`, `ASTTransformer`, `ASTWalker`).
- **`query/`**: CSS-selector-like query language for AST traversal with its own Lark grammar (`query/grammar.lark`).
- **`analysis/`**: Coverage analysis, rule optimization, similarity detection (MinHash/LSH), conflict detection.
- **`streaming/`**: Memory-efficient streaming parser for large rule sets.
- **`serialization/`**: JSON, protobuf, JSON Schema, SARIF serializers.
- **`builder/`**: Fluent builder API for programmatic rule construction.
- **`plugins/`**: Entry-point-based plugin system for extensibility.
- **`cli/`**: Typer-based CLI with subcommands (parse, validate, stats, fmt, to-json, from-json, schema).

### Design Patterns

- **Discriminated unions**: `Rule.options` uses Pydantic's `Field(discriminator="type")` for polymorphic JSON serialization. Each `Option` subclass has a `type: Literal["ClassName"]` field.
- **Mixin composition**: The Lark transformer is composed from multiple mixin classes to keep option parsing modular.
- **Lazy imports**: Many modules use `PLC0415`-suppressed imports inside functions to avoid circular dependencies.
- **Factory + Protocol**: `ParserFactory.create()` returns `IParser` protocol instances, enabling DI and custom parser registration.

## Testing

- **Unit tests** (`tests/unit/`): Core parsing, serialization, visitor, builder, query, streaming tests.
- **Integration tests** (`tests/integration/`): End-to-end API, analysis, streaming pipeline tests.
- **Golden tests** (`tests/golden/`): Parse real rule files from `rules/` directory (30k+ Suricata, 4k Snort3, 561 Snort2.9 rules). Marked `slow`.
- **Fuzz tests** (`tests/fuzzing/`): Hypothesis-based property testing.
- **Fixtures**: `tests/fixtures/` has simple, complex, and malformed rule files. Session-scoped fixtures in `conftest.py` load real rules from `rules/`.

## Tooling

- **Ruff**: Linting + formatting (replaces flake8, black, isort). Config in `pyproject.toml`.
- **MyPy**: Strict mode with Pydantic plugin. Many per-module overrides for Lark decorator and union-attr false positives.
- **Pre-commit**: Ruff, MyPy, Bandit, plus standard hooks.
- **CI**: GitHub Actions with security scan → lint → test matrix (Python 3.11-3.14, Ubuntu/macOS/Windows) → coverage → build → validate. SARIF generation and Code Scanning upload included.
