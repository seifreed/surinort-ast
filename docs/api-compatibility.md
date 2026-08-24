# API Compatibility

## Public surface

The stable Python entry point is `surinort_ast`. The package exports parsing,
printing, validation, serialization, diagnostics, and the core AST types from
that module. The `surinort_ast.api` module exposes the same functional API.

The following modules are public extension points:

- `surinort_ast.analysis` for coverage, conflicts, semantic diff, optimizer,
  engine verification, contexts, and capability targets.
- `surinort_ast.lsp` for the stdio language-server endpoint and its pure helper
  functions.
- `surinort_ast.cli` for the `surinort` command.
- `surinort_ast.printer.SourcePrinter` for retained source blocks and
  `CanonicalPrinter` for normalized output.

Internal modules under `core`, `parsing`, `printer`, and `serialization` may
change without preserving import paths. Use the top-level exports when possible.

## Versioning

`__version__` is the package/API version. `__ast_version__` is the serialized
AST contract version and can change independently. Additive AST fields keep
their protobuf defaults and JSON readers must tolerate omitted fields. A
breaking serialized representation requires an AST major version and a
migration note in `CHANGELOG.md`.

Payloads from AST 3.x can be upgraded explicitly with
`surinort_ast.migrate_ast(payload)`. It preserves bare and metadata-wrapped
JSON shapes, adds defaults for fields introduced by the current schema, and
rejects a different AST major.

## Compatibility policy

- Patch releases fix behavior without removing public names.
- Minor releases may add fields, diagnostics, options, and capabilities.
- Major releases may remove or change public behavior after a deprecation note.
- Heuristic analysis results are advisory; `engine_verified` and
  `behavior_verified` must not be inferred from AST round-tripping.

## CLI and editor tooling

`surinort optimize` reports suggestions by default. Applying changes requires
an explicit output target, `--engine-verify`, and `--engine-command`; this
validates engine loading but does not prove equal alerts on traffic. Add
`--pcap` and a command containing both `{file}` and `{pcap}` to compare the
engine's stdout for the original and candidate rulesets.

`surinort-lsp` implements stdio `initialize`, diagnostics on document changes,
and rule hover. It is intentionally dependency-free so editor integrations can
pin the package and choose their own client.

`surinort validate file1.rules file2.rules` validates a combined ruleset; the
GitHub Action also expands recursive patterns such as `rules/**/*.rules`.
Its optional `comment` input posts a SARIF count summary on pull requests and
requires the consuming workflow to grant `pull-requests: write`.
