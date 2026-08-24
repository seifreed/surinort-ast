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

`parse_file()` keeps its historical `list[Rule]` return type. Use the additive
`parse_source_file()` API when an editor or refactoring tool must retain the
complete source text, rule spans, and unparsed file regions. Pass its result to
`SourcePrinter.print_file()` to preserve unchanged bytes and replace only rules
that were modified.

Internal modules under `core`, `parsing`, `printer`, and `serialization` may
change without preserving import paths. Use the top-level exports when possible.

## Versioning

`__version__` is the package/API version. `__ast_version__` is the serialized
AST contract version and can change independently. Additive AST fields keep
their protobuf defaults and JSON readers must tolerate omitted fields. A
breaking serialized representation requires an AST major version and a
migration note in `CHANGELOG.md`.

AST 4 represents rule forms losslessly: full rules have a `Header`,
protocol-only rules have `header=None` and a separate `protocol`, and
headerless rules have both fields set to `None`. Use `RuleForm` to branch on
the source form instead of treating a wildcard header as a real match space.

Payloads from AST 3.x can be upgraded explicitly with
`surinort_ast.migrate_ast(payload)`. It preserves bare and metadata-wrapped
JSON shapes, converts legacy wildcard headers according to `form`, and rejects
unsupported AST majors.

## Compatibility policy

- Patch releases fix behavior without removing public names.
- Minor releases may add fields, diagnostics, options, and capabilities.
- Major releases may remove or change public behavior after a deprecation note.
- Heuristic analysis results are advisory; `engine_verified` and
  `behavior_verified` must not be inferred from AST round-tripping.
- `EngineTarget` capability checks are tri-state: `True` means supported,
  `False` requires a complete engine listing, and `None` means the target has
  no evidence for that capability. Use `EngineTarget.with_keywords()` with a
  complete output from the installed engine before treating unknown keywords
  as errors. `EngineTarget.from_keyword_listing()` accepts plain or tabular
  `--list-keywords` output and marks the resulting keyword catalog complete.
- `RulesetContext.from_suricata_yaml()` and `from_snort_config()` resolve
  deployment variables for coverage analysis; unresolved variables remain
  indeterminate instead of being reported as uncovered concrete ports.

## CLI and editor tooling

`surinort optimize` reports suggestions by default. Applying changes requires
an explicit output target, `--engine-verify`, and `--engine-command`; this
validates engine loading but does not prove equal alerts on traffic. Add
`--pcap` and a command containing both `{file}` and `{pcap}` to compare the
engine's stdout for the original and candidate rulesets.

`surinort-lsp` implements stdio `initialize`, diagnostics on document changes,
and rule hover. It is intentionally dependency-free so editor integrations can
pin the package and choose their own client.

The repository also ships a dependency-free VS Code client under
`editors/vscode`; it starts `surinort-lsp`, publishes diagnostics, and exposes
rule hover information.

Plugins use API contract version `surinort_ast.plugins.PLUGIN_API_VERSION`.
Plugins that omit `api_version` remain compatible as legacy version `1`
plugins; a declared unsupported version is rejected by the loader.

`surinort validate file1.rules file2.rules` validates a combined ruleset; the
GitHub Action also expands recursive patterns such as `rules/**/*.rules`.
Its optional `comment` input posts a SARIF count summary on pull requests and
requires the consuming workflow to grant `pull-requests: write`.

`apply_safe_fixes(rule)` returns a new rule and only removes exact duplicate
inline content modifiers. Diagnostics with different duplicate values remain
unchanged because selecting a value would require engine-specific semantics.
