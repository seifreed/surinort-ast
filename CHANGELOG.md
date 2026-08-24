# Changelog

All notable changes to this project are documented here.

## [4.0.0] - 2026-08-24

- Represented full, protocol-only, and headerless rules without fabricated
  wildcard headers.
- Added explicit short-form protocol serialization for JSON and Protobuf.
- Added AST 3.x migration for legacy rule-form payloads.

## [3.0.5] - 2026-08-24

- Added reproducible conformance, semantic validation, configured variable
  resolution, semantic diff, and lossless rule-form preservation.
- Marked coverage and optimizer output as heuristic until verified by an IDS
  engine.
- Fixed packaging, documentation, CI extras, and fuzz tests that hid errors.

## [3.0.4] - 2026-04-02

- Released the current parser, AST, CLI, analysis, and serialization APIs.
- Added the issue regression corpus and cross-platform CI coverage.

[3.0.5]: https://github.com/seifreed/surinort-ast/releases/tag/v3.0.5
[4.0.0]: https://github.com/seifreed/surinort-ast/releases/tag/v4.0.0
[3.0.4]: https://github.com/seifreed/surinort-ast/releases/tag/v3.0.4
