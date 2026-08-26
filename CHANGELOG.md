# Changelog

All notable changes are recorded here. Release publication, tag verification,
and artifact provenance are tracked separately in
[`docs/release-verification.md`](docs/release-verification.md).

## [Unreleased]

- Keep the external 288,939-rule corpus and production-traffic benchmarks as
  release-blocking evidence until they are reproducibly available.
- Keep engine capability snapshots and conformance reports tied to the exact
  engine build that produced them.

## [4.0.0] - pending publication

### Added

- Lossless AST forms for full, protocol-only, and headerless rules, with
  source-preserving and canonical printing behavior.
- Explicit short-form protocol serialization for JSON and Protobuf, plus AST
  3.x migration for legacy rule-form payloads.
- Versioned engine capability snapshots and target-aware validation for
  actions, protocols, keywords, features, priorities, and flowbit behavior.
- Conformance lab gates for complete parse and round-trip coverage, including
  error attribution, throughput, memory, and exception metrics.
- Real-engine matrix and optimizer evidence for Suricata 8.0.6, Snort 2.9.20,
  and Snort 3.12.2.0, plus LSP and VS Code editor integrations.
- Release workflows for checksums, SBOMs, Sigstore bundles, and build
  provenance attestations.

### Fixed

- The ten grammar gaps reported in issue #166 across Suricata, Snort 2, and
  Snort 3.
- Empty mixed-content segments that could silently discard literal content.

## [3.0.5] - pending publication

This release line is retained for the hardening fixes that preceded the
lossless AST contract. It must not be treated as published until an annotated,
cryptographically verified `v3.0.5` tag and public release artifacts exist.

### Included hardening

- Parser and printer regressions for real-world Suricata, Snort 2, and Snort 3
  rules.
- Expanded semantic validation, conformance reporting, and reproducible build
  checks.
- Configured variable resolution, semantic diff, and lossless rule-form
  preservation.
- Coverage and optimizer output remain explicitly heuristic until verified by
  an IDS engine.
- Packaging, documentation, CI extras, and fuzz-test hardening.

## [3.0.4]

- Released the parser, AST, CLI, analysis, and serialization APIs.
- Added the issue regression corpus and cross-platform CI coverage.

[Unreleased]: https://github.com/seifreed/surinort-ast/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/seifreed/surinort-ast/releases/tag/v4.0.0
[3.0.5]: https://github.com/seifreed/surinort-ast/releases/tag/v3.0.5
