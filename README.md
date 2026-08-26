<p align="center">
  <img src="https://img.shields.io/badge/surinort--ast-IDS%2FIPS%20AST-blue?style=for-the-badge" alt="surinort-ast">
</p>

<h1 align="center">surinort-ast</h1>

<p align="center">
  <strong>Typed AST parser and analysis toolkit for Suricata/Snort rules</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/surinort-ast/"><img src="https://img.shields.io/pypi/v/surinort-ast?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/surinort-ast/"><img src="https://img.shields.io/pypi/pyversions/surinort-ast?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/surinort-ast/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/surinort-ast/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/surinort-ast/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://github.com/seifreed/surinort-ast/security/code-scanning"><img src="https://img.shields.io/badge/code%20scanning-SARIF%20enabled-brightgreen?style=flat-square" alt="SARIF"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/surinort-ast/stargazers"><img src="https://img.shields.io/github/stars/seifreed/surinort-ast?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/surinort-ast/issues"><img src="https://img.shields.io/github/issues/seifreed/surinort-ast?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**surinort-ast** is a Python toolkit to parse, validate, serialize, and analyze IDS/IPS rules from Suricata, Snort2, and Snort3. It provides a typed AST, CLI workflows, and machine-readable outputs including JSON and SARIF 2.1.0.

### Key Features

| Feature | Description |
|---------|-------------|
| **Typed AST** | Full Pydantic-backed AST for headers, options, and metadata |
| **Multi-dialect** | Suricata, Snort2, and Snort3 support |
| **Validation** | Syntax/semantic diagnostics with severity levels |
| **Serialization** | JSON and protobuf support |
| **SARIF 2.1.0** | Parse/validate/analysis findings export for Code Scanning |
| **CLI + Library** | Use as command-line tool or Python package |
| **Coverage/Optimization Analysis** | Built-in analyzers for coverage and optimization insights |
| **Streaming Mode** | Memory-efficient parsing for large rule sets |

### Supported Outputs

```text
AST Data        JSON, protobuf
Diagnostics     Human-readable tables, SARIF 2.1.0
Analysis        Text reports, SARIF 2.1.0 findings
CI Integration  SARIF artifact + GitHub Code Scanning upload
```

---

## Installation

### From PyPI (Recommended)

```bash
pip install surinort-ast
```

### From Source

```bash
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Optional Extras

The regular package includes the parser, CLI, analysis, and serialization
modules. Install development tooling separately with `pip install -e '.[dev]'`.

---

## Quick Start

```bash
# Parse rule file
surinort parse rules/local.rules

# Validate with strict mode
surinort validate rules/local.rules --strict

# Validate several files as one ruleset
surinort validate rules/*.rules rules/vendor/*.rules

# Export parse findings to SARIF
surinort parse rules/local.rules --format sarif -o parse-results.sarif
```

---

## Usage

### Command Line Interface

```bash
# Parse to JSON
surinort parse rules/local.rules --json -o rules.json

# Validate and export SARIF
surinort validate rules/local.rules --format sarif -o validate-results.sarif

# Stats and coverage findings in SARIF
surinort stats rules/local.rules --format sarif -o stats-results.sarif
```

### Available Options (Main Commands)

| Command | Description |
|--------|-------------|
| `surinort parse` | Parse rules (`text`, `json`, `sarif`) |
| `surinort validate` | Validate rules with optional strict mode and SARIF output |
| `surinort stats` | Rule statistics and optional SARIF coverage findings |
| `surinort fmt` | Canonical formatting for rule files |
| `surinort to-json` | Convert rules to JSON |
| `surinort from-json` | Convert JSON back to rule text |
| `surinort schema` | Print AST JSON schema |

### SARIF Flags

| Option | Description |
|--------|-------------|
| `--format sarif` | Print SARIF content as command output |
| `--sarif-out <file>` | Write SARIF report while keeping default output mode |
| `-o, --output <file>` | Write primary output to file |

---

## Python Library

### Basic Usage

```python
from surinort_ast import parse_rule, validate_rule, to_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
diags = validate_rule(rule)
print(to_json(rule))

for diag in diags:
    print(diag.level, diag.code, diag.message)
```

### SARIF API Usage

```python
from surinort_ast import (
    diagnostics_to_sarif,
    parse_file,
    validate_rule,
)

rules = parse_file("rules/local.rules")
diagnostics = []
for rule in rules:
    diagnostics.extend(validate_rule(rule))

sarif = diagnostics_to_sarif(diagnostics, default_file_path="rules/local.rules")
with open("results.sarif", "w", encoding="utf-8") as f:
    f.write(sarif)
```

### Additional SARIF Helpers

```python
from surinort_ast import (
    coverage_report_to_sarif,
    optimization_results_to_sarif,
    to_sarif,
)
```

---

## CI and GitHub Code Scanning (SARIF)

The project CI supports SARIF generation and upload:

- Generate `results.sarif` from real validation diagnostics.
- Upload SARIF as a workflow artifact.

The repository also provides a composite action for rule validation:

```yaml
# Add `pull-requests: write` only when `comment` is enabled.
permissions:
  contents: read
  pull-requests: write

steps:
  - name: Validate rules
    id: surinort
    uses: seifreed/surinort-ast@740b7c6c9fb74af6c927f31c0ae05e28d1d94139
    with:
      rules: rules/**/*.rules
      dialect: suricata
      engine: suricata
      engine-version: 8.0.6
      capability-file: conformance/capabilities/4.0.0-local.json
      sarif: true
      engine-verify: true
      engine-command: 'suricata -T -S {file}'
      baseline: .github/surinort-baseline.sarif
      comment: true
```

Upload the generated `${{ steps.surinort.outputs.sarif-file }}` with
`github/codeql-action/upload-sarif` when code scanning annotations are desired.
Replace the commit pin with `@v4.0.0` after that public release tag exists.
- Upload SARIF to GitHub Code Scanning.

### Pre-commit and GitLab CI

Use the repository hook from a pre-commit configuration:

```yaml
repos:
  - repo: https://github.com/seifreed/surinort-ast
    rev: v4.0.0
    hooks:
      - id: surinort-validate
```

The repository also includes `.gitlab-ci.yml`, which validates every `*.rules`
file under `RULES_PATH` (default: `rules`) with the same CLI.

For editor integration, install the dependency-free client from
`editors/vscode` after installing this package so `surinort-lsp` is available.

Minimal workflow example:

```yaml
- name: Generate SARIF report
  run: |
    python - <<'PY'
    from pathlib import Path
    from surinort_ast import diagnostics_to_sarif, parse_file, validate_rule

    fixture_path = Path("tests/fixtures/simple_rules.txt")
    rules = parse_file(fixture_path)
    diagnostics = []
    for rule in rules:
        diagnostics.extend(validate_rule(rule))

    Path("results.sarif").write_text(
        diagnostics_to_sarif(diagnostics, default_file_path=str(fixture_path)),
        encoding="utf-8",
    )
    PY

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Requirements

- Python 3.11+
- See [pyproject.toml](pyproject.toml) for dependencies and extras

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the GPL-3.0-or-later license. See [LICENSE](LICENSE).
The current licensing decision is documented in the [license decision](https://seifreed.github.io/surinort-ast/license/).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/surinort-ast](https://github.com/seifreed/surinort-ast)

---

<p align="center">
  <sub>Built for practical IDS/IPS rule engineering and security automation</sub>
</p>
