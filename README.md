<p align="center">
  <img src="https://img.shields.io/badge/surinort--ast-Suricata%2FSnort%20Rule%20Parser-blue?style=for-the-badge" alt="surinort-ast">
</p>

<h1 align="center">surinort-ast</h1>

<p align="center">
  <strong>Production-grade IDS/IPS rule parser and analyzer for Suricata/Snort</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/surinort-ast/"><img src="https://img.shields.io/pypi/v/surinort-ast?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/surinort-ast/"><img src="https://img.shields.io/pypi/pyversions/surinort-ast?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/surinort-ast/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/surinort-ast/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/surinort-ast/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-93%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="https://github.com/seifreed/surinort-ast/stargazers"><img src="https://img.shields.io/github/stars/seifreed/surinort-ast?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/surinort-ast/issues"><img src="https://img.shields.io/github/issues/seifreed/surinort-ast?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

`surinort-ast` provides parsing and structural tooling for IDS/IPS rules used by **Suricata** and **Snort**.
It converts rule text into a typed AST, lets you validate, transform, serialize, analyze, and re-emit rules with stable formatting.

## Highlights

| Feature | Description |
| --- | --- |
| **Typed AST** | Full Pydantic-backed AST for rule headers, options, and metadata. |
| **Multi-dialect** | Suricata, Snort2, and Snort3 parser support. |
| **Serialization** | JSON and protobuf round-trips with consistent schema. |
| **CLI toolkit** | Commands for parsing, formatting, validation, conversion, and corpus stats. |
| **Streaming mode** | Memory-efficient processing for very large rule files. |
| **Validation** | Syntax and semantic diagnostics with severity-based reporting. |
| **Query + Builder** | Optional experimental query selectors and fluent builder APIs. |

## Installation

### From PyPI (recommended)

```bash
pip install surinort-ast
```

### From Source

```bash
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

### Optional extras

```bash
pip install "surinort-ast[all]"
pip install "surinort-ast[cli-enhanced]"   # rich CLI output
pip install "surinort-ast[analysis]"       # analysis utilities
pip install "surinort-ast[serialization]"  # protobuf support
```

## Quick Start

### Python API

```python
from surinort_ast import parse_rule, print_rule, to_json, validate_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP test"; sid:1000001; rev:1;)')
print(rule.action)      # Action.ALERT
print(rule.header.protocol)  # Protocol.TCP
print(print_rule(rule)) # canonical rule text reconstruction

print(to_json(rule))  # JSON serialization

for diag in validate_rule(rule):
    print(f"{diag.level}: {diag.code} - {diag.message}")
```

### Command Line

```bash
surinort --help
surinort parse rules/local.rules
surinort parse rules/local.rules --json -o local.json
surinort fmt rules/local.rules --stable -o local.formatted.rules
surinort validate rules/local.rules --strict
```

## API (Most Used)

```python
from surinort_ast import (
    parse_rule,         # parse one rule
    parse_rules,        # parse many rules, return errors list
    parse_file,         # parse a rule file
    parse_file_streaming, # iterator-based parsing for large files
    print_rule,         # AST -> text
    to_json, from_json, # JSON serialization
    to_json_schema,     # AST JSON Schema
    validate_rule,      # diagnostics list
)
```

### Parse and serialize

```python
from surinort_ast import parse_rule, to_json, from_json

rule = parse_rule("alert tcp any any -> any 22 (msg:\"SSH Probe\"; sid:4001; rev:1;)")
payload = to_json(rule)
restored = from_json(payload)

assert rule == restored
```

### Batch parsing with errors

```python
from surinort_ast import parse_rules

rules, errors = parse_rules([
    'alert tcp any any -> any 80 (msg:"ok"; sid:1; rev:1;)',
    'alert tcp any > any 80 (msg:"bad"; sid:2; rev:2;)',
    'alert udp any any -> any 53 (msg:"dns"; sid:3; rev:1;)',
])

print(len(rules), "parsed")
print("errors:", errors)
```

### Parse large files safely

```python
from pathlib import Path
from surinort_ast import parse_file

rules = parse_file(
    Path("big.rules"),
    workers=8,
    batch_size=200,
    track_locations=False,
    include_raw_text=False,
)
print("parsed:", len(rules))
```

```python
from surinort_ast import parse_file_streaming

for rule in parse_file_streaming("big.rules", track_locations=False):
    if rule.action.value == "alert":
        print(rule.header.protocol, "=>", rule.header.dst_port)
```

## CLI Reference (short)

| Command | What it does |
| --- | --- |
| `surinort parse` | Parse and optionally export parsed rules as JSON. |
| `surinort fmt` | Pretty format rules (`--stable`, `--check`, `--in-place`). |
| `surinort validate` | Validate syntax/semantics (strict mode available). |
| `surinort to-json` | Convert rules to JSON output. |
| `surinort from-json` | Convert JSON back to Suricata/Snort text. |
| `surinort stats` | Produce corpus statistics. |
| `surinort schema` | Print JSON Schema for the AST model. |

### Quick CLI samples

```bash
surinort parse rules/local.rules --json --output local.json
surinort to-json rules/local.rules --compact -o local.compact.json
surinort from-json local.compact.json --output local.rules
surinort validate rules/local.rules --strict
surinort stats rules/local.rules
surinort schema > rule_schema.json
```

## Advanced (Optional)

### Query API (experimental)

```python
from surinort_ast import parse_rule
from surinort_ast.query import query, query_exists

rule = parse_rule('alert tcp any any -> any 80 (content:"admin"; pcre:"/admin/i"; sid:1001; rev:1; )')
has_pcre = query_exists(rule, "PcreOption")
contents = query(rule, "ContentOption")

print("has_pcre:", has_pcre)
print("content options:", len(contents))
```

### Rule builder (experimental)

```python
from surinort_ast.builder import RuleBuilder
from surinort_ast.printer import print_rule

rule = (
    RuleBuilder()
    .alert()
    .tcp()
    .source("$HOME_NET", "any")
    .destination("$EXTERNAL_NET", 80)
    .msg("Suspicious request")
    .content(b"POST")
    .sid(1000001)
    .rev(1)
    .build()
)
print(print_rule(rule))
```

## Examples and project structure

- `examples/` includes executable scripts for core features:
  - `examples/01_basic_parsing.py`
  - `examples/04_json_serialization.py`
  - `examples/05_batch_processing.py`
  - `examples/06_error_handling.py`
  - `examples/09_file_processing.py`
  - `examples/query_basic.py`
  - `examples/streaming_basic.py`
- `src/surinort_ast/` contains parser, AST core, CLI, serialization, analysis, streaming, query, and builder packages.

## Contributing

Contributions are welcome:

1. Open an issue describing the change.
2. Fork the repository.
3. Create a focused branch (`git checkout -b feature/my-change`).
4. Add/update tests when behavior changes.
5. Run the checks and make sure everything passes.
6. Open a pull request.

Recommended checks:

```bash
ruff check .
ruff format --check .
mypy src/
pytest tests/ -v --tb=short --strict-markers
```

## License

Copyright (C) 2026 Marc Rivero López
This project is released under the GNU General Public License v3.0 or later.

## Contact

- **Author:** Marc Rivero López (`@seifreed`)
- **GitHub:** https://github.com/seifreed/surinort-ast
- **Email:** mriverolopez@gmail.com
- **License file:** [LICENSE](LICENSE)

<p align="center">
  <sub>Built for security teams, researchers, and SOC engineers.</sub>
</p>
