# surisnort-ast

[![PyPI version](https://badge.fury.io/py/surisnort-ast.svg)](https://badge.fury.io/py/surisnort-ast)
[![Python Support](https://img.shields.io/pypi/pyversions/surisnort-ast.svg)](https://pypi.org/project/surisnort-ast/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://github.com/mrivero/surisnort-ast/workflows/CI/badge.svg)](https://github.com/mrivero/surisnort-ast/actions)
[![Documentation Status](https://readthedocs.org/projects/surisnort-ast/badge/?version=latest)](https://surisnort-ast.readthedocs.io/)
[![Code Coverage](https://codecov.io/gh/mrivero/surisnort-ast/branch/main/graph/badge.svg)](https://codecov.io/gh/mrivero/surisnort-ast)

A formal parser and Abstract Syntax Tree (AST) implementation for Suricata and Snort IDS/IPS rules in Python.

`surisnort-ast` provides a complete, production-ready solution for parsing, analyzing, manipulating, and generating Suricata/Snort rules programmatically. It implements a formal grammar specification with full AST support, enabling advanced rule analysis, transformation, and validation workflows.

---

## Features

- **Formal Grammar Implementation**: Complete EBNF grammar specification for Suricata/Snort rules
- **Rich AST Representation**: Structured Abstract Syntax Tree with typed nodes for all rule components
- **Bidirectional Conversion**: Parse rules to AST and serialize AST back to valid rule syntax
- **Cross-Compatible**: Supports both Suricata and Snort rule formats with dialect detection
- **Type-Safe**: Fully typed Python API with comprehensive type hints
- **Extensible**: Easy to extend with custom keywords and rule options
- **CLI Tools**: Command-line utilities for parsing, validation, and transformation
- **High Performance**: Optimized parser with efficient memory usage
- **Well-Tested**: Extensive test suite with real-world rule corpus

---

## Installation

### From PyPI

```bash
pip install surisnort-ast
```

### From Source

```bash
git clone https://github.com/mrivero/surisnort-ast.git
cd surisnort-ast
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

---

## Quick Start

### Parsing a Rule

```python
from surisnort_ast import parse_rule

# Parse a Suricata rule
rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'
ast = parse_rule(rule_text)

# Access AST components
print(ast.action)              # "alert"
print(ast.protocol)            # "tcp"
print(ast.destination.port)    # "80"
print(ast.options["msg"])      # "HTTP Traffic"
```

### Modifying and Serializing

```python
from surisnort_ast import parse_rule, serialize_rule

# Parse existing rule
ast = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Modify AST
ast.action = "drop"
ast.options["msg"] = "Modified Rule"
ast.options["priority"] = 1

# Serialize back to rule syntax
modified_rule = serialize_rule(ast)
print(modified_rule)
# Output: drop tcp any any -> any 80 (msg:"Modified Rule"; priority:1; sid:1;)
```

### CLI Usage

```bash
# Parse and validate a rule file
surisnort-ast parse rules.rules

# Convert rules to JSON AST
surisnort-ast parse rules.rules --output json

# Validate rule syntax
surisnort-ast validate rules.rules

# Pretty-print rules
surisnort-ast format rules.rules --indent 2
```

---

## Documentation

### User Documentation

- [Quickstart Guide](docs/user-guide/quickstart.md)
- [CLI Reference](docs/user-guide/cli-usage.md)
- [Library Usage](docs/user-guide/library-usage.md)
- [Pattern Cookbook](docs/user-guide/cookbook.md)
- [Suricata/Snort Equivalences](docs/user-guide/dialect-equivalences.md)

### Technical Documentation

- [Architecture Overview](ARCHITECTURE.md)
- [Grammar Specification (EBNF)](GRAMMAR.md)
- [AST Specification](AST_SPEC.md)
- [API Reference](API_REFERENCE.md)
- [AST Node Reference](docs/technical/ast-nodes.md)
- [Parser Implementation](docs/technical/parser-implementation.md)
- [Extending the AST](docs/technical/extending-ast.md)
- [Testing Strategy](docs/technical/testing-strategy.md)

### Contributing

- [Contributing Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Full documentation available at: [https://surisnort-ast.readthedocs.io/](https://surisnort-ast.readthedocs.io/)

---

## Use Cases

### Rule Analysis and Validation

```python
from surisnort_ast import parse_rule, validate_rule

# Validate rule syntax and semantics
rule = 'alert tcp any any -> any 80 (msg:"Test"; sid:1000001;)'
is_valid, errors = validate_rule(rule)

if not is_valid:
    for error in errors:
        print(f"Error: {error}")
```

### Bulk Rule Transformation

```python
from surisnort_ast import parse_ruleset, serialize_ruleset

# Parse multiple rules
with open("rules.rules") as f:
    ruleset = parse_ruleset(f.read())

# Transform all HTTP rules to HTTPS
for rule in ruleset:
    if rule.destination.port == "80":
        rule.destination.port = "443"
        rule.options["msg"] += " [HTTPS]"

# Write back
with open("rules_https.rules", "w") as f:
    f.write(serialize_ruleset(ruleset))
```

### Rule Generation

```python
from surisnort_ast.nodes import Rule, Header, Address, Port, Options

# Build rule programmatically
rule = Rule(
    action="alert",
    protocol="http",
    source=Address(addr="any", port=Port("any")),
    destination=Address(addr="$HOME_NET", port=Port("any")),
    options=Options({
        "msg": "Suspicious HTTP Request",
        "flow": "established,to_server",
        "content": "|3a 2f 2f|",
        "http_uri": True,
        "sid": 2000001,
        "rev": 1
    })
)

print(rule.serialize())
```

---

## Project Structure

```
surisnort-ast/
├── README.md                    # This file
├── ARCHITECTURE.md              # Architecture and design decisions
├── GRAMMAR.md                   # Formal EBNF grammar specification
├── AST_SPEC.md                  # AST specification with JSON Schema
├── API_REFERENCE.md             # Complete API documentation
├── CONTRIBUTING.md              # Contribution guidelines
├── CHANGELOG.md                 # Version history
├── LICENSE                      # GPLv3 license
├── pyproject.toml               # Project metadata and dependencies
├── mkdocs.yml                   # Documentation configuration
├── surisnort_ast/               # Main package
│   ├── __init__.py
│   ├── parser.py                # Rule parser implementation
│   ├── nodes.py                 # AST node definitions
│   ├── serializer.py            # AST to rule serialization
│   ├── validator.py             # Rule validation logic
│   ├── grammar.py               # Grammar definition
│   ├── cli.py                   # Command-line interface
│   └── utils.py                 # Utility functions
├── tests/                       # Test suite
│   ├── test_parser.py
│   ├── test_ast.py
│   ├── test_serializer.py
│   ├── test_validator.py
│   └── corpus/                  # Real-world rule corpus
├── docs/                        # Documentation source
│   ├── user-guide/
│   │   ├── quickstart.md
│   │   ├── cli-usage.md
│   │   ├── library-usage.md
│   │   ├── cookbook.md
│   │   └── dialect-equivalences.md
│   ├── technical/
│   │   ├── ast-nodes.md
│   │   ├── parser-implementation.md
│   │   ├── extending-ast.md
│   │   └── testing-strategy.md
│   └── api/                     # Auto-generated API docs
└── examples/                    # Example scripts
    ├── parse_basic.py
    ├── transform_rules.py
    ├── validate_ruleset.py
    └── generate_rules.py
```

---

## Grammar Support

`surisnort-ast` implements support for the following rule components:

### Rule Headers
- Actions: `alert`, `drop`, `reject`, `pass`, `log`
- Protocols: `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `tls`, `ssh`, `ftp`
- Address formats: IPs, CIDR, ranges, variables, negation, groups
- Port formats: single, ranges, negation, groups, variables

### Rule Options

**General Options**:
- `msg`, `sid`, `rev`, `gid`, `classtype`, `priority`, `reference`, `metadata`

**Payload Detection**:
- `content`, `uricontent`, `pcre`, `byte_test`, `byte_jump`, `byte_extract`
- `isdataat`, `dsize`, `offset`, `depth`, `distance`, `within`

**Protocol-Specific**:
- HTTP: `http_uri`, `http_header`, `http_method`, `http_cookie`, `http_user_agent`
- DNS: `dns_query`, `dns_opcode`
- TLS: `tls.sni`, `tls.cert_subject`, `tls.cert_issuer`
- SSH: `ssh.proto`, `ssh.software`

**Flow and State**:
- `flow`, `flowbits`, `flowint`, `stream_size`

**Thresholding**:
- `threshold`, `detection_filter`

**File Operations**:
- `filestore`, `filemagic`, `filename`, `fileext`, `filemd5`, `filesha1`, `filesha256`

See [GRAMMAR.md](GRAMMAR.md) for complete specification.

---

## Compatibility

### Python Versions
- Python 3.8+
- Python 3.9+
- Python 3.10+
- Python 3.11+
- Python 3.12+

### IDS/IPS Versions
- Suricata 6.x, 7.x
- Snort 2.9.x
- Snort 3.x (partial support)

---

## Performance

Benchmarks on Intel Core i7-10700K @ 3.80GHz:

| Operation              | Rules/sec | Notes                    |
|------------------------|-----------|--------------------------|
| Parse                  | ~50,000   | Simple rules             |
| Parse (complex)        | ~15,000   | Multi-content, PCRE      |
| Serialize              | ~80,000   | AST to text              |
| Validate               | ~40,000   | Syntax + semantic checks |
| Round-trip             | ~12,000   | Parse + modify + serialize |

Memory usage: ~100 bytes per AST node (average rule: 2-5KB)

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Code of conduct
- Development setup
- Coding standards
- Testing requirements
- Pull request process
- Reporting bugs and requesting features

---

## Testing

```bash
# Run full test suite
pytest

# Run with coverage
pytest --cov=surisnort_ast --cov-report=html

# Run specific test category
pytest tests/test_parser.py

# Test against real-world corpus
pytest tests/corpus/
```

Test corpus includes 10,000+ real-world rules from:
- Emerging Threats
- Suricata ET Open
- Snort Community Rules
- Custom enterprise rulesets

---

## Roadmap

### Version 1.0 (Current)
- [x] Complete EBNF grammar
- [x] Full AST implementation
- [x] Parser and serializer
- [x] CLI tools
- [x] Comprehensive test suite

### Version 1.1 (Planned)
- [ ] Suricata Lua support
- [ ] Rule optimization engine
- [ ] Performance profiling tools
- [ ] Visual AST inspector

### Version 2.0 (Future)
- [ ] Snort 3 full compatibility
- [ ] Rule correlation analysis
- [ ] Machine learning integration
- [ ] Web-based rule editor

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## Related Projects

- [Suricata](https://suricata.io/) - Open Source IDS/IPS/NSM engine
- [Snort](https://www.snort.org/) - Network intrusion detection system
- [idstools](https://github.com/jasonish/py-idstools) - Suricata and Snort rule and event utilities
- [suricate](https://github.com/StamusNetworks/suricata-analytics) - Suricata analytics

---

## License

Copyright (C) 2025 Marc Rivero López

This project is licensed under the GNU General Public License v3.0.

You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions.

See [LICENSE](LICENSE) file for full details.

---

## Citation

If you use `surisnort-ast` in academic work, please cite:

```bibtex
@software{surisnort_ast,
  author = {Rivero López, Marc},
  title = {surisnort-ast: A Formal Parser and AST for Suricata/Snort Rules},
  year = {2025},
  url = {https://github.com/mrivero/surisnort-ast},
  version = {1.0.0}
}
```

---

## Support

- **Documentation**: [https://surisnort-ast.readthedocs.io/](https://surisnort-ast.readthedocs.io/)
- **Issue Tracker**: [https://github.com/mrivero/surisnort-ast/issues](https://github.com/mrivero/surisnort-ast/issues)
- **Discussions**: [https://github.com/mrivero/surisnort-ast/discussions](https://github.com/mrivero/surisnort-ast/discussions)
- **Email**: marc.rivero@example.com

---

## Acknowledgments

- Suricata and Snort communities for comprehensive rule documentation
- Open Information Security Foundation (OISF) for Suricata development
- Cisco Talos for Snort development
- All contributors to this project

---

**Made with precision for security professionals, researchers, and developers.**
