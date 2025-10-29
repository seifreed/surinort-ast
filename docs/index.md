# surisnort-ast

**A formal parser and Abstract Syntax Tree (AST) for Suricata and Snort IDS/IPS rules in Python.**

---

## Overview

`surisnort-ast` provides a complete, production-ready solution for parsing, analyzing, manipulating, and generating Suricata/Snort rules programmatically. It implements a formal grammar specification with full AST support, enabling advanced rule analysis, transformation, and validation workflows.

---

## Key Features

- **Formal Grammar**: Complete EBNF grammar specification for Suricata/Snort rules
- **Rich AST**: Structured Abstract Syntax Tree with typed nodes for all rule components
- **Bidirectional**: Parse rules to AST and serialize AST back to valid rule syntax
- **Cross-Compatible**: Supports both Suricata and Snort rule formats
- **Type-Safe**: Fully typed Python API with comprehensive type hints
- **Extensible**: Easy to extend with custom keywords and rule options
- **CLI Tools**: Command-line utilities for parsing, validation, and transformation
- **Well-Tested**: Extensive test suite with real-world rule corpus

---

## Quick Example

```python
from surisnort_ast import parse_rule, serialize_rule

# Parse a rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

# Access components
print(rule.action)              # Action.ALERT
print(rule.protocol)            # Protocol.TCP
print(rule.destination.port)    # Port(80)

# Modify rule
modified = rule.replace(action="drop")

# Serialize back
output = serialize_rule(modified)
print(output)  # drop tcp any any -> any 80 (msg:"HTTP"; sid:1;)
```

---

## Installation

```bash
pip install surisnort-ast
```

---

## Documentation Sections

### For Users

- **[Quickstart Guide](user-guide/quickstart.md)**: Get started in 5 minutes
- **[CLI Usage](user-guide/cli-usage.md)**: Command-line interface documentation
- **[Library Usage](user-guide/library-usage.md)**: Python library usage
- **[Pattern Cookbook](user-guide/cookbook.md)**: Common patterns and recipes

### For Developers

- **[Architecture Overview](ARCHITECTURE.md)**: System design and architecture
- **[Grammar Specification](GRAMMAR.md)**: Formal EBNF grammar
- **[AST Specification](AST_SPEC.md)**: AST structure and JSON Schema
- **[API Reference](API_REFERENCE.md)**: Complete API documentation

### Contributing

- **[Contributing Guide](CONTRIBUTING.md)**: How to contribute
- **[Changelog](CHANGELOG.md)**: Version history

---

## Use Cases

### Rule Analysis

Analyze and validate rule syntax and semantics:

```python
from surisnort_ast import validate_rule

result = validate_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
if result.is_valid:
    print("Rule is valid!")
```

### Bulk Transformation

Transform multiple rules programmatically:

```python
from surisnort_ast import parse_ruleset, serialize_ruleset

rules = parse_ruleset(open("rules.rules").read())

# Convert all HTTP rules to HTTPS
for rule in rules:
    if rule.destination.port == 80:
        rule = rule.replace(destination=rule.destination.replace(
            port=rule.destination.port.replace(value=443)
        ))

output = serialize_ruleset(rules)
```

### Rule Generation

Generate rules programmatically:

```python
from surisnort_ast.nodes import Rule, Address, Port, Options, SimpleOption

rule = Rule(
    action="alert",
    protocol="tcp",
    source=Address(addr="any", port=Port("any")),
    destination=Address(addr="$HOME_NET", port=Port(80)),
    direction="->",
    options=Options([
        SimpleOption(name="msg", value="HTTP Traffic"),
        SimpleOption(name="sid", value=1000001)
    ])
)

print(rule.serialize())
```

---

## Performance

Benchmarks on Intel Core i7-10700K @ 3.80GHz:

| Operation    | Rules/second | Notes                |
|--------------|--------------|----------------------|
| Parse        | ~50,000      | Simple rules         |
| Parse (complex) | ~15,000   | Multi-content, PCRE  |
| Serialize    | ~80,000      | AST to text          |
| Validate     | ~40,000      | Syntax + semantics   |

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

## Support

- **Documentation**: [https://surisnort-ast.readthedocs.io/](https://surisnort-ast.readthedocs.io/)
- **Issue Tracker**: [GitHub Issues](https://github.com/mrivero/surisnort-ast/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mrivero/surisnort-ast/discussions)
- **PyPI**: [https://pypi.org/project/surisnort-ast/](https://pypi.org/project/surisnort-ast/)

---

## License

Copyright (C) 2025 Marc Rivero López

This project is licensed under the GNU General Public License v3.0.

See [License](license.md) for full details.

---

## Acknowledgments

- Suricata and Snort communities for comprehensive documentation
- Open Information Security Foundation (OISF) for Suricata development
- Cisco Talos for Snort development
- All contributors to this project
