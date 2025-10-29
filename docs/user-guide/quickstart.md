# Quickstart Guide

Get started with `surisnort-ast` in 5 minutes.

---

## Installation

### From PyPI (Recommended)

```bash
pip install surisnort-ast
```

### From Source

```bash
git clone https://github.com/mrivero/surisnort-ast.git
cd surisnort-ast
pip install -e .
```

---

## Basic Usage

### Parsing a Rule

```python
from surisnort_ast import parse_rule

# Parse a simple rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001;)')

# Access rule components
print(f"Action: {rule.action}")           # alert
print(f"Protocol: {rule.protocol}")       # tcp
print(f"Destination Port: {rule.destination.port}")  # 80

# Access options
print(f"Message: {rule.options['msg'].value}")  # "HTTP Traffic"
print(f"SID: {rule.options['sid'].value}")      # 1000001
```

### Modifying a Rule

```python
from surisnort_ast import parse_rule, serialize_rule
from surisnort_ast.types import Action

# Parse rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Modify action (creates new immutable instance)
modified_rule = rule.replace(action=Action.DROP)

# Serialize back to text
output = serialize_rule(modified_rule)
print(output)  # drop tcp any any -> any 80 (msg:"Test"; sid:1;)
```

### Validating Rules

```python
from surisnort_ast import validate_rule

# Validate rule
result = validate_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

if result.is_valid:
    print("Rule is valid!")
else:
    for error in result.errors:
        print(f"Error: {error}")
```

---

## CLI Usage

### Parse and Display

```bash
# Parse rule file
surisnort-ast parse rules.rules

# Output as JSON
surisnort-ast parse rules.rules --output json

# Pretty print AST
surisnort-ast parse rules.rules --output tree
```

### Validate Rules

```bash
# Validate rule file
surisnort-ast validate rules.rules

# Strict validation
surisnort-ast validate rules.rules --level strict

# Check for duplicate SIDs
surisnort-ast validate rules.rules --check-duplicates
```

### Format Rules

```bash
# Format rules (standard style)
surisnort-ast format rules.rules

# Pretty format with indentation
surisnort-ast format rules.rules --style pretty

# Compact format
surisnort-ast format rules.rules --style compact

# Modify file in place
surisnort-ast format rules.rules -i
```

---

## Common Patterns

### Working with Multiple Rules

```python
from surisnort_ast import parse_ruleset, serialize_ruleset

# Parse multiple rules
rules_text = """
alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)
alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)
alert tcp any any -> any 22 (msg:"SSH"; sid:3;)
"""

rules = parse_ruleset(rules_text)
print(f"Parsed {len(rules)} rules")

# Serialize back
output = serialize_ruleset(rules)
```

### Filtering Rules

```python
from surisnort_ast import parse_ruleset
from surisnort_ast.types import Action

with open("rules.rules") as f:
    rules = parse_ruleset(f.read())

# Filter alert rules only
alert_rules = [r for r in rules if r.action == Action.ALERT]

# Filter by port
http_rules = [r for r in rules if r.destination.port.value == 80]

# Filter by option
rules_with_pcre = [r for r in rules if r.has_option("pcre")]
```

### Extracting Information

```python
from surisnort_ast import parse_ruleset

with open("rules.rules") as f:
    rules = parse_ruleset(f.read())

# Extract all SIDs
sids = {rule.options['sid'].value for rule in rules}
print(f"Total SIDs: {len(sids)}")

# Extract all messages
messages = [rule.options['msg'].value for rule in rules]

# Find rules with specific content
admin_rules = [
    rule for rule in rules
    if any(opt.name == "content" and "admin" in str(opt.pattern)
           for opt in rule.options.options)
]
```

---

## Next Steps

- [CLI Usage Guide](cli-usage.md): Detailed CLI documentation
- [Library Usage Guide](library-usage.md): Advanced library usage
- [Pattern Cookbook](cookbook.md): Common patterns and recipes
- [API Reference](../../API_REFERENCE.md): Complete API documentation

---

## Getting Help

- **Documentation**: [https://surisnort-ast.readthedocs.io/](https://surisnort-ast.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/mrivero/surisnort-ast/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mrivero/surisnort-ast/discussions)

---

Copyright (C) 2025 Marc Rivero López

Licensed under the GNU General Public License v3.0.
