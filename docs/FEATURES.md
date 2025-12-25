# surinort-ast v1.0.0 Features

Complete feature documentation for surinort-ast v1.0.0, covering all parsing, analysis, query, and serialization capabilities.

---

## Table of Contents

- [Core Parser Features](#core-parser-features)
- [Analysis Module](#analysis-module)
- [Query API (EXPERIMENTAL)](#query-api-experimental)
- [Serialization](#serialization)
- [Validation](#validation)
- [CLI Tools](#cli-tools)

---

## Core Parser Features

### Production-Grade LALR(1) Parser

The parser is built on a formal LALR(1) grammar using the Lark parser library, providing robust and efficient parsing of IDS rules.

**Key Features:**
- Handles 35,157 real-world production rules with 99.46% compatibility
- Supports Suricata 6.x/7.x, Snort 2.9.x, and Snort 3.x dialects
- Error recovery with detailed diagnostic messages
- Position tracking for all AST nodes
- Comment preservation during parsing

**Grammar Coverage:**
- All standard rule actions (alert, drop, reject, pass, log, sdrop)
- 40+ protocol types (tcp, udp, http, dns, tls, ssh, etc.)
- Complex address specifications (IP, CIDR, ranges, variables, lists)
- 100+ rule options and modifiers
- PCRE patterns with full regex support
- Metadata, flow control, and threshold options

**Example:**
```python
from surinort_ast import parse_rule

# Parse complex rule with multiple options
rule = parse_rule(
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
    '(msg:"HTTP Admin Access"; '
    'flow:established,to_server; '
    'content:"GET"; http_method; '
    'content:"/admin"; http_uri; '
    'pcre:"/\\/admin\\/[a-z]+/i"; '
    'sid:1000001; rev:2;)'
)

# Access parsed components
print(f"Action: {rule.action}")
print(f"Protocol: {rule.header.protocol}")
print(f"Message: {rule.options[0].text}")
```

### AST Representation

Typed Abstract Syntax Tree nodes using Pydantic v2 for validation and serialization.

**Node Types:**
- **Rule**: Top-level container for entire rule
- **Header**: Protocol, addresses, ports, direction
- **Address**: IP addresses, CIDR blocks, variables, ranges
- **Port**: Port specifications (single, range, list, any)
- **Option**: 60+ option types for all rule components

**Immutability:**
All AST nodes are immutable (frozen Pydantic models), ensuring thread-safety and preventing accidental modifications.

**Example:**
```python
from surinort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# AST nodes are immutable - use model_copy to modify
modified_rule = rule.model_copy(update={
    'action': 'drop'
})

print(rule.action)          # 'alert' (unchanged)
print(modified_rule.action) # 'drop'
```

---

## Analysis Module

The analysis module provides tools for analyzing and optimizing IDS rules for better performance without changing detection logic.

### Performance Estimation

Estimate the performance cost of individual rules based on their structure and options.

**Features:**
- Analyzes rule complexity (number of options, PCRE usage, content patterns)
- Provides performance score (0-100, lower is better/faster)
- Identifies performance bottlenecks
- Supports custom scoring models

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.analysis import PerformanceEstimator

estimator = PerformanceEstimator()

# Compare two rules
rule1 = parse_rule('alert tcp any any -> any 80 (content:"test"; sid:1;)')
rule2 = parse_rule('alert tcp any any -> any 80 (pcre:"/complex.*regex/i"; sid:2;)')

score1 = estimator.estimate(rule1)
score2 = estimator.estimate(rule2)

print(f"Rule 1 score: {score1}")  # Lower score (faster)
print(f"Rule 2 score: {score2}")  # Higher score (slower due to PCRE)
```

### Rule Optimization

Automatically optimize rules for better performance while preserving detection logic.

**Optimization Strategies:**
- **Fast Pattern Selection**: Automatically select optimal fast_pattern content
- **Option Reordering**: Reorder options for better performance (cheaper checks first)
- **Redundancy Removal**: Remove duplicate or redundant options
- **Content Consolidation**: Merge adjacent content patterns when possible

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.analysis import RuleOptimizer

optimizer = RuleOptimizer()

# Optimize rule
rule = parse_rule(
    'alert tcp any any -> any 80 '
    '(pcre:"/test/"; content:"test"; content:"admin"; sid:1;)'
)

result = optimizer.optimize(rule)

if result.was_modified:
    print(f"Total improvement: {result.total_improvement:.1f}%")
    print("\nOptimizations applied:")
    for opt in result.optimizations:
        print(f"  - {opt.description}")
        print(f"    Estimated gain: {opt.estimated_gain:.1f}%")
```

### Coverage Analysis

Analyze rule coverage across a corpus to identify gaps and overlaps.

**Features:**
- Identify protocol coverage (TCP, UDP, HTTP, DNS, etc.)
- Detect port coverage gaps
- Find duplicate or overlapping rules
- Generate coverage reports

**Example:**
```python
from surinort_ast import parse_file
from surinort_ast.analysis import CoverageAnalyzer

# Parse entire ruleset
rules = parse_file("rules/suricata.rules")

# Analyze coverage
analyzer = CoverageAnalyzer()
report = analyzer.analyze(rules)

print(f"Total rules: {report.total_rules}")
print(f"Protocols covered: {report.protocols}")
print(f"Port coverage: {report.port_coverage}")

# Find gaps
for gap in report.gaps:
    print(f"Coverage gap: {gap.protocol} port {gap.port}")
```

### Conflict Detection

Detect conflicting rules that may cause unexpected behavior.

**Features:**
- Identify overlapping signatures
- Detect duplicate SIDs
- Find conflicting actions for same traffic
- Generate conflict resolution recommendations

**Example:**
```python
from surinort_ast import parse_file
from surinort_ast.analysis import ConflictDetector

rules = parse_file("rules/custom.rules")

detector = ConflictDetector()
conflicts = detector.detect(rules)

for conflict in conflicts:
    print(f"Conflict: {conflict.type}")
    print(f"  Rule 1 (SID {conflict.rule1_sid}): {conflict.rule1_summary}")
    print(f"  Rule 2 (SID {conflict.rule2_sid}): {conflict.rule2_summary}")
    print(f"  Recommendation: {conflict.recommendation}")
```

---

## Query API (EXPERIMENTAL)

**WARNING: The Query API is experimental and not recommended for production use in v1.0.0. The API may change in future versions.**

CSS-style selectors for searching and filtering AST nodes, inspired by jQuery and CSS selectors.

### Basic Type Selectors

Select nodes by their type name.

**Syntax:**
- `"Rule"` - Select all Rule nodes
- `"ContentOption"` - Select all ContentOption nodes
- `"*"` - Universal selector (all nodes)

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.query import query, query_first, query_exists

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

# Find all ContentOption nodes
contents = query(rule, "ContentOption")
print(f"Found {len(contents)} content patterns")

# Get first SidOption
sid = query_first(rule, "SidOption")
print(f"SID: {sid.value}")

# Check if rule has PCRE
has_pcre = query_exists(rule, "PcreOption")
print(f"Has PCRE: {has_pcre}")
```

### Attribute Selectors

Filter nodes by attribute values.

**Syntax:**
- `"Rule[action=alert]"` - Exact match
- `"SidOption[value=1000001]"` - Match specific value
- `"Header[protocol=tcp]"` - Match protocol

**Example:**
```python
from surinort_ast.query import query

# Find alert rules
alert_rules = query(rule, "Rule[action=alert]")

# Find specific SID
high_sid = query(rule, "SidOption[value>1000000]")  # Note: Comparisons not yet implemented

# Find TCP headers
tcp_headers = query(rule, "Header[protocol=tcp]")
```

### Query Functions

**Available Functions:**

**query(node, selector)**
- Query descendants of a single AST node
- Returns list of matching nodes
- Most common query function

**query_all(nodes, selector)**
- Query multiple AST nodes (e.g., rule collection)
- Returns list of matching nodes from all input nodes
- Useful for corpus-wide searches

**query_first(node, selector)**
- Returns first matching node or None
- More efficient than query() when only one result needed
- Early exit on first match

**query_exists(node, selector)**
- Returns boolean indicating if any match exists
- Fastest query operation
- Preferred for existence checks

**Example:**
```python
from surinort_ast import parse_file
from surinort_ast.query import query_all, query_exists

# Load entire corpus
rules = parse_file("rules/suricata.rules")

# Find all rules with PCRE
pcre_rules = query_all(rules, "PcreOption")
print(f"Rules with PCRE: {len(pcre_rules)}")

# Check if any rule targets port 443
has_https = query_exists(rules, "Port[value=443]")
print(f"Has HTTPS rules: {has_https}")
```

### Current Limitations (Phase 1 MVP)

The experimental Query API in v1.0.0 supports:
- Basic type selectors
- Attribute equality selectors
- Universal selector

**Not Yet Implemented:**
- Hierarchical selectors (descendant, child, sibling)
- Comparison operators (>, <, >=, <=)
- String operators (contains, starts-with, ends-with)
- Pseudo-selectors (:first, :last, :has, :not)
- Compound selectors (multiple conditions)

See the query module documentation for roadmap and planned features.

---

## Serialization

### JSON Serialization

RFC 8259 compliant JSON export/import with full roundtrip support.

**Features:**
- Lossless conversion (parse -> JSON -> parse produces identical AST)
- Human-readable JSON format
- Preserves all rule metadata
- Supports JSON Schema generation

**Example:**
```python
from surinort_ast import parse_rule, to_json, from_json

# Parse rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Convert to JSON
json_str = to_json(rule)
print(json_str)

# Convert back from JSON
restored_rule = from_json(json_str)

# Verify roundtrip
assert rule == restored_rule
```

**JSON Format:**
```json
{
  "node_type": "Rule",
  "action": "alert",
  "header": {
    "node_type": "Header",
    "protocol": "tcp",
    "src_addr": {...},
    "dst_addr": {...},
    "direction": "->"
  },
  "options": [
    {
      "node_type": "MsgOption",
      "text": "Test"
    },
    {
      "node_type": "SidOption",
      "value": 1
    }
  ]
}
```

### Text Serialization

Convert AST back to valid rule text.

**Features:**
- Multiple formatting styles (compact, standard, pretty)
- Stable output (identical AST produces identical text)
- Configurable indentation and spacing
- Comment preservation (future feature)

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.printer import print_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Default formatting
text = print_rule(rule)

# Stable formatting (canonical form)
canonical = print_rule(rule, stable=True)
```

### Schema Generation

Generate JSON Schema for AST structure.

**Example:**
```python
from surinort_ast.serialization import generate_schema_json

# Generate schema for all AST nodes
schema = generate_schema_json()

# Use for validation, documentation, or codegen
import jsonschema
jsonschema.validate(rule_json, schema)
```

---

## Validation

### Syntax Validation

Performed automatically during parsing.

**Checks:**
- Rule structure (action, protocol, addresses, ports, options)
- Option syntax and order
- PCRE pattern syntax
- Address and port specifications

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError

try:
    rule = parse_rule('alert tcp any any > any 80 (sid:1;)')  # Invalid direction
except ParseError as e:
    print(f"Parse error: {e}")
```

### Semantic Validation

Additional validation beyond syntax checking.

**Checks:**
- Required options present (sid, rev, msg)
- SID uniqueness
- Protocol-specific option compatibility
- PCRE pattern validity
- Cross-option dependencies

**Example:**
```python
from surinort_ast import parse_rule, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Validate rule
diagnostics = validate_rule(rule)

# Check for errors
errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]

if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error.message}")

if warnings:
    print("Validation warnings:")
    for warning in warnings:
        print(f"  - {warning.message}")
```

---

## CLI Tools

Seven production-ready command-line tools for rule management.

### parse - Parse and Display Rules

```bash
# Parse single file
surinort parse rules.rules

# Parse with specific dialect
surinort parse rules.rules --dialect suricata

# Parse from stdin
echo 'alert tcp any any -> any 80 (sid:1;)' | surinort parse -

# Parallel parsing (8 workers)
surinort parse large-ruleset.rules -w 8

# Verbose output with AST
surinort parse rules.rules --verbose
```

### validate - Validate Rules

```bash
# Basic validation
surinort validate rules.rules

# Strict mode (warnings as errors)
surinort validate rules.rules --strict

# Batch validation
surinort validate rules/*.rules
```

### fmt - Format Rules

```bash
# Format to stdout
surinort fmt rules.rules

# In-place formatting
surinort fmt rules.rules --in-place

# Check mode (exit 1 if would reformat)
surinort fmt rules.rules --check
```

### to-json / from-json - JSON Conversion

```bash
# Convert to JSON
surinort to-json rules.rules -o rules.json

# Compact JSON
surinort to-json rules.rules --compact

# Convert back to rules
surinort from-json rules.json -o rules.rules

# Roundtrip test
surinort to-json original.rules | surinort from-json - > roundtrip.rules
```

### stats - Analyze Corpus

```bash
# Get statistics
surinort stats rules.rules

# Output:
# Total rules: 1,234
# Actions:
#   alert: 1,200 (97.24%)
#   drop: 34 (2.76%)
# Protocols:
#   tcp: 800 (64.83%)
#   udp: 300 (24.31%)
#   http: 134 (10.86%)
```

### schema - Generate JSON Schema

```bash
# Generate schema
surinort schema -o schema.json

# Output to stdout
surinort schema
```

---

## Performance Considerations

### Parser Performance

- **Simple rules**: ~50,000 rules/second
- **Complex rules**: ~15,000 rules/second
- **30K corpus**: ~2 seconds
- **Memory**: ~2-5 KB per rule AST

### Query Performance (EXPERIMENTAL)

- **Simple type selectors**: O(n) where n = number of nodes
- **Attribute filters**: O(n * k) where k = attribute check cost
- **Target**: <10ms for typical rule (~50 nodes)

### Optimization Tips

**Batch Processing:**
```python
from surinort_ast.parsing import Parser

# Reuse parser instance for better performance
parser = Parser()
rules = [parser.parse(line) for line in rule_lines]
```

**Streaming:**
```python
# Process large files without loading all into memory
with open("large.rules") as f:
    for line in f:
        if line.strip() and not line.startswith('#'):
            rule = parser.parse(line)
            # Process rule immediately
```

---

## Error Handling

### Exception Hierarchy

```
Exception
├── SurinortError (base)
│   ├── ParseError
│   │   ├── SyntaxError
│   │   └── LexerError
│   ├── ValidationError
│   │   ├── SemanticError
│   │   └── SchemaError
│   └── SerializationError
└── QueryError (experimental)
    ├── QuerySyntaxError
    ├── QueryExecutionError
    └── InvalidSelectorError
```

### Best Practices

```python
from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError, ValidationError

try:
    rule = parse_rule(rule_text)
except ParseError as e:
    # Handle syntax errors
    print(f"Syntax error at line {e.line}: {e.message}")
except ValidationError as e:
    # Handle validation errors
    print(f"Validation error: {e.message}")
except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {e}")
```

---

## Type Safety

Full Python type hints with mypy strict mode compliance.

**All public APIs include:**
- Complete type annotations
- Parameter types
- Return types
- Exception specifications

**Example:**
```python
from typing import List
from surinort_ast import parse_rule
from surinort_ast.core.nodes import Rule, Option

# Type-safe API usage
def extract_sids(rules: List[Rule]) -> List[int]:
    """Extract all SIDs from rules."""
    sids: List[int] = []
    for rule in rules:
        for option in rule.options:
            if option.node_type == "SidOption":
                sids.append(option.value)
    return sids

# mypy will catch type errors
rule: Rule = parse_rule('alert tcp any any -> any 80 (sid:1;)')
sids: List[int] = extract_sids([rule])
```

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.
You may copy, distribute and modify the software as long as you track changes/dates in source files.
Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions.

See [LICENSE](../LICENSE) for full details.

---

## See Also

- [API_GUIDE.md](API_GUIDE.md) - Complete API reference
- [EXAMPLES.md](EXAMPLES.md) - Real-world usage examples
- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [README.md](../README.md) - Project overview
