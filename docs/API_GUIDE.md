# surinort-ast API Reference

Complete API reference for surinort-ast v1.0.0, covering all public functions, classes, and modules.

---

## Table of Contents

- [Core Parsing API](#core-parsing-api)
- [Serialization API](#serialization-api)
- [Analysis API](#analysis-api)
- [Query API (EXPERIMENTAL)](#query-api-experimental)
- [AST Node Reference](#ast-node-reference)
- [Exception Reference](#exception-reference)
- [Type Annotations](#type-annotations)

---

## Core Parsing API

### parse_rule()

Parse a single IDS rule into AST.

```python
def parse_rule(
    text: str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True
) -> Rule
```

**Parameters:**
- `text` (str): Rule text to parse
- `dialect` (Dialect, optional): IDS dialect (SURICATA, SNORT2, SNORT3). Default: SURICATA
- `track_locations` (bool, optional): Track source locations in AST. Default: True

**Returns:**
- `Rule`: Parsed rule AST

**Raises:**
- `ParseError`: If rule syntax is invalid
- `ValidationError`: If rule fails semantic validation

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.core.enums import Dialect

# Parse Suricata rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Parse Snort3 rule
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
    dialect=Dialect.SNORT3
)

# Parse without location tracking (faster)
rule = parse_rule(rule_text, track_locations=False)
```

---

### parse_rules()

Parse multiple rules with error collection.

```python
def parse_rules(
    texts: Sequence[str],
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    continue_on_error: bool = True
) -> tuple[list[Rule], list[Diagnostic]]
```

**Parameters:**
- `texts` (Sequence[str]): List of rule texts to parse
- `dialect` (Dialect, optional): IDS dialect. Default: SURICATA
- `track_locations` (bool, optional): Track source locations. Default: True
- `continue_on_error` (bool, optional): Continue parsing after errors. Default: True

**Returns:**
- `tuple[list[Rule], list[Diagnostic]]`: Successfully parsed rules and diagnostics

**Raises:**
- `ParseError`: If continue_on_error=False and parsing fails

**Example:**
```python
from surinort_ast import parse_rules

rules = [
    'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
    'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    'invalid rule syntax',  # Will produce diagnostic
]

parsed_rules, diagnostics = parse_rules(rules)

print(f"Parsed: {len(parsed_rules)} rules")
print(f"Errors: {len(diagnostics)}")

for diag in diagnostics:
    print(f"Line {diag.line}: {diag.message}")
```

---

### parse_file()

Parse rules from a file.

```python
def parse_file(
    path: str | Path,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
    workers: int = 1,
    batch_size: int = 100
) -> list[Rule]
```

**Parameters:**
- `path` (str | Path): File path to parse
- `dialect` (Dialect, optional): IDS dialect. Default: SURICATA
- `track_locations` (bool, optional): Track source locations. Default: True
- `allowed_base` (Path | None, optional): Base directory for security validation. Default: None
- `allow_symlinks` (bool, optional): Allow symlink files. Default: False
- `workers` (int, optional): Number of parallel workers (1=sequential). Default: 1
- `batch_size` (int, optional): Batch size for parallel processing. Default: 100

**Returns:**
- `list[Rule]`: List of successfully parsed rules

**Raises:**
- `ParseError`: If file cannot be read or contains invalid syntax
- `FileNotFoundError`: If file does not exist

**Security:**
- Validates file paths to prevent path traversal attacks (CWE-22)
- Rejects symlinks by default
- Sanitizes error messages to prevent information disclosure (CWE-209)

**Example:**
```python
from surinort_ast import parse_file
from pathlib import Path

# Simple file parsing
rules = parse_file("rules/suricata.rules")

# Parallel parsing (faster for large files)
rules = parse_file(
    "rules/large-ruleset.rules",
    workers=8,
    batch_size=200
)

# Secure parsing (sandbox file access)
rules = parse_file(
    user_provided_path,
    allowed_base=Path("/safe/rules/directory"),
    allow_symlinks=False
)
```

**Performance:**
- Sequential: ~1,353 rules/second
- Parallel (8 workers): ~10,800 rules/second (estimated)
- Recommended batch_size: 50-200 rules

---

### validate_rule()

Validate a parsed rule for semantic correctness.

```python
def validate_rule(
    rule: Rule,
    strict: bool = False
) -> list[Diagnostic]
```

**Parameters:**
- `rule` (Rule): Parsed rule to validate
- `strict` (bool, optional): Treat warnings as errors. Default: False

**Returns:**
- `list[Diagnostic]`: List of validation diagnostics (errors/warnings)

**Example:**
```python
from surinort_ast import parse_rule, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Validate rule
diagnostics = validate_rule(rule)

# Filter by level
errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]

if errors:
    print("Validation failed:")
    for error in errors:
        print(f"  - {error.message}")
```

---

## Serialization API

### to_json()

Convert AST to JSON string.

```python
def to_json(
    rule: Rule,
    indent: int | None = 2,
    sort_keys: bool = False
) -> str
```

**Parameters:**
- `rule` (Rule): Rule AST to serialize
- `indent` (int | None, optional): JSON indentation (None for compact). Default: 2
- `sort_keys` (bool, optional): Sort JSON keys. Default: False

**Returns:**
- `str`: JSON representation of rule

**Raises:**
- `SerializationError`: If serialization fails

**Example:**
```python
from surinort_ast import parse_rule, to_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Pretty JSON
json_str = to_json(rule)

# Compact JSON
compact = to_json(rule, indent=None)

# Sorted keys (canonical form)
canonical = to_json(rule, sort_keys=True)
```

---

### from_json()

Parse AST from JSON string.

```python
def from_json(json_str: str) -> Rule
```

**Parameters:**
- `json_str` (str): JSON string to parse

**Returns:**
- `Rule`: Reconstructed rule AST

**Raises:**
- `SerializationError`: If JSON is invalid or doesn't match schema

**Example:**
```python
from surinort_ast import from_json

json_str = '{"node_type": "Rule", ...}'
rule = from_json(json_str)

# Roundtrip test
assert rule == from_json(to_json(rule))
```

---

### print_rule()

Convert AST to rule text.

```python
def print_rule(
    rule: Rule,
    stable: bool = False,
    compact: bool = False
) -> str
```

**Parameters:**
- `rule` (Rule): Rule AST to print
- `stable` (bool, optional): Use canonical formatting. Default: False
- `compact` (bool, optional): Minimize whitespace. Default: False

**Returns:**
- `str`: Rule text

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.printer import print_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Default formatting
text = print_rule(rule)

# Stable/canonical formatting
canonical = print_rule(rule, stable=True)

# Compact formatting
compact = print_rule(rule, compact=True)
```

---

## Analysis API

### PerformanceEstimator

Estimate rule performance cost.

```python
class PerformanceEstimator:
    def estimate(self, rule: Rule) -> float
```

**Methods:**

**estimate(rule)**
- Estimate performance score for rule
- Lower scores indicate better/faster performance
- Returns float (0-100 typical range)

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

print(f"Rule 1 score: {score1:.2f} (content-based)")
print(f"Rule 2 score: {score2:.2f} (PCRE-based, slower)")
```

---

### RuleOptimizer

Optimize rules for better performance.

```python
class RuleOptimizer:
    def __init__(
        self,
        strategies: list[OptimizationStrategy] | None = None,
        max_iterations: int = 10
    )

    def optimize(self, rule: Rule) -> OptimizationResult
```

**Parameters:**
- `strategies` (list[OptimizationStrategy] | None): Custom strategies. Default: all built-in strategies
- `max_iterations` (int): Maximum optimization passes. Default: 10

**Methods:**

**optimize(rule)**
- Apply optimization strategies to rule
- Returns OptimizationResult with details

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.analysis import RuleOptimizer, OptimizationResult

optimizer = RuleOptimizer()

rule = parse_rule(
    'alert tcp any any -> any 80 '
    '(pcre:"/test/"; content:"test"; content:"admin"; sid:1;)'
)

result: OptimizationResult = optimizer.optimize(rule)

if result.was_modified:
    print(f"Total improvement: {result.total_improvement:.1f}%")
    print("\nOptimizations:")
    for opt in result.optimizations:
        print(f"  - {opt.strategy}: {opt.description}")
        print(f"    Gain: {opt.estimated_gain:.1f}%")

    # Use optimized rule
    from surinort_ast.printer import print_rule
    print(f"\nOptimized rule:\n{print_rule(result.optimized)}")
```

---

### CoverageAnalyzer

Analyze rule coverage across a corpus.

```python
class CoverageAnalyzer:
    def analyze(self, rules: list[Rule]) -> CoverageReport
```

**Methods:**

**analyze(rules)**
- Analyze coverage for rule collection
- Returns CoverageReport with statistics

**Example:**
```python
from surinort_ast import parse_file
from surinort_ast.analysis import CoverageAnalyzer

rules = parse_file("rules/suricata.rules")

analyzer = CoverageAnalyzer()
report = analyzer.analyze(rules)

print(f"Total rules: {report.total_rules}")
print(f"Protocols: {report.protocols}")
print(f"Actions: {report.actions}")

# Find coverage gaps
if report.gaps:
    print("\nCoverage gaps:")
    for gap in report.gaps:
        print(f"  - {gap.protocol} port {gap.port}: {gap.description}")
```

---

## Query API (EXPERIMENTAL)

**WARNING: Experimental API, not recommended for production in v1.0.0**

### query()

Query descendants of a single AST node.

```python
def query(
    node: ASTNode,
    selector: str
) -> list[ASTNode]
```

**Parameters:**
- `node` (ASTNode): Root node to query
- `selector` (str): CSS-style selector string

**Returns:**
- `list[ASTNode]`: Matching nodes

**Raises:**
- `QuerySyntaxError`: If selector syntax is invalid
- `QueryExecutionError`: If execution fails

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.query import query

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

# Find all ContentOption nodes
contents = query(rule, "ContentOption")

# Find specific SID values
high_sids = query(rule, "SidOption[value=1000001]")

# Find TCP headers
tcp_headers = query(rule, "Header[protocol=tcp]")
```

---

### query_first()

Get first matching node.

```python
def query_first(
    node: ASTNode | Sequence[ASTNode],
    selector: str
) -> ASTNode | None
```

**Parameters:**
- `node` (ASTNode | Sequence[ASTNode]): Node or nodes to query
- `selector` (str): CSS-style selector string

**Returns:**
- `ASTNode | None`: First match or None

**Example:**
```python
from surinort_ast.query import query_first

# Get first content pattern
content = query_first(rule, "ContentOption")

# Get SID (typically only one)
sid = query_first(rule, "SidOption")
if sid:
    print(f"SID: {sid.value}")
```

---

### query_exists()

Check if any match exists.

```python
def query_exists(
    node: ASTNode | Sequence[ASTNode],
    selector: str
) -> bool
```

**Parameters:**
- `node` (ASTNode | Sequence[ASTNode]): Node or nodes to query
- `selector` (str): CSS-style selector string

**Returns:**
- `bool`: True if any match exists

**Example:**
```python
from surinort_ast.query import query_exists

# Check if rule has PCRE
has_pcre = query_exists(rule, "PcreOption")

# Check if alert rule
is_alert = query_exists(rule, "Rule[action=alert]")
```

---

### query_all()

Query multiple nodes.

```python
def query_all(
    nodes: Sequence[ASTNode],
    selector: str
) -> list[ASTNode]
```

**Parameters:**
- `nodes` (Sequence[ASTNode]): Collection of nodes to query
- `selector` (str): CSS-style selector string

**Returns:**
- `list[ASTNode]`: All matching nodes from all inputs

**Example:**
```python
from surinort_ast import parse_file
from surinort_ast.query import query_all

rules = parse_file("rules/suricata.rules")

# Find all PCRE options across corpus
pcre_options = query_all(rules, "PcreOption")

# Find all alert rules
alerts = query_all(rules, "Rule[action=alert]")
```

---

## AST Node Reference

### Rule

Top-level AST node representing a complete rule.

```python
@dataclass(frozen=True)
class Rule(ASTNode):
    action: str                    # alert, drop, reject, pass, log, sdrop
    header: Header                 # Protocol and addresses
    options: list[Option]          # Rule options
    raw_text: str | None = None    # Original rule text
    origin: SourceOrigin | None = None  # Source location
```

**Attributes:**
- `action` (str): Rule action (alert, drop, etc.)
- `header` (Header): Rule header with protocol and addresses
- `options` (list[Option]): List of rule options
- `raw_text` (str | None): Original unparsed text
- `origin` (SourceOrigin | None): Source file and line number

**Example:**
```python
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

print(rule.action)           # "alert"
print(rule.header.protocol)  # "tcp"
print(len(rule.options))     # 2 (MsgOption, SidOption)
```

---

### Header

Rule header containing protocol, addresses, and direction.

```python
@dataclass(frozen=True)
class Header(ASTNode):
    protocol: str               # tcp, udp, http, etc.
    src_addr: AddressExpr       # Source address
    src_port: PortExpr          # Source port
    direction: str              # -> or <>
    dst_addr: AddressExpr       # Destination address
    dst_port: PortExpr          # Destination port
```

---

### AddressExpr

Base class for address expressions.

**Subclasses:**
- `AnyAddress`: "any" keyword
- `IPAddress`: Single IP (192.168.1.1)
- `IPNetwork`: CIDR notation (192.168.0.0/16)
- `IPRange`: Range [start-end]
- `Variable`: Variable ($HOME_NET)
- `AddressGroup`: List of addresses
- `NegatedAddress`: Negated address (!addr)

---

### PortExpr

Base class for port expressions.

**Subclasses:**
- `AnyPort`: "any" keyword
- `Port`: Single port (80, 443)
- `PortRange`: Range (1024:65535)
- `PortVariable`: Variable ($HTTP_PORTS)
- `PortGroup`: List of ports
- `NegatedPort`: Negated port (!80)

---

### Option

Base class for all rule options.

**Common Option Types:**
- `MsgOption`: Message text
- `SidOption`: Signature ID
- `RevOption`: Revision number
- `ContentOption`: Content pattern
- `PcreOption`: PCRE regex
- `FlowOption`: Flow direction/state
- `ByteTestOption`: Byte testing
- `ReferenceOption`: External reference
- `MetadataOption`: Metadata key-value pairs

**60+ total option types supported**

---

## Exception Reference

### Base Exceptions

**SurinortError**
- Base exception for all surinort-ast errors
- All exceptions inherit from this

**ParseError**
- Raised when rule syntax is invalid
- Includes line number and position information

**ValidationError**
- Raised when rule fails semantic validation
- Includes diagnostic information

**SerializationError**
- Raised when serialization fails
- Includes details about failure

### Query Exceptions (EXPERIMENTAL)

**QueryError**
- Base exception for query operations

**QuerySyntaxError**
- Invalid query selector syntax

**QueryExecutionError**
- Query execution failed

**Example:**
```python
from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError, ValidationError

try:
    rule = parse_rule(rule_text)
except ParseError as e:
    print(f"Syntax error at line {e.line}: {e.message}")
except ValidationError as e:
    print(f"Validation error: {e.message}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

---

## Type Annotations

All public APIs include complete type annotations compatible with mypy strict mode.

### Common Type Aliases

```python
from typing import Sequence, Callable
from pathlib import Path

# Rule text input
RuleText = str

# File path
FilePath = str | Path

# Diagnostic collection
Diagnostics = list[Diagnostic]

# Rule collection
Rules = list[Rule]
```

### Type-Safe Usage

```python
from typing import List
from surinort_ast import parse_file
from surinort_ast.core.nodes import Rule

def extract_high_sids(rules: List[Rule], threshold: int = 1000000) -> List[int]:
    """Extract all SIDs above threshold."""
    sids: List[int] = []
    for rule in rules:
        for option in rule.options:
            if option.node_type == "SidOption" and option.value > threshold:
                sids.append(option.value)
    return sids

# Type checker will validate all usage
rules: List[Rule] = parse_file("rules.rules")
high_sids: List[int] = extract_high_sids(rules, threshold=2000000)
```

---

## Performance Best Practices

### Reuse Parser Instance

```python
from surinort_ast.parsing import Parser

# Create parser once
parser = Parser()

# Parse many rules
rules = [parser.parse(line) for line in rule_lines]
```

### Use Parallel Parsing

```python
from surinort_ast import parse_file

# Parallel processing for large files
rules = parse_file(
    "large-ruleset.rules",
    workers=8,
    batch_size=200
)
```

### Stream Large Files

```python
# Process without loading entire file
with open("large.rules") as f:
    for line in f:
        if line.strip() and not line.startswith('#'):
            rule = parse_rule(line)
            # Process immediately
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

- [FEATURES.md](FEATURES.md) - Detailed feature documentation
- [EXAMPLES.md](EXAMPLES.md) - Real-world usage examples
- [README.md](../README.md) - Project overview
- [Source Code](../src/surinort_ast/) - Implementation details
