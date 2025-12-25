# surinort-ast Usage Examples

Real-world usage scenarios, common patterns, and best practices for surinort-ast v1.0.0.

---

## Table of Contents

- [Basic Operations](#basic-operations)
- [Rule Analysis](#rule-analysis)
- [Batch Processing](#batch-processing)
- [Rule Optimization](#rule-optimization)
- [Query Operations (EXPERIMENTAL)](#query-operations-experimental)
- [CI/CD Integration](#cicd-integration)
- [Security Research](#security-research)
- [Rule Migration](#rule-migration)
- [Error Handling](#error-handling)
- [Performance Optimization](#performance-optimization)

---

## Basic Operations

### Parsing a Single Rule

```python
from surinort_ast import parse_rule

# Parse Suricata rule
rule = parse_rule(
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
    '(msg:"HTTP GET Request"; '
    'flow:established,to_server; '
    'content:"GET"; http_method; '
    'sid:1000001; rev:1;)'
)

# Access components
print(f"Action: {rule.action}")
print(f"Protocol: {rule.header.protocol}")
print(f"Direction: {rule.header.direction}")
print(f"Source: {rule.header.src_addr}")
print(f"Destination: {rule.header.dst_addr}")

# Iterate through options
for option in rule.options:
    print(f"Option: {option.node_type}")
    if option.node_type == "MsgOption":
        print(f"  Message: {option.text}")
    elif option.node_type == "SidOption":
        print(f"  SID: {option.value}")
```

---

### Modifying Rules

```python
from surinort_ast import parse_rule
from surinort_ast.printer import print_rule

# Parse original rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Modify action (immutable - creates new instance)
modified_rule = rule.model_copy(update={'action': 'drop'})

# Serialize back to text
new_text = print_rule(modified_rule)
print(new_text)
# Output: drop tcp any any -> any 80 (msg:"Test"; sid:1;)

# Modify options
new_options = []
for opt in rule.options:
    if opt.node_type == "SidOption":
        # Increment SID
        new_opt = opt.model_copy(update={'value': opt.value + 1000000})
        new_options.append(new_opt)
    else:
        new_options.append(opt)

modified_rule = rule.model_copy(update={'options': new_options})
print(print_rule(modified_rule))
```

---

### JSON Serialization

```python
from surinort_ast import parse_rule, to_json, from_json

# Parse rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Convert to JSON
json_str = to_json(rule, indent=2)
print(json_str)

# Save to file
with open("rule.json", "w") as f:
    f.write(json_str)

# Load from file
with open("rule.json", "r") as f:
    json_data = f.read()

# Convert back to AST
restored_rule = from_json(json_data)

# Verify roundtrip
assert rule == restored_rule
print("Roundtrip successful!")
```

---

## Rule Analysis

### Extracting Rule Metadata

```python
from surinort_ast import parse_file
from collections import Counter

# Parse all rules
rules = parse_file("rules/suricata.rules")

# Extract statistics
actions = Counter(rule.action for rule in rules)
protocols = Counter(rule.header.protocol for rule in rules)

print(f"Total rules: {len(rules)}\n")

print("Actions:")
for action, count in actions.most_common():
    pct = (count / len(rules)) * 100
    print(f"  {action}: {count} ({pct:.2f}%)")

print("\nProtocols:")
for protocol, count in protocols.most_common(5):
    pct = (count / len(rules)) * 100
    print(f"  {protocol}: {count} ({pct:.2f}%)")
```

---

### Finding Rules by Criteria

```python
from surinort_ast import parse_file

rules = parse_file("rules/suricata.rules")

# Find rules with PCRE
pcre_rules = []
for rule in rules:
    has_pcre = any(opt.node_type == "PcreOption" for opt in rule.options)
    if has_pcre:
        pcre_rules.append(rule)

print(f"Rules with PCRE: {len(pcre_rules)}")

# Find high-priority rules
high_priority = []
for rule in rules:
    for opt in rule.options:
        if opt.node_type == "PriorityOption" and opt.value <= 2:
            high_priority.append(rule)
            break

print(f"High-priority rules: {len(high_priority)}")

# Find rules targeting specific ports
http_rules = []
for rule in rules:
    dst_port = rule.header.dst_port
    if hasattr(dst_port, 'value') and dst_port.value == 80:
        http_rules.append(rule)

print(f"HTTP (port 80) rules: {len(http_rules)}")
```

---

### Analyzing Content Patterns

```python
from surinort_ast import parse_file
from collections import Counter

rules = parse_file("rules/suricata.rules")

# Extract all content patterns
content_patterns = []
for rule in rules:
    for opt in rule.options:
        if opt.node_type == "ContentOption":
            content_patterns.append(opt.pattern)

print(f"Total content patterns: {len(content_patterns)}")

# Find most common patterns
pattern_counts = Counter(content_patterns)
print("\nTop 10 content patterns:")
for pattern, count in pattern_counts.most_common(10):
    print(f"  {pattern}: {count} occurrences")

# Analyze pattern lengths
lengths = [len(p) for p in content_patterns]
avg_length = sum(lengths) / len(lengths)
print(f"\nAverage pattern length: {avg_length:.2f} bytes")
print(f"Min: {min(lengths)}, Max: {max(lengths)}")
```

---

## Batch Processing

### Processing Large Rulesets

```python
from surinort_ast import parse_file
from pathlib import Path

# Process multiple rule files
rule_files = Path("rules").glob("*.rules")

all_rules = []
for file_path in rule_files:
    print(f"Processing {file_path.name}...")
    try:
        rules = parse_file(file_path)
        all_rules.extend(rules)
        print(f"  Loaded {len(rules)} rules")
    except Exception as e:
        print(f"  Error: {e}")

print(f"\nTotal rules loaded: {len(all_rules)}")
```

---

### Parallel Processing

```python
from surinort_ast import parse_file

# Parse large file with parallel workers
rules = parse_file(
    "rules/large-ruleset.rules",
    workers=8,          # Use 8 worker processes
    batch_size=200      # Process 200 rules per batch
)

print(f"Parsed {len(rules)} rules using parallel processing")

# Performance comparison
import time

# Sequential
start = time.time()
rules_seq = parse_file("rules/large-ruleset.rules", workers=1)
seq_time = time.time() - start

# Parallel
start = time.time()
rules_par = parse_file("rules/large-ruleset.rules", workers=8)
par_time = time.time() - start

print(f"Sequential: {seq_time:.2f}s ({len(rules_seq)/seq_time:.0f} rules/sec)")
print(f"Parallel:   {par_time:.2f}s ({len(rules_par)/par_time:.0f} rules/sec)")
print(f"Speedup:    {seq_time/par_time:.2f}x")
```

---

### Streaming Processing

```python
from surinort_ast import parse_rule

# Process large file without loading all into memory
def process_rules_streaming(file_path):
    """Process rules one at a time without loading entire file."""
    processed = 0
    errors = 0

    with open(file_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            try:
                rule = parse_rule(line)
                # Process rule immediately
                yield rule
                processed += 1
            except Exception as e:
                print(f"Error on line {line_num}: {e}")
                errors += 1

    print(f"Processed: {processed}, Errors: {errors}")

# Use streaming processor
for rule in process_rules_streaming("rules/large.rules"):
    # Process each rule as it's parsed
    if rule.action == "alert":
        print(f"Alert rule: SID {next((o.value for o in rule.options if o.node_type == 'SidOption'), None)}")
```

---

## Rule Optimization

### Optimizing Individual Rules

```python
from surinort_ast import parse_rule
from surinort_ast.analysis import RuleOptimizer
from surinort_ast.printer import print_rule

optimizer = RuleOptimizer()

# Original rule (suboptimal order)
rule = parse_rule(
    'alert tcp any any -> any 80 '
    '(pcre:"/admin/i"; content:"GET"; content:"admin"; '
    'msg:"Admin access"; sid:1000001;)'
)

# Optimize
result = optimizer.optimize(rule)

if result.was_modified:
    print(f"✓ Rule optimized ({result.total_improvement:.1f}% improvement)\n")

    print("Optimizations applied:")
    for opt in result.optimizations:
        print(f"  • {opt.description}")
        print(f"    Strategy: {opt.strategy}")
        print(f"    Gain: {opt.estimated_gain:.1f}%\n")

    print("Original rule:")
    print(f"  {print_rule(rule)}\n")

    print("Optimized rule:")
    print(f"  {print_rule(result.optimized)}")
else:
    print("Rule is already optimal")
```

---

### Batch Optimization

```python
from surinort_ast import parse_file
from surinort_ast.analysis import RuleOptimizer
from surinort_ast.printer import print_rule

# Load rules
rules = parse_file("rules/custom.rules")

# Optimize all rules
optimizer = RuleOptimizer()
optimized_rules = []
total_improvement = 0.0
modified_count = 0

for rule in rules:
    result = optimizer.optimize(rule)
    optimized_rules.append(result.optimized)

    if result.was_modified:
        modified_count += 1
        total_improvement += result.total_improvement

print(f"Optimized {modified_count}/{len(rules)} rules")
print(f"Average improvement: {total_improvement/len(rules):.2f}%")

# Save optimized rules
with open("rules/optimized.rules", "w") as f:
    for rule in optimized_rules:
        f.write(print_rule(rule) + "\n")
```

---

### Performance Estimation

```python
from surinort_ast import parse_file
from surinort_ast.analysis import PerformanceEstimator

rules = parse_file("rules/suricata.rules")
estimator = PerformanceEstimator()

# Estimate performance for all rules
scores = []
for rule in rules:
    score = estimator.estimate(rule)
    scores.append((rule, score))

# Sort by performance (lower is better)
scores.sort(key=lambda x: x[1])

# Find slowest rules
print("Top 10 slowest rules:")
for rule, score in scores[-10:]:
    sid = next((o.value for o in rule.options if o.node_type == "SidOption"), None)
    msg = next((o.text for o in rule.options if o.node_type == "MsgOption"), None)
    print(f"  SID {sid}: {score:.2f} - {msg}")

# Find fastest rules
print("\nTop 10 fastest rules:")
for rule, score in scores[:10]:
    sid = next((o.value for o in rule.options if o.node_type == "SidOption"), None)
    msg = next((o.text for o in rule.options if o.node_type == "MsgOption"), None)
    print(f"  SID {sid}: {score:.2f} - {msg}")
```

---

## Query Operations (EXPERIMENTAL)

### Basic Queries

```python
from surinort_ast import parse_rule
from surinort_ast.query import query, query_first, query_exists

rule = parse_rule(
    'alert tcp any any -> any 80 '
    '(msg:"Admin Access"; content:"GET"; content:"admin"; '
    'pcre:"/\\/admin\\//i"; sid:1000001; rev:2;)'
)

# Find all content options
contents = query(rule, "ContentOption")
print(f"Content patterns: {len(contents)}")
for content in contents:
    print(f"  - {content.pattern}")

# Get SID
sid = query_first(rule, "SidOption")
if sid:
    print(f"\nSID: {sid.value}")

# Check for PCRE
has_pcre = query_exists(rule, "PcreOption")
print(f"Uses PCRE: {has_pcre}")

# Check rule type
is_alert = query_exists(rule, "Rule[action=alert]")
is_tcp = query_exists(rule, "Header[protocol=tcp]")
print(f"Alert rule: {is_alert}, TCP: {is_tcp}")
```

---

### Corpus-Wide Queries

```python
from surinort_ast import parse_file
from surinort_ast.query import query_all, query_exists

# Load corpus
rules = parse_file("rules/suricata.rules")

# Find all rules with PCRE
pcre_count = sum(1 for rule in rules if query_exists(rule, "PcreOption"))
print(f"Rules with PCRE: {pcre_count}/{len(rules)}")

# Find all content patterns across corpus
all_contents = []
for rule in rules:
    contents = query(rule, "ContentOption")
    all_contents.extend(contents)

print(f"Total content patterns: {len(all_contents)}")

# Find rules targeting specific protocols
tcp_rules = [r for r in rules if query_exists(r, "Header[protocol=tcp]")]
http_rules = [r for r in rules if query_exists(r, "Header[protocol=http]")]

print(f"TCP rules: {len(tcp_rules)}")
print(f"HTTP rules: {len(http_rules)}")
```

---

### Advanced Queries

```python
from surinort_ast import parse_file
from surinort_ast.query import query, query_exists

rules = parse_file("rules/suricata.rules")

# Find rules with specific characteristics
results = {
    'has_pcre': [],
    'has_flow': [],
    'has_metadata': [],
    'complex_rules': []  # Multiple content + PCRE
}

for rule in rules:
    # PCRE rules
    if query_exists(rule, "PcreOption"):
        results['has_pcre'].append(rule)

    # Flow rules
    if query_exists(rule, "FlowOption"):
        results['has_flow'].append(rule)

    # Metadata rules
    if query_exists(rule, "MetadataOption"):
        results['has_metadata'].append(rule)

    # Complex rules (3+ content patterns + PCRE)
    contents = query(rule, "ContentOption")
    has_pcre = query_exists(rule, "PcreOption")
    if len(contents) >= 3 and has_pcre:
        results['complex_rules'].append(rule)

# Print statistics
print("Rule characteristics:")
for category, rules_list in results.items():
    pct = (len(rules_list) / len(rules)) * 100
    print(f"  {category}: {len(rules_list)} ({pct:.2f}%)")
```

---

## CI/CD Integration

### Validation Script

```python
#!/usr/bin/env python3
"""
CI/CD rule validation script.
Exit code 0 = success, 1 = failure
"""

import sys
from pathlib import Path
from surinort_ast import parse_file, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

def validate_ruleset(file_path: Path) -> bool:
    """Validate ruleset and return success status."""
    try:
        # Parse all rules
        rules = parse_file(file_path)
        print(f"✓ Parsed {len(rules)} rules from {file_path.name}")

        # Validate each rule
        errors = 0
        warnings = 0

        for rule in rules:
            diagnostics = validate_rule(rule, strict=True)

            for diag in diagnostics:
                if diag.level == DiagnosticLevel.ERROR:
                    errors += 1
                    print(f"✗ ERROR: {diag.message}")
                elif diag.level == DiagnosticLevel.WARNING:
                    warnings += 1
                    print(f"⚠ WARNING: {diag.message}")

        print(f"\nValidation complete:")
        print(f"  Errors: {errors}")
        print(f"  Warnings: {warnings}")

        return errors == 0

    except Exception as e:
        print(f"✗ Validation failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: validate.py <rules-file>")
        sys.exit(1)

    success = validate_ruleset(Path(sys.argv[1]))
    sys.exit(0 if success else 1)
```

---

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Validate all modified .rules files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep '\.rules$'); do
    echo "Validating $file..."
    surinort validate "$file" --strict
    if [ $? -ne 0 ]; then
        echo "✗ Validation failed for $file"
        exit 1
    fi
done

echo "✓ All rules validated"
exit 0
```

---

### GitHub Actions Workflow

```yaml
# .github/workflows/validate-rules.yml
name: Validate IDS Rules

on:
  push:
    paths:
      - 'rules/**/*.rules'
  pull_request:
    paths:
      - 'rules/**/*.rules'

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install surinort-ast
        run: pip install surinort-ast

      - name: Validate rules
        run: |
          for file in rules/**/*.rules; do
            echo "Validating $file..."
            surinort validate "$file" --strict || exit 1
          done

      - name: Check formatting
        run: |
          for file in rules/**/*.rules; do
            surinort fmt "$file" --check || exit 1
          done
```

---

## Security Research

### Analyzing Rule Coverage

```python
from surinort_ast import parse_file
from collections import defaultdict

rules = parse_file("rules/suricata.rules")

# Analyze protocol and port coverage
coverage = defaultdict(set)

for rule in rules:
    protocol = rule.header.protocol
    dst_port = rule.header.dst_port

    # Extract port value
    if hasattr(dst_port, 'value'):
        if isinstance(dst_port.value, int):
            coverage[protocol].add(dst_port.value)
        elif dst_port.value == "any":
            coverage[protocol].add("any")

# Print coverage report
print("Protocol and Port Coverage:")
for protocol, ports in sorted(coverage.items()):
    if "any" in ports:
        print(f"  {protocol}: ALL PORTS")
    else:
        port_list = sorted(p for p in ports if isinstance(p, int))
        print(f"  {protocol}: {len(port_list)} ports - {port_list[:10]}...")

# Find coverage gaps
well_known_ports = {
    'tcp': [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080],
    'udp': [53, 67, 68, 69, 123, 161, 162, 514]
}

print("\nCoverage Gaps:")
for protocol, ports in well_known_ports.items():
    covered = coverage.get(protocol, set())
    if "any" not in covered:
        gaps = [p for p in ports if p not in covered]
        if gaps:
            print(f"  {protocol}: {gaps}")
```

---

### Detecting Overlapping Rules

```python
from surinort_ast import parse_file
from itertools import combinations

rules = parse_file("rules/custom.rules")

# Find potentially overlapping rules
def rules_overlap(rule1, rule2):
    """Check if two rules might overlap."""
    # Same protocol and action
    if rule1.header.protocol != rule2.header.protocol:
        return False
    if rule1.action != rule2.action:
        return False

    # Check for overlapping content patterns
    contents1 = set(
        opt.pattern for opt in rule1.options
        if opt.node_type == "ContentOption"
    )
    contents2 = set(
        opt.pattern for opt in rule2.options
        if opt.node_type == "ContentOption"
    )

    # If they share content patterns, might overlap
    return bool(contents1 & contents2)

# Find overlaps
overlaps = []
for rule1, rule2 in combinations(rules, 2):
    if rules_overlap(rule1, rule2):
        sid1 = next((o.value for o in rule1.options if o.node_type == "SidOption"), None)
        sid2 = next((o.value for o in rule2.options if o.node_type == "SidOption"), None)
        overlaps.append((sid1, sid2))

print(f"Found {len(overlaps)} potentially overlapping rule pairs")
for sid1, sid2 in overlaps[:10]:
    print(f"  SID {sid1} <-> SID {sid2}")
```

---

## Rule Migration

### Converting Between Dialects

```python
from surinort_ast import parse_file
from surinort_ast.printer import print_rule
from surinort_ast.core.enums import Dialect

# Parse Snort2 rules
rules = parse_file("rules/snort2.rules", dialect=Dialect.SNORT2)

# Filter rules compatible with Suricata
suricata_only_options = {
    'app-layer-protocol', 'tls.sni', 'dns.query',
    'http2.', 'ja3.', 'ssh.proto'
}

compatible_rules = []
incompatible_rules = []

for rule in rules:
    option_types = {opt.node_type for opt in rule.options}

    # Check for Suricata-specific options
    has_suricata_opts = any(
        opt_type.startswith(tuple(suricata_only_options))
        for opt_type in option_types
    )

    if not has_suricata_opts:
        compatible_rules.append(rule)
    else:
        incompatible_rules.append(rule)

print(f"Compatible rules: {len(compatible_rules)}/{len(rules)}")
print(f"Incompatible rules: {len(incompatible_rules)}")

# Export compatible rules for Suricata
with open("rules/suricata-compatible.rules", "w") as f:
    for rule in compatible_rules:
        f.write(print_rule(rule) + "\n")
```

---

### Bulk SID Update

```python
from surinort_ast import parse_file
from surinort_ast.printer import print_rule

# Load rules
rules = parse_file("rules/original.rules")

# Update SIDs (add offset)
SID_OFFSET = 1000000
updated_rules = []

for rule in rules:
    # Find and update SID option
    new_options = []
    for opt in rule.options:
        if opt.node_type == "SidOption":
            new_opt = opt.model_copy(update={'value': opt.value + SID_OFFSET})
            new_options.append(new_opt)
        else:
            new_options.append(opt)

    # Create updated rule
    updated_rule = rule.model_copy(update={'options': new_options})
    updated_rules.append(updated_rule)

# Save updated rules
with open("rules/updated.rules", "w") as f:
    for rule in updated_rules:
        f.write(print_rule(rule) + "\n")

print(f"Updated {len(updated_rules)} rules (SID offset: +{SID_OFFSET})")
```

---

## Error Handling

### Robust Parsing with Error Collection

```python
from surinort_ast import parse_rules
from surinort_ast.core.diagnostics import DiagnosticLevel

# Parse with error collection
rule_texts = [
    'alert tcp any any -> any 80 (msg:"Valid"; sid:1;)',
    'invalid rule syntax here',
    'alert tcp any any -> any 443 (msg:"Valid"; sid:2;)',
    'alert tcp any any > any 22 (sid:3;)',  # Invalid direction
]

parsed_rules, diagnostics = parse_rules(rule_texts, continue_on_error=True)

print(f"Successfully parsed: {len(parsed_rules)}/{len(rule_texts)} rules")
print(f"Errors encountered: {len(diagnostics)}")

# Categorize diagnostics
errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]

print(f"\nErrors: {len(errors)}")
for error in errors:
    print(f"  Line {error.line}: {error.message}")

print(f"\nWarnings: {len(warnings)}")
for warning in warnings:
    print(f"  Line {warning.line}: {warning.message}")
```

---

### Exception Handling Best Practices

```python
from surinort_ast import parse_file
from surinort_ast.exceptions import ParseError, ValidationError, SurinortError

def safe_parse_file(file_path):
    """Parse file with comprehensive error handling."""
    try:
        rules = parse_file(file_path)
        return rules, None

    except FileNotFoundError:
        return None, f"File not found: {file_path}"

    except ParseError as e:
        return None, f"Parse error: {e.message} (line {e.line})"

    except ValidationError as e:
        return None, f"Validation error: {e.message}"

    except SurinortError as e:
        return None, f"Surinort error: {e}"

    except Exception as e:
        return None, f"Unexpected error: {e}"

# Use safe parser
rules, error = safe_parse_file("rules/test.rules")
if error:
    print(f"Failed to parse: {error}")
else:
    print(f"Successfully parsed {len(rules)} rules")
```

---

## Performance Optimization

### Benchmark Different Approaches

```python
import time
from surinort_ast import parse_file

file_path = "rules/large-ruleset.rules"

# Method 1: Sequential parsing
start = time.time()
rules_seq = parse_file(file_path, workers=1)
seq_time = time.time() - start

# Method 2: Parallel parsing (8 workers)
start = time.time()
rules_par = parse_file(file_path, workers=8)
par_time = time.time() - start

# Method 3: Parallel with larger batches
start = time.time()
rules_batch = parse_file(file_path, workers=8, batch_size=500)
batch_time = time.time() - start

# Results
print("Performance Comparison:")
print(f"Sequential:  {seq_time:.2f}s ({len(rules_seq)/seq_time:.0f} rules/sec)")
print(f"Parallel:    {par_time:.2f}s ({len(rules_par)/par_time:.0f} rules/sec) - {seq_time/par_time:.2f}x speedup")
print(f"Batch:       {batch_time:.2f}s ({len(rules_batch)/batch_time:.0f} rules/sec) - {seq_time/batch_time:.2f}x speedup")
```

---

### Memory-Efficient Processing

```python
from surinort_ast import parse_rule
import gc

def process_large_file_memory_efficient(file_path, chunk_size=1000):
    """Process large file in chunks to minimize memory usage."""
    chunk = []
    processed_count = 0

    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            chunk.append(line)

            # Process chunk when it reaches size
            if len(chunk) >= chunk_size:
                for rule_text in chunk:
                    try:
                        rule = parse_rule(rule_text)
                        # Process rule here
                        processed_count += 1
                    except Exception as e:
                        print(f"Error: {e}")

                # Clear chunk and force garbage collection
                chunk = []
                gc.collect()

        # Process remaining rules
        for rule_text in chunk:
            try:
                rule = parse_rule(rule_text)
                processed_count += 1
            except Exception:
                pass

    return processed_count

# Use memory-efficient processor
count = process_large_file_memory_efficient("rules/huge-ruleset.rules")
print(f"Processed {count} rules with minimal memory usage")
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

- [FEATURES.md](FEATURES.md) - Feature documentation
- [API_GUIDE.md](API_GUIDE.md) - Complete API reference
- [README.md](../README.md) - Project overview
- [examples/](../examples/) - Executable example scripts
