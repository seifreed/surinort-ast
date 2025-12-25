# surinort-ast Examples

This directory contains comprehensive, executable examples demonstrating the capabilities of the surinort-ast library for parsing, analyzing, and manipulating IDS/IPS rules (Suricata/Snort).

## Overview

Each example is a standalone, runnable Python script that demonstrates specific features of surinort-ast. The examples progress from basic to advanced usage patterns.

## Requirements

- Python 3.11 or higher
- surinort-ast installed (`pip install surinort-ast` or `pip install -e .` from project root)

## Quick Start

Run any example directly:

```bash
python 01_basic_parsing.py
python 02_ast_inspection.py
# ... etc
```

Or run all examples:

```bash
for script in *.py; do
    echo "Running $script..."
    python "$script"
    echo ""
done
```

## Examples

### 01_basic_parsing.py
**Basic Parsing Fundamentals**

Learn how to parse IDS/IPS rules and access basic AST components.

**Topics covered:**
- Simple rule parsing with `parse_rule()`
- Accessing rule components (action, protocol, direction)
- Understanding addresses and ports
- Iterating through rule options
- Working with different protocols and actions

**Key functions:**
- `parse_rule()` - Parse a single rule
- Rule access patterns
- Type-safe attribute access

**Run:**
```bash
python 01_basic_parsing.py
```

---

### 02_ast_inspection.py
**AST Traversal and Inspection**

Master techniques for traversing and inspecting parsed rule ASTs.

**Topics covered:**
- Manual AST inspection without visitors
- Using `ASTVisitor` pattern for collection tasks
- Using `ASTWalker` for side-effect operations
- Analyzing nested structures (lists, options)
- Collecting statistics from rules

**Key classes:**
- `ASTVisitor` - Base visitor pattern
- `ASTWalker` - Simple walker for side effects
- Custom visitor implementations

**Run:**
```bash
python 02_ast_inspection.py
```

---

### 03_modify_rules.py
**Rule Modification Patterns**

Learn how to modify rules using Pydantic's immutable model pattern.

**Topics covered:**
- Changing rule actions (alert → drop)
- Updating SIDs and revisions
- Adding new options
- Modifying message text
- Bulk transformations with `ASTTransformer`
- Changing ports and directions

**Key concepts:**
- Immutable AST nodes
- `model_copy()` for creating modified copies
- Working with option lists

**Run:**
```bash
python 03_modify_rules.py
```

---

### 04_json_serialization.py
**JSON Export/Import**

Master JSON serialization and deserialization of rules.

**Topics covered:**
- Basic JSON export with `to_json()`
- Compact vs. pretty-printed JSON
- Importing rules from JSON with `from_json()`
- Roundtrip conversion (rule → JSON → rule)
- JSON Schema generation with `to_json_schema()`
- Working with multiple rules in JSON arrays

**Key functions:**
- `to_json()` - Serialize rule to JSON
- `from_json()` - Deserialize rule from JSON
- `to_json_schema()` - Generate JSON Schema

**Run:**
```bash
python 04_json_serialization.py
```

---

### 05_batch_processing.py
**Batch Processing Patterns**

Efficiently process multiple rules with error handling and statistics.

**Topics covered:**
- Parsing multiple rules with `parse_rules()`
- Handling parse errors gracefully
- Collecting statistics (protocols, actions, directions)
- Filtering rules by criteria
- Bulk transformations
- Option usage analysis
- Batch processing patterns

**Key functions:**
- `parse_rules()` - Parse multiple rules with error collection
- Statistical analysis patterns
- Filtering and transformation

**Run:**
```bash
python 05_batch_processing.py
```

---

### 06_error_handling.py
**Error Handling Strategies**

Implement robust error handling for production use.

**Topics covered:**
- Basic error handling with try/except
- Using `ParseError` exception
- Collecting and reporting errors
- Validation errors vs. parse errors
- Serialization error handling
- Graceful degradation patterns
- Custom error handling strategies

**Key exceptions:**
- `ParseError` - Parsing failures
- `SerializationError` - JSON conversion failures
- `ValidationError` - Validation issues

**Run:**
```bash
python 06_error_handling.py
```

---

### 07_custom_visitor.py
**Custom AST Visitors**

Create powerful custom visitors for advanced analysis.

**Topics covered:**
- Signature ID collection
- Content pattern extraction
- Protocol-specific feature analysis
- Rule complexity scoring
- Finding rule relationships
- Chaining multiple transformers
- Advanced visitor patterns

**Key patterns:**
- Custom `ASTVisitor` subclasses
- Custom `ASTTransformer` subclasses
- Multi-pass transformations
- Metadata extraction

**Run:**
```bash
python 07_custom_visitor.py
```

---

### 08_rule_validation.py
**Rule Validation**

Validate rules for correctness and best practices.

**Topics covered:**
- Basic validation with `validate_rule()`
- Understanding diagnostic levels (ERROR, WARNING, INFO)
- Custom validation logic
- Port range validation
- Content pattern validation
- Batch validation and reporting

**Key functions:**
- `validate_rule()` - Built-in validation
- Custom validators
- Diagnostic handling

**Run:**
```bash
python 08_rule_validation.py
```

---

### 09_file_processing.py
**File I/O Operations**

Work with rule files efficiently.

**Topics covered:**
- Reading rules from files with `parse_file()`
- Handling comments and blank lines
- Writing rules to files
- Streaming large files
- Multi-dialect file processing
- Handling files with errors
- Organized output generation

**Key functions:**
- `parse_file()` - Parse rules from file
- `print_rule()` - Serialize rule to text
- File I/O patterns

**Run:**
```bash
python 09_file_processing.py
```

---

### 10_ast_transformation.py
**Advanced Transformations**

Master complex AST transformation patterns.

**Topics covered:**
- Action conversion (alert → drop)
- SID namespace migration
- Automatic revision bumping
- Metadata enrichment
- Multi-pass transformations
- Conditional transformations
- Complex transformation chains

**Key patterns:**
- `ASTTransformer` subclasses
- Multi-pass transformation pipelines
- Conditional transformation logic
- Metadata management

**Run:**
```bash
python 10_ast_transformation.py
```

---

## Usage Patterns

### Basic Parsing
```python
from surinort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
print(rule.action)  # Action.ALERT
print(rule.header.protocol)  # Protocol.TCP
```

### Visitor Pattern
```python
from surinort_ast.core.visitor import ASTVisitor

class SIDCollector(ASTVisitor):
    def __init__(self):
        self.sids = []

    def visit_SidOption(self, node):
        self.sids.append(node.value)
        return None

collector = SIDCollector()
collector.visit(rule)
print(collector.sids)
```

### Transformation
```python
from surinort_ast.core.visitor import ASTTransformer

class SIDRewriter(ASTTransformer):
    def visit_SidOption(self, node):
        return node.model_copy(update={'value': node.value + 1000000})

transformer = SIDRewriter()
new_rule = transformer.visit(rule)
```

### File Processing
```python
from surinort_ast import parse_file, print_rule

rules = parse_file('rules.rules')
for rule in rules:
    print(print_rule(rule))
```

## Common Tasks

### Extract All SIDs
```python
from surinort_ast import parse_rules

rules, _ = parse_rules(rules_text)
sids = [opt.value for rule in rules for opt in rule.options if opt.node_type == "SidOption"]
```

### Change All Actions
```python
from surinort_ast import Action

new_rule = rule.model_copy(update={'action': Action.DROP})
```

### Add Options
```python
from surinort_ast.core.nodes import RevOption

new_options = list(rule.options) + [RevOption(value=1)]
new_rule = rule.model_copy(update={'options': new_options})
```

### Validate Rules
```python
from surinort_ast import validate_rule

diagnostics = validate_rule(rule)
for diag in diagnostics:
    print(f"{diag.level}: {diag.message}")
```

## Best Practices

1. **Always handle errors**: Use try/except when parsing untrusted input
2. **Use parse_rules() for batches**: It collects errors instead of failing
3. **Immutability**: Remember that all AST nodes are immutable - use `model_copy()`
4. **Type safety**: Leverage Python type hints for better IDE support
5. **Validation**: Always validate rules before deployment
6. **File I/O**: Use `parse_file()` for proper comment and blank line handling

## Learning Path

**Beginner:**
1. Start with `01_basic_parsing.py`
2. Learn inspection with `02_ast_inspection.py`
3. Practice modifications with `03_modify_rules.py`

**Intermediate:**
4. Master JSON with `04_json_serialization.py`
5. Handle batches with `05_batch_processing.py`
6. Learn errors with `06_error_handling.py`

**Advanced:**
7. Create visitors with `07_custom_visitor.py`
8. Validate rules with `08_rule_validation.py`
9. Process files with `09_file_processing.py`
10. Transform ASTs with `10_ast_transformation.py`

## Testing

Run all examples to verify your installation:

```bash
# Bash
for script in [0-9]*.py; do
    echo "Testing $script..."
    python "$script" > /dev/null 2>&1 && echo "✓ PASS" || echo "✗ FAIL"
done

# Python
import subprocess
import sys
from pathlib import Path

examples = sorted(Path('.').glob('[0-9]*.py'))
for example in examples:
    result = subprocess.run([sys.executable, example], capture_output=True)
    status = "✓ PASS" if result.returncode == 0 else "✗ FAIL"
    print(f"{status} {example.name}")
```

## Additional Resources

- **Main Documentation**: [README.md](../README.md)
- **API Reference**: [src/surinort_ast/api.py](../src/surinort_ast/api.py)
- **GitHub**: [https://github.com/seifreed/surinort-ast](https://github.com/seifreed/surinort-ast)
- **Issues**: [https://github.com/seifreed/surinort-ast/issues](https://github.com/seifreed/surinort-ast/issues)

## Contributing

Found an issue or want to add an example? Please submit an issue or pull request!

## License

Copyright (C) 2025 Marc Rivero López

These examples are licensed under the GNU General Public License v3.0.
See [LICENSE](../LICENSE) for full details.

---

**Need Help?**
- GitHub Issues: https://github.com/seifreed/surinort-ast/issues
- Email: mriverolopez@gmail.com
- Author: Marc Rivero (@seifreed)
