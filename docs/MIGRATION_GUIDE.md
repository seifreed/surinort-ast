# Migration Guide

This guide helps you migrate from deprecated APIs to the recommended modern patterns in surinort-ast.

## Table of Contents

- [RuleParser Deprecation (v1.1.0)](#ruleparser-deprecation-v110)
- [API Package Restructuring](#api-package-restructuring)
- [Parser Dependency Injection](#parser-dependency-injection)
- [Type Hints and Protocols](#type-hints-and-protocols)
- [Breaking Changes Timeline](#breaking-changes-timeline)

---

## RuleParser Deprecation (v1.1.0)

### Overview

**Status**: Deprecated in v1.1.0, will be removed in v2.0.0

The `RuleParser` class is deprecated in favor of:
1. **LarkRuleParser** - Direct parser implementation
2. **parse_rule()** - High-level API function with dependency injection support

### Migration Path

#### Before (v1.0.x - Deprecated)

```python
from surinort_ast.parsing.parser import RuleParser

# Direct instantiation
parser = RuleParser()
rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Or convenience function
from surinort_ast.parsing.parser import parse_rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
```

**Warning**: This will emit `DeprecationWarning` in v1.1.0+

#### After (v1.1.0+ - Recommended)

**Option 1: Use API Package (Simplest)**

```python
from surinort_ast.api.parsing import parse_rule

# High-level API with all features
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
```

**Option 2: Use LarkRuleParser Directly**

```python
from surinort_ast.parsing.lark_parser import LarkRuleParser

# Direct parser usage
parser = LarkRuleParser()
rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
```

**Option 3: Dependency Injection (Advanced)**

```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

# Create custom parser instance
custom_parser = LarkRuleParser(dialect=Dialect.SNORT3, strict=True)

# Inject into API function
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)', parser=custom_parser)
```

### File Parsing Migration

#### Before (Deprecated)

```python
from surinort_ast.parsing.parser import RuleParser

parser = RuleParser()
rules = parser.parse_file("rules.rules")
```

or

```python
from surinort_ast.parsing.parser import parse_rules_file

rules = parse_rules_file("rules.rules")
```

#### After (Recommended)

```python
from surinort_ast.api.parsing import parse_file

rules = parse_file("rules.rules")
```

### Advanced Configuration Migration

#### Before (Deprecated)

```python
from surinort_ast.parsing.parser import RuleParser
from surinort_ast.parsing.parser_config import ParserConfig
from surinort_ast.core.enums import Dialect

config = ParserConfig.strict()
parser = RuleParser(
    dialect=Dialect.SNORT3,
    strict=True,
    error_recovery=False,
    config=config
)
rule = parser.parse(text)
```

#### After (Recommended)

```python
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.parsing.parser_config import ParserConfig
from surinort_ast.core.enums import Dialect
from surinort_ast.api.parsing import parse_rule

config = ParserConfig.strict()
parser = LarkRuleParser(
    dialect=Dialect.SNORT3,
    strict=True,
    error_recovery=False,
    config=config
)

# Use with dependency injection
rule = parse_rule(text, parser=parser)
```

---

## API Package Restructuring

### Overview

surinort-ast v1.1.0 introduces a modular `api/` package structure for better separation of concerns and reduced circular dependencies.

### Old Import Paths (Still Work, Not Deprecated)

```python
from surinort_ast import parse_rule, parse_file
from surinort_ast import to_json, from_json
from surinort_ast import validate_rule
from surinort_ast import print_rule
```

### New Import Paths (Recommended)

```python
# Parsing functions
from surinort_ast.api.parsing import parse_rule, parse_file, parse_rules

# Serialization functions
from surinort_ast.api.serialization import to_json, from_json, to_json_schema

# Validation functions
from surinort_ast.api.validation import validate_rule

# Printing functions
from surinort_ast.api.printing import print_rule
```

### Benefits of New Structure

1. **Clear Module Purpose**: Each module has a focused responsibility
2. **Reduced Imports**: Import only what you need
3. **Better IDE Support**: Clearer autocomplete and documentation
4. **No Circular Dependencies**: Clean dependency graph

### Migration Strategy

**Non-Breaking Change**: Old imports still work via `__init__.py` re-exports. You can migrate gradually:

```python
# Both work in v1.1.0+
from surinort_ast import parse_rule  # Still works (re-exported)
from surinort_ast.api.parsing import parse_rule  # Recommended
```

**Recommendation**: Update imports to new paths in new code, migrate existing code gradually.

---

## Parser Dependency Injection

### Overview

v1.1.0 adds support for parser dependency injection, enabling custom parser implementations without modifying core code.

### Use Cases

1. **Custom Validation**: Add strict validation rules
2. **Preprocessing**: Normalize input before parsing
3. **Caching**: Cache parsed results for performance
4. **Testing**: Inject mock parsers for unit tests
5. **Middleware**: Apply transformations before/after parsing

### Migration Pattern

#### Before (v1.0.x)

```python
from surinort_ast.parsing.parser import RuleParser

# No way to customize parser behavior without subclassing
parser = RuleParser()
rule = parser.parse(text)
```

#### After (v1.1.0+)

```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

# Define custom parser
class StrictParser:
    def __init__(self):
        self._lark_parser = LarkRuleParser(strict=True)

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Add custom validation
        if not rule.options:
            raise ValueError("Rule must have at least one option")

        return rule

# Use custom parser via injection
strict_parser = StrictParser()
rule = parse_rule(text, parser=strict_parser)
```

### Testing with Mock Parsers

#### Before (Complex)

```python
from unittest.mock import patch

with patch('surinort_ast.parsing.parser.RuleParser.parse') as mock_parse:
    mock_parse.return_value = mock_rule
    # Test code
```

#### After (Simple)

```python
class MockParser:
    def parse(self, text, file_path=None, line_offset=0):
        return mock_rule

# Inject mock parser
rule = parse_rule(text, parser=MockParser())
```

---

## Type Hints and Protocols

### Overview

v1.1.0 improves type hints throughout the codebase for better IDE support and type checking.

### Parser Protocol (Implicit)

While there's no formal `IParser` protocol class (yet), the parser injection pattern expects this interface:

```python
from typing import Protocol
from surinort_ast.core.nodes import Rule

class ParserProtocol(Protocol):
    """Implicit protocol for parser implementations."""

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0
    ) -> Rule:
        """Parse rule text to AST."""
        ...
```

### Benefits

1. **Type Safety**: mypy and pyright can verify parser compatibility
2. **IDE Autocomplete**: Better method signature hints
3. **Documentation**: Clear interface contract
4. **Flexibility**: No inheritance required, duck typing supported

### Migration for Type Checking

#### Before (v1.0.x)

```python
# No type hints on custom parsers
class CustomParser:
    def parse(self, text):
        return some_rule
```

#### After (v1.1.0+)

```python
from surinort_ast.core.nodes import Rule

class CustomParser:
    """Custom parser with proper type hints."""

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0
    ) -> Rule:
        """Parse rule text to AST."""
        return some_rule
```

---

## Breaking Changes Timeline

### v1.1.0 (Current)

**Deprecations** (Warnings Only):
- `RuleParser` class
- `surinort_ast.parsing.parser.parse_rule()` function
- `surinort_ast.parsing.parser.parse_rules_file()` function

**New Features**:
- `LarkRuleParser` class (recommended replacement)
- `surinort_ast.api.parsing` module with dependency injection
- Parser injection via `parser` parameter
- Modular `api/` package structure

**Backward Compatibility**:
- All deprecated APIs still work
- `DeprecationWarning` emitted on usage
- No breaking changes

### v2.0.0 (Planned)

**Breaking Changes**:
- Remove `RuleParser` class
- Remove `surinort_ast.parsing.parser.parse_rule()` convenience function
- Remove `surinort_ast.parsing.parser.parse_rules_file()` convenience function

**Required Actions**:
- Migrate to `LarkRuleParser` or `surinort_ast.api.parsing.parse_rule()`
- Update imports to `surinort_ast.api.*` paths
- Update custom parser implementations to match protocol signature

---

## Quick Migration Checklist

### For Basic Users

- [ ] Replace `from surinort_ast.parsing.parser import RuleParser` with `from surinort_ast.api.parsing import parse_rule`
- [ ] Replace `parser = RuleParser(); rule = parser.parse(text)` with `rule = parse_rule(text)`
- [ ] Replace `parse_rules_file()` with `parse_file()` from `surinort_ast.api.parsing`
- [ ] Test code to ensure no `DeprecationWarning` is emitted

### For Advanced Users

- [ ] Replace `RuleParser` instantiation with `LarkRuleParser`
- [ ] Add type hints to custom parser classes
- [ ] Use dependency injection pattern for custom parsers
- [ ] Update imports to `surinort_ast.api.*` structure
- [ ] Run type checker (mypy/pyright) to verify compatibility

### For Library Maintainers

- [ ] Review all uses of `RuleParser` in library code
- [ ] Add `parser` parameter support for customization
- [ ] Document migration path for library users
- [ ] Update examples to use recommended patterns
- [ ] Add type hints for parser parameters

---

## Examples

### Complete Migration Example

#### Before (v1.0.x)

```python
from surinort_ast.parsing.parser import RuleParser
from surinort_ast.core.enums import Dialect

# Initialize parser
parser = RuleParser(dialect=Dialect.SURICATA, strict=False)

# Parse single rule
rule = parser.parse('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')

# Parse file
rules = parser.parse_file("rules.rules")

# Process rules
for rule in rules:
    print(rule.action, rule.header.protocol)
```

#### After (v1.1.0+)

```python
from surinort_ast.api.parsing import parse_rule, parse_file
from surinort_ast.core.enums import Dialect

# Parse single rule (no parser instance needed)
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
    dialect=Dialect.SURICATA
)

# Parse file
rules = parse_file("rules.rules", dialect=Dialect.SURICATA)

# Process rules (same as before)
for rule in rules:
    print(rule.action, rule.header.protocol)
```

### Custom Parser Migration

#### Before (v1.0.x) - Subclassing

```python
from surinort_ast.parsing.parser import RuleParser

class StrictRuleParser(RuleParser):
    def parse(self, text, file_path=None, line_offset=0):
        rule = super().parse(text, file_path, line_offset)
        # Custom validation
        if not rule.options:
            raise ValueError("Missing options")
        return rule

parser = StrictRuleParser()
rule = parser.parse(text)
```

#### After (v1.1.0+) - Composition with Injection

```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

class StrictParser:
    def __init__(self):
        self._lark_parser = LarkRuleParser(strict=True)

    def parse(self, text, file_path=None, line_offset=0):
        rule = self._lark_parser.parse(text, file_path, line_offset)
        # Custom validation
        if not rule.options:
            raise ValueError("Missing options")
        return rule

# Use with dependency injection
strict_parser = StrictParser()
rule = parse_rule(text, parser=strict_parser)
```

---

## Troubleshooting

### DeprecationWarning: RuleParser is deprecated

**Solution**: Migrate to `LarkRuleParser` or `parse_rule()` function:

```python
# Old (deprecated)
from surinort_ast.parsing.parser import RuleParser
parser = RuleParser()

# New (recommended)
from surinort_ast.api.parsing import parse_rule
rule = parse_rule(text)
```

### ImportError: cannot import name 'parse_rule'

**Solution**: Update import path:

```python
# Old path (deprecated)
from surinort_ast.parsing.parser import parse_rule

# New path (recommended)
from surinort_ast.api.parsing import parse_rule
```

### Custom parser not working with parse_rule()

**Solution**: Ensure your parser implements the required `parse()` method signature:

```python
class CustomParser:
    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        # Implementation
        pass
```

### Tests failing after migration

**Solution**: Update test imports and verify mock parser signatures:

```python
# Before
from surinort_ast.parsing.parser import RuleParser

# After
from surinort_ast.parsing.lark_parser import LarkRuleParser
# Or use dependency injection with mock parsers
```

---

## Additional Resources

- [Extension Patterns Guide](EXTENSION_PATTERNS.md) - Custom parser patterns
- [API Guide](API_GUIDE.md) - Complete API reference
- [Examples](../examples/parser_dependency_injection.py) - Working examples
- [CHANGELOG](../CHANGELOG.md) - Version history

---

## Support

For migration questions:

- GitHub Issues: https://github.com/seifreed/surinort-ast/issues
- Discussions: https://github.com/seifreed/surinort-ast/discussions
- Email: mriverolopez@gmail.com

---

## Version Compatibility Matrix

| Feature | v1.0.x | v1.1.0 | v2.0.0 (Planned) |
|---------|--------|--------|------------------|
| `RuleParser` | ✅ | ⚠️ Deprecated | ❌ Removed |
| `LarkRuleParser` | ❌ | ✅ | ✅ |
| `api.parsing.parse_rule()` | ❌ | ✅ | ✅ |
| Parser injection | ❌ | ✅ | ✅ |
| Old imports | ✅ | ⚠️ Works with warnings | ❌ Removed |

**Legend**:
- ✅ Fully supported
- ⚠️ Deprecated (works with warnings)
- ❌ Not available / removed
