# Extension Patterns Guide

This guide provides comprehensive patterns for extending surinort-ast with custom parsers, rule options, serialization formats, and plugins.

## Table of Contents

- [Custom Parser Implementation](#custom-parser-implementation)
- [Custom Option Types](#custom-option-types)
- [Custom Serialization Formats](#custom-serialization-formats)
- [Custom Analyzers](#custom-analyzers)
- [Plugin Development](#plugin-development)
- [Best Practices](#best-practices)

---

## Custom Parser Implementation

### Overview

surinort-ast uses dependency injection to support custom parser implementations. The `parse_rule()` function accepts a `parser` parameter that enables you to inject custom parsing logic without modifying the core codebase.

### Step 1: Implement the Parser Protocol

Create a parser class that implements the basic parsing interface:

```python
from pathlib import Path
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

class CustomParser:
    """
    Custom parser with additional validation or preprocessing.

    The parser must implement the parse() method signature.
    """

    def __init__(self, **kwargs):
        """Initialize the custom parser."""
        self._lark_parser = LarkRuleParser(**kwargs)

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0
    ) -> Rule:
        """
        Parse a rule with custom logic.

        Args:
            text: Rule text to parse
            file_path: Optional source file path
            line_offset: Line number offset for multi-line files

        Returns:
            Parsed Rule AST
        """
        # Add custom preprocessing
        text = self._preprocess(text)

        # Parse with LarkRuleParser
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Add custom post-processing
        rule = self._postprocess(rule)

        return rule

    def _preprocess(self, text: str) -> str:
        """Preprocess rule text before parsing."""
        # Example: normalize whitespace
        return " ".join(text.split())

    def _postprocess(self, rule: Rule) -> Rule:
        """Post-process parsed rule."""
        # Example: add custom validation
        return rule
```

### Step 2: Use the Custom Parser with Dependency Injection

```python
from surinort_ast.api.parsing import parse_rule

# Create custom parser instance
custom_parser = CustomParser()

# Inject into parse_rule()
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
    parser=custom_parser
)
```

### Advanced Example: Strict Validation Parser

```python
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.exceptions import ParseError

class StrictValidationParser:
    """
    Parser with strict validation requirements.

    Ensures rules have required options and follow specific patterns.
    """

    def __init__(self, required_options=None, **kwargs):
        self._lark_parser = LarkRuleParser(**kwargs)
        self.required_options = required_options or ["sid", "msg", "rev"]

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        # Parse with Lark
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Validate required options
        option_types = {opt.node_type for opt in rule.options}

        for required in self.required_options:
            required_type = f"{required.capitalize()}Option"
            if required_type not in option_types:
                raise ParseError(
                    f"Rule missing required option: {required}\n"
                    f"Rule text: {text}"
                )

        # Validate SID range
        sid_option = next((opt for opt in rule.options if opt.node_type == "SidOption"), None)
        if sid_option and sid_option.value < 1000000:
            raise ParseError(
                f"SID {sid_option.value} is below minimum threshold of 1000000"
            )

        return rule

# Usage
strict_parser = StrictValidationParser(required_options=["sid", "msg", "rev", "classtype"])
rule = parse_rule(rule_text, parser=strict_parser)
```

### Advanced Example: Wrapper Parser with Caching

```python
from functools import lru_cache
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.core.nodes import Rule

class CachingParser:
    """Parser that caches parsed rules for repeated parse operations."""

    def __init__(self, cache_size=1000, **kwargs):
        self._lark_parser = LarkRuleParser(**kwargs)
        self._cache_size = cache_size
        # Create cached parse method
        self._cached_parse = lru_cache(maxsize=cache_size)(self._parse_impl)

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        # Use cached parse for identical text
        return self._cached_parse(text, file_path, line_offset)

    def _parse_impl(self, text: str, file_path: str | None, line_offset: int) -> Rule:
        return self._lark_parser.parse(text, file_path, line_offset)

    def clear_cache(self):
        """Clear the parse cache."""
        self._cached_parse.cache_clear()

# Usage
caching_parser = CachingParser(cache_size=5000)
rule = parse_rule(rule_text, parser=caching_parser)
```

### Advanced Example: Parser Middleware Pattern

```python
from typing import Callable
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.lark_parser import LarkRuleParser

class ParserMiddleware:
    """
    Parser that applies middleware functions before/after parsing.
    """

    def __init__(self, **kwargs):
        self._lark_parser = LarkRuleParser(**kwargs)
        self._preprocessors: list[Callable[[str], str]] = []
        self._postprocessors: list[Callable[[Rule], Rule]] = []

    def add_preprocessor(self, func: Callable[[str], str]) -> None:
        """Add a text preprocessing function."""
        self._preprocessors.append(func)

    def add_postprocessor(self, func: Callable[[Rule], Rule]) -> None:
        """Add a rule post-processing function."""
        self._postprocessors.append(func)

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        # Apply preprocessors
        for preprocessor in self._preprocessors:
            text = preprocessor(text)

        # Parse
        rule = self._lark_parser.parse(text, file_path, line_offset)

        # Apply postprocessors
        for postprocessor in self._postprocessors:
            rule = postprocessor(rule)

        return rule

# Usage
def normalize_whitespace(text: str) -> str:
    return " ".join(text.split())

def add_metadata(rule: Rule) -> Rule:
    # Add custom metadata option
    return rule  # Simplified for example

parser = ParserMiddleware()
parser.add_preprocessor(normalize_whitespace)
parser.add_postprocessor(add_metadata)

rule = parse_rule(rule_text, parser=parser)
```

---

## Custom Option Types

### Overview

To add support for new IDS rule options (e.g., a hypothetical "reputation" option), follow these steps:

### Step 1: Define the AST Node

Create a new Pydantic model in your extension module:

```python
from pydantic import Field
from surinort_ast.core.nodes import Option

class ReputationOption(Option):
    """
    Reputation score option for rules.

    Example: reputation:high;
    """
    node_type: str = Field("ReputationOption", frozen=True)
    score: str = Field(..., description="Reputation score (low, medium, high)")

    def __str__(self) -> str:
        return f"reputation:{self.score}"
```

### Step 2: Update the Grammar

If you're extending the grammar, add the new token and rule:

```lark
// In your custom grammar extension
reputation_option: "reputation" ":" REPUTATION_VALUE
REPUTATION_VALUE: "low" | "medium" | "high"
```

### Step 3: Create a Transformer Mixin

```python
from lark import Tree
from surinort_ast.parsing.transformer import RuleTransformer

class ReputationTransformerMixin:
    """Mixin for transforming reputation options."""

    def reputation_option(self, items):
        """Transform reputation option."""
        score = str(items[0])
        return ReputationOption(score=score)
```

### Step 4: Extend the Transformer

```python
class ExtendedRuleTransformer(RuleTransformer, ReputationTransformerMixin):
    """Transformer with custom option support."""
    pass
```

### Step 5: Add Serialization Support

```python
from surinort_ast.printer.text_printer import TextPrinter

class ExtendedTextPrinter(TextPrinter):
    """Printer with custom option support."""

    def print_reputation_option(self, option: ReputationOption) -> str:
        return f"reputation:{option.score}"
```

---

## Custom Serialization Formats

### Overview

Add support for new serialization formats like YAML, TOML, or MessagePack.

### Example: YAML Serializer

```python
import yaml
from typing import Any
from surinort_ast.core.nodes import Rule
from surinort_ast.serialization.json_serializer import to_dict, from_dict

class YAMLSerializer:
    """Serialize rules to/from YAML format."""

    @staticmethod
    def to_yaml(rule: Rule, **kwargs) -> str:
        """
        Serialize rule to YAML.

        Args:
            rule: Rule to serialize
            **kwargs: Additional yaml.dump() arguments

        Returns:
            YAML string
        """
        # Convert to dict using existing JSON serializer
        rule_dict = to_dict(rule)

        # Serialize to YAML
        return yaml.safe_dump(rule_dict, **kwargs)

    @staticmethod
    def from_yaml(data: str | dict) -> Rule:
        """
        Deserialize rule from YAML.

        Args:
            data: YAML string or dict

        Returns:
            Rule instance
        """
        if isinstance(data, str):
            rule_dict = yaml.safe_load(data)
        else:
            rule_dict = data

        # Use existing JSON deserializer
        return from_dict(rule_dict)

# Usage
from surinort_ast.api.parsing import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Serialize to YAML
yaml_str = YAMLSerializer.to_yaml(rule)
print(yaml_str)

# Deserialize from YAML
restored_rule = YAMLSerializer.from_yaml(yaml_str)
```

### Example: MessagePack Serializer

```python
import msgpack
from surinort_ast.core.nodes import Rule
from surinort_ast.serialization.json_serializer import to_dict, from_dict

class MessagePackSerializer:
    """Serialize rules to/from MessagePack format."""

    @staticmethod
    def to_msgpack(rule: Rule) -> bytes:
        """
        Serialize rule to MessagePack.

        Args:
            rule: Rule to serialize

        Returns:
            MessagePack bytes
        """
        rule_dict = to_dict(rule)
        return msgpack.packb(rule_dict, use_bin_type=True)

    @staticmethod
    def from_msgpack(data: bytes) -> Rule:
        """
        Deserialize rule from MessagePack.

        Args:
            data: MessagePack bytes

        Returns:
            Rule instance
        """
        rule_dict = msgpack.unpackb(data, raw=False)
        return from_dict(rule_dict)

# Usage
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Serialize to MessagePack
msgpack_bytes = MessagePackSerializer.to_msgpack(rule)
print(f"MessagePack size: {len(msgpack_bytes)} bytes")

# Deserialize from MessagePack
restored_rule = MessagePackSerializer.from_msgpack(msgpack_bytes)
```

---

## Custom Analyzers

### Overview

Create custom analyzers for rule inspection and metrics collection.

### Example: Security Impact Analyzer

```python
from dataclasses import dataclass
from surinort_ast.core.nodes import Rule
from surinort_ast.core.visitor import Visitor

@dataclass
class SecurityImpact:
    """Security impact assessment."""
    severity: str
    exploitability: str
    attack_surface: str
    detection_confidence: str

class SecurityImpactAnalyzer(Visitor):
    """Analyze security impact of rules."""

    def analyze(self, rule: Rule) -> SecurityImpact:
        """
        Analyze rule for security impact.

        Args:
            rule: Rule to analyze

        Returns:
            SecurityImpact assessment
        """
        # Determine severity from classtype
        severity = self._assess_severity(rule)

        # Determine exploitability from protocol and ports
        exploitability = self._assess_exploitability(rule)

        # Determine attack surface
        attack_surface = self._assess_attack_surface(rule)

        # Determine detection confidence
        confidence = self._assess_confidence(rule)

        return SecurityImpact(
            severity=severity,
            exploitability=exploitability,
            attack_surface=attack_surface,
            detection_confidence=confidence
        )

    def _assess_severity(self, rule: Rule) -> str:
        """Assess severity based on classtype and metadata."""
        classtype_option = next(
            (opt for opt in rule.options if opt.node_type == "ClasstypeOption"),
            None
        )

        if not classtype_option:
            return "unknown"

        critical_classes = ["trojan-activity", "exploit-kit", "malware-cnc"]
        high_classes = ["web-application-attack", "attempted-admin"]

        if classtype_option.classtype in critical_classes:
            return "critical"
        elif classtype_option.classtype in high_classes:
            return "high"
        else:
            return "medium"

    def _assess_exploitability(self, rule: Rule) -> str:
        """Assess exploitability based on protocol and direction."""
        if rule.header.direction.value == "->":
            return "outbound"
        else:
            return "inbound"

    def _assess_attack_surface(self, rule: Rule) -> str:
        """Assess attack surface."""
        # Simplified example
        return "internet"

    def _assess_confidence(self, rule: Rule) -> str:
        """Assess detection confidence."""
        # Count detection options
        pcre_count = sum(1 for opt in rule.options if opt.node_type == "PcreOption")
        content_count = sum(1 for opt in rule.options if opt.node_type == "ContentOption")

        if pcre_count >= 2 or content_count >= 3:
            return "high"
        elif pcre_count >= 1 or content_count >= 2:
            return "medium"
        else:
            return "low"

# Usage
from surinort_ast.api.parsing import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; classtype:trojan-activity; sid:1;)')
analyzer = SecurityImpactAnalyzer()
impact = analyzer.analyze(rule)
print(f"Severity: {impact.severity}, Confidence: {impact.detection_confidence}")
```

---

## Plugin Development

### Overview

Create plugins that can be discovered and loaded dynamically.

### Step 1: Define Plugin Interface

```python
from abc import ABC, abstractmethod
from surinort_ast.core.nodes import Rule

class ParserPlugin(ABC):
    """Base class for parser plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass

    @abstractmethod
    def process(self, rule: Rule) -> Rule:
        """Process a parsed rule."""
        pass
```

### Step 2: Implement Plugin

```python
class CustomMetadataPlugin(ParserPlugin):
    """Plugin that adds custom metadata to rules."""

    @property
    def name(self) -> str:
        return "custom_metadata"

    def process(self, rule: Rule) -> Rule:
        """Add custom metadata to rule."""
        # Example: add processing timestamp
        from datetime import datetime

        # Note: In real implementation, you'd create a new MetadataOption
        # and append it to rule.options
        return rule
```

### Step 3: Plugin Registry

```python
class PluginRegistry:
    """Registry for parser plugins."""

    def __init__(self):
        self._plugins: dict[str, ParserPlugin] = {}

    def register(self, plugin: ParserPlugin) -> None:
        """Register a plugin."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> ParserPlugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def apply_all(self, rule: Rule) -> Rule:
        """Apply all registered plugins to a rule."""
        for plugin in self._plugins.values():
            rule = plugin.process(rule)
        return rule

# Usage
registry = PluginRegistry()
registry.register(CustomMetadataPlugin())

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
rule = registry.apply_all(rule)
```

---

## Best Practices

### Parser Extensions

1. **Wrap, Don't Replace**: Wrap LarkRuleParser instead of replacing it
2. **Validate Early**: Add validation in custom parsers before expensive operations
3. **Preserve Immutability**: Use `model_copy(update={...})` for modifications
4. **Document Behavior**: Clearly document custom parser behavior and requirements

### Custom Options

1. **Follow Naming Conventions**: Use CapitalizedCamelCase for option class names
2. **Include node_type**: Always set node_type field for serialization
3. **Implement __str__**: Provide string representation for text printing
4. **Add Examples**: Document option syntax with examples

### Serialization

1. **Reuse Existing Logic**: Leverage JSON serializer's to_dict/from_dict
2. **Handle Errors Gracefully**: Catch serialization errors and provide context
3. **Test Roundtrips**: Verify serialize -> deserialize produces identical AST
4. **Document Format**: Provide format specification and examples

### Analyzers

1. **Use Visitor Pattern**: Extend Visitor for tree traversal
2. **Keep Stateless**: Make analyzers stateless for thread safety
3. **Return Structured Data**: Use dataclasses for analysis results
4. **Provide Metrics**: Include quantitative metrics in analysis

### Plugins

1. **Define Clear Interface**: Use ABC to enforce plugin contract
2. **Enable Discovery**: Support entry points for automatic discovery
3. **Version Compatibility**: Document compatible surinort-ast versions
4. **Test Isolation**: Ensure plugins don't interfere with each other

---

## Additional Resources

- [API Guide](API_GUIDE.md) - Complete API reference
- [Migration Guide](MIGRATION_GUIDE.md) - Upgrading from deprecated APIs
- [Examples](../examples/) - Working code examples
- [Source Code](../src/surinort_ast/) - Implementation reference

---

## Support

For questions or issues with extensions:

- GitHub Issues: https://github.com/seifreed/surinort-ast/issues
- Discussions: https://github.com/seifreed/surinort-ast/discussions
- Email: mriverolopez@gmail.com
