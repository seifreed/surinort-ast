# Plugin Development Guide

**Version**: 1.0.0
**License**: GNU General Public License v3.0
**Author**: Marc Rivero López

## Table of Contents

1. [Introduction](#introduction)
2. [Plugin Types](#plugin-types)
3. [Creating Your First Plugin](#creating-your-first-plugin)
4. [Plugin Registration](#plugin-registration)
5. [Testing Plugins](#testing-plugins)
6. [Publishing Plugins](#publishing-plugins-to-pypi)
7. [Best Practices](#best-practices)
8. [Advanced Topics](#advanced-topics)

## Introduction

This guide walks you through creating, testing, and publishing surinort-ast plugins. Plugins extend surinort-ast with custom parsers, serializers, analyzers, and query capabilities.

## Plugin Types

Surinort-ast supports four plugin types:

### 1. Parser Plugins

Extend parsing capabilities with custom dialects or alternative parsers.

**Interface**: `ParserPlugin`

**Required Methods**:
- `create_parser(config) -> IParser`

### 2. Serializer Plugins

Add support for additional serialization formats.

**Interface**: `SerializerPlugin`

**Required Methods**:
- `get_format_name() -> str`
- `serialize(rule: Rule) -> str | bytes`
- `deserialize(data: str | bytes) -> Rule`

### 3. Analysis Plugins

Perform static analysis, validation, and optimization.

**Interface**: `AnalysisPlugin`

**Required Methods**:
- `analyze(rule: Rule) -> dict[str, Any]`

### 4. Query Plugins

Extend query system with custom selectors.

**Interface**: `QueryPlugin`

**Required Methods**:
- `get_selector_type() -> str`
- `create_selector(query: str) -> Any`

## Creating Your First Plugin

Let's create a TOML serializer plugin step by step.

### Step 1: Project Structure

Create a new Python package:

```
surinort-toml/
├── pyproject.toml
├── README.md
├── LICENSE
└── src/
    └── surinort_toml/
        ├── __init__.py
        └── plugin.py
```

### Step 2: Define Plugin Class

Create `src/surinort_toml/plugin.py`:

```python
"""TOML serializer plugin for surinort-ast."""

from surinort_ast.plugins import SerializerPlugin, get_registry
from surinort_ast.core.nodes import Rule


class TOMLSerializerPlugin(SerializerPlugin):
    """Serialize IDS rules to TOML format."""

    @property
    def name(self) -> str:
        return "toml_serializer"

    @property
    def version(self) -> str:
        return "1.0.0"

    def get_format_name(self) -> str:
        return "toml"

    def serialize(self, rule: Rule) -> str:
        """Serialize rule to TOML."""
        try:
            import tomli_w
        except ImportError as e:
            raise ImportError(
                "tomli-w is required for TOML serialization. "
                "Install with: pip install tomli-w"
            ) from e

        rule_dict = rule.model_dump(mode="python")
        return tomli_w.dumps(rule_dict)

    def deserialize(self, data: str) -> Rule:
        """Deserialize TOML to rule."""
        try:
            import tomli
        except ImportError as e:
            raise ImportError(
                "tomli is required for TOML deserialization. "
                "Install with: pip install tomli"
            ) from e

        rule_dict = tomli.loads(data)
        return Rule.model_validate(rule_dict)

    def register(self, registry):
        """Register with plugin registry."""
        registry.register_serializer(self.get_format_name(), self)
```

### Step 3: Package Initialization

Create `src/surinort_toml/__init__.py`:

```python
"""TOML serializer plugin for surinort-ast."""

from .plugin import TOMLSerializerPlugin

__version__ = "1.0.0"
__all__ = ["TOMLSerializerPlugin"]
```

### Step 4: Configure pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "surinort-toml"
version = "1.0.0"
description = "TOML serialization plugin for surinort-ast"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "GPL-3.0-or-later" }
authors = [
    { name = "Your Name", email = "your.email@example.com" }
]
dependencies = [
    "surinort-ast>=1.0.0",
    "tomli>=2.0.0",
    "tomli-w>=1.0.0",
]

# Entry point for plugin discovery
[project.entry-points."surinort_ast.plugins"]
toml = "surinort_toml.plugin:TOMLSerializerPlugin"

[project.urls]
Homepage = "https://github.com/yourname/surinort-toml"
Repository = "https://github.com/yourname/surinort-toml"
```

## Plugin Registration

Plugins can be registered in three ways:

### 1. Entry Points (Recommended)

Define in `pyproject.toml`:

```toml
[project.entry-points."surinort_ast.plugins"]
toml = "surinort_toml.plugin:TOMLSerializerPlugin"
```

Plugins auto-load when surinort-ast imports:

```python
from surinort_ast.plugins import get_registry

# Entry point plugins automatically loaded
registry = get_registry()
toml_plugin = registry.get_serializer("toml")
```

### 2. Manual Registration

```python
from surinort_ast.plugins import get_registry
from surinort_toml import TOMLSerializerPlugin

plugin = TOMLSerializerPlugin()
registry = get_registry()
registry.register_serializer("toml", plugin)
```

### 3. Auto-registration on Import

In your plugin module:

```python
# At end of plugin.py
from surinort_ast.plugins import get_registry

_plugin = TOMLSerializerPlugin()
_plugin.register(get_registry())
```

Then users can simply import:

```python
import surinort_toml  # Auto-registers
```

## Testing Plugins

### Unit Tests

Create `tests/test_toml_plugin.py`:

```python
import pytest
from surinort_ast.parsing import parse_rule
from surinort_toml import TOMLSerializerPlugin


class TestTOMLPlugin:
    """Test TOML serializer plugin."""

    def test_serialization_roundtrip(self):
        """Test serialize -> deserialize roundtrip."""
        # Parse a rule
        rule = parse_rule(
            'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'
        )

        # Serialize
        plugin = TOMLSerializerPlugin()
        toml_data = plugin.serialize(rule)

        # Deserialize
        reconstructed = plugin.deserialize(toml_data)

        # Verify
        assert reconstructed.action == rule.action
        assert reconstructed.header.protocol == rule.header.protocol
        assert len(reconstructed.options) == len(rule.options)

    def test_serialize_format(self):
        """Test TOML output format."""
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        plugin = TOMLSerializerPlugin()
        toml_data = plugin.serialize(rule)

        # Verify it's valid TOML
        assert 'action = "alert"' in toml_data
        assert '[header]' in toml_data

    def test_registration(self):
        """Test plugin registration."""
        from surinort_ast.plugins import get_registry, reset_registry

        # Reset for clean test
        reset_registry()

        # Register plugin
        plugin = TOMLSerializerPlugin()
        registry = get_registry()
        plugin.register(registry)

        # Verify registration
        retrieved = registry.get_serializer("toml")
        assert retrieved is plugin

    def test_missing_dependency(self, monkeypatch):
        """Test graceful handling of missing dependencies."""
        # Mock missing tomli
        import sys
        monkeypatch.setitem(sys.modules, 'tomli', None)

        plugin = TOMLSerializerPlugin()
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        with pytest.raises(ImportError, match="tomli is required"):
            plugin.deserialize("invalid")
```

### Integration Tests

```python
def test_cli_integration(tmp_path):
    """Test plugin works with CLI."""
    import subprocess

    # Create test rule file
    rule_file = tmp_path / "test.rules"
    rule_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    # Convert to TOML using CLI
    output_file = tmp_path / "output.toml"
    result = subprocess.run(
        ["surinort", "to-toml", str(rule_file), "-o", str(output_file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()
```

### Property-Based Testing

```python
from hypothesis import given, strategies as st
from surinort_ast.parsing import parse_rule

@given(st.integers(min_value=1, max_value=65535))
def test_port_serialization(port):
    """Test serialization with various ports."""
    rule = parse_rule(f'alert tcp any any -> any {port} (msg:"Test"; sid:1;)')

    plugin = TOMLSerializerPlugin()
    toml_data = plugin.serialize(rule)
    reconstructed = plugin.deserialize(toml_data)

    assert reconstructed.header.dst_port.value == port
```

## Publishing Plugins to PyPI

### Step 1: Prepare Package

Ensure your package has:

- ✅ `pyproject.toml` with metadata
- ✅ `README.md` with usage examples
- ✅ `LICENSE` file (GPL-3.0 compatible)
- ✅ Tests with >80% coverage
- ✅ Documentation

### Step 2: Build Package

```bash
# Install build tools
pip install build twine

# Build distribution
python -m build

# This creates:
# dist/surinort_toml-1.0.0-py3-none-any.whl
# dist/surinort_toml-1.0.0.tar.gz
```

### Step 3: Publish to PyPI

```bash
# Upload to Test PyPI first
twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ surinort-toml

# If everything works, upload to production PyPI
twine upload dist/*
```

### Step 4: Installation

Users install with:

```bash
pip install surinort-toml
```

Plugin auto-loads via entry point:

```python
from surinort_ast.plugins import get_registry

registry = get_registry()
toml = registry.get_serializer("toml")  # Available!
```

## Best Practices

### 1. Naming Conventions

- **Package names**: `surinort-{feature}` (e.g., `surinort-yaml`, `surinort-security`)
- **Plugin classes**: `{Feature}Plugin` (e.g., `YAMLSerializerPlugin`)
- **Entry point keys**: Descriptive lowercase (e.g., `yaml_serializer`)

### 2. Error Handling

Always provide helpful error messages:

```python
def serialize(self, rule: Rule) -> str:
    try:
        import yaml
    except ImportError as e:
        raise ImportError(
            "pyyaml is required for YAML serialization.\n"
            "Install with: pip install pyyaml"
        ) from e

    try:
        return yaml.dump(rule.model_dump())
    except Exception as e:
        raise RuntimeError(f"YAML serialization failed: {e}") from e
```

### 3. Version Compatibility

Declare compatible surinort-ast versions:

```python
class MyPlugin(SerializerPlugin):
    REQUIRES_SURINORT = ">=1.0.0,<2.0.0"

    def register(self, registry):
        # Check version compatibility
        import surinort_ast
        from packaging.version import parse

        version = parse(surinort_ast.__version__)
        if not (parse("1.0.0") <= version < parse("2.0.0")):
            raise PluginVersionError(
                f"Plugin requires surinort-ast {self.REQUIRES_SURINORT}, "
                f"got {surinort_ast.__version__}"
            )

        registry.register_serializer(self.get_format_name(), self)
```

### 4. Documentation

Document all public methods with docstrings:

```python
def serialize(self, rule: Rule) -> str:
    """
    Serialize Rule to YAML format.

    Args:
        rule: Rule AST node to serialize

    Returns:
        YAML string representation

    Raises:
        ImportError: If pyyaml is not installed
        SerializationError: If serialization fails

    Example:
        >>> yaml_data = plugin.serialize(rule)
        >>> print(yaml_data)
        action: alert
        header:
          protocol: tcp
          ...
    """
```

### 5. Thread Safety

Make plugins thread-safe:

```python
import threading

class MyAnalyzer(AnalysisPlugin):
    def __init__(self):
        self._lock = threading.Lock()
        self._cache = {}

    def analyze(self, rule: Rule) -> dict:
        with self._lock:
            # Thread-safe analysis
            return self._analyze_impl(rule)
```

### 6. Resource Management

Use context managers for resources:

```python
def serialize_to_file(self, rule: Rule, path: Path) -> None:
    """Serialize rule to file."""
    with open(path, 'w') as f:
        yaml.dump(rule.model_dump(), f)
```

### 7. Logging

Use standard logging:

```python
import logging

logger = logging.getLogger(__name__)

class MyPlugin(SerializerPlugin):
    def serialize(self, rule: Rule) -> str:
        logger.debug(f"Serializing rule with SID {self._get_sid(rule)}")
        # ...
        logger.info("Serialization complete")
        return result
```

## Advanced Topics

### Custom Configuration

Support plugin-specific configuration:

```python
class ConfigurablePlugin(AnalysisPlugin):
    def __init__(self, config_path: Path | None = None):
        if config_path:
            self.config = self._load_config(config_path)
        else:
            self.config = self._default_config()

    def _load_config(self, path: Path) -> dict:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)

    def _default_config(self) -> dict:
        return {
            'severity_threshold': 'medium',
            'enable_performance_checks': True,
        }
```

### Plugin Composition

Compose multiple plugins:

```python
class CompressedYAMLSerializer(SerializerPlugin):
    """YAML serializer with gzip compression."""

    def __init__(self):
        self.yaml_serializer = YAMLSerializerPlugin()

    def serialize(self, rule: Rule) -> bytes:
        import gzip

        # First serialize to YAML
        yaml_data = self.yaml_serializer.serialize(rule)

        # Then compress
        return gzip.compress(yaml_data.encode('utf-8'))

    def deserialize(self, data: bytes) -> Rule:
        import gzip

        # Decompress
        yaml_data = gzip.decompress(data).decode('utf-8')

        # Deserialize YAML
        return self.yaml_serializer.deserialize(yaml_data)
```

### Async Plugins

Support async analysis:

```python
import asyncio

class AsyncAnalyzer(AnalysisPlugin):
    async def analyze_async(self, rule: Rule) -> dict:
        """Async analysis for I/O-bound operations."""
        # Perform async operations
        results = await self._fetch_threat_intel(rule)
        return results

    def analyze(self, rule: Rule) -> dict:
        """Sync wrapper for async analysis."""
        return asyncio.run(self.analyze_async(rule))
```

### Caching Results

Implement result caching:

```python
from functools import lru_cache
import hashlib

class CachedAnalyzer(AnalysisPlugin):
    @lru_cache(maxsize=1000)
    def analyze(self, rule: Rule) -> dict:
        # Cache based on rule hash
        return self._analyze_impl(rule)

    def _rule_hash(self, rule: Rule) -> str:
        """Create hash of rule for caching."""
        rule_bytes = rule.model_dump_json().encode()
        return hashlib.sha256(rule_bytes).hexdigest()
```

## License

All plugin code should be compatible with GPLv3. Include license header:

```python
"""
TOML Serializer Plugin for surinort-ast

Licensed under GNU General Public License v3.0
Author: Your Name | @username | your.email@example.com
"""
```

## Resources

- [Plugin Architecture Documentation](./PLUGIN_ARCHITECTURE.md)
- [API Reference](./API_REFERENCE.md)
- [Example Plugins](../examples/plugins/)
- [Surinort-AST GitHub](https://github.com/seifreed/surinort-ast)

## Support

For plugin development help:

- GitHub Discussions: https://github.com/seifreed/surinort-ast/discussions
- Issues: https://github.com/seifreed/surinort-ast/issues
- Email: mriverolopez@gmail.com

## Changelog

### v1.0.0 (2025-12-25)
- Initial plugin development guide
- Examples for all plugin types
- Testing guidelines
- Publishing workflow
- Best practices and advanced topics
