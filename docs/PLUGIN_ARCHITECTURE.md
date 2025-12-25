# Plugin Architecture

**Version**: 1.0.0
**License**: GNU General Public License v3.0
**Author**: Marc Rivero López

## Overview

The Surinort-AST plugin system provides a robust, type-safe extensibility framework for extending parser, serialization, analysis, and query capabilities. The architecture follows strict separation of concerns with Protocol-based interfaces and a centralized registry pattern.

## Design Principles

### 1. Type Safety
All plugin interfaces use Python Protocols and ABCs to enforce structural and behavioral contracts. This ensures compile-time type checking with mypy and runtime validation.

### 2. Decoupling
Plugins are discovered and loaded dynamically through entry points or directory scanning. Core library code has zero knowledge of specific plugins, maintaining clean architecture boundaries.

### 3. Composability
Plugins can be combined and chained. For example, a compression plugin can wrap a serialization plugin, or multiple analyzer plugins can run in sequence.

### 4. Backward Compatibility
The plugin system is additive-only. Core APIs remain stable, and plugins extend functionality without modifying existing interfaces.

### 5. Security
Plugins are sandboxed with resource limits. Malicious or poorly written plugins cannot compromise the core parser or other plugins.

## Plugin Types

### A. Parser Plugins

Parser plugins extend parsing capabilities with custom implementations, middleware, or dialect-specific extensions.

**Use Cases**:
- Custom IDS dialects (e.g., proprietary formats)
- Parser middleware for preprocessing rules
- Alternative parsing backends (e.g., tree-sitter, ANTLR)
- Performance-optimized parsers for specific workloads

**Interface**: `ParserPlugin`

**Capabilities**:
- Create custom parser instances implementing `IParser` protocol
- Register dialect-specific transformers
- Provide parser configuration overrides

**Example**:
```python
from surinort_ast.plugins import ParserPlugin
from surinort_ast.parsing.protocols import IParser

class CustomDialectParser(ParserPlugin):
    def create_parser(self, config):
        return MyCustomParser(config)
```

### B. Serialization Plugins

Serialization plugins add support for additional data formats beyond JSON.

**Use Cases**:
- YAML serialization for human-readable config
- TOML format for configuration files
- MessagePack for binary efficiency
- Protocol Buffers for cross-language compatibility
- Compression plugins (gzip, brotli, zstd)
- Encryption plugins for sensitive rules

**Interface**: `SerializerPlugin`

**Capabilities**:
- Bidirectional serialization (serialize/deserialize)
- Format detection and validation
- Streaming support for large rulesets
- Custom encoding options

**Example**:
```python
from surinort_ast.plugins import SerializerPlugin

class YAMLSerializer(SerializerPlugin):
    def get_format_name(self) -> str:
        return "yaml"

    def serialize(self, rule: Rule) -> str:
        import yaml
        return yaml.dump(rule.model_dump())

    def deserialize(self, data: str) -> Rule:
        import yaml
        return Rule.model_validate(yaml.safe_load(data))
```

### C. Analysis Plugins

Analysis plugins perform static analysis, optimization, and validation on parsed rules.

**Use Cases**:
- Security auditing (detect overly permissive rules)
- Performance analysis (identify inefficient patterns)
- Coverage analysis (find gaps in rule coverage)
- Optimization recommendations
- Custom linting and validation
- Rule complexity metrics

**Interface**: `AnalysisPlugin`

**Capabilities**:
- Analyze individual rules or entire rulesets
- Return structured analysis results
- Support incremental analysis
- Generate reports and visualizations

**Example**:
```python
from surinort_ast.plugins import AnalysisPlugin

class SecurityAuditor(AnalysisPlugin):
    def analyze(self, rule: Rule) -> dict:
        issues = []
        if self._is_too_broad(rule):
            issues.append({
                'severity': 'high',
                'message': 'Rule matches too broadly'
            })
        return {'issues': issues}
```

### D. Query Plugins

Query plugins extend the query system with custom selectors, optimizations, and indexing strategies.

**Use Cases**:
- Custom selector types (e.g., regex-based selectors)
- Query optimization strategies
- Index providers for large rulesets
- Caching strategies
- Distributed query execution

**Interface**: `QueryPlugin`

**Capabilities**:
- Register custom selector types
- Provide query optimization hints
- Implement custom indexing
- Cache query results

## Architecture Components

### 1. Plugin Interface Layer

**Location**: `/src/surinort_ast/plugins/interface.py`

Defines base protocols and abstract classes for all plugin types:

```python
# Base protocol - all plugins must implement
class SurinortPlugin(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def register(self, registry: PluginRegistry) -> None: ...

# Type-specific ABCs
class ParserPlugin(ABC): ...
class SerializerPlugin(ABC): ...
class AnalysisPlugin(ABC): ...
class QueryPlugin(ABC): ...
```

### 2. Plugin Registry

**Location**: `/src/surinort_ast/plugins/registry.py`

Centralized registry for plugin discovery and management:

```python
class PluginRegistry:
    def register_parser(name: str, plugin: ParserPlugin)
    def register_serializer(format_name: str, plugin: SerializerPlugin)
    def register_analyzer(name: str, plugin: AnalysisPlugin)
    def register_query(name: str, plugin: QueryPlugin)

    def get_parser(name: str) -> ParserPlugin | None
    def get_serializer(format_name: str) -> SerializerPlugin | None
    def get_analyzer(name: str) -> AnalysisPlugin | None
    def list_plugins() -> dict[str, list[str]]
```

Features:
- Thread-safe registration
- Name collision detection
- Version compatibility checking
- Plugin dependency resolution

### 3. Plugin Loader

**Location**: `/src/surinort_ast/plugins/loader.py`

Dynamic plugin discovery and loading:

```python
class PluginLoader:
    def load_entry_points(group: str = "surinort_ast.plugins")
    def load_directory(plugin_dir: Path)
    def load_plugin(plugin_path: Path)
    def validate_plugin(plugin: Any) -> bool
```

Features:
- Entry point-based discovery (recommended)
- Directory scanning for development
- Lazy loading for performance
- Error isolation (failing plugins don't crash loader)
- Circular dependency detection

### 4. Plugin Lifecycle

```
┌─────────────────────────────────────────┐
│  1. Discovery                           │
│     - Scan entry points                 │
│     - Scan plugin directories           │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  2. Loading                             │
│     - Import plugin module              │
│     - Instantiate plugin class          │
│     - Validate interface compliance     │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  3. Registration                        │
│     - Call plugin.register(registry)    │
│     - Store in appropriate registry     │
│     - Check version compatibility       │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  4. Activation                          │
│     - Plugin ready for use              │
│     - Accessible via registry           │
└─────────────────────────────────────────┘
```

## Plugin Discovery

### Method 1: Entry Points (Recommended)

Define plugins in `pyproject.toml`:

```toml
[project.entry-points."surinort_ast.plugins"]
yaml_serializer = "surinort_yaml:YAMLSerializerPlugin"
security_auditor = "surinort_security:SecurityAuditorPlugin"
```

Plugins are auto-discovered on import:

```python
from surinort_ast.plugins import get_registry

# Automatically loads all entry point plugins
registry = get_registry()
yaml_plugin = registry.get_serializer("yaml")
```

### Method 2: Directory Loading (Development)

```python
from surinort_ast.plugins import PluginLoader

loader = PluginLoader()
loader.load_directory(Path("./local_plugins"))
```

### Method 3: Manual Registration

```python
from surinort_ast.plugins import get_registry
from my_plugin import MyPlugin

plugin = MyPlugin()
get_registry().register_analyzer("my_analyzer", plugin)
```

## Plugin Configuration

Plugins can accept configuration via:

### 1. Constructor Arguments

```python
class MyPlugin(SerializerPlugin):
    def __init__(self, indent: int = 2, sort_keys: bool = True):
        self.indent = indent
        self.sort_keys = sort_keys
```

### 2. Configuration Files

```yaml
# ~/.surinort/plugins.yaml
plugins:
  yaml_serializer:
    indent: 4
    sort_keys: true
  security_auditor:
    severity_threshold: "medium"
```

### 3. Environment Variables

```python
import os

class MyPlugin(AnalysisPlugin):
    def __init__(self):
        self.threshold = int(os.getenv("SURINORT_THRESHOLD", "10"))
```

## Security Considerations

### 1. Code Signing
Production deployments should verify plugin signatures before loading.

### 2. Sandboxing
Plugins run with resource limits:
- Memory limit: 512 MB per plugin
- CPU time: 30 seconds per operation
- File system access: Read-only by default

### 3. Capability System
Plugins declare required capabilities:

```python
class MyPlugin(SerializerPlugin):
    REQUIRED_CAPABILITIES = ["network.http", "filesystem.read"]
```

### 4. Audit Logging
All plugin operations are logged for security auditing.

## Performance Optimization

### 1. Lazy Loading
Plugins are loaded only when first accessed:

```python
# Registry implements lazy loading
serializer = registry.get_serializer("yaml")  # Loaded on first access
```

### 2. Caching
Plugin results can be cached:

```python
from surinort_ast.plugins import cached_plugin

@cached_plugin
class MyAnalyzer(AnalysisPlugin):
    def analyze(self, rule: Rule) -> dict:
        # Results cached by rule hash
        return perform_expensive_analysis(rule)
```

### 3. Parallel Execution
Analysis plugins can execute in parallel:

```python
from surinort_ast.plugins import parallel_analyze

results = parallel_analyze(
    rules=ruleset,
    analyzers=["security", "performance", "coverage"],
    max_workers=4
)
```

## Testing Plugins

### Unit Testing

```python
import pytest
from surinort_ast.plugins.testing import PluginTestCase

class TestMyPlugin(PluginTestCase):
    def test_serialization(self):
        plugin = YAMLSerializerPlugin()
        rule = self.create_test_rule()

        # Serialize
        yaml_data = plugin.serialize(rule)

        # Deserialize
        reconstructed = plugin.deserialize(yaml_data)

        assert reconstructed == rule
```

### Integration Testing

```python
def test_plugin_integration():
    from surinort_ast.plugins import get_registry

    registry = get_registry()
    plugin = registry.get_serializer("yaml")

    assert plugin is not None
    assert plugin.get_format_name() == "yaml"
```

## Plugin Distribution

### PyPI Distribution

1. Create plugin package:
```
surinort-yaml/
├── pyproject.toml
├── src/
│   └── surinort_yaml/
│       ├── __init__.py
│       └── plugin.py
```

2. Define entry point in `pyproject.toml`:
```toml
[project.entry-points."surinort_ast.plugins"]
yaml = "surinort_yaml.plugin:YAMLSerializerPlugin"
```

3. Publish to PyPI:
```bash
python -m build
twine upload dist/*
```

4. Install plugin:
```bash
pip install surinort-yaml
```

### Private Distribution

For internal plugins, use private PyPI server or direct installation:

```bash
pip install git+https://github.com/myorg/surinort-custom-plugin
```

## Best Practices

### 1. Naming Conventions
- Plugin packages: `surinort-{name}`
- Plugin classes: `{Name}Plugin`
- Entry point keys: descriptive names (e.g., `yaml_serializer`)

### 2. Versioning
Follow semantic versioning and declare compatible surinort-ast versions:

```python
class MyPlugin(SerializerPlugin):
    VERSION = "1.2.3"
    REQUIRES_SURINORT = ">=1.0.0,<2.0.0"
```

### 3. Error Handling
Plugins should never crash the host application:

```python
def serialize(self, rule: Rule) -> str:
    try:
        return self._do_serialize(rule)
    except Exception as e:
        logger.error(f"Serialization failed: {e}")
        raise PluginError(f"Failed to serialize: {e}") from e
```

### 4. Documentation
All plugins must include:
- README with installation instructions
- API documentation
- Usage examples
- Changelog

### 5. Testing
Minimum test coverage: 80%
Required tests:
- Unit tests for all public methods
- Integration tests with surinort-ast
- Performance benchmarks

## Migration Path

### From Built-in to Plugin

If functionality is moved from core to plugin:

1. Deprecate core functionality with clear migration path
2. Provide automatic plugin installation
3. Maintain backward compatibility for 2 major versions

Example:
```python
# surinort_ast/serialization/yaml.py (deprecated)
import warnings

def serialize_to_yaml(rule: Rule) -> str:
    warnings.warn(
        "Built-in YAML serialization is deprecated. "
        "Install surinort-yaml plugin: pip install surinort-yaml",
        DeprecationWarning,
        stacklevel=2
    )
    # Fallback implementation
```

## License

All plugin architecture components are released under GNU General Public License v3.0.

**Author**: Marc Rivero López
**Copyright**: (c) 2025 Marc Rivero López

Third-party plugins may use different licenses but must be compatible with GPLv3 if they link to surinort-ast.

## References

- [Plugin Development Guide](./PLUGIN_DEVELOPMENT.md)
- [API Reference](./API_REFERENCE.md)
- [Example Plugins](../examples/plugins/)

## Changelog

### v1.0.0 (2025-12-25)
- Initial plugin architecture design
- Support for Parser, Serializer, Analysis, and Query plugins
- Entry point-based discovery
- Type-safe interfaces with Protocols
- Security sandboxing and resource limits
