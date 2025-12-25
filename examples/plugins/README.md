# Example Plugins

This directory contains example plugins demonstrating how to extend surinort-ast with custom functionality.

## Available Example Plugins

### 1. YAML Serializer Plugin

**File**: `yaml_serializer_plugin.py`

**Description**: Serializes IDS rules to YAML format and deserializes YAML back to Rule objects.

**Dependencies**: `pyyaml`

**Installation**:
```bash
pip install pyyaml
```

**Usage**:
```python
from surinort_ast.plugins import get_registry
from surinort_ast.parsing import parse_rule

# Import plugin (auto-registers)
import sys
sys.path.insert(0, "examples/plugins")
import yaml_serializer_plugin

# Get plugin from registry
registry = get_registry()
yaml_plugin = registry.get_serializer("yaml")

# Use plugin
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
yaml_data = yaml_plugin.serialize(rule)
print(yaml_data)

# Deserialize
reconstructed = yaml_plugin.deserialize(yaml_data)
```

**CLI Usage**:
```bash
# Load plugin from directory
surinort plugins load examples/plugins

# List plugins
surinort plugins list

# Verify it's loaded
surinort plugins info yaml --type serializer
```

### 2. Security Analyzer Plugin

**File**: `security_analyzer_plugin.py`

**Description**: Analyzes IDS rules for security issues and performance problems.

**Features**:
- Detects overly broad rules (any/any)
- Identifies missing fast_pattern optimization
- Flags PCRE without content anchor
- Checks for missing metadata
- Validates threshold settings

**Usage**:
```python
from surinort_ast.plugins import get_registry
from surinort_ast.parsing import parse_rule

# Import plugin (auto-registers)
import sys
sys.path.insert(0, "examples/plugins")
import security_analyzer_plugin

# Get plugin from registry
registry = get_registry()
analyzer = registry.get_analyzer("security_auditor")

# Analyze rule
rule = parse_rule('alert tcp any any -> any any (msg:"Test"; sid:1;)')
results = analyzer.analyze(rule)

print(f"Score: {results['score']}")
for issue in results['issues']:
    print(f"[{issue['severity']}] {issue['message']}")
```

**CLI Usage**:
```bash
# Load plugin
surinort plugins load examples/plugins

# Analyze rules
surinort plugins analyze rules.rules --analyzer security_auditor

# Save results to JSON
surinort plugins analyze rules.rules -a security_auditor -o results.json
```

## Creating Your Own Plugin

See [Plugin Development Guide](../../docs/PLUGIN_DEVELOPMENT.md) for detailed instructions on creating custom plugins.

### Quick Start

1. Choose plugin type (Parser, Serializer, Analyzer, or Query)
2. Extend appropriate base class
3. Implement required methods
4. Register plugin with registry

**Example - Simple Analyzer**:

```python
from surinort_ast.plugins import AnalysisPlugin, get_registry

class MyAnalyzer(AnalysisPlugin):
    @property
    def name(self):
        return "my_analyzer"

    @property
    def version(self):
        return "1.0.0"

    def analyze(self, rule):
        return {"score": 100, "issues": []}

    def register(self, registry):
        registry.register_analyzer(self.name, self)

# Register plugin
plugin = MyAnalyzer()
plugin.register(get_registry())
```

## Plugin Testing

Test your plugins with pytest:

```python
import pytest
from surinort_ast.parsing import parse_rule
from your_plugin import YourPlugin

def test_plugin():
    plugin = YourPlugin()
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    # Test serialization
    data = plugin.serialize(rule)
    assert data is not None

    # Test roundtrip
    reconstructed = plugin.deserialize(data)
    assert reconstructed.action == rule.action
```

## Publishing Plugins

To publish your plugin to PyPI:

1. Create package structure:
   ```
   surinort-myplugin/
   ├── pyproject.toml
   ├── README.md
   └── src/
       └── surinort_myplugin/
           ├── __init__.py
           └── plugin.py
   ```

2. Define entry point in `pyproject.toml`:
   ```toml
   [project.entry-points."surinort_ast.plugins"]
   myplugin = "surinort_myplugin.plugin:MyPlugin"
   ```

3. Build and publish:
   ```bash
   python -m build
   twine upload dist/*
   ```

4. Users install with:
   ```bash
   pip install surinort-myplugin
   ```

## License

All example plugins are released under GNU General Public License v3.0.

**Author**: Marc Rivero López
**Email**: mriverolopez@gmail.com

## Resources

- [Plugin Architecture Documentation](../../docs/PLUGIN_ARCHITECTURE.md)
- [Plugin Development Guide](../../docs/PLUGIN_DEVELOPMENT.md)
- [API Reference](../../docs/API_REFERENCE.md)
- [Main Repository](https://github.com/seifreed/surinort-ast)
