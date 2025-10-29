# Documentation Structure Overview

Complete documentation structure for the `surisnort-ast` project.

---

## Documentation Files Structure

```
surisnort-ast/
│
├── README.md                           # Main project documentation
├── ARCHITECTURE.md                     # System architecture and design decisions
├── GRAMMAR.md                          # Complete EBNF grammar specification
├── AST_SPEC.md                         # AST specification with JSON Schema
├── API_REFERENCE.md                    # Complete API reference
├── CONTRIBUTING.md                     # Contribution guidelines
├── CHANGELOG.md                        # Version history and release notes
├── LICENSE                             # GPLv3 license text
├── pyproject.toml                      # Project metadata and dependencies
├── mkdocs.yml                          # MkDocs configuration
│
├── docs/                               # Documentation source files
│   ├── index.md                        # Documentation homepage
│   │
│   ├── getting-started/                # Getting started guides
│   │   ├── installation.md             # Installation instructions
│   │   ├── quickstart.md               # Quick start guide (5 min)
│   │   └── examples.md                 # Basic examples
│   │
│   ├── user-guide/                     # User documentation
│   │   ├── quickstart.md               # Quickstart guide
│   │   ├── cli-usage.md                # CLI command reference
│   │   ├── library-usage.md            # Python library usage
│   │   ├── cookbook.md                 # Common patterns and recipes
│   │   └── dialect-equivalences.md     # Suricata vs Snort differences
│   │
│   ├── technical/                      # Technical documentation
│   │   ├── parser-implementation.md    # Parser internals
│   │   ├── ast-nodes.md                # AST node reference (auto-generated)
│   │   ├── extending-ast.md            # How to extend the AST
│   │   └── testing-strategy.md         # Testing approach and corpus
│   │
│   ├── api/                            # API documentation (auto-generated)
│   │   ├── core.md                     # Core functions API
│   │   ├── nodes.md                    # AST nodes API
│   │   ├── parser.md                   # Parser API
│   │   ├── serializer.md               # Serializer API
│   │   ├── validator.md                # Validator API
│   │   └── utils.md                    # Utility functions API
│   │
│   ├── contributing/                   # Contribution documentation
│   │   ├── code-of-conduct.md          # Code of conduct
│   │   ├── development.md              # Development setup
│   │   └── releases.md                 # Release process
│   │
│   ├── project/                        # Project information
│   │   ├── roadmap.md                  # Feature roadmap
│   │   └── faq.md                      # Frequently asked questions
│   │
│   ├── stylesheets/                    # Custom CSS
│   │   └── extra.css                   # Additional styles
│   │
│   └── javascripts/                    # Custom JavaScript
│       └── extra.js                    # Additional scripts
│
├── examples/                           # Example scripts
│   ├── parse_basic.py                  # Basic parsing example
│   ├── parse_advanced.py               # Advanced parsing with options
│   ├── transform_rules.py              # Rule transformation
│   ├── validate_ruleset.py             # Validation example
│   ├── generate_rules.py               # Rule generation
│   ├── bulk_processing.py              # Bulk rule processing
│   └── custom_visitor.py               # Custom AST visitor
│
└── tests/                              # Test documentation
    └── corpus/                         # Test corpus documentation
        ├── README.md                   # Corpus description
        ├── suricata/                   # Suricata test rules
        └── snort/                      # Snort test rules
```

---

## Documentation Categories

### 1. Main Documentation (Root Level)

**Purpose**: Essential documentation accessible from repository root.

**Files**:
- `README.md`: Project overview, quick start, features, installation
- `ARCHITECTURE.md`: System design, components, data flow
- `GRAMMAR.md`: Complete EBNF grammar specification
- `AST_SPEC.md`: AST structure with JSON Schema
- `API_REFERENCE.md`: Complete API documentation
- `CONTRIBUTING.md`: How to contribute
- `CHANGELOG.md`: Version history
- `LICENSE`: GPLv3 license

**Audience**: All users (developers, contributors, researchers)

---

### 2. User Documentation

**Purpose**: Help users understand and use the library.

**Location**: `docs/user-guide/`

**Contents**:
- **quickstart.md**: Get started in 5 minutes
- **cli-usage.md**: Command-line interface documentation
- **library-usage.md**: Python library usage guide
- **cookbook.md**: Common patterns and recipes
- **dialect-equivalences.md**: Suricata vs Snort differences

**Audience**: End users, security engineers, developers

---

### 3. Technical Documentation

**Purpose**: Detailed technical information for advanced users and contributors.

**Location**: `docs/technical/`

**Contents**:
- **parser-implementation.md**: Parser internals and algorithms
- **ast-nodes.md**: Complete AST node reference
- **extending-ast.md**: How to add custom keywords
- **testing-strategy.md**: Testing approach and corpus

**Audience**: Contributors, advanced developers

---

### 4. API Documentation

**Purpose**: Auto-generated API reference from docstrings.

**Location**: `docs/api/`

**Generation**: MkDocs with mkdocstrings plugin

**Contents**:
- **core.md**: Core functions (parse_rule, serialize_rule, etc.)
- **nodes.md**: AST node classes
- **parser.md**: Parser class and methods
- **serializer.md**: Serializer class
- **validator.md**: Validator class
- **utils.md**: Utility functions

**Audience**: Developers integrating the library

---

### 5. Examples

**Purpose**: Runnable code examples demonstrating usage.

**Location**: `examples/`

**Contents**:
- **parse_basic.py**: Basic rule parsing
- **parse_advanced.py**: Advanced parsing options
- **transform_rules.py**: Rule transformation
- **validate_ruleset.py**: Validation examples
- **generate_rules.py**: Programmatic rule generation
- **bulk_processing.py**: Processing large rulesets
- **custom_visitor.py**: Custom AST traversal

**Audience**: All developers

---

## Documentation Tools

### MkDocs

**Purpose**: Static site generator for documentation.

**Configuration**: `mkdocs.yml`

**Theme**: Material for MkDocs

**Features**:
- Navigation tabs
- Search
- Code highlighting
- Dark mode
- Mobile responsive

**Build Commands**:
```bash
# Serve locally
mkdocs serve

# Build static site
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

---

### mkdocstrings

**Purpose**: Auto-generate API documentation from docstrings.

**Configuration**: In `mkdocs.yml`

**Style**: Google-style docstrings

**Example**:
```python
def parse_rule(rule_text: str, strict: bool = True) -> Rule:
    """Parse a Suricata/Snort rule.

    Args:
        rule_text: The rule text to parse
        strict: If True, raise on errors

    Returns:
        Parsed rule AST

    Raises:
        ParseError: If rule syntax is invalid
    """
```

---

### Sphinx (Alternative)

**Purpose**: Alternative documentation generator (not currently used).

**Advantages**:
- More powerful for API docs
- Better autodoc features
- LaTeX/PDF output

**Disadvantages**:
- More complex setup
- Heavier dependency

---

## Documentation Workflows

### For Contributors

1. **Code Changes**:
   - Update relevant documentation
   - Add docstrings to new code
   - Update CHANGELOG.md

2. **Documentation Changes**:
   - Edit Markdown files in `docs/`
   - Test with `mkdocs serve`
   - Ensure links work

3. **API Changes**:
   - Update docstrings
   - Regenerate API docs
   - Update examples

---

### For Maintainers

1. **Release Process**:
   - Update CHANGELOG.md
   - Update version in pyproject.toml
   - Tag release
   - Deploy documentation

2. **Documentation Deployment**:
   - Build docs: `mkdocs build`
   - Deploy: `mkdocs gh-deploy`
   - Verify on ReadTheDocs/GitHub Pages

---

## Documentation Standards

### Markdown Format

- Use ATX-style headers (`#`, `##`, `###`)
- Code blocks with language identifiers
- Tables for structured data
- Links with descriptive text

### Code Examples

- Complete, runnable examples
- Include imports
- Add comments explaining key points
- Show expected output

### Docstrings

- Google-style docstrings
- Complete parameter descriptions
- Return value documentation
- Exception documentation
- Usage examples

---

## Auto-Generated Documentation

### AST Node Reference

**Source**: `surisnort_ast/nodes.py`

**Generator**: mkdocstrings

**Template**:
```markdown
# AST Nodes

::: surisnort_ast.nodes
    options:
      show_root_heading: true
      show_source: true
```

### API Reference

**Source**: All `surisnort_ast/*.py` files

**Generator**: mkdocstrings

**Configuration**: `mkdocs.yml`

---

## Documentation Versioning

### Version Strategy

- **Latest**: Development version (main branch)
- **Stable**: Latest release
- **Versioned**: Previous releases (1.0, 0.9, etc.)

### Tools

- **mike**: Multi-version documentation for MkDocs
- **ReadTheDocs**: Automatic version management

### Configuration

```yaml
# In mkdocs.yml
extra:
  version:
    provider: mike
    default: stable
```

---

## PyPI Documentation

### README for PyPI

**Source**: `README.md`

**Format**: Markdown (converted to reStructuredText for PyPI)

**Contents**:
- Project description
- Installation instructions
- Quick example
- Links to full documentation

### Project Metadata

**File**: `pyproject.toml`

**Fields**:
- `description`: Short description
- `keywords`: Searchable keywords
- `classifiers`: PyPI classifiers
- `urls`: Documentation, repository, issues

---

## Documentation Quality Checklist

### Before Release

- [ ] All code has docstrings
- [ ] All examples run without errors
- [ ] All links work
- [ ] Documentation builds without warnings
- [ ] API reference is complete
- [ ] CHANGELOG.md is updated
- [ ] Version numbers are consistent
- [ ] License information is present

---

## Documentation Maintenance

### Regular Tasks

- Review and update examples
- Fix broken links
- Update screenshots/diagrams
- Refresh performance benchmarks
- Update dependency versions

### Version-Specific Tasks

- Archive old version docs
- Update compatibility matrix
- Review and update FAQ
- Update roadmap

---

## Documentation Metrics

### Coverage Goals

- **API Coverage**: 100% (all public APIs documented)
- **Example Coverage**: Major use cases covered
- **Guide Coverage**: All features have guides

### Quality Metrics

- **Link Validity**: 100% (no broken links)
- **Build Success**: 100% (no build errors/warnings)
- **Code Example Success**: 100% (all examples run)

---

## Tools and Scripts

### Documentation Scripts

**Generate API docs**:
```bash
python scripts/generate_api_docs.py
```

**Check links**:
```bash
python scripts/check_links.py
```

**Build all formats**:
```bash
python scripts/build_docs.py --all
```

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.
