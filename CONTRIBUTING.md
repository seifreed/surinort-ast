# Contributing to surinort-ast

Thank you for your interest in contributing to `surinort-ast`. This document provides guidelines and instructions for contributing to the project.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Development Workflow](#development-workflow)
5. [Coding Standards](#coding-standards)
6. [Testing Guidelines](#testing-guidelines)
7. [Documentation](#documentation)
8. [Pull Request Process](#pull-request-process)
9. [Bug Reports](#bug-reports)
10. [Feature Requests](#feature-requests)
11. [Release Process](#release-process)

---

## Code of Conduct

### Our Pledge

We pledge to make participation in this project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes**:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes**:
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Project maintainers have the right to remove, edit, or reject comments, commits, code, issues, and other contributions that do not align with this Code of Conduct. Violations may be reported to marc.rivero@example.com.

---

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- pip and virtualenv

### First Contribution

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/surinort-ast.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Push to your fork: `git push origin feature/your-feature-name`
6. Open a Pull Request

---

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
pip install -e ".[dev]"
```

This installs:
- Core dependencies
- Testing tools (pytest, pytest-cov)
- Code quality tools (black, ruff, mypy)
- Documentation tools (mkdocs, mkdocs-material)

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

This ensures code quality checks run automatically before commits.

### 5. Verify Setup

```bash
# Run tests
pytest

# Check code style
black --check .
ruff check .

# Type checking
mypy surinort_ast/
```

---

## Development Workflow

### Branch Strategy

- `main`: Stable production code
- `develop`: Integration branch for features
- `feature/*`: New features
- `bugfix/*`: Bug fixes
- `hotfix/*`: Critical fixes for production

### Workflow Steps

1. **Sync with upstream**:
   ```bash
   git checkout main
   git pull upstream main
   ```

2. **Create feature branch**:
   ```bash
   git checkout -b feature/add-new-keyword
   ```

3. **Make changes**:
   - Write code
   - Add tests
   - Update documentation

4. **Run quality checks**:
   ```bash
   # Format code
   black surinort_ast/ tests/

   # Lint
   ruff check surinort_ast/ tests/

   # Type check
   mypy surinort_ast/

   # Run tests
   pytest
   ```

5. **Commit changes**:
   ```bash
   git add .
   git commit -m "feat: add new keyword support"
   ```

6. **Push and create PR**:
   ```bash
   git push origin feature/add-new-keyword
   ```

---

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 100 characters (not 79)
- **Quotes**: Double quotes for strings
- **Imports**: Absolute imports preferred
- **Type hints**: Required for all public APIs

### Code Formatting

**Tool**: Black (configured in `pyproject.toml`)

```bash
# Format all code
black .

# Check without modifying
black --check .
```

### Linting

**Tool**: Ruff

```bash
# Lint code
ruff check .

# Auto-fix issues
ruff check --fix .
```

### Type Checking

**Tool**: mypy

```bash
# Type check
mypy surinort_ast/

# Strict mode
mypy --strict surinort_ast/
```

### Code Structure

```python
"""Module docstring.

Detailed description of module purpose.
"""

from __future__ import annotations

from typing import Optional, List, Dict, Any
from dataclasses import dataclass

# Constants
DEFAULT_TIMEOUT = 30

# Classes
@dataclass(frozen=True)
class ExampleNode:
    """Short description.

    Longer description with usage examples.

    Attributes:
        name: Node name
        value: Node value
    """

    name: str
    value: Optional[int] = None

    def method(self, param: str) -> bool:
        """Method description.

        Args:
            param: Parameter description

        Returns:
            Return value description

        Raises:
            ValueError: When param is invalid
        """
        pass
```

### Docstring Style

**Format**: Google style docstrings

```python
def parse_rule(rule_text: str, strict: bool = True) -> Rule:
    """Parse a Suricata/Snort rule.

    Args:
        rule_text: The rule text to parse
        strict: If True, raise on errors; if False, use error recovery

    Returns:
        Parsed rule AST

    Raises:
        ParseError: If rule syntax is invalid (when strict=True)

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> print(rule.action)
        Action.ALERT
    """
    pass
```

---

## Testing Guidelines

### Test Structure

```
tests/
├── unit/               # Unit tests
│   ├── test_parser.py
│   ├── test_ast.py
│   └── test_serializer.py
├── integration/        # Integration tests
│   └── test_roundtrip.py
├── corpus/             # Real-world test rules
│   ├── suricata/
│   └── snort/
└── conftest.py         # Pytest fixtures
```

### Writing Tests

**Framework**: pytest

```python
import pytest
from surinort_ast import parse_rule, ParseError

def test_parse_simple_rule():
    """Test parsing simple rule."""
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
    assert rule.action == Action.ALERT
    assert rule.protocol == Protocol.TCP

def test_parse_invalid_rule():
    """Test parsing invalid rule raises error."""
    with pytest.raises(ParseError) as exc_info:
        parse_rule('invalid rule syntax')
    assert "syntax error" in str(exc_info.value).lower()

@pytest.mark.parametrize("rule_text,expected_action", [
    ('alert tcp any any -> any 80 (msg:"Test"; sid:1;)', Action.ALERT),
    ('drop tcp any any -> any 80 (msg:"Test"; sid:1;)', Action.DROP),
    ('reject tcp any any -> any 80 (msg:"Test"; sid:1;)', Action.REJECT),
])
def test_parse_actions(rule_text, expected_action):
    """Test parsing different actions."""
    rule = parse_rule(rule_text)
    assert rule.action == expected_action
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_parser.py

# Run with coverage
pytest --cov=surinort_ast --cov-report=html

# Run specific test
pytest tests/unit/test_parser.py::test_parse_simple_rule

# Run tests matching pattern
pytest -k "parse"

# Verbose output
pytest -v
```

### Coverage Requirements

- **Minimum coverage**: 90%
- **Critical modules**: 95%+ (parser, ast, serializer)
- **CI enforcement**: Coverage must not decrease

### Test Categories

**Unit Tests**:
- Test single functions/methods
- Mock external dependencies
- Fast execution

**Integration Tests**:
- Test component interactions
- No external mocks
- Slower execution

**Corpus Tests**:
- Test against real-world rules
- Ensure compatibility
- Regression prevention

---

## Documentation

### Types of Documentation

1. **Code Documentation**: Docstrings in code
2. **API Reference**: Auto-generated from docstrings
3. **User Guide**: How-to guides and tutorials
4. **Technical Docs**: Architecture and internals

### Documentation Tools

- **MkDocs**: Documentation site generator
- **mkdocs-material**: Theme
- **mkdocstrings**: Auto-generate API docs from docstrings

### Building Documentation

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Serve locally
mkdocs serve

# Build static site
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

### Documentation Standards

- Use Markdown format
- Include code examples
- Provide context and rationale
- Keep examples runnable
- Link to related sections

---

## Pull Request Process

### Before Submitting

1. **Ensure tests pass**:
   ```bash
   pytest
   ```

2. **Check code quality**:
   ```bash
   black --check .
   ruff check .
   mypy surinort_ast/
   ```

3. **Update documentation**:
   - Update relevant docs
   - Add docstrings to new code
   - Update CHANGELOG.md

4. **Update tests**:
   - Add tests for new features
   - Ensure coverage remains high

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Coverage maintained/improved

## Related Issues
Fixes #123
```

### PR Review Process

1. **Automated checks**: CI must pass (tests, linting, type checking)
2. **Code review**: At least one maintainer approval required
3. **Testing**: Reviewer tests functionality
4. **Documentation**: Verify docs are updated
5. **Merge**: Squash and merge to main

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Maintenance

**Examples**:
```
feat(parser): add support for Snort 3 syntax

Implement parser extensions for Snort 3 specific keywords
including service-based detection and inline normalization.

Closes #45
```

```
fix(serializer): correct PCRE escaping

Fix issue where PCRE patterns with backslashes were not
properly escaped during serialization.

Fixes #67
```

---

## Bug Reports

### Before Reporting

1. Search existing issues
2. Verify bug in latest version
3. Create minimal reproduction

### Bug Report Template

```markdown
**Description**
Clear description of the bug.

**To Reproduce**
Steps to reproduce:
1. Parse rule '...'
2. Call method '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.0]
- surinort-ast: [e.g., 1.0.0]

**Minimal Example**
```python
from surinort_ast import parse_rule
rule = parse_rule('...')  # Bug occurs here
```

**Additional Context**
Any other relevant information.
```

---

## Feature Requests

### Feature Request Template

```markdown
**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
What other approaches did you consider?

**Use Case**
Describe how you would use this feature.

**Additional Context**
Any other relevant information.
```

---

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

### Release Steps

1. **Update version**:
   ```bash
   # In pyproject.toml
   version = "1.1.0"
   ```

2. **Update CHANGELOG.md**:
   - Add release date
   - Categorize changes

3. **Create release commit**:
   ```bash
   git commit -m "chore: release v1.1.0"
   ```

4. **Tag release**:
   ```bash
   git tag -a v1.1.0 -m "Release v1.1.0"
   git push origin v1.1.0
   ```

5. **Build and publish**:
   ```bash
   python -m build
   twine upload dist/*
   ```

6. **Create GitHub release**:
   - Use tag v1.1.0
   - Copy CHANGELOG entry
   - Attach built distributions

---

## Getting Help

- **Documentation**: https://seifreed.github.io/surinort-ast
- **Issues**: https://github.com/seifreed/surinort-ast/issues
- **Discussions**: https://github.com/seifreed/surinort-ast/discussions
- **Email**: mriverolopez@gmail.com

---

## License

By contributing to `surinort-ast`, you agree that your contributions will be licensed under the GNU General Public License v3.0.

All contributions must include the following header:

```python
# Copyright (C) 2025 Marc Rivero López
# Licensed under the GNU General Public License v3.0
# See LICENSE file for details
```

---

## Acknowledgments

Thank you for contributing to `surinort-ast`. Your efforts help make this project better for the entire security community.

---

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.
