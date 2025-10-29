# Changelog

All notable changes to `surisnort-ast` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Initial project structure
- Complete documentation framework

---

## [1.0.0] - 2025-01-15

### Added
- Complete EBNF grammar specification for Suricata/Snort rules
- Formal AST implementation with immutable nodes
- Recursive descent parser with error recovery
- Bidirectional serialization (parse → AST → serialize)
- Comprehensive validation (syntax and semantics)
- CLI tools for parsing, validation, and formatting
- Support for Suricata 6.x, 7.x protocols (HTTP, DNS, TLS, SSH, etc.)
- Support for Snort 2.9.x rule syntax
- Content matching with all modifiers (nocase, offset, depth, distance, within, etc.)
- PCRE support with all modifiers
- Flow and flowbits support
- Byte operations (byte_test, byte_jump, byte_extract)
- Threshold and detection_filter options
- File inspection options (filestore, filemagic, filemd5, etc.)
- Complete test suite with 90%+ coverage
- Real-world rule corpus testing (10,000+ rules)
- Documentation: README, ARCHITECTURE, GRAMMAR, AST_SPEC, API_REFERENCE
- MkDocs documentation site with user guides and technical docs
- Type hints throughout codebase
- JSON Schema for AST validation

### Features by Category

#### Parser
- Hand-written recursive descent parser
- One-token lookahead (LL(1))
- Panic-mode error recovery
- Position tracking for error reporting
- Dialect auto-detection (Suricata/Snort)

#### AST
- Immutable dataclass nodes
- Complete type safety
- JSON/YAML serialization
- Visitor pattern support
- Position tracking for all nodes

#### Serialization
- Three formatting styles: compact, standard, pretty
- Comment preservation
- Whitespace control
- Configurable indentation

#### Validation
- Syntax validation during parsing
- Semantic validation post-parse
- Cross-rule validation (duplicate SIDs)
- Protocol compatibility checks
- PCRE syntax validation

#### CLI
- `parse`: Parse rules and display AST
- `validate`: Validate rules
- `format`: Pretty-print rules
- `convert`: Convert between formats (text/JSON/YAML)

### Documentation
- Comprehensive README with quick start
- Architecture design document
- Complete EBNF grammar specification
- Formal AST specification with JSON Schema
- Full API reference with examples
- User guides (quickstart, CLI usage, library usage, cookbook)
- Technical docs (parser implementation, extending AST, testing)
- Contributing guidelines
- Code of conduct

### Performance
- Parse: ~50,000 simple rules/second
- Parse (complex): ~15,000 rules/second
- Serialize: ~80,000 rules/second
- Memory: ~2KB per rule AST

---

## [0.3.0] - 2024-12-20 (Beta)

### Added
- Protocol-specific options (HTTP, DNS, TLS)
- File inspection keywords
- Improved error messages with context
- Performance optimizations (30% faster parsing)

### Changed
- Refactored parser for better maintainability
- Improved type hints coverage to 98%

### Fixed
- PCRE escaping in serialization
- Address group parsing edge cases
- Memory leak in large rulesets

---

## [0.2.0] - 2024-11-15 (Alpha)

### Added
- Basic AST implementation
- Parser for core rule syntax
- Simple serialization
- Unit tests for parser

### Changed
- Switched from parser generator to hand-written parser

### Fixed
- Variable parsing in address specifications
- Port range parsing

---

## [0.1.0] - 2024-10-01 (Alpha)

### Added
- Initial project setup
- Basic grammar definition
- Lexer implementation
- Proof-of-concept parser

---

## Release Notes

### Version 1.0.0 - First Stable Release

This is the first stable release of `surisnort-ast`, providing a complete, production-ready solution for parsing and manipulating Suricata/Snort rules.

**Key Highlights**:
- **Complete Grammar**: Full support for Suricata 7.x and Snort 2.9.x syntax
- **Production Ready**: Extensively tested with 10,000+ real-world rules
- **Well Documented**: Comprehensive documentation for users and developers
- **Type Safe**: Full type hints throughout codebase
- **Extensible**: Easy to add custom keywords and options
- **Performance**: Optimized for handling large rulesets

**Breaking Changes from Beta**:
- API renamed: `RuleParser` → `Parser`
- `parse()` method now requires keyword arguments for options
- AST node structure changed to use frozen dataclasses
- Serialization API changed to use `SerializationStyle` enum

**Migration Guide from 0.3.0**:

```python
# Old API (0.3.0)
from surisnort_ast import RuleParser
parser = RuleParser()
rule = parser.parse(rule_text)

# New API (1.0.0)
from surisnort_ast import parse_rule
rule = parse_rule(rule_text)

# Old serialization
rule_text = rule.to_string()

# New serialization
from surisnort_ast import serialize_rule
rule_text = serialize_rule(rule)
```

**Upgrade Recommendations**:
1. Review API changes in [API_REFERENCE.md](API_REFERENCE.md)
2. Update imports to use new function names
3. Replace `to_string()` calls with `serialize_rule()`
4. Test with your existing rulesets
5. Report any issues on GitHub

---

## Version History

| Version | Date       | Type    | Status      |
|---------|------------|---------|-------------|
| 1.0.0   | 2025-01-15 | Stable  | Latest      |
| 0.3.0   | 2024-12-20 | Beta    | Deprecated  |
| 0.2.0   | 2024-11-15 | Alpha   | Deprecated  |
| 0.1.0   | 2024-10-01 | Alpha   | Deprecated  |

---

## Roadmap

### Version 1.1.0 (Planned - Q2 2025)
- Suricata Lua scripting support
- Rule optimization engine
- Performance profiling tools
- Visual AST inspector
- Snort 3.x partial support

### Version 1.2.0 (Planned - Q3 2025)
- Incremental parsing for large files
- Parallel processing support
- Advanced cross-rule analysis
- Machine learning integration for rule scoring

### Version 2.0.0 (Planned - Q4 2025)
- Snort 3.x full compatibility
- Breaking API improvements
- Plugin architecture for custom keywords
- Query language for AST (XPath-like)
- Web-based rule editor

---

## Deprecation Policy

- **Minor versions**: Deprecations announced, support for 6 months
- **Major versions**: Breaking changes allowed, migration guide provided
- **Security fixes**: Backported to last two minor versions

---

## Changelog Guidelines

When contributing, update this file following these guidelines:

### Categories
- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security fixes

### Format
```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- Feature description with context
- Another feature

### Fixed
- Bug description with issue reference (#123)
```

### Examples

**Good**:
```markdown
### Added
- Support for Suricata 7.x TLS keywords (tls.sni, tls.cert_subject, etc.)

### Fixed
- Fix PCRE escaping when pattern contains backslashes (#45)
```

**Bad**:
```markdown
### Added
- New feature

### Fixed
- Bug fix
```

---

## License

Copyright (C) 2025 Marc Rivero López

This project is licensed under the GNU General Public License v3.0.

You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions.

See [LICENSE](LICENSE) for full details.

---

[Unreleased]: https://github.com/mrivero/surisnort-ast/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mrivero/surisnort-ast/releases/tag/v1.0.0
[0.3.0]: https://github.com/mrivero/surisnort-ast/releases/tag/v0.3.0
[0.2.0]: https://github.com/mrivero/surisnort-ast/releases/tag/v0.2.0
[0.1.0]: https://github.com/mrivero/surisnort-ast/releases/tag/v0.1.0
