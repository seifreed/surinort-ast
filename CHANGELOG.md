# Changelog

All notable changes to `surinort-ast` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Deprecated
- **RuleParser** class - Use `LarkRuleParser` or `surinort_ast.api.parsing.parse_rule()` instead
  - Will be removed in version 2.0.0
  - Deprecation warnings added with stacklevel=2 for clear source location
  - All functionality preserved through delegation to LarkRuleParser
  - See `docs/MIGRATION_GUIDE.md` for migration instructions
- **surinort_ast.parsing.parser.parse_rule()** - Use `surinort_ast.api.parsing.parse_rule()` instead
  - Will be removed in version 2.0.0
  - High-level API function provides same interface with dependency injection support
- **surinort_ast.parsing.parser.parse_rules_file()** - Use `surinort_ast.api.parsing.parse_file()` instead
  - Will be removed in version 2.0.0
  - New function provides enhanced features (parallel processing, security, streaming)

### Added
- **LarkRuleParser** - Modern parser implementation with clean separation of concerns
  - Recommended replacement for deprecated RuleParser
  - Same interface and functionality as RuleParser
  - Better testability and extensibility
  - No deprecation warnings
- **Parser Dependency Injection** - Custom parser support via `parser` parameter
  - `parse_rule()` accepts optional `parser` parameter for custom implementations
  - Enables parser middleware, caching, validation, and testing patterns
  - See `examples/parser_dependency_injection.py` for examples
- **Extension Patterns Documentation** - Comprehensive guide at `docs/EXTENSION_PATTERNS.md`
  - Custom parser implementation patterns
  - Custom option types (adding new IDS keywords)
  - Custom serialization formats (YAML, TOML, MessagePack examples)
  - Custom analyzers and metrics
  - Plugin development patterns
- **Migration Guide** - Step-by-step migration instructions at `docs/MIGRATION_GUIDE.md`
  - RuleParser to LarkRuleParser migration
  - API package restructuring guide
  - Parser dependency injection patterns
  - Type hints and protocol documentation
  - Breaking changes timeline and version compatibility matrix
- **Custom Parser Example** - Working implementation at `examples/custom_parser_implementation.py`
  - StrictParser with validation
  - CachingParser with LRU cache
  - ParserMiddleware pattern
  - Integration with api.parsing functions

### Changed
- **RuleParser** now wraps LarkRuleParser via delegation pattern
  - All methods delegate to internal LarkRuleParser instance
  - Backward compatibility maintained 100%
  - Deprecation warnings emitted on instantiation and method calls
  - Internal methods (_get_parser, _handle_parse_error, etc.) still exposed for test compatibility

### Documentation
- Added comprehensive Sphinx-style docstrings to deprecated APIs
- Updated examples in docstrings with before/after comparisons
- Added "See Also" sections linking to recommended replacements
- Created extension and migration guides in docs/ directory

---

## [1.0.0] - 2025-12-22

### Added - First Stable Release

#### Core Parser
- **Parser**: LALR(1) grammar using Lark, supporting 99.46% of real-world IDS rules (35,157 rules tested)
- **Compatibility**: 100% Suricata (30,579 rules), 100% Snort2 (561 rules), 100% Snort3 (4,017 rules)
- **AST**: Complete typed AST with Pydantic v2, immutable nodes, full type safety
- **Type Safety**: Full Python type hints with mypy strict mode
- Support for 100+ rule options including PCRE, content modifiers, HTTP keywords, flow control
- Support for Suricata 6.x/7.x and Snort 2.9.x/3.x dialects
- Error recovery with detailed diagnostic messages
- Position tracking for all AST nodes

#### Analysis Module (NEW)
- **Performance Estimation**: Estimate rule performance cost based on structure and options
  - Analyzes rule complexity (number of options, PCRE usage, content patterns)
  - Provides performance score (0-100, lower is better)
  - Identifies performance bottlenecks
- **Rule Optimization**: Automatically optimize rules for better performance
  - Fast pattern selection strategy
  - Option reordering (cheaper checks first)
  - Redundancy removal
  - Content consolidation
  - Tracks estimated performance improvements
- **Coverage Analysis**: Analyze rule coverage across corpus
  - Protocol coverage detection
  - Port coverage analysis
  - Duplicate and overlapping rule detection
  - Coverage gap identification
- **Conflict Detection**: Detect conflicting rules
  - Overlapping signature detection
  - Duplicate SID detection
  - Conflicting action detection
  - Resolution recommendations

#### Query API (EXPERIMENTAL)
- **CSS-Style Selectors**: Query AST nodes using CSS-inspired syntax
  - Type selectors (`"ContentOption"`, `"Rule"`)
  - Universal selector (`"*"`)
  - Attribute equality selectors (`"Rule[action=alert]"`, `"SidOption[value=1000001]"`)
  - Combined selectors (type + attributes)
- **Query Functions**:
  - `query()` - Query descendants of single node
  - `query_all()` - Query multiple nodes (collection)
  - `query_first()` - Get first match
  - `query_exists()` - Check existence
- **Performance**: <10ms for typical rule queries
- **Warning**: Experimental feature, API may change in future versions
- Phase 1 MVP implementation (basic type and attribute selectors)

#### Serialization
- **JSON Serialization**: RFC 8259 compliant JSON export/import with roundtrip support
  - Lossless conversion (parse → JSON → parse produces identical AST)
  - Human-readable JSON format
  - Preserves all rule metadata
- **Text Serialization**: Convert AST back to valid rule text
  - Multiple formatting styles (compact, standard, pretty)
  - Stable output (canonical form)
  - Configurable indentation and spacing
- **Schema Generation**: JSON Schema export for AST structure
  - Complete schema for all AST nodes
  - Validation support
  - Documentation and codegen support

#### Validation
- **Syntax Validation**: Automatic during parsing
  - Rule structure validation
  - Option syntax and order checking
  - PCRE pattern syntax validation
  - Address and port specification validation
- **Semantic Validation**: Post-parse validation
  - Required options checking (sid, rev, msg)
  - SID uniqueness validation
  - Protocol-specific option compatibility
  - PCRE pattern validity
  - Cross-option dependency validation

#### CLI Tools
- **Seven Production-Ready Commands**:
  - `parse` - Parse and display rules with AST details
  - `validate` - Validate rules (syntax + semantics)
  - `fmt` - Format and pretty-print rules
  - `to-json` - Export rules to JSON
  - `from-json` - Import rules from JSON
  - `stats` - Analyze rule corpus statistics
  - `schema` - Generate JSON Schema
- **Parallel Processing**: Support for multi-worker parsing (8x speedup)
- **Batch Processing**: Optimized batch processing for large rulesets
- **Streaming Support**: Process large files without loading all into memory

#### Testing & Quality
- **Testing**: 93.42% code coverage, 804 passing tests, zero mocks
- **Golden Tests**: Validated against 35,157 real-world production rules
- **Property-Based Testing**: Hypothesis for edge cases
- **Performance Tests**: Benchmarked parsing throughput
- **Security Tests**: Path traversal and error sanitization coverage

#### Performance
- **Parsing**: 1,353 rules/sec (sequential), ~10,800 rules/sec (8 workers)
- **Simple rules**: ~50,000 rules/second
- **Complex rules**: ~15,000 rules/second
- **30K corpus**: ~2 seconds
- **Memory**: ~2-5 KB per rule AST

#### Documentation
- **Complete README**: Project overview with quick start
- **FEATURES.md**: Detailed feature documentation
- **API_GUIDE.md**: Complete API reference with examples
- **EXAMPLES.md**: Real-world usage scenarios and best practices
- **API Reference**: Complete docstrings for all public functions
- **Examples**: 10+ comprehensive, executable examples
- **Technical Guides**: Architecture, grammar, and AST specifications

#### Security
- **Path Traversal Protection (CWE-22)**: Secure file path validation
  - Directory sandboxing via `allowed_base` parameter
  - Symlink detection and rejection
  - Resolved path validation
- **Error Message Sanitization (CWE-209)**: Prevent information disclosure
  - Sanitized file paths in error messages
  - No directory structure exposure
- **27 Security Tests**: Complete coverage of security-critical code paths

### Changed
- Project name correction from "surisnort-ast" to "surinort-ast"
- Version bumped to 1.0.0 indicating production stability
- Enhanced parser with modular transformer architecture (split into 4 files)
- Improved type hints coverage to 100% with mypy strict mode
- Optimized parallel processing with batch support (40% throughput improvement)

### Fixed
- CWE-22 path traversal security vulnerability with comprehensive protection
- CWE-209 information exposure through sanitized error messages
- Parallel processing race conditions and serialization issues
- PCRE and sticky buffer parsing edge cases
- Metadata, actions, and content modifiers parsing issues
- Memory leaks in large rulesets
- Address group parsing edge cases
- PCRE escaping in serialization

### Migration Guide

This is the first stable release. No migration needed from beta versions.

For future updates, see migration guides in individual version sections.

### Known Limitations

- **Query API**: Experimental feature, Phase 1 MVP only
  - No hierarchical selectors (descendant, child, sibling)
  - No comparison operators (>, <, >=, <=)
  - No string operators (contains, starts-with, ends-with)
  - No pseudo-selectors (:first, :last, :has, :not)
  - Full implementation planned for future versions
- **Builder Pattern**: Not included in v1.0.0 (planned for v1.1.0)
- **Protobuf Serialization**: Not included in v1.0.0 (planned for v1.1.0)
- **Lua Script Execution**: References supported, execution out of scope

### Breaking Changes from Beta

None - this is the first stable release.

### Deprecations

None

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

This is the first stable release of `surinort-ast`, providing a complete, production-ready solution for parsing and manipulating Suricata/Snort rules.

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
from surinort_ast import RuleParser
parser = RuleParser()
rule = parser.parse(rule_text)

# New API (1.0.0)
from surinort_ast import parse_rule
rule = parse_rule(rule_text)

# Old serialization
rule_text = rule.to_string()

# New serialization
from surinort_ast import serialize_rule
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

[Unreleased]: https://github.com/seifreed/surinort-ast/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/seifreed/surinort-ast/releases/tag/v1.0.0
[0.3.0]: https://github.com/seifreed/surinort-ast/releases/tag/v0.3.0
[0.2.0]: https://github.com/seifreed/surinort-ast/releases/tag/v0.2.0
[0.1.0]: https://github.com/seifreed/surinort-ast/releases/tag/v0.1.0
