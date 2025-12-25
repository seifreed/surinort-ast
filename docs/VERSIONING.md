# Versioning Strategy

**Project:** surinort-ast
**Author:** Marc Rivero López
**License:** GNU General Public License v3.0

---

## Semantic Versioning

surinort-ast follows [Semantic Versioning 2.0.0](https://semver.org/) (SemVer).

Given a version number **MAJOR.MINOR.PATCH**, we increment:

1. **MAJOR** version when making incompatible API changes
2. **MINOR** version when adding functionality in a backward compatible manner
3. **PATCH** version when making backward compatible bug fixes

---

## Version History and API Evolution

### v1.0.0 - Initial Stable Release (Current)

**Release Date:** 2025-10-29

**Status:** Production/Stable

**Key Features:**
- Complete Suricata/Snort IDS rule parser
- AST representation with full type safety
- JSON serialization/deserialization
- Rule validation and diagnostics
- Text formatting and printing
- 99.46% real-world rule compatibility (35,000+ rules tested)

**API Structure:**
- Top-level imports from `surinort_ast` package
- Modular `api/` package structure introduced (not documented)

**Import Patterns:**
```python
# Both patterns work in v1.0.0
from surinort_ast import parse_rule, to_json
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
```

---

### v1.1.0 - Modular API Documentation (Planned)

**Target Release:** January 2026

**Status:** In Development

**Key Changes:**
- **No breaking changes** - Full backward compatibility
- Documentation updated to recommend modular API structure
- Migration guide and tooling provided
- All examples updated to use modular imports
- Enhanced docstrings with cross-references

**New Features:**
- Automated import migration tool (`tools/migrate_imports.py`)
- LibCST-based codemod for AST refactoring
- Comprehensive migration documentation
- Migration examples and best practices

**API Structure:**
- Both import patterns fully supported
- Modular imports recommended in documentation
- Top-level imports still work (convenience)

**Import Patterns:**
```python
# Both patterns continue to work
from surinort_ast import parse_rule  # Convenience (still supported)
from surinort_ast.api.parsing import parse_rule  # Modular (recommended)
```

**Migration Path:**
- Users can migrate at their own pace
- No forced migration required
- Tools provided to assist migration

---

### v1.2.0 - Enhanced API Features (Planned)

**Target Release:** March 2026

**Status:** Planning

**Potential Features:**
- Enhanced query API (if implemented)
- Additional analysis tools
- Performance optimizations
- Community-requested features

**API Changes:**
- No breaking changes
- Additive only
- Continued support for both import patterns

---

### v1.x.x - Minor Releases (Ongoing)

**Timeline:** 2026-2027

**Approach:**
- **Backward compatibility guaranteed** for all v1.x releases
- Incremental feature additions
- Bug fixes and performance improvements
- Documentation enhancements
- Migration support and tooling improvements

**Deprecation Policy:**
- Deprecation warnings (if any) will be added at least 6 months before removal
- Deprecated features will be documented clearly
- Migration guides provided for deprecated features
- Minimum 12-month deprecation period before v2.0.0

---

### v2.0.0 - Stability Milestone (Planned)

**Target Release:** December 2026 (12+ months from v1.1.0)

**Status:** Long-term Planning

**Philosophy:**
- **Stability over breaking changes**
- Current plan: **No breaking changes**
- Focus on long-term API stability

**Potential Changes (TBD based on community feedback):**
- Possible deprecation of less-used patterns (only if <5% adoption)
- API refinements based on real-world usage
- Performance improvements
- Enhanced type safety

**Current Commitment:**
- Both import patterns will continue to work
- No forced migration planned
- Decision based on user feedback and adoption metrics

**Decision Criteria for Breaking Changes:**
- User surveys and feedback
- Adoption metrics (if available)
- Community consensus
- Significant architectural benefits

---

## Version Compatibility Matrix

| Version | Import Style | Status | Recommendation | Support |
|---------|--------------|--------|----------------|---------|
| v1.0.0  | Top-level | ✅ Stable | Either | Full |
| v1.0.0  | Modular | ✅ Stable | Either | Full |
| v1.1.0+ | Top-level | ✅ Stable | Convenience | Full |
| v1.1.0+ | Modular | ✅ Stable | Production | Full |
| v2.0.0  | Top-level | ✅ Planned | Convenience | Full (TBD) |
| v2.0.0  | Modular | ✅ Planned | Production | Full |
| v3.0.0+ | Top-level | ⚠️ TBD | TBD | Re-evaluate |
| v3.0.0+ | Modular | ✅ Guaranteed | Production | Full |

---

## Support and Maintenance Windows

### Long-Term Support (LTS)

**Current Policy:**
- Latest minor version of each major version receives active support
- Security fixes backported to previous minor versions for 12 months
- Critical bugs fixed in latest stable release

**Example:**
- v1.5.0 released → v1.4.x receives security fixes for 12 months
- v2.0.0 released → v1.x receives security fixes for 12 months

### Active Support

**Definition:** Active development, new features, bug fixes, documentation updates

**Current Status:**
- v1.0.x: Active support
- v1.1.x: Active development

### Security Support

**Definition:** Security vulnerabilities fixed, no new features

**Policy:**
- Previous major version: 12 months after new major release
- Previous minor version: 12 months after new minor release

---

## Deprecation Policy

### Deprecation Process

When deprecating a feature:

1. **Announcement** (Month 0)
   - Feature marked as deprecated in documentation
   - Deprecation warning added to docstring
   - Alternative approach documented
   - GitHub issue created for tracking

2. **Deprecation Period** (Months 1-6)
   - Feature continues to work normally
   - Optional runtime warnings (if non-intrusive)
   - Migration guide provided
   - Community support for migration

3. **Final Warning** (Months 7-12)
   - Stronger documentation warnings
   - Clear timeline for removal
   - Final migration assistance

4. **Removal** (Month 12+)
   - Feature removed in next major version
   - Breaking change properly documented
   - Migration path clearly explained

### Minimum Deprecation Timeline

- **Minor features:** 6 months
- **Major API changes:** 12 months
- **Core functionality:** 18+ months

### Current Deprecations

**None.** No features are currently deprecated.

---

## Breaking Changes Policy

### What Constitutes a Breaking Change

**Breaking changes include:**
- Removing public API functions
- Changing function signatures (adding required parameters)
- Changing return types in incompatible ways
- Renaming modules or packages
- Changing default behavior that affects existing code

**NOT breaking changes:**
- Adding new optional parameters with defaults
- Adding new functions or modules
- Fixing bugs that match documented behavior
- Internal implementation changes
- Documentation updates

### How Breaking Changes Are Handled

1. **Avoid When Possible**
   - Prefer additive changes
   - Use deprecation for transitions
   - Maintain backward compatibility

2. **When Necessary**
   - Announce at least 12 months in advance
   - Provide automated migration tools
   - Document migration path clearly
   - Offer transition period with warnings

3. **Major Version Bump**
   - Breaking changes only in major versions
   - Never in minor or patch versions
   - Clear upgrade guide provided

---

## Python Version Support

### Current Support

**Supported Python Versions:**
- Python 3.11 ✅ (minimum)
- Python 3.12 ✅
- Python 3.13 ✅
- Python 3.14 ✅

**End of Life Policy:**
- Follow official Python EOL schedule
- Drop support 6 months after Python version EOL
- Announce planned drops 12 months in advance

### Future Python Support

**When New Python Versions Release:**
- Test compatibility within 1 month
- Add to CI/CD within 2 months
- Official support within 3 months

**When Dropping Old Python Versions:**
- Announce 12 months before dropping
- Drop only in major or minor versions (never patch)
- Provide migration guide for affected users

---

## Release Cadence

### Target Schedule

**Minor Releases:** Every 2-3 months
- New features
- Non-breaking improvements
- Documentation updates

**Patch Releases:** As needed
- Critical bug fixes
- Security fixes
- Documentation corrections

**Major Releases:** 12-24 months
- Breaking changes (if any)
- Architectural improvements
- Major feature milestones

### Release Process

1. **Planning** (2-4 weeks before release)
   - Feature freeze
   - Documentation review
   - Testing sprint

2. **Beta/RC** (1-2 weeks before release)
   - Release candidate published
   - Community testing
   - Final bug fixes

3. **Release**
   - PyPI publication
   - GitHub release
   - Documentation deployment
   - Announcement

4. **Post-Release**
   - Monitor for issues
   - Patch releases if needed
   - Gather feedback

---

## Version Numbering Examples

### Patch Releases (Bug Fixes)

```
v1.0.0 → v1.0.1: Fix parser edge case
v1.0.1 → v1.0.2: Fix serialization bug
v1.0.2 → v1.0.3: Security fix in path validation
```

### Minor Releases (New Features)

```
v1.0.3 → v1.1.0: Add modular API documentation
v1.1.0 → v1.2.0: Add query API features
v1.2.0 → v1.3.0: Add analysis tools
```

### Major Releases (Breaking Changes)

```
v1.9.0 → v2.0.0: API stability milestone (no breaking changes planned)
v2.9.0 → v3.0.0: Future major release (if needed)
```

---

## Pre-Release Versions

### Alpha Releases

**Format:** `v1.2.0a1`, `v1.2.0a2`

**Purpose:** Early testing of major features
**Stability:** Unstable, API may change
**Audience:** Early adopters, testers

### Beta Releases

**Format:** `v1.2.0b1`, `v1.2.0b2`

**Purpose:** Feature-complete, testing phase
**Stability:** Feature-frozen, minor changes only
**Audience:** Integration testing

### Release Candidates

**Format:** `v1.2.0rc1`, `v1.2.0rc2`

**Purpose:** Final testing before release
**Stability:** Stable, critical fixes only
**Audience:** Production-like testing

---

## Compatibility Promise

### What We Guarantee

**For all v1.x releases:**
- Public API remains backward compatible
- Existing code continues to work
- No forced migrations
- Deprecation warnings before removals

**For v2.0.0 and beyond:**
- Maintain modular import patterns
- Long-term stability commitment
- Breaking changes only when necessary and well-justified

### What We Don't Guarantee

**Internal APIs:**
- Modules prefixed with `_` (e.g., `_internal.py`)
- Undocumented functions or classes
- Implementation details

**Experimental Features:**
- Clearly marked as experimental
- May change or be removed without deprecation
- Use at your own risk

---

## Version Selection Guide

### Which Version Should I Use?

**Production Systems:**
- Use latest stable minor version (e.g., v1.5.0)
- Pin major version in dependencies: `surinort-ast>=1.5.0,<2.0.0`
- Test updates before deploying

**Development/Testing:**
- Use latest stable or beta version
- Test new features early
- Provide feedback

**Quick Scripts/REPL:**
- Use latest stable version
- Top-level imports are fine
- Don't worry about future changes

---

## Communication Channels

### Where to Find Version Information

**Official Sources:**
- CHANGELOG.md - Detailed release notes
- GitHub Releases - Release announcements
- PyPI - Version metadata
- Documentation site - Version-specific docs

**Community:**
- GitHub Discussions - Version planning discussions
- GitHub Issues - Bug reports and feature requests

---

## Conclusion

surinort-ast is committed to **stability, backward compatibility, and gradual evolution**. We prioritize user experience and minimize disruption while continuing to improve the library.

**Key Principles:**
1. Semantic versioning strictly followed
2. Backward compatibility within major versions
3. Long deprecation periods for changes
4. Clear communication about changes
5. Community feedback drives decisions

---

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**License:** GNU General Public License v3.0
