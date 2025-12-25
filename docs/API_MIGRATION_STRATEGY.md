# API Migration Strategy

**Project:** surinort-ast
**Author:** Marc Rivero López
**License:** GNU General Public License v3.0
**Last Updated:** 2025-12-25

---

## Executive Summary

This document outlines the complete migration strategy for transitioning from the monolithic `api.py` module to a modular `api/` package structure in surinort-ast. The migration follows a phased approach over 12+ months to ensure minimal disruption to existing users while modernizing the codebase architecture.

---

## Table of Contents

1. [Migration Rationale](#migration-rationale)
2. [Current State Analysis](#current-state-analysis)
3. [Target Architecture](#target-architecture)
4. [Migration Phases](#migration-phases)
5. [Compatibility Matrix](#compatibility-matrix)
6. [Timeline](#timeline)
7. [Risk Assessment](#risk-assessment)
8. [Rollback Strategy](#rollback-strategy)
9. [Success Metrics](#success-metrics)

---

## Migration Rationale

### Problems with Monolithic `api.py`

1. **Poor Separation of Concerns**: All API functions (parsing, serialization, validation, printing) in a single file
2. **Difficult Maintenance**: Changes to one functional area require touching the entire module
3. **Limited Extensibility**: Hard to add new API categories without bloating the file
4. **Testing Complexity**: Unit tests must import entire API surface even for isolated functionality
5. **Import Performance**: Loading the API module loads all dependencies regardless of actual usage

### Benefits of Modular `api/` Package

1. **Clear Functional Boundaries**: Each submodule handles one responsibility
2. **Improved Maintainability**: Changes are isolated to specific submodules
3. **Better Testability**: Unit tests can target specific functionality
4. **Lazy Loading**: Import only what you need
5. **Future Extensibility**: New categories (e.g., `api/query.py`, `api/analysis.py`) fit naturally
6. **Industry Standard**: Aligns with Python packaging best practices

---

## Current State Analysis

### Existing Structure (v1.0.0)

**Status:** New modular structure already exists, but not documented or promoted

```
src/surinort_ast/
├── __init__.py           # Re-exports from api/ for convenience
├── api/                  # NEW: Modular API package
│   ├── __init__.py       # Re-exports all submodules
│   ├── _internal.py      # Internal helpers
│   ├── parsing.py        # Parse functions
│   ├── printing.py       # Print functions
│   ├── serialization.py  # JSON serialization
│   └── validation.py     # Validation functions
└── [other packages]
```

### Import Patterns Currently Supported

Both patterns work today (v1.0.0):

```python
# Pattern 1: Top-level import (convenient, recommended)
from surinort_ast import parse_rule, to_json, validate_rule

# Pattern 2: Modular import (explicit, future-proof)
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.validation import validate_rule
```

### Key Insight

**The migration infrastructure is already in place.** The task is to:
1. Document the new structure
2. Encourage adoption through examples
3. Plan eventual deprecation of less explicit patterns (if needed)
4. Provide automated migration tools

---

## Target Architecture

### Final Structure (v2.0.0+)

```
src/surinort_ast/
├── __init__.py           # Minimal: version info, basic re-exports
├── api/                  # Primary public interface
│   ├── __init__.py       # Re-export all submodules
│   ├── parsing.py        # parse_rule, parse_rules, parse_file, parse_file_streaming
│   ├── printing.py       # print_rule, format_rule
│   ├── serialization.py  # to_json, from_json, to_json_schema
│   ├── validation.py     # validate_rule, validate_rules
│   └── _internal.py      # Internal utilities (not public)
├── core/                 # AST nodes, enums, types
├── parsing/              # Parser implementation
├── printer/              # Printer implementation
├── serialization/        # Serializer implementations
└── [other packages]
```

### Import Patterns (v2.0.0+)

**Recommended Pattern:**

```python
# Explicit modular imports (encouraged)
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.validation import validate_rule
```

**Also Supported (convenience):**

```python
# Top-level imports (still works, convenient for quick scripts)
from surinort_ast import parse_rule, to_json, validate_rule
```

---

## Migration Phases

### Phase 1: Soft Migration (Current - v1.1.x) - **In Progress**

**Duration:** 3-6 months
**Status:** Ready to begin
**Goal:** Make new structure discoverable and usable without breaking changes

#### Activities

1. **Documentation Updates**
   - Update README.md to show both import patterns
   - Add migration guide to documentation
   - Update all examples to prefer modular imports
   - Add docstring references to new structure

2. **Developer Experience**
   - Ensure IDE auto-completion works for both patterns
   - Add type hints to all API functions
   - Improve docstrings with cross-references

3. **Communication**
   - Release v1.1.0 announcement highlighting new structure
   - Blog post explaining benefits
   - Update documentation site

#### Deliverables

- [ ] Documentation updates (README, examples, guides)
- [ ] Migration guide document
- [ ] Automated migration tool (migrate_imports.py)
- [ ] Updated examples showing new patterns
- [ ] Release notes for v1.1.0

#### Breaking Changes

**None.** All existing code continues to work.

---

### Phase 2: Deprecation Period (v1.2.x - v1.9.x)

**Duration:** 6-12 months
**Goal:** Signal future direction while maintaining compatibility

#### Activities

1. **Soft Deprecation** (v1.2.0 - optional)
   - Add documentation notes recommending modular imports
   - Update all official examples to use modular imports
   - Provide migration checklist for users

2. **Active Promotion** (v1.3.0 - v1.5.0)
   - Add migration script to repository
   - Write case studies on migration
   - Monitor user adoption via GitHub discussions

3. **Compatibility Monitoring** (v1.6.0 - v1.9.0)
   - Gather feedback on migration pain points
   - Adjust tooling based on user reports
   - Prepare for v2.0.0 breaking change

#### Deliverables

- [ ] Migration tool improvements
- [ ] User feedback collection
- [ ] Migration success stories
- [ ] Pre-v2.0.0 preparation guide

#### Breaking Changes

**None.** All existing code continues to work. Documentation shift toward new patterns.

---

### Phase 3: Hard Migration (v2.0.0)

**Target Date:** 12+ months from v1.1.0 release
**Goal:** Remove legacy patterns, commit to modular structure

#### Activities

1. **Breaking Change Implementation**
   - No breaking changes planned currently
   - Both patterns remain supported for backward compatibility
   - Future consideration: If usage data shows minimal adoption of old patterns

2. **Documentation Finalization**
   - Remove references to deprecated patterns (if any)
   - Finalize migration guide
   - Archive legacy examples

#### Deliverables

- [ ] v2.0.0 release with updated documentation
- [ ] Final migration guide
- [ ] Archived legacy documentation
- [ ] Post-migration retrospective

#### Breaking Changes (Potential - TBD)

**Current Plan: None.** Both import patterns will continue to work.

**Future Consideration:** If telemetry shows <5% usage of top-level imports, consider deprecating in v3.0.0+.

---

## Compatibility Matrix

| Version  | Top-level Import | Modular Import | Recommendation | Notes |
|----------|------------------|----------------|----------------|-------|
| v1.0.0   | ✅ Works         | ✅ Works       | Either         | Both patterns supported |
| v1.1.x   | ✅ Works         | ✅ Recommended | Modular        | Documentation promotes modular |
| v1.2.x   | ✅ Works         | ✅ Recommended | Modular        | Examples use modular |
| v1.3-1.9 | ✅ Works         | ✅ Recommended | Modular        | Migration tools available |
| v2.0.0   | ✅ Works         | ✅ Recommended | Modular        | No breaking changes planned |
| v3.0.0+  | ⚠️ TBD           | ✅ Guaranteed  | Modular        | Re-evaluate based on usage |

### Import Pattern Support

#### Top-level Import (Convenience)

```python
from surinort_ast import parse_rule, to_json
```

**Status:** Supported indefinitely
**Use Case:** Quick scripts, REPL usage, simple tools
**Maintenance:** Zero overhead (re-export in `__init__.py`)

#### Modular Import (Explicit)

```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
```

**Status:** Recommended, guaranteed long-term
**Use Case:** Production code, libraries, large projects
**Benefits:** Explicit dependencies, better tree-shaking

---

## Timeline

### Month 0 (December 2025 - Current)

- [x] Modular structure created
- [ ] Migration strategy document (this doc)
- [ ] Migration tooling created
- [ ] Examples updated

### Month 1 (January 2026)

- [ ] Release v1.1.0 with migration guide
- [ ] Announce new structure
- [ ] Update documentation site
- [ ] Publish migration blog post

### Month 3 (March 2026)

- [ ] Release v1.2.0 with enhanced tools
- [ ] Gather initial user feedback
- [ ] Update examples repository

### Month 6 (June 2026)

- [ ] Survey users on migration progress
- [ ] Publish case studies
- [ ] Adjust tooling based on feedback

### Month 9 (September 2026)

- [ ] Release v1.5.0 milestone
- [ ] Evaluate adoption metrics
- [ ] Plan v2.0.0 features

### Month 12 (December 2026)

- [ ] Release v2.0.0 (no breaking changes, stability milestone)
- [ ] Migration retrospective
- [ ] Long-term support commitment

---

## Risk Assessment

### High Risk

**None identified.** Both import patterns work simultaneously.

### Medium Risk

1. **User Confusion**
   - **Risk:** Two import patterns may confuse new users
   - **Mitigation:** Clear documentation stating both work, recommend modular
   - **Impact:** Low - documentation clarity resolves this

2. **Third-party Dependency**
   - **Risk:** Downstream packages may depend on specific import patterns
   - **Mitigation:** Maintain both patterns indefinitely
   - **Impact:** Low - no forced migration

### Low Risk

1. **Documentation Maintenance**
   - **Risk:** Keeping examples up-to-date across versions
   - **Mitigation:** Automated testing of documentation examples
   - **Impact:** Low - manageable with CI/CD

2. **Tooling Complexity**
   - **Risk:** Migration tool may not cover all edge cases
   - **Mitigation:** Dry-run mode, backup recommendations, manual review
   - **Impact:** Low - tool is optional

---

## Rollback Strategy

### Scenario 1: Migration Tooling Issues

**Symptoms:** Automated migration script breaks user code

**Response:**
1. Immediately publish advisory recommending manual review
2. Release patch fixing tool issues
3. Provide manual migration guide
4. Extend deprecation timeline if needed

**Rollback:** Not needed (both patterns work)

### Scenario 2: User Adoption Resistance

**Symptoms:** <20% adoption after 6 months

**Response:**
1. Survey users to understand blockers
2. Improve tooling and documentation
3. Extend timeline for Phase 2
4. Consider maintaining both patterns indefinitely

**Rollback:** Cancel hard migration (Phase 3), commit to dual-pattern support

### Scenario 3: Unexpected Breaking Changes

**Symptoms:** Reports of broken imports after update

**Response:**
1. Hotfix release restoring compatibility
2. Root cause analysis
3. Enhanced testing of import patterns
4. Communication to affected users

**Rollback:** Revert to previous version, issue patch release

### Rollback Procedure

Since both import patterns are supported, rollback is minimal:

1. **Restore documentation:** Git revert documentation changes
2. **Notify users:** GitHub announcement, PyPI description update
3. **Patch release:** Issue v1.x.y with fixes
4. **Investigation:** Analyze what went wrong
5. **Revised plan:** Adjust timeline and approach

---

## Success Metrics

### Phase 1 Success Criteria

- [ ] 100% of official examples use modular imports
- [ ] Migration guide published and accessible
- [ ] Migration tool available and tested
- [ ] No regression in CI/CD tests
- [ ] Positive community feedback on new structure

### Phase 2 Success Criteria

- [ ] >50% of new code uses modular imports (if measurable)
- [ ] <5 GitHub issues related to migration confusion
- [ ] Migration tool used by at least 10 external projects
- [ ] Documentation examples all updated
- [ ] Zero breaking changes reported

### Phase 3 Success Criteria

- [ ] v2.0.0 released on schedule
- [ ] 100% test coverage maintained
- [ ] Zero critical bugs in import system
- [ ] Positive sentiment in release feedback
- [ ] Long-term stability commitment

### Monitoring Approach

**Quantitative:**
- GitHub issue tracker for migration problems
- Test coverage reports
- CI/CD success rates

**Qualitative:**
- User feedback in discussions
- Stack Overflow questions
- Community sentiment

---

## Communication Plan

### Channels

1. **GitHub Repository**
   - Release notes for each version
   - Migration guide in documentation
   - Pinned issue with migration FAQ

2. **Documentation Site**
   - Banner announcing new structure (v1.1.0+)
   - Dedicated migration page
   - Updated quickstart guide

3. **PyPI Package Page**
   - Update long description to mention modular structure
   - Link to migration guide

4. **Community Engagement**
   - Blog post explaining rationale and benefits
   - Discussion thread for questions
   - Example migrations from real projects

### Messaging Timeline

**v1.1.0 Release:**
> "surinort-ast v1.1.0 introduces a modular API structure for better maintainability and extensibility. Your existing code continues to work unchanged. See our migration guide for how to adopt the new recommended patterns at your own pace."

**v1.2.0 Release:**
> "All official examples now use the modular API structure. Both import styles remain fully supported. Check out our migration tool to automatically update your code."

**v2.0.0 Release:**
> "surinort-ast v2.0.0 marks a stability milestone with full commitment to the modular API structure. All import patterns remain supported. Thank you for your feedback during the migration period."

---

## Conclusion

This migration strategy prioritizes **user experience** and **backward compatibility** over rapid change. The phased approach allows users to migrate at their own pace while providing clear guidance and tooling support.

### Key Principles

1. **No Forced Migration:** Both import patterns work indefinitely
2. **Clear Guidance:** Documentation and examples show the recommended way
3. **User Empowerment:** Tools and guides help users migrate when ready
4. **Measured Approach:** Long timeline ensures minimal disruption
5. **Flexibility:** Timeline adjusts based on user feedback

### Next Steps

1. Complete migration tooling (see `tools/migrate_imports.py`)
2. Update all documentation and examples
3. Release v1.1.0 with migration guide
4. Monitor community feedback and adjust approach

---

**Document Version:** 1.0
**License:** GNU General Public License v3.0
**Author:** Marc Rivero López
**Contact:** mriverolopez@gmail.com
