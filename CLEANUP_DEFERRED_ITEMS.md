# Deferred Cleanup Items - surinort-ast

This document tracks cleanup items identified during the 2025-12-25 code cleanup that were **NOT** applied due to risk level or requiring additional review.

---

## YELLOW Category - Requires Manual Review

### 1. TODO/FIXME Comments - Query Module (11 instances)

**Status:** Deferred pending product owner review
**Risk:** Medium - unclear if implementation phases are complete

**Locations:**

#### src/surinort_ast/query/executor.py
- Line 518: `# TODO: Implement in Phase 3 (post-MVP)`
- Line 539: `# TODO: Implement in Phase 3 (post-MVP)`
- Line 597: `# TODO: Implement early exit in Phase 1`
- Line 625: `# TODO: Implement in Phase 1`
- Line 707: `# TODO: Implement in Phase 3`
- Line 729: `# TODO: Implement in Phase 3`

#### src/surinort_ast/query/parser.py
- Line 504: `# TODO: Implement validation in Phase 1`
- Line 527: `# TODO: Implement in Phase 1`

#### src/surinort_ast/query/selectors.py
- Line 790: `# TODO: Implement in Phase 1`

#### src/surinort_ast/query/__init__.py
- Line 475: `# TODO: Implement in Phase 3`
- Line 511: `# TODO: Implement in Phase 3`

**Action Required:**
1. Review with product owner which implementation phases are complete
2. For completed phases: Remove TODO, verify implementation exists
3. For incomplete phases: Keep TODO or create GitHub issue
4. Recommended: Add phase completion tracking in project management

---

### 2. Deprecated Docstring Markers (Multiple instances)

**Status:** Deferred - part of backward compatibility strategy
**Risk:** Low - intentional deprecation warnings

**Locations:**

#### src/surinort_ast/parsing/parser.py
- Line 100: `>>> # Deprecated` (in docstring example)
- Line 184: `>>> # Deprecated` (in docstring example)
- Line 221: `>>> # Deprecated` (in docstring example)
- Line 257: `>>> # Deprecated` (in docstring example)
- Line 295: `>>> # Deprecated` (in docstring example)

**Rationale:**
These are example code snippets showing deprecated usage patterns. They should remain until:
- RuleParser class is removed (planned for v2.0.0)
- All deprecated APIs are sunset
- Migration period is complete

**Action Required:**
None - keep until v2.0.0 release.

---

### 3. Stub Function Parameters - conflicts_outline.py

**Status:** Deferred - intentional design template
**Risk:** None (file not used in production)

**File:** `src/surinort_ast/analysis/conflicts_outline.py`

**Unused Parameters (Vulture reports):**
- Line 385: `general`, `specific` in `_is_shadowed()`
- Line 402: `general`, `specific` in `_address_subsumes()`
- Line 419: `general`, `specific` in `_port_subsumes()`
- Line 492: `patterns_a`, `patterns_b` in method
- Line 579: `detector_types` in method
- Line 658: `detectors` in method
- Line 698: `report` in method
- Line 700: `conflict_types`, `sids` in method

**Rationale:**
File header (line 8) states: **"DO NOT USE THIS FILE DIRECTLY - It is a design template only."**

These are intentional interface definitions for a conflict detection system that hasn't been implemented yet.

**Action Required:**
Decision needed:
1. **Implement:** Complete the conflict detection functionality
2. **Remove:** Delete the file if feature is canceled
3. **Document:** Add to roadmap if planned for future release

---

## RED Category - Do Not Touch

### 1. Deprecated RuleParser Class

**Status:** Keep until v2.0.0
**Risk:** High - breaking change for external users

**File:** `src/surinort_ast/parsing/parser.py`
**Class:** `RuleParser`

**Rationale:**
- Public API class with external users
- Has `DeprecationWarning` emitted on use
- Backward compatibility wrapper around `LarkRuleParser`
- Migration guide exists: `docs/MIGRATION_GUIDE.md`

**Timeline:**
- v1.1.0: Deprecated, warning emitted
- v2.0.0: Planned removal

**Action Required:**
None - maintain until v2.0.0 per backward compatibility policy.

---

### 2. Conditional Type-Checking Imports

**Status:** Keep - required for optional dependencies
**Risk:** High - would break type checking

**File:** `src/surinort_ast/serialization/protobuf/serializer.py`

**Imports:**
```python
try:
    from google.protobuf.message import Message as ProtoMessage
    from . import ast_pb2 as pb
    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False
    ProtoMessage = Any  # type: ignore
    pb = Any  # type: ignore
```

**Rationale:**
- Protobuf is an optional dependency
- Import used for type checking when available
- Falls back to `Any` when not installed
- Pattern is correct for optional type checking

**Action Required:**
None - this is idiomatic Python for optional dependencies.

---

### 3. Public API Deprecation Warnings

**Status:** Keep - essential for migration strategy
**Risk:** High - breaks migration path

**Examples:**
- `surinort_ast.parsing.parser.parse_rule()` - deprecated function
- Various `warnings.warn()` calls with `DeprecationWarning`

**Rationale:**
- Part of gradual migration strategy
- Helps users update their code
- Provides clear migration path
- Industry standard practice

**Action Required:**
None - maintain deprecation warnings until deprecated features are removed.

---

## Pre-Existing Issues Found

### Test Failure (Unrelated to Cleanup)

**File:** `tests/unit/test_parser_initialization.py`
**Test:** `test_parser_default_initialization`
**Error:** `AttributeError: 'RuleParser' object has no attribute '_lark_parser'`

**Root Cause:**
Test expects `_lark_parser` attribute that was removed when RuleParser was refactored to wrap LarkRuleParser.

**Fix:**
Update test to check for `_parser` instead of `_lark_parser`, or remove internal attribute checking.

**Recommended Change:**
```python
# OLD (broken)
assert parser._lark_parser is None

# NEW (options)
# Option 1: Check public API only
assert parser.dialect == Dialect.SURICATA

# Option 2: Update to new internal structure
assert hasattr(parser, '_parser')
assert isinstance(parser._parser, LarkRuleParser)
```

**Action Required:**
Create issue or PR to fix test compatibility with refactored RuleParser.

---

## Recommendations

### Short-Term (Next Sprint)

1. **Fix broken test** - `test_parser_initialization.py`
   - Estimated effort: 15 minutes
   - Priority: Medium

2. **Review Phase TODOs** - Query module
   - Schedule meeting with product owner
   - Estimated effort: 1 hour
   - Priority: Medium

3. **Decision on conflicts_outline.py**
   - Keep as roadmap item, implement, or remove?
   - Estimated effort: 5 minutes (decision), varies (implementation)
   - Priority: Low

### Long-Term (Before v2.0.0)

1. **Plan deprecation cleanup**
   - Remove RuleParser class
   - Remove deprecated functions
   - Update all documentation
   - Estimated effort: 4-8 hours
   - Priority: High (for v2.0.0)

2. **Automated cleanup prevention**
   - Add pre-commit hook with autoflake
   - Add vulture to CI/CD pipeline
   - Add TODO/FIXME linting rules
   - Estimated effort: 2 hours
   - Priority: Medium

3. **TODO/FIXME audit**
   - Review all remaining TODOs
   - Convert to GitHub issues or remove
   - Estimated effort: 3-4 hours
   - Priority: Low

---

## Summary Statistics

### Items Deferred by Category
- **YELLOW (Manual review):** 3 categories, ~25 instances total
- **RED (Do not touch):** 3 categories, intentionally kept
- **Pre-existing issues:** 1 test failure

### Estimated Cleanup Potential
If all YELLOW items are addressed:
- **TODO comments:** 11 removals possible
- **Deprecated markers:** Keep until v2.0.0
- **Stub parameters:** 1 file decision needed

### Future Cleanup Opportunities
- **v2.0.0 deprecation cleanup:** ~500-1000 lines removable
- **Phase TODO resolution:** ~11 comments removable
- **Test fixes:** ~5-10 lines to update

---

**Last Updated:** 2025-12-25
**Review Cycle:** Quarterly recommended
**Next Review:** 2025-03-25 (or before v2.0.0 planning)
