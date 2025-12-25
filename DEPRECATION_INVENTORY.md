# Deprecation Inventory - surinort-ast

**Complete inventory of deprecated, legacy, and cleanup-required code**

---

## Summary Statistics

| Category | Count | Total Size | Priority |
|----------|-------|------------|----------|
| Backup Files | 1 | 44KB | HIGH |
| Deleted (Pending Commit) | 29 | ~200KB | MEDIUM |
| Internal Source Using Deprecated | 2 files | N/A | HIGH |
| Test Files Using Deprecated | 9 files | N/A | MEDIUM |
| Deprecated Public APIs (Keep) | 3 items | N/A | LOW (keep) |
| Active TODOs | 11 items | N/A | LOW |
| **TOTAL** | **55** | **~244KB** | - |

---

## 1. Critical: Backup Files (Remove Immediately)

### CRIT-001: option_transformer.py.bak

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/mixins/option_transformer.py.bak`

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **Type** | Backup file |
| **Size** | 44KB (1,372 lines) |
| **Created** | 2024-12-22 |
| **Imported by** | None |
| **Impact** | None - dead file |
| **Action** | DELETE |

**Command:**
```bash
rm /Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/mixins/option_transformer.py.bak
```

**Risk:** ZERO - File is not referenced anywhere in codebase

---

## 2. Internal Source Code Using Deprecated APIs

### INTERN-001: StreamParser using RuleParser

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/streaming/parser.py`

| Property | Value |
|----------|-------|
| **Severity** | HIGH |
| **Type** | Internal implementation using deprecated API |
| **Lines** | 26, 133, 529 |
| **Impact** | Performance (minimal), maintenance (medium) |
| **Users Affected** | None (internal only) |
| **Deprecation Warnings** | Yes (triggers warnings in user code) |
| **Action** | MIGRATE to LarkRuleParser |

**Current Code:**
```python
# Line 26
from ..parsing.parser import RuleParser

# Line 133
self._parser = RuleParser(
    dialect=dialect,
    strict=False,
    error_recovery=True,
    config=self.config,
)

# Line 529
parser = RuleParser(dialect=dialect, strict=False, error_recovery=True)
```

**Required Changes:**
```python
# Line 26
from ..parsing.lark_parser import LarkRuleParser

# Line 133
self._parser = LarkRuleParser(
    dialect=dialect,
    strict=False,
    error_recovery=True,
    config=self.config,
)

# Line 529
parser = LarkRuleParser(dialect=dialect, strict=False, error_recovery=True)
```

**Testing:**
```bash
pytest tests/unit/test_streaming* -v
pytest tests/integration/ -v
```

**Risk:** LOW - RuleParser is thin wrapper, functionally identical

---

### INTERN-002: CLI plugins using parse_rules_file

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/cli/commands/plugins.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Internal CLI using deprecated function |
| **Lines** | 243, 264 |
| **Impact** | Maintenance |
| **Users Affected** | None (internal CLI code) |
| **Deprecation Warnings** | Yes |
| **Action** | MIGRATE to parse_file |

**Current Code:**
```python
# Line 243
from surinort_ast.parsing import parse_rules_file

# Line 264
rules = parse_rules_file(input_file)
```

**Required Changes:**
```python
# Line 243
from surinort_ast.api.parsing import parse_file

# Line 264
rules = parse_file(input_file)
```

**Testing:**
```bash
pytest tests/unit/test_cli* -v
surinort plugins analyze <test_file>
```

**Risk:** LOW - Function signature identical, behavior unchanged

---

## 3. Test Files Using Deprecated APIs

### TEST-001: test_api_exception_handlers.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_api_exception_handlers.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser |
| **Line** | 22 |
| **Usage** | Creates RuleParser() instances |
| **Impact** | Maintenance, deprecation warnings in test output |
| **Action** | MIGRATE to LarkRuleParser |

**Migration:**
```python
# Before:
from surinort_ast.parsing.parser import RuleParser
parser = RuleParser()

# After:
from surinort_ast.parsing.lark_parser import LarkRuleParser
parser = LarkRuleParser()
```

---

### TEST-002: test_location_nodes_core.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_location_nodes_core.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser |
| **Line** | 25 |
| **Usage** | Creates RuleParser() instances |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

---

### TEST-003: test_parser_error_recovery.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_parser_error_recovery.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser + parse_rule |
| **Line** | 20 |
| **Usage** | Both RuleParser class and parse_rule function |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser + api.parsing.parse_rule |

**Migration:**
```python
# Before:
from surinort_ast.parsing.parser import RuleParser, parse_rule

# After:
from surinort_ast.parsing.lark_parser import LarkRuleParser
from surinort_ast.api.parsing import parse_rule
```

---

### TEST-004: test_parser_specific_lines.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_parser_specific_lines.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser |
| **Line** | 16 |
| **Usage** | Creates RuleParser(strict=True/False) |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

---

### TEST-005: test_parser_visit_errors.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_parser_visit_errors.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser |
| **Line** | 16 |
| **Usage** | Creates RuleParser() instances |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

---

### TEST-006: test_redos_protection.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_redos_protection.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser extensively |
| **Line** | 20 |
| **Usage** | ~20 instances with various config parameters |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

**Notes:** This file has extensive usage. Consider search/replace:
```bash
# In test_redos_protection.py:
RuleParser( → LarkRuleParser(
```

---

### TEST-007: test_transformer_coverage.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_transformer_coverage.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser |
| **Line** | 33 |
| **Usage** | Creates RuleParser with various configs |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

---

### TEST-008: test_transformer_real_world_rules.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_transformer_real_world_rules.py`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Test using deprecated RuleParser extensively |
| **Line** | 12 |
| **Usage** | ~40 test methods, each creating RuleParser(dialect=Dialect.SURICATA) |
| **Impact** | Maintenance |
| **Action** | MIGRATE to LarkRuleParser |

**Notes:** Large file with many instances. Consider fixture or setup method:
```python
# Option 1: pytest fixture
@pytest.fixture
def suricata_parser():
    return LarkRuleParser(dialect=Dialect.SURICATA)

# Option 2: setUp method (if using unittest)
def setUp(self):
    self.parser = LarkRuleParser(dialect=Dialect.SURICATA)
```

---

### TEST-009: test_parser_initialization.py

**Location:** `/Users/seifreed/tools/malware/surinort-ast/tests/unit/test_parser_initialization.py`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Test accessing internal _lark_parser |
| **Usage** | Tests RuleParser delegation to LarkRuleParser |
| **Impact** | Tests implementation details |
| **Action** | DECISION REQUIRED |

**Options:**
1. **Remove:** If testing backward compatibility is no longer needed
2. **Keep:** If validating deprecated wrapper still works
3. **Migrate:** Rewrite to test LarkRuleParser initialization directly

**Recommendation:** Remove - tests implementation detail, not behavior

---

## 4. Deprecated Public APIs (Keep Until v2.0.0)

### DEPR-001: RuleParser Class

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/parser.py`

| Property | Value |
|----------|-------|
| **Severity** | N/A (Intentional) |
| **Type** | Backward compatibility wrapper |
| **Lines** | 35-229 |
| **Status** | Properly deprecated with warnings |
| **Removal Target** | Version 2.0.0 |
| **Action** | KEEP |

**Deprecation Warning (Lines 108-114):**
```python
warnings.warn(
    "RuleParser is deprecated and will be removed in version 2.0.0. "
    "Use LarkRuleParser directly or the parse_rule() function from surinort_ast.api.parsing instead. "
    "See docs/MIGRATION_GUIDE.md for migration instructions.",
    DeprecationWarning,
    stacklevel=2,
)
```

**External Usage:**
- Unknown number of external users
- Migration guide provided
- Deprecation clearly communicated

**Decision:** ✅ KEEP - Essential for backward compatibility

---

### DEPR-002: parse_rule() Function

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/parser.py`

| Property | Value |
|----------|-------|
| **Severity** | N/A (Intentional) |
| **Type** | Deprecated convenience function |
| **Lines** | 237-272 |
| **Status** | Properly deprecated with warnings |
| **Removal Target** | Version 2.0.0 |
| **Action** | KEEP |

**Deprecation Warning (Lines 265-270):**
```python
warnings.warn(
    "surinort_ast.parsing.parser.parse_rule() is deprecated. "
    "Use surinort_ast.api.parsing.parse_rule() instead.",
    DeprecationWarning,
    stacklevel=2,
)
```

**Migration Path:**
```python
# Old (deprecated):
from surinort_ast.parsing.parser import parse_rule

# New (recommended):
from surinort_ast.api.parsing import parse_rule
```

**Decision:** ✅ KEEP - Common pattern, needs deprecation period

---

### DEPR-003: parse_rules_file() Function

**Location:** `/Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/parser.py`

| Property | Value |
|----------|-------|
| **Severity** | N/A (Intentional) |
| **Type** | Deprecated convenience function |
| **Lines** | 275-310 |
| **Status** | Properly deprecated with warnings |
| **Removal Target** | Version 2.0.0 |
| **Action** | KEEP |

**Deprecation Warning (Lines 303-308):**
```python
warnings.warn(
    "surinort_ast.parsing.parser.parse_rules_file() is deprecated. "
    "Use surinort_ast.api.parsing.parse_file() instead.",
    DeprecationWarning,
    stacklevel=2,
)
```

**Migration Path:**
```python
# Old (deprecated):
from surinort_ast.parsing.parser import parse_rules_file
rules = parse_rules_file("rules.rules")

# New (recommended):
from surinort_ast.api.parsing import parse_file
rules = parse_file("rules.rules")
```

**Decision:** ✅ KEEP - Common pattern, needs deprecation period

---

## 5. Active TODOs (Convert to Issues)

### Query Module - Phase 1 (Core Features)

#### TODO-001: Early Exit Optimization

**Location:** `src/surinort_ast/query/executor.py:597`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Performance optimization |
| **Phase** | 1 (Core) |
| **Comment** | `# TODO: Implement early exit in Phase 1` |
| **Action** | Create GitHub issue |

**Context:**
```python
def _execute_with_descendant_combinator(self, ...):
    # TODO: Implement early exit in Phase 1
    # Could stop searching once we have matches
```

---

#### TODO-002: Child Combinator

**Location:** `src/surinort_ast/query/executor.py:625`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Core feature |
| **Phase** | 1 (Core) |
| **Comment** | `# TODO: Implement in Phase 1` |
| **Action** | Create GitHub issue |

**Context:**
```python
def _execute_with_child_combinator(self, ...):
    # TODO: Implement in Phase 1
```

---

#### TODO-003: Query Parser Validation

**Location:** `src/surinort_ast/query/parser.py:504`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Validation logic |
| **Phase** | 1 (Core) |
| **Comment** | `# TODO: Implement validation in Phase 1` |
| **Action** | Create GitHub issue |

---

#### TODO-004: Parser Feature

**Location:** `src/surinort_ast/query/parser.py:527`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Core parser feature |
| **Phase** | 1 (Core) |
| **Comment** | `# TODO: Implement in Phase 1` |
| **Action** | Create GitHub issue |

---

#### TODO-005: Selector Implementation

**Location:** `src/surinort_ast/query/selectors.py:790`

| Property | Value |
|----------|-------|
| **Severity** | MEDIUM |
| **Type** | Core selector feature |
| **Phase** | 1 (Core) |
| **Comment** | `# TODO: Implement in Phase 1` |
| **Action** | Create GitHub issue |

---

### Query Module - Phase 3 (Advanced Features)

#### TODO-006: Preceding Siblings

**Location:** `src/surinort_ast/query/executor.py:518`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced feature |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3 (post-MVP)` |
| **Action** | Create GitHub issue |

**Context:**
```python
def _collect_preceding_siblings(self, node: ASTNode, parent: ASTNode) -> list[ASTNode]:
    # TODO: Implement in Phase 3 (post-MVP)
```

---

#### TODO-007: Following Siblings

**Location:** `src/surinort_ast/query/executor.py:539`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced feature |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3 (post-MVP)` |
| **Action** | Create GitHub issue |

---

#### TODO-008: Adjacent Sibling Combinator

**Location:** `src/surinort_ast/query/executor.py:707`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced combinator |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3` |
| **Action** | Create GitHub issue |

---

#### TODO-009: General Sibling Combinator

**Location:** `src/surinort_ast/query/executor.py:729`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced combinator |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3` |
| **Action** | Create GitHub issue |

---

#### TODO-010: Advanced Query Feature 1

**Location:** `src/surinort_ast/query/__init__.py:475`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced feature |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3` |
| **Action** | Create GitHub issue |

---

#### TODO-011: Advanced Query Feature 2

**Location:** `src/surinort_ast/query/__init__.py:511`

| Property | Value |
|----------|-------|
| **Severity** | LOW |
| **Type** | Advanced feature |
| **Phase** | 3 (Post-MVP) |
| **Comment** | `# TODO: Implement in Phase 3` |
| **Action** | Create GitHub issue |

---

## 6. NOT Deprecated (Keep - Architectural)

### Protocol Interfaces (Essential Architecture)

#### ARCH-001: Query Protocols

**Location:** `src/surinort_ast/query/protocols.py`

| Property | Value |
|----------|-------|
| **Type** | Circular dependency solution |
| **Purpose** | Break circular imports using structural typing |
| **Status** | ✅ ESSENTIAL - Keep |
| **Action** | None |

**Protocols Defined:**
- `SelectorProtocol`
- `PseudoSelectorProtocol`
- `SelectorChainProtocol`
- `ExecutionContextProtocol`
- `QueryExecutorProtocol`

**Reason to Keep:** This is the **solution** to circular dependencies, not legacy code.

---

#### ARCH-002: Parser Interface

**Location:** `src/surinort_ast/parsing/interfaces.py`

| Property | Value |
|----------|-------|
| **Type** | Dependency injection interface |
| **Purpose** | Enable parser swapping, SOLID principles |
| **Status** | ✅ ESSENTIAL - Keep |
| **Action** | None |

**Protocol Defined:**
- `IParser` - Parser interface using Protocol for dependency injection

**Reason to Keep:** Core architectural pattern for:
- Dependency inversion
- Parser library independence
- Testability
- Extensibility

---

## 7. User-Facing Deprecations (Keep)

### RULE-001: uricontent Deprecated Warning

**Location:** `src/surinort_ast/parsing/mixins/content_transformer.py:233-238`

| Property | Value |
|----------|-------|
| **Type** | IDS rule syntax deprecation |
| **Purpose** | Warn users about deprecated rule options |
| **Status** | ✅ CORRECT - Keep |
| **Action** | None |

**Code:**
```python
self._diagnostics.append(
    Diagnostic(
        level=DiagnosticLevel.WARNING,
        message="uricontent is deprecated, use content with http_uri buffer",
        location=location,
    )
)
```

**Reason to Keep:** Helps users migrate their IDS rule files. This is user-facing, not code deprecation.

---

## 8. Files Already Deleted (29 files)

These files are deleted in the working directory but not yet committed:

### Documentation (18 files)
- API_REFERENCE.md
- ARCHITECTURE.md
- AST_SPEC.md
- DEPENDENCIES.md
- DEPENDENCY_SUMMARY.md
- DEPLOYMENT_SUMMARY.md
- DOCUMENTATION_STRUCTURE.md
- DOCUMENTATION_SUMMARY.md
- ENVIRONMENT.md
- GRAMMAR.md
- INSTALL.md
- PRINTER_SERIALIZER_IMPLEMENTATION.md
- PYPI_SETUP.md
- REAL_RULES_COMPATIBILITY_REPORT.md
- SETUP_COMPLETE.md
- docs/index.md
- docs/user-guide/quickstart.md
- mkdocs.yml

### Tests (8 files)
- test_api.py
- test_cli.sh
- test_real_rules.py
- test_rules.json
- test_rules.txt
- test_rules_roundtrip.txt
- tests/unit/test_transformer_edge_cases.py
- verify_venv.py

### Source (2 files)
- src/surinort_ast/builder/__init__.py
- src/surinort_ast/serialization/protobuf/__init__.py

### Dependencies (1 file)
- requirements-example.txt

**Action:** Commit with `git add -u && git commit -m "chore: remove obsolete files"`

---

## 9. Examples (Keep - Educational)

### EDU-001: parser_dependency_injection.py

**Location:** `examples/parser_dependency_injection.py`

| Property | Value |
|----------|-------|
| **Type** | Educational example |
| **Usage** | Shows deprecated RuleParser for backward compatibility demo |
| **Status** | ✅ CORRECT - Keep |
| **Action** | None |

**Function:** `example_7_backward_compatibility()`
```python
# Intentionally uses RuleParser to demonstrate it still works
old_parser = RuleParser()
```

**Reason to Keep:** Educational - shows users the migration path

---

### EDU-002: migration_examples.py

**Location:** `examples/migration_examples.py`

| Property | Value |
|----------|-------|
| **Type** | Migration guide examples |
| **Usage** | Demonstrates old vs new patterns |
| **Status** | ✅ CORRECT - Keep |
| **Action** | None |

**Reason to Keep:** Helps users understand how to migrate their code

---

## Summary Matrix

| ID | File/Item | Type | Severity | Action | Impact |
|----|-----------|------|----------|--------|--------|
| CRIT-001 | option_transformer.py.bak | Backup | HIGH | DELETE | None |
| INTERN-001 | streaming/parser.py | Deprecated API | HIGH | MIGRATE | Internal only |
| INTERN-002 | cli/commands/plugins.py | Deprecated API | MEDIUM | MIGRATE | Internal only |
| TEST-001 to TEST-009 | Test files | Deprecated API | MEDIUM | MIGRATE | Tests only |
| DEPR-001 to DEPR-003 | Public APIs | Intentional | LOW | KEEP | External users |
| TODO-001 to TODO-011 | Query TODOs | Feature | LOW | ISSUE | None |
| ARCH-001 to ARCH-002 | Protocols | Architecture | N/A | KEEP | Essential |
| RULE-001 | uricontent warning | User-facing | N/A | KEEP | User guidance |
| EDU-001 to EDU-002 | Examples | Educational | N/A | KEEP | User education |

---

## Recommended Priority Order

1. **IMMEDIATE (Day 1):**
   - Remove backup file (CRIT-001)
   - Migrate internal source (INTERN-001, INTERN-002)
   - Run tests
   - Commit

2. **SHORT-TERM (Week 1-2):**
   - Migrate test files (TEST-001 to TEST-009)
   - Create PR
   - Merge after review

3. **MEDIUM-TERM (Month 1):**
   - Create GitHub issues for TODOs (TODO-001 to TODO-011)
   - Update CHANGELOG with v2.0.0 deprecation plan
   - Review documentation

4. **LONG-TERM (v2.0.0):**
   - Remove deprecated public APIs (DEPR-001 to DEPR-003)
   - Remove backward compatibility wrappers
   - Update major version

---

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**Next Review:** Before v2.0.0 release
