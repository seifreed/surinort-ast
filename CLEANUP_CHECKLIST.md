# Cleanup Checklist - surinort-ast

**Quick reference for code cleanup tasks**

## ✅ Immediate Actions (Do Now)

### 1. Remove Backup File
```bash
rm /Users/seifreed/tools/malware/surinort-ast/src/surinort_ast/parsing/mixins/option_transformer.py.bak
```
- **Size:** 44KB
- **Impact:** None
- **Why:** Left over from refactoring

### 2. Fix StreamParser (Internal Code)
**File:** `src/surinort_ast/streaming/parser.py`

```python
# Line 26 - CHANGE:
from ..parsing.parser import RuleParser
# TO:
from ..parsing.lark_parser import LarkRuleParser

# Line 133 - CHANGE:
self._parser = RuleParser(
# TO:
self._parser = LarkRuleParser(

# Line 529 - CHANGE:
parser = RuleParser(dialect=dialect, strict=False, error_recovery=True)
# TO:
parser = LarkRuleParser(dialect=dialect, strict=False, error_recovery=True)
```

**Test:** `pytest tests/unit/test_streaming* -v`

### 3. Fix CLI Plugin Command (Internal Code)
**File:** `src/surinort_ast/cli/commands/plugins.py`

```python
# Line 243 - CHANGE:
from surinort_ast.parsing import parse_rules_file
# TO:
from surinort_ast.api.parsing import parse_file

# Line 264 - CHANGE:
rules = parse_rules_file(input_file)
# TO:
rules = parse_file(input_file)
```

**Test:** `pytest tests/unit/test_cli* -v`

### 4. Commit Immediate Changes
```bash
# After making above changes:
git add -A
git commit -m "chore: remove backup file and migrate internal code from deprecated APIs

- Remove option_transformer.py.bak (44KB)
- Migrate StreamParser to use LarkRuleParser
- Migrate CLI plugins command to use parse_file from API
- No public API changes, internal refactoring only"

# Run full test suite
pytest tests/ -v

# If tests pass, push
git push origin main
```

---

## 📋 Test Migration (Plan for Later)

### Files to Migrate (9 files)

Create branch first:
```bash
git checkout -b test/migrate-deprecated-parser
```

#### Test Files Requiring Migration:

1. **test_api_exception_handlers.py**
   - Replace: `RuleParser` → `LarkRuleParser`

2. **test_location_nodes_core.py**
   - Replace: `RuleParser` → `LarkRuleParser`

3. **test_parser_error_recovery.py**
   - Replace: `RuleParser` → `LarkRuleParser`
   - Replace: `parse_rule` import to use `surinort_ast.api.parsing`

4. **test_parser_specific_lines.py**
   - Replace: `RuleParser(strict=...)` → `LarkRuleParser(strict=...)`

5. **test_parser_visit_errors.py**
   - Replace: `RuleParser` → `LarkRuleParser`

6. **test_redos_protection.py**
   - Replace: All `RuleParser` → `LarkRuleParser`

7. **test_transformer_coverage.py**
   - Replace: `RuleParser` → `LarkRuleParser`

8. **test_transformer_real_world_rules.py**
   - Replace: ~40 instances of `RuleParser` → `LarkRuleParser`

9. **test_parser_initialization.py**
   - Decision needed: Remove or migrate to test LarkRuleParser directly

#### Migration Template (for each file):

```bash
# 1. Edit file
# 2. Replace imports:
#    from surinort_ast.parsing.parser import RuleParser
#    → from surinort_ast.parsing.lark_parser import LarkRuleParser
#
# 3. Replace all instances: RuleParser( → LarkRuleParser(
#
# 4. Test
pytest tests/unit/<file_name>.py -v

# 5. Commit
git commit -m "test: migrate <file_name> to LarkRuleParser"
```

#### Final Steps:
```bash
# After all 9 files migrated:
pytest tests/ -v

# Create PR
gh pr create \
  --title "Migrate test suite from deprecated RuleParser to LarkRuleParser" \
  --body "Migrates 9 test files to use LarkRuleParser instead of deprecated RuleParser wrapper. No functional changes, tests remain identical."
```

---

## 🗂️ Create GitHub Issues (Optional)

Convert 11 TODOs in query module to issues:

### Phase 1 TODOs (Core Features):
1. Early exit optimization in descendant combinator (`executor.py:597`)
2. Child combinator implementation (`executor.py:625`)
3. Validation in query parser (`parser.py:504`)
4. Parser feature (`parser.py:527`)
5. Selector implementation (`selectors.py:790`)

### Phase 3 TODOs (Advanced Features):
6. Preceding siblings collection (`executor.py:518`)
7. Following siblings collection (`executor.py:539`)
8. Adjacent sibling combinator (`executor.py:707`)
9. General sibling combinator (`executor.py:729`)
10. Advanced query feature 1 (`__init__.py:475`)
11. Advanced query feature 2 (`__init__.py:511`)

**Template for issues:**
```markdown
## Description
Implement [feature name] for query module

## Location
File: `src/surinort_ast/query/[filename].py`
Line: [line number]

## Context
[Copy TODO comment and surrounding context]

## Implementation Phase
- [ ] Phase 1 (Core)
- [ ] Phase 3 (Advanced)

## Dependencies
- None / [list dependencies]

Labels: `enhancement`, `query-module`, `phase-1` or `phase-3`
```

---

## ❌ DO NOT Remove (Keep Until v2.0.0)

These are **intentionally deprecated** for backward compatibility:

- ✅ `RuleParser` class in `src/surinort_ast/parsing/parser.py`
- ✅ `parse_rule()` function in `src/surinort_ast/parsing/parser.py`
- ✅ `parse_rules_file()` function in `src/surinort_ast/parsing/parser.py`
- ✅ Exports in `src/surinort_ast/parsing/__init__.py`
- ✅ Examples showing old APIs (educational purpose)
- ✅ Protocol interfaces in `query/protocols.py` and `parsing/interfaces.py` (architectural)

**Reason:** External users depend on these. Deprecation warnings guide migration. Remove only in v2.0.0.

---

## 📊 Progress Tracking

- [ ] Remove backup file
- [ ] Fix StreamParser
- [ ] Fix CLI plugin command
- [ ] Run full test suite
- [ ] Commit and push immediate changes
- [ ] Migrate test file 1/9
- [ ] Migrate test file 2/9
- [ ] Migrate test file 3/9
- [ ] Migrate test file 4/9
- [ ] Migrate test file 5/9
- [ ] Migrate test file 6/9
- [ ] Migrate test file 7/9
- [ ] Migrate test file 8/9
- [ ] Migrate test file 9/9
- [ ] Create PR for test migration
- [ ] Create GitHub issues for TODOs (optional)

---

## 🎯 Success Criteria

**Immediate cleanup complete when:**
- ✅ Backup file deleted
- ✅ No internal source code uses deprecated RuleParser
- ✅ All tests pass
- ✅ Changes committed

**Test migration complete when:**
- ✅ All 9 test files use LarkRuleParser
- ✅ All tests pass
- ✅ PR merged

**Full cleanup complete when:**
- ✅ Immediate cleanup done
- ✅ Test migration done
- ✅ TODOs converted to issues (optional)
- ✅ CHANGELOG.md updated with v2.0.0 plan
