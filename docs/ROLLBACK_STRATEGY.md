# Rollback Strategy - API Migration

**Project:** surinort-ast
**Author:** Marc Rivero López
**License:** GNU General Public License v3.0

---

## Overview

This document defines the rollback strategy for the surinort-ast API migration. While the migration is designed to be non-breaking and low-risk, this guide provides clear procedures for reverting changes if unexpected issues arise.

---

## Risk Assessment

### Migration Risk Level: **LOW**

**Rationale:**
- Both import patterns work simultaneously
- No breaking changes introduced
- Users migrate at their own pace
- Extensive testing performed
- Rollback capability built-in

### Potential Issues Requiring Rollback

| Issue | Severity | Likelihood | Impact |
|-------|----------|------------|--------|
| Migration tool damages code | High | Very Low | Individual users |
| Documentation confusion | Medium | Low | All users |
| Import incompatibility | High | Very Low | Specific Python versions |
| Performance regression | Medium | Very Low | All users |
| Unexpected breaking change | Critical | Very Low | All users |

---

## Rollback Scenarios

### Scenario 1: Migration Tool Issues

**Symptoms:**
- Migration tool incorrectly transforms imports
- User code breaks after running migration tool
- Tool crashes or produces invalid Python

**Impact:** Individual users who ran the tool

**Rollback Procedure:**

1. **Immediate User Action**
   ```bash
   # Restore from git
   git checkout <file>  # Restore specific file
   git reset --hard HEAD  # Restore all files (if not committed)

   # Or restore from backup
   cp file.py.bak file.py
   ```

2. **Tool Fix**
   - Identify bug in migration tool
   - Create regression test
   - Fix and release updated tool
   - Notify users who downloaded tool

3. **Communication**
   ```markdown
   ## Migration Tool Issue - v1.1.0

   We've identified a bug in the migration tool that affects [specific scenario].

   **If you ran the tool:**
   - Review changes carefully before committing
   - Use git diff to check modifications
   - Restore from backup if needed

   **Fix available:**
   - Updated tool released: [link]
   - Issue tracking: #XXX

   **Affected versions:** tools/migrate_imports.py from v1.1.0 release
   **Fixed in:** v1.1.1 (patch release)
   ```

**Prevention:**
- Thorough testing of migration tool on diverse codebases
- Always create backups by default
- Dry-run mode prominently featured
- Clear warnings about reviewing changes

---

### Scenario 2: Documentation Confusion

**Symptoms:**
- Increased GitHub issues about import confusion
- Users report unclear migration path
- Conflicting information in documentation

**Impact:** All users, particularly new users

**Rollback Procedure:**

1. **Assess Confusion**
   - Review GitHub issues
   - Identify common confusion points
   - Determine root cause

2. **Documentation Fix**
   ```markdown
   # Add prominent clarification to README.md

   ## Import Patterns - Clarification

   **Both patterns work in all v1.x versions:**

   ```python
   # Pattern 1: Convenience (works everywhere)
   from surinort_ast import parse_rule

   # Pattern 2: Modular (recommended for new code)
   from surinort_ast.api.parsing import parse_rule
   ```

   **You do NOT need to migrate.** Choose what works for you.
   ```

3. **Communication**
   - Post clarification in GitHub Discussions
   - Update FAQ
   - Add banner to documentation site
   - Send clarification email (if applicable)

4. **Monitoring**
   - Track if confusion decreases
   - Adjust documentation further if needed
   - Consider video tutorial if confusion persists

**Prevention:**
- Clear, prominent messaging about backward compatibility
- Examples showing both patterns with clear labels
- FAQ addressing common confusion points
- Community review of documentation before release

---

### Scenario 3: Import Incompatibility

**Symptoms:**
- Imports fail on specific Python versions
- Import errors in specific environments
- Circular import issues

**Impact:** Users on affected Python versions/environments

**Rollback Procedure:**

1. **Immediate Patch**
   ```python
   # Fix in src/surinort_ast/api/__init__.py

   # Add compatibility shim if needed
   try:
       from .parsing import parse_rule
   except ImportError:
       # Fallback for incompatible environments
       from ..legacy_api import parse_rule
   ```

2. **Patch Release**
   - Create v1.1.1 with fix
   - Publish to PyPI immediately
   - Document issue and fix in release notes

3. **Communication**
   ```markdown
   ## Critical Fix: Import Compatibility (v1.1.1)

   **Issue:** Imports fail on [specific Python version/environment]

   **Fix:** Upgrade to v1.1.1
   ```bash
   pip install --upgrade surinort-ast
   ```

   **Workaround (if can't upgrade):**
   - Use top-level imports only
   - Avoid modular imports until upgrade

   **Details:** GitHub issue #XXX
   ```

**Prevention:**
- Test on all supported Python versions (3.11-3.14)
- Test on multiple platforms (Linux, macOS, Windows)
- CI/CD testing for all environments
- Beta testing period before release

---

### Scenario 4: Performance Regression

**Symptoms:**
- Import time increased significantly
- Memory usage increased
- Runtime performance degraded

**Impact:** All users

**Rollback Procedure:**

1. **Verify Regression**
   ```bash
   # Benchmark import time
   python -m timeit "from surinort_ast import parse_rule"
   python -m timeit "from surinort_ast.api.parsing import parse_rule"

   # Profile memory
   python -m memory_profiler script.py
   ```

2. **Identify Cause**
   - Check for circular imports
   - Verify lazy loading works correctly
   - Profile import chain

3. **Fix Options**

   **Option A: Quick fix (optimize imports)**
   ```python
   # Lazy import expensive modules
   def parse_rule(*args, **kwargs):
       from ..parsing.parser import LarkParser  # Lazy
       # ... rest of function
   ```

   **Option B: Patch release**
   - Implement performance fix
   - Release v1.1.1
   - Benchmark to verify improvement

   **Option C: Revert (last resort)**
   - Only if regression is severe (>50% slowdown)
   - Revert api/ structure changes
   - Release v1.1.1 with revert
   - Re-plan migration approach

4. **Communication**
   ```markdown
   ## Performance Fix (v1.1.1)

   We identified a performance regression in v1.1.0 related to
   [specific cause].

   **Fix:** Upgrade to v1.1.1

   **Performance improvement:**
   - Import time: [before] → [after]
   - Memory usage: [before] → [after]

   **Note:** We've added performance benchmarks to CI/CD to prevent
   future regressions.
   ```

**Prevention:**
- Benchmark import time in CI/CD
- Profile memory usage
- Test with large rulesets
- Lazy loading for expensive imports

---

### Scenario 5: Unexpected Breaking Change

**Symptoms:**
- User code breaks after upgrade to v1.1.0
- Functions behave differently
- Tests fail unexpectedly

**Impact:** Critical - affects existing user code

**Rollback Procedure:**

**This is the most serious scenario and requires immediate action.**

1. **Immediate Response (Within 2 hours)**
   ```markdown
   ## URGENT: Breaking Change Identified in v1.1.0

   We've identified a breaking change affecting [specific scenario].

   **Immediate action:**
   - DO NOT upgrade to v1.1.0 if you haven't already
   - If you've upgraded and are affected, downgrade:
     ```bash
     pip install surinort-ast==1.0.0
     ```

   **Status:** We're working on a fix. Updates in this issue: #XXX
   ```

2. **Investigation (Within 4 hours)**
   - Reproduce the breaking change
   - Identify affected code paths
   - Determine scope of impact
   - Plan fix strategy

3. **Fix Implementation (Within 24 hours)**

   **Option A: Hot patch (preferred)**
   ```python
   # Restore backward compatibility while keeping new features
   # Release as v1.1.1
   ```

   **Option B: Yank v1.1.0 (if severe)**
   ```bash
   # Yank from PyPI (prevents new installs)
   pip install twine
   twine yank surinort-ast 1.1.0
   ```

   **Option C: Full revert (last resort)**
   ```bash
   # Revert all v1.1.0 changes
   git revert <v1.1.0-merge-commit>
   # Release as v1.1.1
   ```

4. **Patch Release (Within 48 hours)**
   - Release fixed version (v1.1.1 or v1.0.1)
   - Publish to PyPI
   - Update documentation
   - Notify all users

5. **Communication**
   ```markdown
   ## Post-Mortem: v1.1.0 Breaking Change

   **What happened:**
   [Detailed explanation of the breaking change]

   **Who was affected:**
   [Scope of impact]

   **How we fixed it:**
   [Description of fix in v1.1.1]

   **How we'll prevent this:**
   - Added regression tests for [specific scenario]
   - Enhanced CI/CD testing
   - Extended beta testing period
   - [Other preventive measures]

   **We're sorry:**
   This was our mistake. We've implemented measures to prevent
   recurrence.

   **Questions?**
   [Contact information]
   ```

**Prevention:**
- Comprehensive test suite covering all API functions
- Test with real-world user code (with permission)
- Beta testing period with community testers
- Automated backward compatibility checks in CI/CD
- Manual review of all API changes

---

## Rollback Decision Matrix

| Issue Severity | Impact Scope | Rollback Action | Timeline |
|----------------|--------------|----------------|----------|
| Critical | All users | Full revert or immediate patch | 24-48 hours |
| High | >25% users | Hot patch release | 48-72 hours |
| Medium | <25% users | Patch in next release | 1-2 weeks |
| Low | Few users | Document workaround | Next minor release |

---

## Technical Rollback Procedures

### Rollback Type 1: Git Revert

**When:** Full revert of v1.1.0 changes needed

**Procedure:**
```bash
# 1. Create rollback branch
git checkout -b rollback-v1.1.0

# 2. Revert the merge commit
git revert -m 1 <v1.1.0-merge-commit-sha>

# 3. Test thoroughly
pytest
ruff check .
mypy src/

# 4. Update version
# Edit pyproject.toml: version = "1.0.1" or "1.1.1"

# 5. Update CHANGELOG
# Add entry explaining revert

# 6. Commit and tag
git commit -m "Revert v1.1.0 changes due to [issue]"
git tag v1.0.1  # or v1.1.1

# 7. Build and publish
python -m build
twine upload dist/*

# 8. Update documentation
# Revert documentation changes if needed
```

### Rollback Type 2: Selective Revert

**When:** Only specific changes need reverting

**Procedure:**
```bash
# 1. Identify specific commits to revert
git log --oneline

# 2. Revert specific commits
git revert <commit-sha-1> <commit-sha-2>

# 3. Test
pytest

# 4. Release patch version
# Follow standard release process
```

### Rollback Type 3: Hot Patch

**When:** Keep v1.1.0 but fix specific issue

**Procedure:**
```bash
# 1. Create hotfix branch
git checkout -b hotfix-v1.1.1 v1.1.0

# 2. Implement fix
# Edit necessary files

# 3. Test fix thoroughly
pytest
# Add regression test

# 4. Update version to v1.1.1
# Edit pyproject.toml

# 5. Update CHANGELOG
# Add fix details

# 6. Commit and release
git commit -m "Fix [issue] in v1.1.0"
git tag v1.1.1
python -m build
twine upload dist/*
```

---

## PyPI Package Management

### Yanking a Release

**When:** Version has critical bug and should not be installed

**Procedure:**
```bash
# Yank the broken version
twine yank surinort-ast 1.1.0 -m "Critical bug: [description]"

# Note: Existing installations not affected
# Only prevents new pip install surinort-ast
```

**Important:**
- Yanking doesn't delete the version
- Existing installations continue to work
- Users must explicitly downgrade or upgrade
- Use only for critical issues

### Un-Yanking (if needed)

```bash
# If yank was a mistake
twine unyank surinort-ast 1.1.0
```

---

## User Support During Rollback

### Support Checklist

- [ ] Post immediate notification on GitHub
- [ ] Update documentation with workarounds
- [ ] Create FAQ for rollback questions
- [ ] Monitor GitHub issues continuously
- [ ] Respond to affected users within 24 hours
- [ ] Provide clear upgrade/downgrade instructions
- [ ] Document lessons learned

### User Instructions Template

```markdown
## How to Rollback from v1.1.0

**If you upgraded to v1.1.0 and experienced [issue]:**

### Option 1: Downgrade to v1.0.0 (Stable)

```bash
pip install surinort-ast==1.0.0
```

### Option 2: Wait for Fix (v1.1.1 coming within [timeframe])

We're releasing a fix soon. Track progress: #XXX

### Option 3: Use Workaround

[Describe temporary workaround if available]

### Need Help?

- GitHub Issue: #XXX
- GitHub Discussions: [link]
- Email: mriverolopez@gmail.com

We apologize for the inconvenience and are working quickly to resolve this.
```

---

## Post-Rollback Actions

### Immediate (Within 48 hours)

- [ ] Release fixed version
- [ ] Verify fix resolves issue
- [ ] Update all documentation
- [ ] Notify affected users
- [ ] Post status update

### Short-term (Within 1 week)

- [ ] Conduct post-mortem
- [ ] Add regression tests
- [ ] Update CI/CD to catch issue
- [ ] Review release process
- [ ] Document lessons learned

### Long-term (Within 1 month)

- [ ] Implement preventive measures
- [ ] Improve testing coverage
- [ ] Enhance documentation
- [ ] Adjust migration timeline if needed
- [ ] Rebuild community trust

---

## Post-Mortem Template

```markdown
## Post-Mortem: [Issue Name]

**Date:** [Date]
**Severity:** [Critical/High/Medium/Low]
**Author:** Marc Rivero López

### Summary

[Brief description of what happened]

### Timeline

- **[Time]:** Issue introduced (v1.1.0 released)
- **[Time]:** Issue reported by [user/system]
- **[Time]:** Issue acknowledged
- **[Time]:** Investigation began
- **[Time]:** Root cause identified
- **[Time]:** Fix implemented
- **[Time]:** Fix released (v1.1.1)
- **[Time]:** Issue resolved

### Root Cause

[Detailed technical explanation of what went wrong]

### Impact

- **Users affected:** [Number/percentage]
- **Duration:** [Time from issue to fix]
- **Severity:** [Description of impact]

### Resolution

[How the issue was fixed]

### Preventive Measures

1. [Measure 1]
2. [Measure 2]
3. [Measure 3]

### Lessons Learned

1. [Lesson 1]
2. [Lesson 2]
3. [Lesson 3]

### Action Items

- [ ] [Action item 1] - Owner: [Name] - Deadline: [Date]
- [ ] [Action item 2] - Owner: [Name] - Deadline: [Date]
```

---

## Conclusion

While the API migration is designed to be low-risk with no breaking changes, this rollback strategy ensures we're prepared for any unexpected issues. The key principles are:

1. **Quick Response:** Acknowledge issues within hours
2. **Clear Communication:** Keep users informed at every step
3. **Multiple Options:** Provide rollback, workaround, and fix paths
4. **Learn and Improve:** Conduct post-mortems and implement preventive measures
5. **User First:** Prioritize user experience and minimize disruption

**Remember:** Because both import patterns work, most "rollback" scenarios involve fixing bugs rather than reverting the entire migration.

---

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**License:** GNU General Public License v3.0
