# Migration Checklist

**Project:** surinort-ast API Migration
**Author:** Marc Rivero López
**License:** GNU General Public License v3.0

---

## For Users: Migrating Your Code

This checklist helps you migrate your codebase to the new modular API structure.

### Phase 1: Assessment (15-30 minutes)

- [ ] **Review your current imports**
  ```bash
  # Find all surinort-ast imports in your project
  grep -r "from surinort_ast import" your_project/
  grep -r "import surinort_ast" your_project/
  ```

- [ ] **Check your surinort-ast version**
  ```bash
  pip show surinort-ast
  ```

- [ ] **Read the migration strategy**
  - Review `docs/API_MIGRATION_STRATEGY.md`
  - Understand that both import patterns work

- [ ] **Estimate migration scope**
  - Count files using surinort-ast imports
  - Identify critical vs. non-critical code paths
  - Plan testing strategy

### Phase 2: Preparation (30-60 minutes)

- [ ] **Backup your code**
  ```bash
  git commit -m "Pre-migration checkpoint"
  # Or create a branch
  git checkout -b migrate-surinort-ast-api
  ```

- [ ] **Update surinort-ast to v1.1.0+**
  ```bash
  pip install --upgrade surinort-ast
  ```

- [ ] **Run existing tests**
  ```bash
  pytest  # or your test command
  ```
  - Ensure all tests pass before migration
  - Establish baseline

- [ ] **Install migration tools (optional)**
  ```bash
  # For automated migration
  python /path/to/surinort-ast/tools/migrate_imports.py --help

  # For AST-based migration
  pip install libcst
  ```

### Phase 3: Migration (1-4 hours, depending on codebase size)

#### Option A: Automated Migration (Recommended)

- [ ] **Run dry-run migration**
  ```bash
  python tools/migrate_imports.py /path/to/your/project --dry-run
  ```

- [ ] **Review proposed changes**
  - Check the migration report
  - Verify changes are correct
  - Identify any edge cases

- [ ] **Apply migration with backups**
  ```bash
  python tools/migrate_imports.py /path/to/your/project --backup
  ```

- [ ] **Review changes in version control**
  ```bash
  git diff
  ```

#### Option B: Manual Migration

- [ ] **Migrate parsing imports**
  ```python
  # Old
  from surinort_ast import parse_rule, parse_file

  # New
  from surinort_ast.api.parsing import parse_rule, parse_file
  ```

- [ ] **Migrate serialization imports**
  ```python
  # Old
  from surinort_ast import to_json, from_json

  # New
  from surinort_ast.api.serialization import to_json, from_json
  ```

- [ ] **Migrate validation imports**
  ```python
  # Old
  from surinort_ast import validate_rule

  # New
  from surinort_ast.api.validation import validate_rule
  ```

- [ ] **Migrate printing imports**
  ```python
  # Old
  from surinort_ast import print_rule

  # New
  from surinort_ast.api.printing import print_rule
  ```

### Phase 4: Testing (1-2 hours)

- [ ] **Run all tests**
  ```bash
  pytest  # or your test command
  ```

- [ ] **Verify critical paths**
  - Test rule parsing
  - Test serialization/deserialization
  - Test validation
  - Test printing/formatting

- [ ] **Check for import errors**
  ```bash
  python -c "from surinort_ast.api.parsing import parse_rule; print('OK')"
  python -c "from surinort_ast.api.serialization import to_json; print('OK')"
  ```

- [ ] **Run linting and type checking**
  ```bash
  ruff check .
  mypy your_project/
  ```

- [ ] **Performance testing (if applicable)**
  - Verify no performance regression
  - Check memory usage
  - Test with large rulesets

### Phase 5: Validation (30-60 minutes)

- [ ] **Code review**
  - Review all changed files
  - Verify import statements are correct
  - Check for any missed imports

- [ ] **Documentation updates**
  - Update your project's README if it shows import examples
  - Update internal documentation
  - Add migration notes to your changelog

- [ ] **Clean up**
  ```bash
  # Remove backup files if migration successful
  find . -name "*.bak" -delete
  ```

### Phase 6: Deployment

- [ ] **Commit changes**
  ```bash
  git add .
  git commit -m "Migrate to surinort-ast modular API structure"
  ```

- [ ] **Update dependencies**
  - Update `requirements.txt` or `pyproject.toml` if needed
  - Pin surinort-ast version if desired: `surinort-ast>=1.1.0`

- [ ] **CI/CD pipeline**
  - Ensure CI tests pass
  - Verify deployment pipeline works

- [ ] **Deploy to staging/testing**
  - Test in non-production environment
  - Verify functionality

- [ ] **Deploy to production**
  - Follow your standard deployment process
  - Monitor for issues

### Phase 7: Post-Migration Monitoring

- [ ] **Monitor application logs**
  - Check for import errors
  - Verify expected behavior

- [ ] **User acceptance testing**
  - Validate functionality with stakeholders
  - Gather feedback

- [ ] **Performance monitoring**
  - Check for any degradation
  - Verify resource usage

---

## For Maintainers: Managing the Migration

This checklist helps maintainers coordinate the migration effort.

### Pre-Release Preparation

- [ ] **Complete migration infrastructure**
  - [x] Create migration strategy document
  - [x] Build automated migration tool
  - [x] Create LibCST codemods
  - [ ] Write migration examples
  - [ ] Prepare communication materials

- [ ] **Update documentation**
  - [ ] Update README.md with new import patterns
  - [ ] Update quickstart guide
  - [ ] Create migration guide
  - [ ] Update API reference
  - [ ] Add migration banner to docs site

- [ ] **Update examples**
  - [ ] Migrate all examples to modular imports
  - [ ] Create before/after examples
  - [ ] Test all examples

- [ ] **Testing**
  - [ ] Test migration tool on real projects
  - [ ] Verify both import patterns work
  - [ ] Add regression tests
  - [ ] Test with different Python versions

### v1.1.0 Release Checklist

- [ ] **Code freeze**
  - [ ] All migration infrastructure merged
  - [ ] All tests passing
  - [ ] Documentation complete

- [ ] **Release preparation**
  - [ ] Update version to 1.1.0
  - [ ] Update CHANGELOG.md
  - [ ] Tag release in git
  - [ ] Build distribution packages

- [ ] **Communication**
  - [ ] Draft release notes
  - [ ] Prepare announcement
  - [ ] Update documentation site
  - [ ] Schedule social media posts

- [ ] **Release**
  - [ ] Publish to PyPI
  - [ ] Create GitHub release
  - [ ] Update documentation site
  - [ ] Post announcements

### Post-Release Monitoring (v1.1.x)

- [ ] **Track adoption**
  - [ ] Monitor GitHub issues
  - [ ] Track discussions/questions
  - [ ] Gather user feedback

- [ ] **Support users**
  - [ ] Answer migration questions
  - [ ] Help with edge cases
  - [ ] Improve documentation based on feedback

- [ ] **Iterate on tooling**
  - [ ] Fix migration tool bugs
  - [ ] Add requested features
  - [ ] Improve error messages

### v1.2.0 Preparation (Deprecation Period)

- [ ] **Soft deprecation**
  - [ ] Add documentation notes about preferred patterns
  - [ ] Update all official examples
  - [ ] Create migration success stories

- [ ] **Enhanced tooling**
  - [ ] Improve migration tool based on feedback
  - [ ] Add more automated checks
  - [ ] Create video tutorials (optional)

- [ ] **Community engagement**
  - [ ] Write blog posts
  - [ ] Present at meetups (optional)
  - [ ] Gather testimonials

### v2.0.0 Planning (12+ months out)

- [ ] **Evaluate migration success**
  - [ ] Survey adoption rate
  - [ ] Review issue tracker
  - [ ] Assess community sentiment

- [ ] **Decide on breaking changes**
  - [ ] Current plan: No breaking changes
  - [ ] Re-evaluate based on usage data
  - [ ] Consult with major users

- [ ] **Prepare for major release**
  - [ ] Finalize v2.0.0 scope
  - [ ] Plan migration for stragglers
  - [ ] Create comprehensive migration guide

---

## Troubleshooting

### Common Issues

#### Import Error: "No module named 'surinort_ast.api.parsing'"

**Solution:** Upgrade to surinort-ast v1.1.0+
```bash
pip install --upgrade surinort-ast
```

#### Migration Tool Doesn't Detect Imports

**Possible Causes:**
- Using wildcard imports (`from surinort_ast import *`) - not recommended
- Dynamic imports - migrate manually
- Imports in generated code - exclude from migration

**Solution:** Review file manually and migrate explicitly

#### Tests Fail After Migration

**Debugging Steps:**
1. Check if migration tool modified test files incorrectly
2. Verify all imports are correct
3. Check for circular import issues
4. Review diff carefully

**Solution:** Restore from backup and migrate manually

#### Performance Regression

**Investigation:**
- Profile your application before/after migration
- Check if lazy loading is being used effectively
- Verify no accidental eager imports

**Solution:** Imports should not affect performance. If you see issues, report a bug.

---

## Quick Reference

### Import Migration Map

| Old Import | New Import | Category |
|------------|-----------|----------|
| `from surinort_ast import parse_rule` | `from surinort_ast.api.parsing import parse_rule` | Parsing |
| `from surinort_ast import parse_rules` | `from surinort_ast.api.parsing import parse_rules` | Parsing |
| `from surinort_ast import parse_file` | `from surinort_ast.api.parsing import parse_file` | Parsing |
| `from surinort_ast import parse_file_streaming` | `from surinort_ast.api.parsing import parse_file_streaming` | Parsing |
| `from surinort_ast import to_json` | `from surinort_ast.api.serialization import to_json` | Serialization |
| `from surinort_ast import from_json` | `from surinort_ast.api.serialization import from_json` | Serialization |
| `from surinort_ast import to_json_schema` | `from surinort_ast.api.serialization import to_json_schema` | Serialization |
| `from surinort_ast import validate_rule` | `from surinort_ast.api.validation import validate_rule` | Validation |
| `from surinort_ast import print_rule` | `from surinort_ast.api.printing import print_rule` | Printing |

### Multi-Import Example

```python
# Old (single import line)
from surinort_ast import parse_rule, to_json, validate_rule

# New (modular - multiple lines)
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.validation import validate_rule
```

---

## Support

### Getting Help

- **Documentation:** [https://seifreed.github.io/surinort-ast](https://seifreed.github.io/surinort-ast)
- **Issues:** [GitHub Issues](https://github.com/seifreed/surinort-ast/issues)
- **Discussions:** [GitHub Discussions](https://github.com/seifreed/surinort-ast/discussions)

### Reporting Migration Problems

When reporting issues, include:
1. Your surinort-ast version (`pip show surinort-ast`)
2. Python version (`python --version`)
3. Error message or unexpected behavior
4. Minimal reproducible example
5. Output of migration tool (if used)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-25
**License:** GNU General Public License v3.0
