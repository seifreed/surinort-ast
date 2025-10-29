# PyPI Publication Setup Guide

## Overview

Complete guide to configure surinort-ast for publication on PyPI using secure, enterprise-grade CI/CD pipelines.

## Prerequisites

### Required Accounts

1. **PyPI Account**: https://pypi.org/account/register/
2. **TestPyPI Account**: https://test.pypi.org/account/register/
3. **GitHub Repository**: https://github.com/seifreed/surinort-ast

### Local Tools

```bash
pip install build twine
```

## Step 1: Configure PyPI Trusted Publisher (Recommended)

Trusted Publishers eliminate the need to store API tokens as secrets. This is the most secure method.

### On PyPI

1. Go to https://pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Fill in:
   - **PyPI Project Name**: `surinort-ast`
   - **Owner**: `seifreed`
   - **Repository name**: `surinort-ast`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
4. Click "Add"

### On TestPyPI (for testing)

1. Go to https://test.pypi.org/manage/account/publishing/
2. Repeat the same process as above

## Step 2: Configure GitHub Environments

### Create PyPI Environment

1. Go to: https://github.com/seifreed/surinort-ast/settings/environments
2. Click "New environment"
3. Name: `pypi`
4. Configure environment protection rules:
   - Required reviewers: `seifreed` (optional)
   - Deployment branches: Only `main` and tags matching `v*`
5. Click "Save"

### Create TestPyPI Environment (optional)

Repeat for `testpypi` environment for testing releases.

## Step 3: Configure GitHub Secrets (Alternative Method)

If Trusted Publishers are not available, use API tokens:

### Generate PyPI API Token

1. Go to: https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: `surinort-ast-github-ci`
4. Scope: Select "Project: surinort-ast" (after first manual upload)
5. Copy the token (starts with `pypi-`)

### Add to GitHub Secrets

1. Go to: https://github.com/seifreed/surinort-ast/settings/secrets/actions
2. Click "New repository secret"
3. Name: `PYPI_TOKEN`
4. Value: Paste the token
5. Click "Add secret"

### Update release.yml

If using tokens instead of Trusted Publishers, modify `.github/workflows/release.yml`:

```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_TOKEN }}  # Add this line
    verbose: true
    print-hash: true
```

## Step 4: Configure Codecov (Optional)

For coverage reporting:

1. Go to: https://codecov.io/gh/seifreed/surinort-ast
2. Copy the upload token
3. Add to GitHub Secrets:
   - Name: `CODECOV_TOKEN`
   - Value: Paste token

## Step 5: First Release Checklist

Before creating your first release:

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Run full test suite
./scripts/test.sh

# 3. Build package
./scripts/build.sh

# 4. Test on TestPyPI (optional)
./scripts/publish.sh --test

# 5. Verify TestPyPI installation
pip install --index-url https://test.pypi.org/simple/ surinort-ast==0.1.0

# 6. Update version in pyproject.toml if needed
# version = "0.1.0"

# 7. Commit changes
git add pyproject.toml
git commit -m "Prepare release v0.1.0"
git push origin main

# 8. Create and push tag
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

## Step 6: Automated Release via GitHub Actions

Once the tag is pushed, GitHub Actions will automatically:

1. Run full CI pipeline (lint, test, security)
2. Build distributions (sdist, wheel)
3. Generate SBOM (Software Bill of Materials)
4. Publish to PyPI
5. Create GitHub Release
6. Sign artifacts with Sigstore

Monitor the release at:
- Actions: https://github.com/seifreed/surinort-ast/actions
- Releases: https://github.com/seifreed/surinort-ast/releases

## Step 7: Manual Release via Scripts

For manual releases without GitHub Actions:

```bash
# Full release process
./scripts/publish.sh

# Test release only
./scripts/publish.sh --test

# Dry run (validation only)
./scripts/publish.sh --dry-run
```

## Verification

After release, verify:

```bash
# Check PyPI page
open https://pypi.org/project/surinort-ast/

# Install from PyPI
pip install surinort-ast==0.1.0

# Verify installation
surinort-ast --help
python -c "import surinort_ast; print(surinort_ast.__version__)"
```

## Troubleshooting

### Permission Denied on PyPI

**Problem**: Upload fails with 403 Forbidden

**Solutions**:
1. Verify Trusted Publisher configuration matches exactly
2. Ensure environment name in workflow matches PyPI configuration
3. Check that workflow is triggered by a tag push

### Package Already Exists

**Problem**: Version already exists on PyPI

**Solution**: Versions on PyPI are immutable. Increment version in `pyproject.toml`:

```toml
version = "0.1.1"
```

### Build Failures

**Problem**: Package build fails

**Solutions**:
1. Run `./scripts/build.sh` locally to see detailed errors
2. Ensure all files are committed
3. Check `MANIFEST.in` includes all necessary files
4. Verify `pyproject.toml` syntax

### Test Failures in CI

**Problem**: Tests pass locally but fail in CI

**Solutions**:
1. Check Python version compatibility (3.11-3.14)
2. Review OS-specific issues (Ubuntu, macOS, Windows)
3. Ensure all dependencies are in `requirements.txt`

## Security Best Practices

1. **Never commit API tokens**: Use Trusted Publishers or GitHub Secrets
2. **Review releases**: Check GitHub Actions logs before approval
3. **Verify artifacts**: Download and test before announcing
4. **Monitor security**: Watch for Dependabot alerts

## GitHub Branch Protection

Recommended settings for `main` branch:

1. Go to: https://github.com/seifreed/surinort-ast/settings/branches
2. Add rule for `main`:
   - Require pull request reviews before merging
   - Require status checks to pass:
     - `security`
     - `lint`
     - `test`
     - `coverage`
     - `build`
   - Require conversation resolution before merging
   - Require linear history
   - Include administrators

## Post-Release Tasks

After successful release:

1. Update `CHANGELOG.md` with release notes
2. Announce on relevant channels
3. Close related issues and PRs
4. Update documentation if needed
5. Monitor PyPI download statistics

## Support

For issues with:
- **PyPI publication**: https://github.com/pypi/support/issues
- **GitHub Actions**: https://github.com/seifreed/surinort-ast/issues
- **Package bugs**: https://github.com/seifreed/surinort-ast/issues

---

**Copyright**: Marc Rivero López
**License**: GNU General Public License v3.0
**Last Updated**: 2025-10-29
