# Security Policy

## Supported Versions

The following versions of surinort-ast are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The surinort-ast team takes security issues seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

If you discover a security vulnerability, please follow these steps:

1. **DO NOT** open a public GitHub issue
2. Email the maintainer directly at: mriverolopez@gmail.com
3. Include the following information:
   - Type of vulnerability
   - Full description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if available)

### What to Expect

- **Initial Response**: Within 48 hours of your report
- **Status Update**: Within 7 days with a preliminary assessment
- **Resolution Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 60 days

### Security Update Process

1. Vulnerability is verified and assessed
2. Fix is developed in a private repository
3. Security advisory is drafted
4. Patch is released and advisory is published
5. Reporter is credited (if desired)

## Security Best Practices

When using surinort-ast:

1. **Keep Dependencies Updated**: Regularly update to the latest version
2. **Validate Input**: Always validate rule files from untrusted sources
3. **Sandboxing**: Parse untrusted rules in isolated environments
4. **Monitor Advisories**: Watch the GitHub Security Advisories for this project

## Known Security Considerations

### Input Validation

surinort-ast parses complex rule syntax. When parsing rules from untrusted sources:

- Use resource limits to prevent denial of service
- Validate file sizes before parsing
- Consider parsing in a sandboxed environment

### Supply Chain Security

This project implements:

- Pinned dependencies with integrity verification
- Automated security scanning (Bandit, Safety)
- SBOM generation for transparency
- Signed releases with Sigstore

## Security Scanning

This project uses:

- **Bandit**: SAST for Python security issues
- **Safety**: Dependency vulnerability scanning
- **pip-audit**: PyPI package audit
- **Dependabot**: Automated dependency updates
- **Pre-commit hooks**: Secret detection and validation

## Secure Development

Contributors should:

1. Never commit secrets or credentials
2. Run security checks before submitting PRs
3. Follow secure coding practices
4. Review dependencies before adding them

## Contact

Security concerns: mriverolopez@gmail.com
General issues: https://github.com/seifreed/surinort-ast/issues

## Attribution

This security policy is based on industry best practices and is maintained by Marc Rivero López.
