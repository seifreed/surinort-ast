# Versioned Deliverables

The `4.0.0` compatibility line contains these deliverables:

| Deliverable | Version | Installation | Verification |
| --- | --- | --- | --- |
| Python package and `surinort-lsp` | `4.0.0` | `pip install surinort-ast==4.0.0` | `surinort-lsp` over stdio |
| GitHub Action | `v4.0.0` | `uses: seifreed/surinort-ast@v4.0.0` | Action validation and optional engine check |
| VS Code extension | `4.0.0` | Install the `.vsix` release asset | VS Code `^1.85.0` |

The extension is also installable from the repository during development:

```bash
python -m pip install surinort-ast==4.0.0
code --install-extension editors/vscode
```

Marketplace publication is a separate external operation requiring the
publisher account and token. Until that operation is completed, the signed
`.vsix` attached to the GitHub release is the canonical extension artifact.

Use the [release verification checklist](release-verification.md) to verify
public tags, checksums, provenance, and SBOMs after publishing a release.
