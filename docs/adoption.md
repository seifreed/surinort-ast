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

For version-aware LSP diagnostics and documentation, configure the concrete
engine target in VS Code settings:

```json
{
  "surinortAst.engine": "suricata",
  "surinortAst.engineVersion": "8.0.6",
  "surinortAst.capabilityFile": "conformance/capabilities/4.0.0-local.json"
}
```

The release workflow publishes the extension to the Marketplace through the
`vscode-marketplace` environment. Configure the `VSCE_PAT` environment secret
for the `seifreed` publisher before creating a release tag; publication is a
required release job. Until the first publication is completed, the signed
`.vsix` attached to the GitHub release is the canonical extension artifact.

Use the [release verification checklist](release-verification.md) to verify
public tags, checksums, provenance, and SBOMs after publishing a release.
