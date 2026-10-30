# Versioned Deliverables

The `4.0.x` compatibility line contains these deliverables:

| Deliverable | Version | Installation | Verification |
| --- | --- | --- | --- |
| Python package and `surinort-lsp` | `4.0.1` | `pip install surinort-ast==4.0.1` | `surinort-lsp` over stdio |
| GitHub Action | `v4.0.1` | `uses: seifreed/surinort-ast@v4.0.1` | Action validation and optional engine check |
| VS Code extension | `4.0.1` | Install the `.vsix` release asset | VS Code `^1.85.0` |

The extension is also installable from the repository during development:

```bash
python -m pip install surinort-ast==4.0.1
code --install-extension editors/vscode
```

For version-aware LSP diagnostics and documentation, configure the concrete
engine target in VS Code settings. The engine value may be `suricata`, `snort`,
`snort2`, or `snort3`; Snort aliases resolve only to compatible major versions:

```json
{
  "surinortAst.engine": "suricata",
  "surinortAst.engineVersion": "8.0.6",
  "surinortAst.capabilityFile": "conformance/capabilities/4.0.0-local.json"
}
```

The release workflow publishes the extension to the Marketplace when the
`VSCE_PAT` secret is configured in the `vscode-marketplace` environment. If the
secret is absent, Marketplace publishing is skipped; the signed `.vsix` attached
to the GitHub release remains the canonical extension artifact.

PyPI uses Trusted Publisher through the `pypi` environment, so no PyPI token is
stored in GitHub. Register this publisher on the `surinort-ast` PyPI project
with owner `seifreed`, repository `surinort-ast`, workflow
`.github/workflows/release.yml`, and environment `pypi`. The workflow grants
`id-token: write` only to the publishing job.

Use the [release verification checklist](release-verification.md) to verify
public tags, checksums, provenance, and SBOMs after publishing a release.
