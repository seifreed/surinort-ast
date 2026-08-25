# Surinort AST for VS Code

Install the Python package first so `surinort-lsp` is on `PATH`, then install
this directory as an extension:

```bash
code --install-extension editors/vscode
```

The extension starts the stdio language server for Suricata and Snort rule
files, publishes syntax/semantic diagnostics, and provides SID/protocol hover,
keyword completion, formatting, and safe duplicate-modifier quick fixes. Set
`surinortAst.lspCommand` when the executable is not on `PATH`.
