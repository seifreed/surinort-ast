const vscode = require("vscode");
const { spawn } = require("child_process");

function activate(context) {
  const command = vscode.workspace.getConfiguration("surinortAst").get("lspCommand", "surinort-lsp");
  const server = spawn(command, [], { shell: false, stdio: ["pipe", "pipe", "inherit"] });
  let nextId = 1;
  let input = Buffer.alloc(0);
  const pending = new Map();
  const diagnostics = vscode.languages.createDiagnosticCollection("surinort-ast");

  function send(message) {
    const body = Buffer.from(JSON.stringify(message));
    server.stdin.write(Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]));
  }

  function request(method, params) {
    const id = nextId++;
    send({ jsonrpc: "2.0", id, method, params });
    return new Promise((resolve) => pending.set(id, resolve));
  }

  function consume(chunk) {
    input = Buffer.concat([input, chunk]);
    while (true) {
      const separator = input.indexOf("\r\n\r\n");
      if (separator < 0) return;
      const header = input.subarray(0, separator).toString("ascii");
      const match = header.match(/Content-Length:\s*(\d+)/i);
      if (!match) return;
      const length = Number(match[1]);
      const start = separator + 4;
      if (input.length < start + length) return;
      const message = JSON.parse(input.subarray(start, start + length).toString("utf8"));
      input = input.subarray(start + length);
      if (message.id !== undefined && pending.has(message.id)) {
        pending.get(message.id)(message.result);
        pending.delete(message.id);
      }
      if (message.method === "textDocument/publishDiagnostics") {
        const uri = vscode.Uri.parse(message.params.uri);
        diagnostics.set(uri, (message.params.diagnostics || []).map((item) => {
          const range = new vscode.Range(
            item.range.start.line,
            item.range.start.character,
            item.range.end.line,
            item.range.end.character,
          );
          const severity = [null, vscode.DiagnosticSeverity.Error, vscode.DiagnosticSeverity.Warning, vscode.DiagnosticSeverity.Information][item.severity] || vscode.DiagnosticSeverity.Information;
          const diagnostic = new vscode.Diagnostic(range, item.message, severity);
          diagnostic.code = item.code;
          diagnostic.source = item.source;
          return diagnostic;
        }));
      }
    }
  }

  server.stdout.on("data", consume);
  server.on("error", (error) => vscode.window.showErrorMessage(`Surinort LSP failed: ${error.message}`));
  context.subscriptions.push(diagnostics);

  request("initialize", {
    processId: process.pid,
    rootUri: vscode.workspace.workspaceFolders?.[0]?.uri.toString() || null,
    capabilities: {},
  }).then(() => send({ jsonrpc: "2.0", method: "initialized", params: {} }));

  function open(document) {
    if (!["suricata", "snort2", "snort3"].includes(document.languageId)) return;
    send({
      jsonrpc: "2.0",
      method: "textDocument/didOpen",
      params: { textDocument: { uri: document.uri.toString(), languageId: document.languageId, version: document.version, text: document.getText() } },
    });
  }

  for (const document of vscode.workspace.textDocuments) {
    if (["suricata", "snort2", "snort3"].includes(document.languageId)) open(document);
  }
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(open));
  context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
    if (!["suricata", "snort2", "snort3"].includes(event.document.languageId)) return;
    send({
      jsonrpc: "2.0",
      method: "textDocument/didChange",
      params: { textDocument: { uri: event.document.uri.toString(), version: event.document.version }, contentChanges: [{ text: event.document.getText() }] },
    });
  }));
  context.subscriptions.push(vscode.languages.registerHoverProvider(["suricata", "snort2", "snort3"], {
    provideHover(document, position) {
      return request("textDocument/hover", {
        textDocument: { uri: document.uri.toString() },
        position: { line: position.line, character: position.character },
      }).then((result) => result ? new vscode.Hover(result.contents.value || result.contents) : undefined);
    },
  }));
  context.subscriptions.push({
    dispose() {
      send({ jsonrpc: "2.0", id: nextId++, method: "shutdown", params: null });
      send({ jsonrpc: "2.0", method: "exit", params: null });
      server.kill();
      diagnostics.dispose();
    },
  });
}

function deactivate() {}

module.exports = { activate, deactivate };
