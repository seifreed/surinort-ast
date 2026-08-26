const vscode = require("vscode");
const { spawn } = require("child_process");
const path = require("path");

function configuredCapabilityFile() {
  const configured = vscode.workspace.getConfiguration("surinortAst").get("capabilityFile", "");
  if (!configured || path.isAbsolute(configured) || !vscode.workspace.workspaceFolders?.length) {
    return configured;
  }
  return path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, configured);
}

function activate(context) {
  const command = vscode.workspace.getConfiguration("surinortAst").get("lspCommand", "surinort-lsp");
  const server = spawn(command, [], { shell: false, stdio: ["pipe", "pipe", "inherit"] });
  let nextId = 1;
  let input = Buffer.alloc(0);
  const pending = new Map();
  const diagnostics = vscode.languages.createDiagnosticCollection("surinort-ast");
  const output = vscode.window.createOutputChannel("Surinort AST");

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
    initializationOptions: {
      engine: vscode.workspace.getConfiguration("surinortAst").get("engine", ""),
      engineVersion: vscode.workspace.getConfiguration("surinortAst").get("engineVersion", ""),
      capabilityFile: configuredCapabilityFile(),
    },
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
  context.subscriptions.push(vscode.languages.registerCompletionItemProvider(["suricata", "snort2", "snort3"], {
    provideCompletionItems(document, position) {
      return request("textDocument/completion", {
        textDocument: { uri: document.uri.toString() },
        position: { line: position.line, character: position.character },
      }).then((items) => (items || []).map((item) => {
        const completion = new vscode.CompletionItem(item.label, vscode.CompletionItemKind.Keyword);
        completion.detail = item.detail;
        if (item.documentation) {
          completion.documentation = new vscode.MarkdownString(
            item.documentation.value || item.documentation,
          );
        }
        return completion;
      }));
    },
  }, ":", ";", " "));
  context.subscriptions.push(vscode.languages.registerDocumentFormattingEditProvider(["suricata", "snort2", "snort3"], {
    provideDocumentFormattingEdits(document) {
      return request("textDocument/formatting", {
        textDocument: { uri: document.uri.toString() },
        options: { tabSize: 2, insertSpaces: true },
      }).then((edits) => (edits || []).map((edit) => new vscode.TextEdit(
        new vscode.Range(
          edit.range.start.line,
          edit.range.start.character,
          edit.range.end.line,
          edit.range.end.character,
        ),
        edit.newText,
      )));
    },
  }));
  context.subscriptions.push(vscode.languages.registerCodeActionsProvider(["suricata", "snort2", "snort3"], {
    provideCodeActions(document, range) {
      return request("textDocument/codeAction", {
        textDocument: { uri: document.uri.toString() },
        range: {
          start: { line: range.start.line, character: range.start.character },
          end: { line: range.end.line, character: range.end.character },
        },
        context: { diagnostics: [] },
      }).then((actions) => (actions || []).map((action) => {
        const codeAction = new vscode.CodeAction(action.title, vscode.CodeActionKind.QuickFix);
        const edit = new vscode.WorkspaceEdit();
        const change = action.edit && action.edit.range;
        if (change) {
          edit.replace(document.uri, new vscode.Range(
            change.start.line,
            change.start.character,
            change.end.line,
            change.end.character,
          ), action.edit.newText || "");
          codeAction.edit = edit;
        }
        return codeAction;
      }));
    },
  }));
  context.subscriptions.push(vscode.languages.registerDefinitionProvider(["suricata", "snort2", "snort3"], {
    provideDefinition(document, position) {
      return request("textDocument/definition", {
        textDocument: { uri: document.uri.toString() },
        position: { line: position.line, character: position.character },
      }).then((locations) => (locations || []).map((location) => new vscode.Location(
        vscode.Uri.parse(location.uri),
        new vscode.Range(
          location.range.start.line,
          location.range.start.character,
          location.range.end.line,
          location.range.end.character,
        ),
      )));
    },
  }));
  context.subscriptions.push(vscode.languages.registerReferenceProvider(["suricata", "snort2", "snort3"], {
    provideReferences(document, position) {
      return request("textDocument/references", {
        textDocument: { uri: document.uri.toString() },
        position: { line: position.line, character: position.character },
        context: { includeDeclaration: true },
      }).then((locations) => (locations || []).map((location) => new vscode.Location(
        vscode.Uri.parse(location.uri),
        new vscode.Range(
          location.range.start.line,
          location.range.start.character,
          location.range.end.line,
          location.range.end.character,
        ),
      )));
    },
  }));
  context.subscriptions.push(vscode.commands.registerCommand("surinortAst.validateWithEngine", async () => {
    const editor = vscode.window.activeTextEditor;
    const command = vscode.workspace.getConfiguration("surinortAst").get("engineCommand", "");
    if (!editor || !command) {
      vscode.window.showErrorMessage("Configure surinortAst.engineCommand and open a rule file first.");
      return;
    }
    const result = await request("surinort/engineValidate", {
      textDocument: { uri: editor.document.uri.toString() },
      command,
    });
    if (result && result.status === "passed") {
      vscode.window.showInformationMessage("Surinort engine validation passed.");
    } else {
      vscode.window.showErrorMessage(`Surinort engine validation: ${result?.status || "error"}`);
    }
  }));
  context.subscriptions.push(vscode.commands.registerCommand("surinortAst.showMatchSpace", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const result = await request("surinort/matchSpacePreview", {
      textDocument: { uri: editor.document.uri.toString() },
    });
    output.clear();
    output.appendLine(JSON.stringify(result, null, 2));
    output.show(true);
  }));
  context.subscriptions.push({
    dispose() {
      send({ jsonrpc: "2.0", id: nextId++, method: "shutdown", params: null });
      send({ jsonrpc: "2.0", method: "exit", params: null });
      server.kill();
      diagnostics.dispose();
      output.dispose();
    },
  });
}

function deactivate() {}

module.exports = { activate, deactivate };
