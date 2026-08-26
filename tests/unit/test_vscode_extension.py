import json
from pathlib import Path


def test_vscode_extension_manifest_and_entrypoint_exist() -> None:
    root = Path("editors/vscode")
    manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))

    assert manifest["main"] == "./extension.js"
    assert {event.split(":", 1)[1] for event in manifest["activationEvents"]} == {
        "suricata",
        "snort2",
        "snort3",
    }
    assert (root / manifest["main"][2:]).exists()


def test_vscode_extension_resolves_capability_files_from_workspace() -> None:
    source = Path("editors/vscode/extension.js").read_text(encoding="utf-8")

    assert "path.isAbsolute(configured)" in source
    assert "workspaceFolders[0].uri.fsPath" in source
    assert "capabilityFile: configuredCapabilityFile()" in source


def test_vscode_extension_exposes_all_supported_engine_aliases() -> None:
    manifest = json.loads(Path("editors/vscode/package.json").read_text(encoding="utf-8"))

    assert set(
        manifest["contributes"]["configuration"]["properties"]["surinortAst.engine"]["enum"]
    ) == {
        "",
        "suricata",
        "snort",
        "snort2",
        "snort3",
    }
