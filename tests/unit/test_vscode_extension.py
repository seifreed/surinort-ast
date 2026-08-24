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
