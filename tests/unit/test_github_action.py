from pathlib import Path


def test_github_action_declares_validation_inputs_and_sarif_output() -> None:
    action = Path("action.yml").read_text(encoding="utf-8")

    assert "using: composite" in action
    for input_name in (
        "rules",
        "dialect",
        "engine",
        "engine-version",
        "capability-file",
        "sarif",
        "engine-command",
        "engine-verify",
        "comment",
    ):
        assert f"  {input_name}:" in action
    assert "  sarif-file:" in action
    assert "  baseline:" in action
    assert "CAPABILITY_FILE: ${{ inputs.capability-file }}" in action
    assert 'args+=(--capability-file "$CAPABILITY_FILE")' in action
    assert "capability-file requires engine and engine-version" in action
