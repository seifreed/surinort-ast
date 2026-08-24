from pathlib import Path


def test_github_action_declares_validation_inputs_and_sarif_output() -> None:
    action = Path("action.yml").read_text(encoding="utf-8")

    assert "using: composite" in action
    for input_name in (
        "rules",
        "dialect",
        "engine",
        "engine-version",
        "sarif",
        "engine-command",
        "engine-verify",
    ):
        assert f"  {input_name}:" in action
    assert "  sarif-file:" in action
