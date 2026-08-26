from pathlib import Path

import pytest
from tools.snort2_engine import render_config


def test_render_config_replaces_rules_include(tmp_path: Path) -> None:
    rules = tmp_path / "rules.rules"

    rendered = render_config("include /rules/community.rules\n", rules)

    assert f"include {rules.resolve()}" in rendered


def test_render_config_requires_one_rules_include(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        render_config("", tmp_path / "rules.rules")
