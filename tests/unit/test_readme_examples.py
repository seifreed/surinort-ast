"""Keep executable README examples aligned with the public CLI surface."""

from __future__ import annotations

import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from typer.main import get_command

from surinort_ast.cli import app

README = Path(__file__).parents[2] / "README.md"
FENCE = re.compile(r"^```(?P<language>[^\n]*)\n(?P<body>.*?)^```$", re.MULTILINE | re.DOTALL)


def _blocks(language: str) -> list[str]:
    return [
        match.group("body")
        for match in FENCE.finditer(README.read_text(encoding="utf-8"))
        if match.group("language").strip() == language
    ]


def test_python_readme_examples_compile() -> None:
    blocks = _blocks("python")
    assert blocks
    for index, block in enumerate(blocks):
        compile(block, f"README.md:python:{index}", "exec")


def test_readme_cli_commands_exist() -> None:
    command = get_command(app)
    documented = re.findall(
        r"^\s*surinort\s+([a-z][a-z0-9-]*)\b",
        "\n".join(_blocks("bash")),
        re.MULTILINE,
    )

    assert documented
    assert set(documented) <= set(command.commands)


def test_readme_yaml_examples_have_unique_keys() -> None:
    class UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
        pass

    def construct_mapping(
        loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
    ) -> dict:
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                raise AssertionError(f"duplicate YAML key in README: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )

    blocks = _blocks("yaml")
    assert blocks
    for block in blocks:
        yaml.load(block, Loader=UniqueKeyLoader)
