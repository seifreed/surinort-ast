"""Build a Snort 2 keyword capability snapshot from detection-plugin sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from surinort_ast.analysis import EngineTarget

_REGISTERED_OPTION = re.compile(r'RegisterRuleOption\s*\(\s*"([^"]+)"')
_CORE_RULE_KEYWORDS = frozenset(
    {
        "classtype",
        "detection_filter",
        "gid",
        "metadata",
        "msg",
        "priority",
        "reference",
        "rev",
        "sid",
        "ssl_state",
    }
)


def _tree_sha256(files: list[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def registered_keywords(source_dir: Path) -> tuple[frozenset[str], str, int]:
    """Return registered Snort 2 options and a deterministic source fingerprint."""
    files = sorted(path for path in source_dir.rglob("*.c") if path.is_file())
    if not files:
        raise ValueError(f"no C source files found below {source_dir}")
    keywords = {
        match.group(1).lower()
        for path in files
        for match in _REGISTERED_OPTION.finditer(path.read_text(encoding="utf-8"))
    }
    if not keywords:
        raise ValueError(f"no RegisterRuleOption calls found below {source_dir}")
    return frozenset(keywords), _tree_sha256(files, source_dir), len(files)


def snapshot(source_dir: Path, version: str) -> dict[str, Any]:
    """Create a versioned source-backed Snort 2 capability snapshot."""
    registered, source_sha256, source_file_count = registered_keywords(source_dir)
    target = EngineTarget(
        engine="snort2",
        version=version,
        keywords=registered | _CORE_RULE_KEYWORDS,
        keyword_catalog_complete=True,
    )
    return {
        "schema_version": 1,
        "scope": "Snort 2 detection-plugin registrations plus observed core rule keywords",
        "sources": [
            {
                "kind": "source-tree",
                "path": "src/detection-plugins",
                "sha256": source_sha256,
                "file_count": source_file_count,
            }
        ],
        "targets": [target.to_dict()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rendered = json.dumps(snapshot(args.source_dir, args.version), indent=2, sort_keys=True) + "\n"
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
