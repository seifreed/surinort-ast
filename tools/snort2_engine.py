"""Validate a Snort2 ruleset by injecting it into a config template."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

_RULE_INCLUDE = "include /rules/community.rules"


def render_config(template: str, rules: Path) -> str:
    """Replace the fixture include with one absolute ruleset path."""
    if template.count(_RULE_INCLUDE) != 1:
        raise ValueError(f"config must contain exactly one {_RULE_INCLUDE!r} line")
    return template.replace(_RULE_INCLUDE, f"include {rules.resolve()}")


def validate(
    rules: Path,
    config: Path,
    engine: str = "snort",
    timeout: float = 30.0,
) -> int:
    """Run Snort2 in test mode with the supplied ruleset."""
    if not rules.is_file():
        raise FileNotFoundError(rules)
    if not config.is_file():
        raise FileNotFoundError(config)
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    if shutil.which(engine) is None:
        print(f"engine not found: {engine}", file=sys.stderr)
        return 127

    with TemporaryDirectory(prefix="surinort-snort2-") as directory:
        generated = Path(directory) / "snort.conf"
        generated.write_text(
            render_config(config.read_text(encoding="utf-8"), rules), encoding="utf-8"
        )
        try:
            completed = subprocess.run(
                [engine, "-T", "-c", str(generated)],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"engine timed out after {timeout}s", file=sys.stderr)
            return 124
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--engine", default="snort")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    return validate(args.rules, args.config, args.engine, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
