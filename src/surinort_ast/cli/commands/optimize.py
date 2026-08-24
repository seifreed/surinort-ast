"""Command: optimize."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated, Any

import typer

from ...analysis import EngineVerifier, RuleOptimizer
from ...api import print_rule
from ...core.enums import Dialect
from ...core.nodes import extract_sid
from ..shared import (
    DialectOption,
    OutputOption,
    cli_error_handler,
    console,
    count_rule_blocks,
    err_console,
    load_rules,
    parsing_progress,
    write_output,
)


def _result_dict(result: Any) -> dict[str, Any]:
    return {
        "sid": extract_sid(result.original),
        "changed": result.was_modified,
        "strategies": result.strategy_names,
        "estimated_improvement": result.total_improvement,
        "experimental": result.experimental,
        "confidence": result.confidence,
        "engine_verified": result.engine_verified,
        "behavior_verified": result.behavior_verified,
    }


def _verify_candidate(
    verifier: EngineVerifier, original: str, candidate: str
) -> tuple[bool, str, str]:
    with tempfile.TemporaryDirectory(prefix="surinort-optimize-") as directory:
        directory_path = Path(directory)
        original_path = directory_path / "original.rules"
        candidate_path = directory_path / "candidate.rules"
        original_path.write_text(original, encoding="utf-8")
        candidate_path.write_text(candidate, encoding="utf-8")
        original_result = verifier.verify(original_path)
        candidate_result = verifier.verify(candidate_path)
    if not original_result.passed:
        return False, "original", original_result.status
    if not candidate_result.passed:
        return False, "candidate", candidate_result.status
    return True, "", "passed"


def optimize_command(
    file: Annotated[Path | None, typer.Argument(help="Rule file to analyze")],
    dialect: DialectOption = Dialect.SURICATA,
    output: OutputOption = None,
    json_output: Annotated[
        bool, typer.Option("--json", "-j", help="Output suggestions as JSON")
    ] = False,
    suggest: Annotated[
        bool, typer.Option("--suggest", help="Report suggestions without writing changes")
    ] = False,
    apply: Annotated[
        bool, typer.Option("--apply", help="Write changes after engine verification")
    ] = False,
    in_place: Annotated[
        bool, typer.Option("--in-place", "-i", help="Replace the input file after verification")
    ] = False,
    engine_command: Annotated[
        str | None,
        typer.Option("--engine-command", help="Engine command template containing {file}"),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Engine verification timeout in seconds")
    ] = 30.0,
) -> None:
    """Suggest safe-looking optimizations; require explicit verification to apply them."""
    with cli_error_handler():
        if suggest and apply:
            raise ValueError("--suggest and --apply are mutually exclusive")
        if in_place and output is not None:
            raise ValueError("--in-place and --output are mutually exclusive")
        if apply and not (output or in_place):
            raise ValueError("--apply requires --output or --in-place")
        if apply and not engine_command:
            raise ValueError("--apply requires --engine-command")

        with parsing_progress("Optimizing rules..."):
            rules, content, source = load_rules(file, dialect)
        if len(rules) < count_rule_blocks(content):
            raise ValueError("refusing to optimize because some rules failed to parse")

        results = RuleOptimizer().optimize_ruleset(rules)
        candidate = "\n".join(print_rule(result.optimized) for result in results) + "\n"

        if apply:
            assert engine_command is not None
            verifier = EngineVerifier(engine_command, timeout)
            verified, target, status = _verify_candidate(verifier, content, candidate)
            if not verified:
                err_console.print(f"Error: engine verification failed for {target}: {status}")
                raise typer.Exit(1) from None
            for result in results:
                result.engine_verified = True
            target_path = source if in_place else output
            assert target_path is not None
            write_output(candidate, target_path)

        report = [_result_dict(result) for result in results]
        if json_output:
            console.print(json.dumps(report, indent=2, sort_keys=True))
        elif not apply:
            for item in report:
                console.print(
                    f"SID {item['sid']}: {', '.join(item['strategies']) or 'no change'} "
                    f"(estimated {item['estimated_improvement']:+.1f}%, "
                    f"confidence {item['confidence']})"
                )
