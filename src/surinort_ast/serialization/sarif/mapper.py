"""
Mapper from normalized findings to SARIF structures.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import hashlib

from ...analysis.findings import Finding
from ...version import __version__
from .models import (
    SarifDriver,
    SarifLocation,
    SarifLog,
    SarifMessage,
    SarifPhysicalLocation,
    SarifRegion,
    SarifReportingDescriptor,
    SarifResult,
    SarifRun,
)


def _build_fingerprint(finding: Finding) -> str:
    loc = finding.location
    path = loc.file_path if loc is not None and loc.file_path else ""
    start_line = str(loc.start_line) if loc is not None and loc.start_line is not None else ""
    start_column = str(loc.start_column) if loc is not None and loc.start_column is not None else ""
    seed = "|".join([finding.rule_id, path, start_line, start_column, finding.message])
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _to_rule_descriptor(finding: Finding) -> SarifReportingDescriptor:
    return SarifReportingDescriptor(
        id=finding.rule_id,
        name=finding.rule_id,
        short_description=finding.description or finding.message,
        help_text=finding.help_text,
        properties={"category": finding.category},
    )


def _to_location(finding: Finding) -> list[SarifLocation]:
    if finding.location is None:
        return []

    region = SarifRegion(
        start_line=finding.location.start_line,
        start_column=finding.location.start_column,
        end_line=finding.location.end_line,
        end_column=finding.location.end_column,
    )
    physical = SarifPhysicalLocation(uri=finding.location.file_path, region=region)
    return [SarifLocation(physical_location=physical)]


def _to_result(finding: Finding) -> SarifResult:
    return SarifResult(
        rule_id=finding.rule_id,
        level=finding.level.value,
        message=SarifMessage(text=finding.message),
        locations=_to_location(finding),
        partial_fingerprints={"surinortFingerprint": _build_fingerprint(finding)},
    )


def findings_to_sarif_log(findings: list[Finding]) -> SarifLog:
    """Build a SARIF log from findings."""
    by_rule: dict[str, SarifReportingDescriptor] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, _to_rule_descriptor(finding))

    driver = SarifDriver(name="surinort-ast", version=__version__, rules=list(by_rule.values()))
    run = SarifRun(tool_driver=driver, results=[_to_result(finding) for finding in findings])
    return SarifLog(runs=[run])


__all__ = ["findings_to_sarif_log"]
