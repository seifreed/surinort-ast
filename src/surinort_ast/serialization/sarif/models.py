"""
SARIF 2.1.0 model helpers.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Drop None and empty list/dict fields recursively."""
    compact: dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested = _compact_dict(value)
            if nested:
                compact[key] = nested
            continue
        if isinstance(value, list):
            if value:
                compact[key] = value
            continue
        compact[key] = value
    return compact


@dataclass(frozen=True)
class SarifMessage:
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text}


@dataclass(frozen=True)
class SarifRegion:
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "startLine": self.start_line,
                "startColumn": self.start_column,
                "endLine": self.end_line,
                "endColumn": self.end_column,
            }
        )


@dataclass(frozen=True)
class SarifPhysicalLocation:
    uri: str | None = None
    region: SarifRegion | None = None

    def to_dict(self) -> dict[str, Any]:
        artifact_location: dict[str, Any] | None = None
        if self.uri is not None:
            artifact_location = {"uri": self.uri}

        return _compact_dict(
            {
                "artifactLocation": artifact_location,
                "region": self.region.to_dict() if self.region is not None else None,
            }
        )


@dataclass(frozen=True)
class SarifLocation:
    physical_location: SarifPhysicalLocation

    def to_dict(self) -> dict[str, Any]:
        return {"physicalLocation": self.physical_location.to_dict()}


@dataclass(frozen=True)
class SarifReportingDescriptor:
    id: str
    name: str
    short_description: str
    help_text: str | None = None
    properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "id": self.id,
                "name": self.name,
                "shortDescription": {"text": self.short_description},
                "help": {"text": self.help_text} if self.help_text else None,
                "properties": self.properties,
            }
        )


@dataclass(frozen=True)
class SarifResult:
    rule_id: str
    level: str
    message: SarifMessage
    locations: list[SarifLocation]
    partial_fingerprints: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "ruleId": self.rule_id,
                "level": self.level,
                "message": self.message.to_dict(),
                "locations": [location.to_dict() for location in self.locations],
                "partialFingerprints": self.partial_fingerprints,
            }
        )


@dataclass(frozen=True)
class SarifDriver:
    name: str
    version: str
    rules: list[SarifReportingDescriptor]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
        }


@dataclass(frozen=True)
class SarifRun:
    tool_driver: SarifDriver
    results: list[SarifResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"driver": self.tool_driver.to_dict()},
            "results": [result.to_dict() for result in self.results],
        }


@dataclass(frozen=True)
class SarifLog:
    runs: list[SarifRun]
    version: str = "2.1.0"
    schema: str = "https://json.schemastore.org/sarif-2.1.0.json"

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [run.to_dict() for run in self.runs],
        }


__all__ = [
    "SarifDriver",
    "SarifLocation",
    "SarifLog",
    "SarifMessage",
    "SarifPhysicalLocation",
    "SarifRegion",
    "SarifReportingDescriptor",
    "SarifResult",
    "SarifRun",
]
