"""Run an explicitly configured IDS engine against a rule file."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EngineVerification:
    """Outcome of one engine validation attempt."""

    status: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""

    @property
    def passed(self) -> bool:
        """Whether the engine accepted the input."""
        return self.status == "passed"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable result."""
        return asdict(self)


@dataclass(frozen=True)
class BehavioralVerification:
    """Comparison of engine output for an original and candidate ruleset."""

    status: str
    original: EngineVerification
    candidate: EngineVerification

    @property
    def passed(self) -> bool:
        """Whether both runs succeeded and emitted identical output."""
        return self.status == "passed"


class EngineVerifier:
    """Execute a trusted engine command without invoking a shell.

    The command must contain a ``{file}`` placeholder. Arguments are parsed
    with :func:`shlex.split`, so shell operators are intentionally unsupported.
    """

    def __init__(self, command: str, timeout: float = 30.0) -> None:
        parts = shlex.split(command, posix=os.name != "nt")
        if os.name == "nt":
            parts = [
                part[1:-1] if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'" else part
                for part in parts
            ]
        if not parts or "{file}" not in command:
            raise ValueError("engine command must include a {file} placeholder")
        if timeout <= 0:
            raise ValueError("engine timeout must be greater than zero")
        self.command = command
        self.timeout = timeout
        self._parts = parts

    def verify(self, path: Path) -> EngineVerification:
        """Validate ``path`` and return a stable status instead of raising."""
        return self._execute(path)

    def verify_behavior(
        self, original: Path, candidate: Path, pcap: Path
    ) -> BehavioralVerification:
        """Run both rulesets against ``pcap`` and compare their stdout."""
        if "{pcap}" not in self.command:
            raise ValueError("behavior command must include a {pcap} placeholder")
        original_result = self._execute(original, pcap)
        candidate_result = self._execute(candidate, pcap)
        if not original_result.passed:
            status = original_result.status
        elif not candidate_result.passed:
            status = candidate_result.status
        elif original_result.stdout != candidate_result.stdout:
            status = "mismatch"
        else:
            status = "passed"
        return BehavioralVerification(status, original_result, candidate_result)

    def _execute(self, path: Path, pcap: Path | None = None) -> EngineVerification:
        if pcap is None and "{pcap}" in self.command:
            raise ValueError("engine command containing {pcap} requires behavior verification")
        parts = [part.replace("{file}", str(path)) for part in self._parts]
        if pcap is not None:
            parts = [part.replace("{pcap}", str(pcap)) for part in parts]
        if shutil.which(parts[0]) is None:
            return EngineVerification(status="unavailable")
        try:
            completed = subprocess.run(
                parts,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return EngineVerification(
                status="timeout",
                stdout=(exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout) or "",
                stderr=(exc.stderr.decode() if isinstance(exc.stderr, bytes) else exc.stderr) or "",
            )
        except OSError as exc:
            return EngineVerification(status="error", stderr=str(exc))
        return EngineVerification(
            status="passed" if completed.returncode == 0 else "failed",
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


__all__ = ["BehavioralVerification", "EngineVerification", "EngineVerifier"]
