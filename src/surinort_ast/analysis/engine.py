"""Run an explicitly configured IDS engine against a rule file."""

from __future__ import annotations

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


class EngineVerifier:
    """Execute a trusted engine command without invoking a shell.

    The command must contain a ``{file}`` placeholder. Arguments are parsed
    with :func:`shlex.split`, so shell operators are intentionally unsupported.
    """

    def __init__(self, command: str, timeout: float = 30.0) -> None:
        parts = shlex.split(command)
        if not parts or "{file}" not in command:
            raise ValueError("engine command must include a {file} placeholder")
        if timeout <= 0:
            raise ValueError("engine timeout must be greater than zero")
        self.command = command
        self.timeout = timeout
        self._parts = parts

    def verify(self, path: Path) -> EngineVerification:
        """Validate ``path`` and return a stable status instead of raising."""
        parts = [part.replace("{file}", str(path)) for part in self._parts]
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


__all__ = ["EngineVerification", "EngineVerifier"]
