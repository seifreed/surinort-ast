"""
File-path security validation (CWE-22 and CWE-209 prevention).

Single source of truth for resolving and validating file paths against
directory-traversal, symlink, and information-disclosure risks. API and CLI
layers wrap this with their own exception types.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path


class PathSecurityError(Exception):
    """Raised when a path fails CWE-22 traversal/symlink validation."""


def sanitize_path_for_error(path: Path) -> str:
    """
    Return only the filename for use in error messages.

    Prevents CWE-209 (Information Exposure Through Error Messages) by stripping
    directory components that could reveal system structure.
    """
    return path.name


def validate_path(
    path: Path,
    *,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
    must_exist: bool = False,
) -> Path:
    """
    Resolve ``path`` and validate it against security constraints.

    Implements CWE-22 (Path Traversal) prevention: always validates the RESOLVED
    path, never the raw input. Rejects embedded null bytes and (by default)
    symlinks, and — when ``allowed_base`` is given — enforces that the resolved
    path stays within that base directory.

    Args:
        path: Path to validate.
        allowed_base: Base directory that must contain the resolved path.
        allow_symlinks: Whether to permit symlinks (default: False).
        must_exist: Whether the path must already exist (``Path.resolve`` strict).

    Returns:
        The resolved absolute path.

    Raises:
        PathSecurityError: If the path is invalid or violates a constraint.
    """
    if "\x00" in str(path):
        raise PathSecurityError(f"Invalid path: {sanitize_path_for_error(path)}")

    try:
        resolved = path.resolve(strict=must_exist)
    except (OSError, RuntimeError) as e:
        raise PathSecurityError(f"Invalid path: {sanitize_path_for_error(path)}") from e

    if not allow_symlinks and path.is_symlink():
        raise PathSecurityError(f"Symlinks not allowed: {sanitize_path_for_error(path)}")

    if allowed_base is not None:
        try:
            allowed_resolved = allowed_base.resolve()
        except (OSError, RuntimeError) as e:
            raise PathSecurityError("Invalid base directory") from e

        if not resolved.is_relative_to(allowed_resolved):
            raise PathSecurityError(
                f"Path outside allowed directory: {sanitize_path_for_error(path)}"
            )

    return resolved
