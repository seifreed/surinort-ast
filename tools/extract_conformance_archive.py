"""Safely extract an authorized gzip-compressed conformance archive."""

from __future__ import annotations

import argparse
import tarfile
from pathlib import Path


def extract_archive(archive_path: Path, destination: Path) -> None:
    """Extract regular files and directories without allowing archive escapes."""
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (root / member.name).resolve()
            if target != root and root not in target.parents:
                raise ValueError(f"archive member escapes extraction directory: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"archive links are not allowed: {member.name}")
            if not member.isfile() and not member.isdir():
                raise ValueError(f"archive member type is not allowed: {member.name}")
        archive.extractall(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    extract_archive(args.archive, args.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
