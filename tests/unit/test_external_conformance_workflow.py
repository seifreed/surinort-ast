import io
import tarfile
from pathlib import Path

import pytest
from tools.extract_conformance_archive import extract_archive


def test_external_conformance_workflow_verifies_and_publishes_corpus_metrics() -> None:
    workflow = Path(".github/workflows/external-conformance.yml").read_text(encoding="utf-8")

    assert "corpus_url:" in workflow
    assert "corpus_sha256:" in workflow
    assert "source_label:" in workflow
    assert "--proto '=https' --tlsv1.2" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "tools/extract_conformance_archive.py" in workflow
    assert "--summary-only" in workflow
    assert "--output external-conformance-report.json" in workflow
    assert "set +e" in workflow
    assert 'exit "$status"' in workflow
    assert "if: always()" in workflow
    assert "external-conformance-report.json" in workflow


def _archive(path: Path, member: tarfile.TarInfo) -> None:
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(b"alert tcp any any -> any 80 (sid:1;)\n"))


def test_conformance_archive_rejects_path_traversal_and_links(tmp_path: Path) -> None:
    content = b"alert tcp any any -> any 80 (sid:1;)\n"
    safe = tarfile.TarInfo("suricata/rules.rules")
    safe.size = len(content)
    safe_archive = tmp_path / "safe.tar.gz"
    _archive(safe_archive, safe)
    safe_destination = tmp_path / "safe-extract"
    extract_archive(safe_archive, safe_destination)
    assert (safe_destination / "suricata/rules.rules").read_bytes() == content

    escaping = tarfile.TarInfo("../outside.rules")
    escaping.size = len(content)
    escaping_archive = tmp_path / "escaping.tar.gz"
    _archive(escaping_archive, escaping)

    with pytest.raises(ValueError, match="escapes extraction directory"):
        extract_archive(escaping_archive, tmp_path / "extract")

    link = tarfile.TarInfo("link.rules")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    link_archive = tmp_path / "link.tar.gz"
    with tarfile.open(link_archive, "w:gz") as archive:
        archive.addfile(link)

    with pytest.raises(ValueError, match="links are not allowed"):
        extract_archive(link_archive, tmp_path / "link-extract")
