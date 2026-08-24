from pathlib import Path

RELEASE_WORKFLOW = Path(".github/workflows/release.yml")


def test_release_verifies_provenance_before_uploading_distributions() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    attestation = workflow.index("actions/attest-build-provenance@")
    verification = workflow.index("- name: Verify build provenance")
    upload = workflow.index("- name: Upload build artifacts")

    assert attestation < verification < upload
    verification_block = workflow[verification:upload]
    assert 'gh attestation verify "$file"' in verification_block
    assert '--repo "$GITHUB_REPOSITORY"' in verification_block
    assert "--signer-workflow .github/workflows/release.yml" in verification_block
