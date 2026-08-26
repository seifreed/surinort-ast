from pathlib import Path

RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
CI_WORKFLOW = Path(".github/workflows/ci.yml")


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


def test_release_requires_a_verified_annotated_tag_before_building() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    tag_format = workflow.index("- name: Verify tag format")
    signed_tag = workflow.index("- name: Verify signed release tag")
    merged_tag = workflow.index("- name: Verify release commit is merged into main")
    setup_python = workflow.index("- name: Set up Python", signed_tag)

    assert tag_format < signed_tag < merged_tag < setup_python
    signed_tag_block = workflow[signed_tag:setup_python]
    assert 'git rev-parse "${VERSION}^{tag}"' in signed_tag_block
    assert "must be an annotated tag" in signed_tag_block
    assert "git/tags/${TAG_OBJECT}" in signed_tag_block
    assert ".verification.verified" in signed_tag_block
    assert "git fetch --no-tags origin main" in signed_tag_block
    assert 'git merge-base --is-ancestor "${VERSION}^{commit}" "origin/main"' in signed_tag_block
    assert "must point to a commit already merged into main" in signed_tag_block


def test_github_release_attaches_downloaded_provenance_bundles() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    download = workflow.index("- name: Download build provenance bundles")
    release = workflow.index("- name: Create GitHub Release", download)
    github_release = workflow.index("  github-release:")
    release_block = workflow[release : workflow.index("  # Sign release artifacts", release)]

    assert download < release
    assert "attestations: read" in workflow[github_release:download]
    assert (
        'gh attestation download "../$file" --repo "$GITHUB_REPOSITORY"'
        in workflow[download:release]
    )
    assert "provenance/*.jsonl" in release_block


def test_github_release_does_not_upload_sigstore_bundles_twice() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    release = workflow[workflow.index("- name: Create GitHub Release") :]
    files = release[
        release.index("          files: |") : release.index("          fail_on_unmatched_files:")
    ]

    file_patterns = [
        line.strip()
        for line in files.splitlines()
        if line.strip() and not line.strip().endswith("files: |")
    ]

    assert "dist/*" not in file_patterns
    assert {"dist/*.whl", "dist/*.tar.gz", "dist/*.vsix"} <= set(file_patterns)
    assert file_patterns.count("signed-artifacts/*.sigstore.json") == 1


def test_release_publishes_and_signs_the_versioned_vscode_artifact() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    build = workflow[workflow.index("  build:") : workflow.index("  # Generate release notes")]
    pypi = workflow[workflow.index("  publish-pypi:") : workflow.index("  # Create GitHub Release")]
    signing = workflow[
        workflow.index("  sign-artifacts:") : workflow.index("  # Post-release verification")
    ]

    assert "vsce package --no-dependencies" in build
    assert "surinort-ast-${{ needs.validate.outputs.version }}.vsix" in build
    assert "twine check dist/*.whl dist/*.tar.gz" in build
    assert "rm -f dist/*.vsix" in pypi
    assert "for file in *.whl *.tar.gz *.vsix; do" in signing


def test_release_publishes_vscode_extension_to_marketplace() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    publish = workflow[
        workflow.index("  publish-vscode:") : workflow.index("  # Sign release artifacts")
    ]

    assert "needs: [validate, build, github-release]" in publish
    assert "name: vscode-marketplace" in publish
    assert "secrets.VSCE_PAT" in publish
    assert 'vsce publish --packagePath dist/*.vsix --pat "$VSCE_PAT"' in publish
    summary = workflow[workflow.index("  release-success:") :]
    assert "publish-vscode" in summary
    assert "needs.publish-vscode.result" in summary


def test_ci_summary_matches_the_protected_branch_check_name() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "ci-success:" in workflow
    summary = workflow[workflow.index("ci-success:") :]
    assert "name: CI Success" in summary
