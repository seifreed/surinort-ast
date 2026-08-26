from pathlib import Path

DOCS_WORKFLOW = Path(".github/workflows/docs.yml")


def test_pages_deploys_the_site_built_with_the_dashboard_snapshot() -> None:
    workflow = DOCS_WORKFLOW.read_text(encoding="utf-8")

    build = workflow[workflow.index("  build:") : workflow.index("  # Deploy to GitHub Pages")]
    deploy = workflow[
        workflow.index("  deploy:") : workflow.index("  # Documentation link checker")
    ]

    snapshot = workflow[
        workflow.index("- name: Generate conformance dashboard snapshot") : workflow.index(
            "- name: Require MkDocs configuration"
        )
    ]
    assert "if: ${{ github.event_name != 'pull_request' }}" in snapshot
    assert 'snapshot="conformance/history/bundled-${GITHUB_SHA}.json"' in build
    assert 'semantic_snapshot="conformance/history/semantic-${GITHUB_SHA}.json"' in build
    assert "tools/semantic_matrix.py" in build
    assert "actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9" in build
    assert "path: site/" in build
    assert "actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128" in deploy
    assert "contents: write" not in deploy
    assert "mkdocs gh-deploy" not in deploy
