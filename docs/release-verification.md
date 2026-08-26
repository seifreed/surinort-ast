# Release Verification

Release verification must be performed against the public GitHub release, not
against a local build. The commands below verify the annotated tag, checksums,
GitHub build provenance, and the published SBOM files.

```bash
REPO=seifreed/surinort-ast
TAG=v4.0.0
DIR="release-${TAG}"

TAG_REF=$(gh api "repos/${REPO}/git/ref/tags/${TAG}")
test "$(jq -r '.object.type' <<<"${TAG_REF}")" = tag
TAG_OBJECT=$(jq -r '.object.sha' <<<"${TAG_REF}")
test "$(gh api "repos/${REPO}/git/tags/${TAG_OBJECT}" --jq '.verification.verified')" = true

gh release download "${TAG}" --repo "${REPO}" --dir "${DIR}"
(cd "${DIR}" && sha256sum --ignore-missing -c SHA256SUMS)

for file in "${DIR}"/*.whl "${DIR}"/*.tar.gz "${DIR}"/*.vsix; do
  gh attestation verify "${file}" \
    --repo "${REPO}" \
    --signer-workflow .github/workflows/release.yml
done

test -s "${DIR}/sbom.json"
test -s "${DIR}/sbom.xml"
```

The tag check rejects lightweight or unverified tags. The attestation check
must pass for every wheel, source archive, and VS Code extension. A release is
not considered verified when an expected artifact, checksum, SBOM, or
provenance bundle is missing.

The current repository contains release workflow support for this procedure;
the commands become evidence for `v3.0.5` and `v4.0.0` only after those public
releases have been created and the complete output has been retained.
