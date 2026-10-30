# Release Verification

Release verification must be performed against the public GitHub release, not
against a local build. The commands below verify the annotated tag, checksums,
GitHub build provenance, and the published SBOM files.

```bash
REPO=seifreed/surinort-ast
TAG=v4.0.1
DIR="release-${TAG}"

TAG_REF=$(gh api "repos/${REPO}/git/ref/tags/${TAG}")
test "$(jq -r '.object.type' <<<"${TAG_REF}")" = tag
TAG_OBJECT=$(jq -r '.object.sha' <<<"${TAG_REF}")
test "$(gh api "repos/${REPO}/git/tags/${TAG_OBJECT}" --jq '.verification.verified')" = true

gh release download "${TAG}" --repo "${REPO}" --dir "${DIR}"
(cd "${DIR}" && sha256sum --check --strict SHA256SUMS)

for file in "${DIR}"/*.whl "${DIR}"/*.tar.gz "${DIR}"/*.vsix "${DIR}"/sbom.json "${DIR}"/sbom.xml; do
  sigstore verify identity "${file}" \
    --bundle "${file}.sigstore.json" \
    --cert-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
    --cert-oidc-issuer "https://token.actions.githubusercontent.com"
  gh attestation verify "${file}" \
    --repo "${REPO}" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "${TAG}"
done

test -s "${DIR}/sbom.json"
test -s "${DIR}/sbom.xml"
```

The tag check rejects lightweight or unverified tags. The checksum, Sigstore,
and attestation checks must pass for every wheel, source archive, VS Code
extension, and published SBOM. A release is not considered verified when an expected artifact,
signature bundle, checksum, SBOM, or provenance record is missing.

Run this checklist against each published tag and retain its complete output
with the release record. The workflow's own checks do not replace downloading and
verifying the assets exposed by the public GitHub release.
