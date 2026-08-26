# License Decision

## Decision

The project remains licensed under the GNU General Public License, version 3
or later (`GPL-3.0-or-later`). No relicensing, LGPL exception, dual license, or
commercial license is offered by this repository.

This decision applies to the Python package, the `surinort-lsp` executable, the
GitHub Action, and the VS Code client distributed from this repository. The
canonical terms are in [`LICENSE`](https://github.com/seifreed/surinort-ast/blob/main/LICENSE).

## Rationale

The existing source headers, package metadata, VS Code manifest, and published
documentation already use GPL-3.0-or-later. Keeping one license avoids making
the SDK embedding and distribution terms ambiguous while preserving the
project's current copyleft terms.

This is a project-maintainer decision, not legal advice. Revisit it before
accepting a contribution or distribution arrangement that requires proprietary
embedding, an LGPL exception, or a separate commercial license.
