# surinort-ast

`surinort-ast` parses Suricata, Snort 2, and Snort 3 rules into a typed AST
that can be queried, transformed, serialized, and printed again.

## Quick start

```bash
pip install surinort-ast
surinort parse rules.rules
```

The [README](https://github.com/seifreed/surinort-ast#readme) contains the
full Python API and CLI reference.

## Scope

The parser and printers are intended for source-to-source tooling. Analysis
reports are heuristic and should be checked with the target IDS engine before
changing a production ruleset.
