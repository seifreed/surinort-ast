# Conformance Lab

The checked-in corpus is a small, redistributable smoke corpus. Run it with:

```bash
python tools/conformance_lab.py --manifest conformance/manifest.json
```

Larger corpora can be supplied with `--corpus` and described by a local JSON
manifest. Keep externally sourced rules outside this repository unless their
license permits redistribution. A manifest records the dialect and expected
parse result per file, plus constructions that require an engine or deployment
configuration and therefore cannot be proven by the AST alone.

The repository also includes `manifest.bundled.json` for the three tracked
corpora. It reproduces the aggregate parser measurement without adding any
external rules:

```bash
python tools/conformance_lab.py \
  --manifest conformance/manifest.bundled.json \
  --output conformance/bundled-report.json
```

Summary reports include each input file's byte size and SHA-256 fingerprint;
the published snapshot is rendered in the [conformance dashboard](../docs/conformance-dashboard.md).
Use `--summary-only` when publishing aggregate evidence without per-rule cases.

## External corpus workflow

The manual `External Conformance` workflow accepts an authorized `.tar.gz`
corpus without storing its rules in this repository. The archive must contain
`*.rules` files; include `suricata`, `snort2`, or `snort3` in their paths when
the dialect differs from the Suricata default. Supply the archive URL, its
SHA-256 digest, and a source/license label in the workflow dispatch form. The
workflow verifies the digest, runs the lab, and uploads
`external-conformance-report.json` even when the corpus has unexpected
failures.

The versioned semantic target matrix is reproducible locally with:

```bash
python tools/semantic_matrix.py \
  --manifest conformance/semantic-matrix.json \
  --output semantic-matrix-report.json
```

It compares exact diagnostic sets for Suricata 8.0.6, Snort 2.9.20, and Snort
3.12.2.0 across the declared semantic cases. Adding a case requires its
expected result for every target so unsupported engine differences stay
explicit.

For differential behavior checks, provide a traffic fixture and an engine
command containing both placeholders. The command must print a stable alert
projection to stdout. The repository includes a Suricata adapter because
Suricata writes alerts to EVE JSON rather than stdout:

```bash
python tools/conformance_lab.py \
  --manifest conformance/manifest.json \
  --engine-command 'python tools/suricata_behavior.py --rules {file} --pcap {pcap}' \
  --pcap fixtures/http.pcap
```

The lab runs the original and printed rule against the same fixture and
reports a mismatch in the normalized alert projection as an unexpected
failure.

For engine-load checks without a traffic fixture, use the engine's native
rule-loading command. Snort++ can validate both Snort 3 and compatible Snort 2
rule syntax:

```bash
python tools/conformance_lab.py \
  --corpus conformance/corpus/snort3 \
  --engine-command 'snort -R {file} -T'
```

Snort2 does not support Snort3's `-R` rules-file option. Use the checked-in
config-template wrapper instead:

```bash
python tools/conformance_lab.py \
  --corpus conformance/corpus/snort2 \
  --engine-command 'python tools/snort2_engine.py --config conformance/engines/snort2-2.9.20.conf --rules {file}'
```

For a complete ruleset check, `tools/engine_scale.py` parses and prints every
rule, then loads the combined original and printed rulesets once in the native
engine. Its JSON report records per-file hashes, parse/round-trip rates,
throughput, memory, and engine status for both loads.

```bash
python -m tools.engine_scale \
  --manifest /path/to/manifest.json \
  --engine-command 'suricata -T -c /etc/suricata/suricata.yaml -S {file}' \
  --output /tmp/engine-scale.json
```
