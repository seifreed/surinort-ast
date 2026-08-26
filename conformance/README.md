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
