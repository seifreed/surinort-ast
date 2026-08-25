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
