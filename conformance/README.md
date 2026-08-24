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

For differential behavior checks, provide a traffic fixture and an engine
command containing both placeholders. The lab runs the original and printed
rule against the same fixture and reports a mismatch as an unexpected failure:

```bash
python tools/conformance_lab.py \
  --manifest conformance/manifest.json \
  --engine-command 'suricata --runmode autofp -S {file} -r {pcap}' \
  --pcap fixtures/http.pcap
```
