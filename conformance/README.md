# Conformance lab

Run the checked-in corpus with:

```bash
python tools/conformance_lab.py --output conformance/report.json
```

The runner measures per-rule parse success and structural equality after
`parse -> print -> parse`. Files below `conformance/corpus/<dialect>/` select
the dialect. Files in an `invalid/` directory are expected to fail parsing.

An installed engine can be used as an additional check with a command template:

```bash
python tools/conformance_lab.py \
  --engine-command 'suricata -T -S {file}'
```

Engine validation is reported as `passed`, `failed`, `timeout`, or
`unavailable`; the parser conformance check remains independent of local engine
availability.
