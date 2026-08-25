# Engine Validation

The parser and printer can be checked against real Suricata and Snort
installations with the versioned matrix runner:

```bash
python -m tools.engine_matrix \
  --matrix conformance/engine-matrix.example.json \
  --output engine-matrix-report.json
```

Each entry must identify an engine, concrete version label, dialect, manifest,
and command containing `{file}`. The command is executed without a shell. A
missing binary, rejected original rule, rejected printed rule, timeout, or
behavior mismatch is recorded as an unexpected failure.

The example matrix is a declaration template, not evidence that those engines
are installed. Publish a report only after running it with the exact engine
builds and configuration used for the release. For optimizer behavior checks,
add a `pcap` path and a command containing both `{file}` and `{pcap}`; the
conformance report then compares the original and printed ruleset output.

For an optimized ruleset, compare the original and candidate files over a
fixture battery:

```bash
python -m tools.optimizer_behavior_lab \
  --original rules/original.rules \
  --candidate rules/optimized.rules \
  --pcap traffic/one.pcap \
  --pcap traffic/two.pcap \
  --engine-command 'suricata -T -S {file} --pcap {pcap}' \
  --output optimizer-behavior-report.json
```

The report is evidence only for the supplied engine build, configuration, and
PCAPs. It must not be generalized into a universal semantic-equivalence claim.
