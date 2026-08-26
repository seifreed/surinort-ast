# Engine Validation

The parser and printer can be checked against real Suricata and Snort
installations with the versioned matrix runner:

```bash
python -m tools.engine_matrix \
  --matrix conformance/engine-matrix.example.json \
  --output engine-matrix-report.json
```

Each entry must identify an engine, concrete numeric version (for example
`8.0.6`), dialect, manifest, and command containing `{file}`. Wildcard labels
such as `8.x` are rejected because they cannot identify reproducible evidence.
The command is executed without a shell. A
missing binary, rejected original rule, rejected printed rule, timeout, or
behavior mismatch is recorded as an unexpected failure.

The example matrix is a declaration template, not evidence that those engines
are installed. Publish a report only after running it with the exact engine
builds and configuration used for the release. For optimizer behavior checks,
add a `pcap` path and a command containing both `{file}` and `{pcap}`; the
conformance report then compares the original and printed ruleset output.

The bundled engine-scale snapshot in
`conformance/history/4.0.0-engine-scale.json` records parse, round-trip, and
real-engine loading for Suricata 8.0.6 and Snort3 3.12.2.0. It does not include
PCAP alert-equivalence results; those require a supplied PCAP corpus and
engine commands that expose alerts.

The external public snapshot in
`conformance/history/4.0.0-external-engine-scale.json` covers 56,658 rules from
the current ET Open, Snort Community, and Snort3 Community archives. It records
successful original and printed loads for Suricata 8.0.6, Snort 2.9.20, and
Snort 3.12.2.0. The historical 288,939-rule figure remains unreproduced because
the referenced issue does not publish that corpus and its registered Snort
component is not redistributable.

The issue #166 grammar regression snapshot in
`conformance/history/4.0.0-issue-166.json` covers all ten reported grammar gaps
with 15 rules across Snort 2, Snort 3, and Suricata. All 15 parsed and all 15
round-tripped without exceptions or unexpected failures.

The checked-in `conformance/history/4.0.0-optimizer-smoke.json` is a narrow
Suricata 8.0.6 smoke result over two synthetic PCAPs. The broader public-PCAP
result is recorded in
`conformance/history/4.0.0-optimizer-public-pcap.json`: it compares the same
optimizer fixture over ten PCAPs from OISF's `suricata-verify` repository and
records equal alert projections for all ten cases. This is stronger regression
evidence than the smoke test, but it is still not universal equivalence or a
production traffic corpus; the report records those limitations and hashes the
referenced, non-redistributed PCAPs.

The bundled-scale optimizer result is recorded in
`conformance/history/4.0.0-optimizer-bundled-public-pcap.json`. It runs the
optimizer over all 30,579 bundled Suricata rules, confirms that both the
original and printed rulesets load in Suricata 8.0.6, and compares alert
projections over the same ten public PCAPs with 10/10 equal results. The
snapshot is evidence for this bundled corpus and engine build only; it does
not establish universal optimizer equivalence or a production performance
benchmark.

The bundled Snort optimizer result is recorded in
`conformance/history/4.0.0-optimizer-engine-scale.json`. It validates the
parse -> optimize -> print -> engine path for 561 Snort2 rules on Snort 2.9.20
and 4,017 Snort3 rules on Snort 3.12.2.0. Both original and optimized files
loaded successfully. Snort3 uses the reproducible variable configuration in
`conformance/engines/snort3-3.12.2.lua`; it is an acceptance-test fixture,
not a deployment policy. PCAP alert equivalence and production traffic
calibration remain open for these dialects.

The public-PCAP optimizer result is recorded in
`conformance/history/4.0.0-optimizer-snort-public-pcap.json`. It compares the
bundled Snort2 and Snort3 original/optimized outputs over nine valid public
PCAPs, with 9/9 equivalent cases for each engine. The tenth downloaded
fixture is excluded because Snort2 rejects its invalid capture length; the
report records its hash and reason. This is regression evidence, not a
production traffic benchmark.

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
