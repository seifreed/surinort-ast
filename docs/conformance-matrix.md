# Supported Engine Matrix

Support claims use concrete engine versions and are backed by the checked-in
reports below. The matrix records parser round-trip and full-ruleset engine
loading; it does not imply that every keyword has identical semantics across
engines.

| Engine | Version | Dialect | Bundled rules | External rules | Original load | Printed load |
| --- | --- | --- | ---: | ---: | --- | --- |
| Suricata | 8.0.6 | `suricata` | 30,579 | 52,080 | passed | passed |
| Snort 2 | 2.9.20 | `snort2` | 561 | 561 | passed | passed |
| Snort 3 | 3.12.2.0 | `snort3` | 4,017 | 4,017 | passed | passed |

The bundled and external counts are parser-successful rules from the
corresponding snapshots. Every listed load validates the combined original
and printed ruleset through the concrete engine build.

The semantic matrix contains 26 cases and 78 engine-target evaluations. It
includes capability-backed keyword differences, such as `appids` being
catalogued for Snort 3 but not for the Suricata 8.0.6 or Snort 2.9.20 snapshots.
The matrix is checked in at
[`conformance/semantic-matrix.json`](https://github.com/seifreed/surinort-ast/blob/main/conformance/semantic-matrix.json).

Evidence:

- [Bundled engine-scale report](https://github.com/seifreed/surinort-ast/blob/main/conformance/history/4.0.0-engine-scale.json)
- [External engine-scale report](https://github.com/seifreed/surinort-ast/blob/main/conformance/history/4.0.0-external-engine-scale.json)
- [Bundled parser conformance report](https://github.com/seifreed/surinort-ast/blob/main/conformance/history/4.0.0-bundled.json)
- [External parser conformance report](https://github.com/seifreed/surinort-ast/blob/main/conformance/history/4.0.0-external-public.json)
- [Snort 2 source capability snapshot](https://github.com/seifreed/surinort-ast/blob/main/conformance/capabilities/4.0.0-snort2-source.json)

The external 288,939-rule figure from the historical review is not reproduced
because that issue does not publish the corpus and the registered Snort
component is not redistributable. The current public external snapshot is the
one recorded in the linked report.

This page is a versioned evidence snapshot, not a guarantee for future engine
releases. New engine versions require a new matrix entry and report.
