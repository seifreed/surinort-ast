# Engine Capability Snapshots

`4.0.0-local.json` contains complete keyword snapshots captured from the
installed Suricata 8.0.6 and Snort 3.12.2.0 builds. The source command and
SHA-256 hash are recorded for each listing. Empty action, protocol, and
feature catalogs remain unknown; they are not interpreted as unsupported.

Load the snapshot in the validator with:

```bash
surinort validate rules.rules \
  --engine suricata \
  --engine-version 8.0.6 \
  --capability-file conformance/capabilities/4.0.0-local.json
```

The Snort 2.9.20 matrix engine does not expose an equivalent complete keyword
listing through its command-line interface, so it is intentionally absent from
this capability snapshot. Its parser and engine-load evidence remains in the
versioned conformance reports.
