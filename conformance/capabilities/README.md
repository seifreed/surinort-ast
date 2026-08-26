# Engine Capability Snapshots

`4.0.0-local.json` contains complete keyword snapshots captured from the
installed Suricata 8.0.6 and Snort 3.12.2.0 builds. The source command and
SHA-256 hash are recorded for each listing. `base64_data` is additionally
recorded for Snort 3 because the engine accepts it in the community ruleset
although it is absent from the module listing. Empty action, protocol, and
feature catalogs remain unknown; they are not interpreted as unsupported.

Load the snapshot in the validator with:

```bash
surinort validate rules.rules \
  --engine suricata \
  --engine-version 8.0.6 \
  --capability-file conformance/capabilities/4.0.0-local.json
```

Snort 2.9.20 does not expose an equivalent complete keyword listing through its
command-line interface. Build its source-backed snapshot from the official
detection-plugin sources with:

```bash
python tools/snort2_capabilities.py \
  --source-dir /path/to/snort-2.9.20/src/detection-plugins \
  --version 2.9.20 \
  --output conformance/capabilities/4.0.0-snort2-source.json
```

The generator fingerprints every C file, extracts each `RegisterRuleOption`
registration, and adds Snort's core rule metadata keywords (`sid`, `gid`,
`rev`, `msg`, and related fields), plus core keywords observed in the complete
Snort Community ruleset (`detection_filter` and `ssl_state`), which are parsed
outside the plugin registry.
Actions, protocols, and semantic feature domains remain unknown because these
sources do not prove those contracts; engine-load evidence remains in the
versioned conformance reports.
