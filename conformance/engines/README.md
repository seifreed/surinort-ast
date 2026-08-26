# Reproducible Snort2 Engine

The Snort2 scale snapshot uses Snort `2.9.20 GRE (Build 82)` built from the
official source archives in a Debian Bookworm container. Download the sources
from the official Snort site, verify these SHA-256 values, and build the image:

```bash
mkdir -p /tmp/surinort-snort2-build
curl -fsSL -A 'Mozilla/5.0' \
  -o /tmp/surinort-snort2-build/daq-2.0.7.tar.gz \
  https://snort.org/downloads/snort/daq-2.0.7.tar.gz
curl -fsSL -A 'Mozilla/5.0' \
  -o /tmp/surinort-snort2-build/snort-2.9.20.tar.gz \
  https://snort.org/downloads/snort/snort-2.9.20.tar.gz
cp conformance/engines/snort2-2.9.20.Dockerfile /tmp/surinort-snort2-build/Dockerfile
cp conformance/engines/snort2-2.9.20.conf /tmp/surinort-snort2-build/snort.conf
sha256sum /tmp/surinort-snort2-build/daq-2.0.7.tar.gz
sha256sum /tmp/surinort-snort2-build/snort-2.9.20.tar.gz
docker build --file /tmp/surinort-snort2-build/Dockerfile \
  --tag surinort-snort2:2.9.20 /tmp/surinort-snort2-build
```

Expected archive hashes:

```text
d1f6709bc5dbddee3fdf170cdc1e49fb926e2031d4869ecf367a8c47efc87279  daq-2.0.7.tar.gz
29400e13f53b1831e0b8b10ec1224a1cbaa6dc1533a5322a20dd80bb84b4981c  snort-2.9.20.tar.gz
```

Validate the original and printed community rulesets independently:

```bash
docker run --rm \
  -v "$PWD/rules/snort/snort29-community-rules/community-rules/community.rules:/rules/community.rules:ro" \
  surinort-snort2:2.9.20 -T -c /etc/snort/snort.conf
```

The committed report records engine loading for both files. It does not claim
PCAP alert equivalence; that remains a separate traffic-fixture check.

## Snort3

The optimizer scale check uses Snort `3.12.2.0` with the minimal reproducible
configuration in `snort3-3.12.2.lua`:

```bash
snort -T \
  -c conformance/engines/snort3-3.12.2.lua \
  -R path/to/rules.rules
```

The fixture defines the variables referenced by the bundled community corpus
as `any` so the check measures parser/printer compatibility. It is not a
recommended network policy. The optimizer result is recorded in
`conformance/history/4.0.0-optimizer-engine-scale.json`; it does not claim
PCAP alert equivalence.
