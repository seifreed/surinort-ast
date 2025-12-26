# surinort-ast

[![Python Support](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Code Coverage](https://img.shields.io/badge/coverage-93.42%25-brightgreen)](https://github.com/seifreed/surinort-ast)
[![Compatibility](https://img.shields.io/badge/compatibility-99.46%25-brightgreen)](https://github.com/seifreed/surinort-ast)

---

**Support the Project**: If you find surinort-ast useful, consider [supporting development](https://buymeacoffee.com/seifreed).

---

Production-grade Abstract Syntax Tree parser for IDS/IPS rules (Suricata/Snort) with comprehensive validation and serialization support.

surinort-ast provides a complete, battle-tested solution for parsing, analyzing, manipulating, and generating Suricata and Snort IDS/IPS rules programmatically. Built on a formal LALR(1) grammar with full AST support, it enables advanced rule analysis, transformation, and validation workflows for security researchers, SOC engineers, and malware analysts.

**Tested with 35,157 real-world production rules from Suricata, Snort2, and Snort3.**

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Features](#core-features)
  - [Parser](#parser)
  - [Query API](#query-api-experimental)
  - [Analysis Module](#analysis-module)
  - [Builder Pattern](#builder-pattern-experimental)
  - [Serialization](#serialization)
  - [Validation](#validation)
- [Command-Line Interface](#command-line-interface)
- [Python API](#python-api)
- [Security](#security)
- [AST Nodes](#ast-nodes)
- [Examples](#examples)
- [Architecture](#architecture)
- [Performance](#performance)
- [Use Cases](#use-cases)
- [Compatibility](#compatibility)
- [Development](#development)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contact](#contact)

---

## Features

### Core Capabilities

- **Production-Ready Parser**: LALR(1) grammar parser built with Lark, validated against 35,157 real rules
- **100% Compatibility**
  - 100% Suricata compatibility (30,579 rules)
  - 100% Snort2 compatibility (561 rules)
  - 100% Snort3 compatibility (4,017 rules)
- **Rich AST Representation**: Typed AST nodes with Pydantic v2 for all rule components
- **Bidirectional Conversion**: Parse rules to AST and serialize back to valid syntax
- **Multi-Dialect Support**: Suricata 6.x/7.x, Snort 2.9.x, and Snort 3.x
- **Comprehensive Validation**: Syntax and semantic validation with detailed error reporting
- **Multiple Serialization Formats**:
  - JSON (RFC 8259 compliant with roundtrip support)
  - Protocol Buffers (66% size reduction, 2x faster than JSON)
  - Text (bidirectional conversion with stable formatting)
- **Query API (EXPERIMENTAL)**: CSS-style selectors for searching and filtering AST nodes
  - Phase 1: Basic type and attribute selectors
  - Phase 2: Hierarchical selectors (descendant, child, adjacent sibling)
  - Phase 3: Advanced selectors (pseudo-classes, attribute operators)
- **Rule Analysis**: Performance estimation, coverage analysis, and optimization recommendations
- **Statistical Analysis**: Rule corpus analysis with protocol, action, and direction metrics
- **Builder Pattern (EXPERIMENTAL)**: Fluent API for constructing rules programmatically
- **Streaming API**: Memory-efficient processing of large rulesets
- **Schema Generation**: JSON Schema and Protocol Buffer schema export

### Technical Highlights

- **Type-Safe**: Full Python type hints with mypy strict mode
- **Well-Tested**: 93.42% code coverage, 804 passing tests, zero mocks
- **High Performance**: Parses 30,000 rules in ~2 seconds (1,353 rules/sec sequential, ~10,800 rules/sec with 8 workers)
- **Memory Efficient**: Streaming API supports processing arbitrarily large files with constant memory
- **CLI Tools**: Seven production-ready command-line utilities
- **Extensible**: Clean architecture for custom analyzers and transformers
- **Dependency Injection**: Custom parser support via dependency injection pattern

### Supported Rule Options Reference

surinort-ast supports 100+ IDS rule options across all major categories. Below is a complete reference organized by functional category.

#### General Metadata

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| msg | `msg:"text"` | `msg:"HTTP Traffic"` | Rule message (human-readable description) |
| sid | `sid:number` | `sid:1000001` | Signature ID - unique identifier (required) |
| rev | `rev:number` | `rev:1` | Rule revision number |
| gid | `gid:number` | `gid:1` | Generator ID (rule source identifier) |
| classtype | `classtype:type` | `classtype:trojan-activity` | Rule classification category |
| priority | `priority:number` | `priority:1` | Alert priority level (1-4, 1=highest) |
| reference | `reference:type,id` | `reference:cve,2021-12345` | External reference (CVE, URL, bugtraq, etc.) |
| metadata | `metadata:key value` | `metadata:author Security Team` | Custom key-value metadata pairs |

#### Content Matching

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| content | `content:"pattern"` | `content:"GET"` | Pattern matching (quoted string or hex) |
| content (hex) | `content:\|hex\|` | `content:\|47 45 54\|` | Pattern matching with hex notation |
| content (negated) | `content:!"pattern"` | `content:!"safe"` | Negated pattern (alert if NOT found) |
| uricontent | `uricontent:"pattern"` | `uricontent:"/admin"` | URI pattern matching (deprecated, use http.uri) |
| pcre | `pcre:"/regex/flags"` | `pcre:"/admin/i"` | Perl-compatible regex matching |
| pcre (negated) | `pcre:!"/regex/"` | `pcre:!"/safe/"` | Negated regex match |

#### Content Modifiers

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| nocase | `nocase` | `content:"admin"; nocase;` | Case-insensitive matching |
| rawbytes | `rawbytes` | `content:"test"; rawbytes;` | Ignore HTTP decoding, match raw bytes |
| depth | `depth:N` | `depth:20` | Search only first N bytes of payload |
| offset | `offset:N` | `offset:10` | Skip first N bytes before searching |
| distance | `distance:N` | `distance:5` | Relative offset from previous match (can be negative) |
| within | `within:N` | `within:50` | Limit search to N bytes after previous match |
| startswith | `startswith` | `content:"GET"; startswith;` | Pattern must be at start of buffer |
| endswith | `endswith` | `content:"/"; endswith;` | Pattern must be at end of buffer |
| fast_pattern | `fast_pattern` | `content:"admin"; fast_pattern;` | Use this pattern for fast matching engine |
| fast_pattern (offset) | `fast_pattern:offset,length` | `fast_pattern:10,20` | Use 20 bytes starting at offset 10 for fast matching |

#### HTTP Keywords (Sticky Buffers)

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| http.uri | `http.uri` | `http.uri; content:"/admin";` | Match against HTTP URI (normalized) |
| http_uri | `http_uri` | `http_uri; content:"/admin";` | Match against HTTP URI (underscore variant) |
| http.header | `http.header` | `http.header; content:"Host:";` | Match against HTTP headers |
| http_header | `http_header` | `http_header; content:"Host:";` | Match against HTTP headers (underscore variant) |
| http.header_names | `http.header_names` | `http.header_names; content:"X-Custom";` | Match against HTTP header names only |
| http_header_names | `http_header_names` | `http_header_names; content:"X-Custom";` | Match against HTTP header names (underscore variant) |
| http.method | `http.method` | `http.method; content:"POST";` | Match against HTTP request method |
| http_method | `http_method` | `http_method; content:"POST";` | Match against HTTP method (underscore variant) |
| http.cookie | `http.cookie` | `http.cookie; content:"sessionid";` | Match against HTTP cookies |
| http_cookie | `http_cookie` | `http_cookie; content:"sessionid";` | Match against HTTP cookies (underscore variant) |
| http.user_agent | `http.user_agent` | `http.user_agent; content:"curl";` | Match against User-Agent header |
| http_user_agent | `http_user_agent` | `http_user_agent; content:"curl";` | Match against User-Agent (underscore variant) |
| http.host | `http.host` | `http.host; content:"evil.com";` | Match against HTTP Host header |
| http_host | `http_host` | `http_host; content:"evil.com";` | Match against HTTP Host (underscore variant) |
| http.raw_uri | `http.raw_uri` | `http.raw_uri; content:"%2e%2e";` | Match against raw (non-normalized) URI |
| http_raw_uri | `http_raw_uri` | `http_raw_uri; content:"%2e%2e";` | Match against raw URI (underscore variant) |
| http.stat_msg | `http.stat_msg` | `http.stat_msg; content:"OK";` | Match against HTTP status message |
| http_stat_msg | `http_stat_msg` | `http_stat_msg; content:"OK";` | Match against HTTP status message (underscore variant) |
| http.stat_code | `http.stat_code` | `http.stat_code; content:"200";` | Match against HTTP status code |
| http_stat_code | `http_stat_code` | `http_stat_code; content:"200";` | Match against HTTP status code (underscore variant) |
| urilen | `urilen:N` | `urilen:>500` | HTTP URI length check (supports <, >, <=, >=, =) |

#### DNS Keywords

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| dns.query | `dns.query` | `dns.query; content:"evil.com";` | Match against DNS query name |
| dns_query | `dns_query` | `dns_query; content:"evil.com";` | Match against DNS query (underscore variant) |

#### TLS/SSL Keywords

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| tls.sni | `tls.sni` | `tls.sni; content:"evil.com";` | Match against TLS Server Name Indication |
| tls_sni | `tls_sni` | `tls_sni; content:"evil.com";` | Match against TLS SNI (underscore variant) |
| tls.cert_subject | `tls.cert_subject` | `tls.cert_subject; content:"CN=";` | Match against TLS certificate subject |
| tls_cert_subject | `tls_cert_subject` | `tls_cert_subject; content:"CN=";` | Match against TLS cert subject (underscore variant) |
| tls.cert_issuer | `tls.cert_issuer` | `tls.cert_issuer; content:"CA";` | Match against TLS certificate issuer |
| tls_cert_issuer | `tls_cert_issuer` | `tls_cert_issuer; content:"CA";` | Match against TLS cert issuer (underscore variant) |

#### SSH Keywords

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| ssh.proto | `ssh.proto` | `ssh.proto; content:"2.0";` | Match against SSH protocol version |
| ssh_proto | `ssh_proto` | `ssh_proto; content:"2.0";` | Match against SSH protocol (underscore variant) |
| ssh.software | `ssh.software` | `ssh.software; content:"OpenSSH";` | Match against SSH software string |
| ssh_software | `ssh_software` | `ssh_software; content:"OpenSSH";` | Match against SSH software (underscore variant) |

#### File Keywords

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| file.data | `file.data` | `file.data; content:"MZ";` | Match against file data buffer |
| file_data | `file_data` | `file_data; content:"MZ";` | Match against file data (underscore variant) |
| filestore | `filestore` | `filestore;` | Extract file from traffic for analysis |
| filestore (params) | `filestore:dir,scope` | `filestore:request,file` | Extract file with direction and scope parameters |

#### Packet Data Keywords

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| pkt.data | `pkt.data` | `pkt.data; content:"test";` | Match against packet payload data |
| pkt_data | `pkt_data` | `pkt_data; content:"test";` | Match against packet data (underscore variant) |

#### Flow Control

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| flow | `flow:direction,state` | `flow:established,to_server` | Stateful flow tracking (direction and state) |
| flowbits | `flowbits:action,name` | `flowbits:set,exploit.started` | Flow state variables (boolean flags) |
| flowint | `flowint:name,op,value` | `flowint:counter,+,1` | Flow integer variables (counters) |

**Flow Directions**: `to_server`, `to_client`, `from_server`, `from_client`

**Flow States**: `established`, `stateless`, `only_stream`, `no_stream`, `only_frag`, `no_frag`

**Flowbits Actions**: `set`, `isset`, `isnotset`, `toggle`, `unset`, `noalert`

#### Byte Operations

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| byte_test | `byte_test:bytes,op,val,offset[,flags]` | `byte_test:4,>,1000,0` | Test byte values at specific offsets |
| byte_jump | `byte_jump:bytes,offset[,flags]` | `byte_jump:4,0,relative` | Jump to dynamic offsets in payload |
| byte_extract | `byte_extract:bytes,offset,name[,flags]` | `byte_extract:4,0,extracted` | Extract byte values to variables |
| byte_math | `byte_math:bytes,offset,op,rval,result` | `byte_math:4,0,+,10,calc` | Perform arithmetic on extracted bytes |
| isdataat | `isdataat:offset[,flags]` | `isdataat:100,relative` | Verify data availability at offset |

**Byte Test Operators**: `>`, `<`, `>=`, `<=`, `=`, `!=`, `&`, `!&`

**Common Flags**: `relative`, `big`, `little`, `string`, `hex`, `dec`, `oct`, `rawbytes`

#### Thresholding

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| threshold | `threshold:type t,track by,count N,seconds S` | `threshold:type limit,track by_src,count 1,seconds 60` | Alert rate limiting |
| detection_filter | `detection_filter:track by,count N,seconds S` | `detection_filter:track by_src,count 5,seconds 60` | Require N matches before alerting |

**Threshold Types**: `limit`, `threshold`, `both`

**Track By**: `by_src`, `by_dst`

#### Packet Tagging

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| tag | `tag:type,count,metric[,direction]` | `tag:session,10,packets` | Mark related packets for capture |
| flags | `flags:flagspec[,mask]` | `flags:S` | TCP flag combinations matching |

**Tag Types**: `session`, `host`

**TCP Flags**: `S` (SYN), `A` (ACK), `F` (FIN), `R` (RST), `P` (PSH), `U` (URG), `C` (CWR), `E` (ECE)

**Flag Modifiers**: `!` (not set), `*` (must be set), `+` (set with others)

#### Scripting

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| lua | `lua:script.lua` | `lua:detect.lua` | Execute Lua script for custom detection |
| lua (negated) | `lua:!script.lua` | `lua:!safe.lua` | Alert if Lua script returns false |
| luajit | `luajit:script.lua` | `luajit:fast_detect.lua` | Execute LuaJIT script (performance-optimized) |
| luajit (negated) | `luajit:!script.lua` | `luajit:!safe.lua` | Alert if LuaJIT script returns false |

#### Generic/Extensibility

| Option | Syntax | Example | Description |
|--------|--------|---------|-------------|
| generic | `keyword:value` | `custom_option:value` | Generic fallback for unknown/future options |

**Note**: The generic option handler preserves syntax for round-trip parsing of unknown, vendor-specific, experimental, or future IDS options not explicitly supported.

---

**Total Supported Options**: 100+ across 14 functional categories

**Compatibility**: Suricata 6.x/7.x, Snort 2.9.x, Snort 3.x

---

## Installation

### From PyPI (recommended)

```bash
# Basic installation
pip install surinort-ast

# With all optional features
pip install "surinort-ast[all]"

# With specific feature sets
pip install "surinort-ast[cli-enhanced]"  # Enhanced CLI output with rich formatting
pip install "surinort-ast[security]"      # Security scanning tools (bandit, safety)
pip install "surinort-ast[analysis]"      # Advanced analysis features (networkx)
pip install "surinort-ast[formats]"       # Additional format support (YAML, file detection)
pip install "surinort-ast[serialization]" # Binary serialization (msgpack, protobuf)
```

### From Source

```bash
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast
pip install -e .

# Or with optional features
pip install -e ".[all]"
```

### Development Installation

```bash
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast
pip install -e ".[dev]"
pre-commit install
```

### Requirements

- **Python**: 3.11 or higher (tested on 3.11, 3.12, 3.13, 3.14)
- **Core dependencies**: lark, pydantic, typer, jsonschema
- **Optional dependencies**: rich, bandit, safety, networkx, pyyaml, python-magic, msgpack, protobuf

---

## Quick Start

### Parse a Rule

```python
from surinort_ast import parse_rule

# Parse a Suricata rule
rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'
rule = parse_rule(rule_text)

# Access AST components
print(rule.action)                    # Action.ALERT
print(rule.header.protocol)           # Protocol.TCP
print(rule.header.dst_port)           # Port(value=80)

# Access options
for option in rule.options:
    if option.node_type == "MsgOption":
        print(option.text)            # "HTTP Traffic"
```

### Build Rules Programmatically (EXPERIMENTAL)

```python
from surinort_ast.builder import RuleBuilder

# Build rule using fluent API
rule = (
    RuleBuilder()
    .alert()
    .tcp()
    .source(addr="$HOME_NET", port="any")
    .destination(addr="$EXTERNAL_NET", port=80)
    .msg("Suspicious HTTP Request")
    .content(b"admin")
    .content(b"login", nocase=True)
    .pcre(r"/admin\.php\?.*=/i")
    .sid(1000001)
    .rev(1)
    .build()
)

# Convert to rule text
from surinort_ast.printer import print_rule
print(print_rule(rule))
```

### Query Rules (EXPERIMENTAL)

```python
from surinort_ast import parse_rule
from surinort_ast.query import query, query_exists

# Parse a rule
rule = parse_rule('alert tcp any any -> any 80 (content:"admin"; pcre:"/test/i"; sid:1;)')

# Find all ContentOption nodes
contents = query(rule, "ContentOption")
print(f"Found {len(contents)} content patterns")

# Check if rule has PCRE
has_pcre = query_exists(rule, "PcreOption")
print(f"Uses PCRE: {has_pcre}")

# Phase 2: Hierarchical selectors
# Find ContentOptions with nocase modifiers
nocase_contents = query(rule, "ContentOption:has(NocaseModifier)")

# Phase 3: Advanced selectors
# Find rules with high SIDs
high_sid_rules = query(rule, "SidOption[value>1000000]")

# Find first rule with specific classtype
web_rules = query(rule, "Rule:has(ClasstypeOption[value^='web-application'])")
```

### Analyze Rules

```python
from surinort_ast import parse_rule
from surinort_ast.analysis import PerformanceEstimator, RuleOptimizer

# Parse a rule
rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; content:"admin"; sid:1;)')

# Estimate performance
estimator = PerformanceEstimator()
score = estimator.estimate(rule)
print(f"Performance score: {score}")

# Optimize rule
optimizer = RuleOptimizer()
result = optimizer.optimize(rule)
if result.was_modified:
    print(f"Improvement: {result.total_improvement:.1f}%")
    for opt in result.optimizations:
        print(f"  - {opt}")
```

### Serialize to Multiple Formats

```python
from surinort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# JSON (human-readable)
from surinort_ast import to_json
json_str = to_json(rule)

# Protocol Buffers (compact, fast)
from surinort_ast.serialization import to_protobuf, from_protobuf
pb_bytes = to_protobuf(rule)  # 66% smaller than JSON
restored = from_protobuf(pb_bytes)

# Text (stable formatting)
from surinort_ast.printer import print_rule
text = print_rule(rule, stable=True)
```

### Stream Large Rulesets

```python
from surinort_ast.streaming import stream_parse_file

# Memory-efficient streaming for large files
for rule, line_num in stream_parse_file("huge-ruleset.rules"):
    # Process rules one at a time without loading entire file
    if rule.action == "alert":
        print(f"Line {line_num}: Alert rule SID {rule.sid}")
```

---

## Advanced Usage

### Parser Dependency Injection

surinort-ast provides a flexible parser architecture based on dependency inversion, allowing you to customize, extend, or replace the parser implementation without modifying existing code.

#### IParser Interface

The IParser protocol defines the contract that all parser implementations must satisfy:

```python
from surinort_ast.parsing import IParser, LarkRuleParser, ParserFactory

# Method 1: Direct LarkRuleParser instantiation
parser: IParser = LarkRuleParser()
rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
print(rule.header.protocol)  # Protocol.TCP
```

#### ParserFactory Pattern

Use ParserFactory for centralized parser creation and configuration:

```python
from surinort_ast.parsing import ParserFactory, ParserConfig
from surinort_ast.core.enums import Dialect

# Create default parser
parser = ParserFactory.create()
rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

# Create parser with custom configuration
config = ParserConfig.strict()  # Strict resource limits for untrusted input
parser = ParserFactory.create(config=config, dialect=Dialect.SNORT3)
rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

# Create parser with specific settings
parser = ParserFactory.create(
    dialect=Dialect.SURICATA,
    strict=True,  # Raise exceptions on parse errors
    error_recovery=False,  # Disable error recovery
    config=ParserConfig.permissive()  # Relaxed limits for trusted input
)
```

#### Parser Configuration

Configure parser resource limits to prevent DoS attacks:

```python
from surinort_ast.parsing import ParserConfig, LarkRuleParser

# Default configuration (balanced security/performance)
config = ParserConfig.default()
print(f"Max rule length: {config.max_rule_length:,} chars")
print(f"Timeout: {config.timeout_seconds}s")

# Strict configuration (untrusted input)
strict_config = ParserConfig.strict()
parser = LarkRuleParser(config=strict_config)
# Limits: 10KB rules, 100 options, 10s timeout

# Permissive configuration (trusted input)
permissive_config = ParserConfig.permissive()
parser = LarkRuleParser(config=permissive_config)
# Limits: 1MB rules, 10,000 options, no timeout

# Custom configuration
custom_config = ParserConfig(
    max_rule_length=50_000,  # 50KB per rule
    max_options=500,
    max_nesting_depth=30,
    timeout_seconds=15.0,
    max_input_size=50_000_000  # 50MB total input
)
```

#### Custom Parser Implementation

Implement custom parsers by satisfying the IParser protocol:

```python
from pathlib import Path
from surinort_ast.parsing import IParser
from surinort_ast.core.nodes import Rule

class CustomParser:
    """Custom parser implementation."""

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> Rule:
        """Parse single rule with custom logic."""
        # Your custom parsing implementation
        # Must return a Rule AST node
        ...

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        skip_errors: bool = True,
    ) -> list[Rule]:
        """Parse rules from file with custom logic."""
        # Your custom file parsing implementation
        # Must return list of Rule AST nodes
        ...

# Use custom parser directly
custom_parser: IParser = CustomParser()
rule = custom_parser.parse('alert tcp any any -> any 80 (sid:1;)')
```

#### Dependency Injection

Inject custom parsers into API functions:

```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.parsing import ParserFactory

# Create custom-configured parser
parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True)

# Inject parser into API function
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
    parser=parser  # Use custom parser instance
)

# This enables:
# - Testing with mock parsers
# - Performance optimization for specific use cases
# - Custom parser implementations without API changes
```

#### Registering Default Parser

Register a custom parser as the application-wide default:

```python
from surinort_ast.parsing import ParserFactory

# Register custom parser class as default
ParserFactory.register_default(CustomParser)

# All factory calls now use CustomParser
parser = ParserFactory.create()
isinstance(parser, CustomParser)  # True

# Reset to default LarkRuleParser
ParserFactory.reset_default()
parser = ParserFactory.create()
isinstance(parser, LarkRuleParser)  # True
```

#### Working with Lark Parser Directly

Access Lark-specific features when needed:

```python
from surinort_ast.parsing import ParserFactory

# Create LarkRuleParser explicitly
lark_parser = ParserFactory.create_lark_parser(
    dialect=Dialect.SURICATA,
    strict=False,
    error_recovery=True,
    config=ParserConfig.default()
)

# Access Lark-specific internals
grammar = lark_parser._get_grammar()
lark_instance = lark_parser._get_parser()
```

---

## Core Features

### Parser

#### Production-Grade LALR(1) Grammar

Built on a formal LALR(1) grammar using Lark parser library:

- Handles 35,157 real-world production rules
- Supports Suricata 6.x/7.x, Snort 2.9.x, and Snort 3.x dialects
- Error recovery with detailed diagnostic messages
- Position tracking for all AST nodes
- 500+ production rules in grammar definition

**Example:**
```python
from surinort_ast import parse_rule

# Parse complex rule with multiple options
rule = parse_rule(
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 '
    '(msg:"HTTP Admin Access"; '
    'flow:established,to_server; '
    'content:"GET"; http_method; '
    'content:"/admin"; http_uri; '
    'pcre:"/\\/admin\\/[a-z]+/i"; '
    'sid:1000001; rev:2;)'
)
```

#### Parallel Processing

Process large rulesets efficiently with multi-worker support:

```python
from surinort_ast import parse_file

# Sequential processing (single worker)
rules = parse_file("rules.rules", workers=1)

# Parallel processing (8 workers, ~8x speedup)
rules = parse_file("rules.rules", workers=8, batch_size=200)
```

**Performance:**
- Sequential: ~1,353 rules/second
- Parallel (8 workers): ~10,800 rules/second

---

### Query API (EXPERIMENTAL)

CSS-style selectors for searching and filtering AST nodes, inspired by jQuery and CSS.

**WARNING: The Query API is experimental. The API may change in future versions.**

#### Phase 1: Basic Selectors (v1.0.0)

Type and attribute selectors for simple queries:

```python
from surinort_ast import parse_rule
from surinort_ast.query import query, query_first, query_exists

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

# Type selectors
contents = query(rule, "ContentOption")          # Find all ContentOption nodes
sid = query_first(rule, "SidOption")            # Get first SidOption
has_pcre = query_exists(rule, "PcreOption")     # Check if PcreOption exists

# Attribute selectors
alert_rules = query(rule, "Rule[action=alert]")             # Exact match
tcp_headers = query(rule, "Header[protocol=tcp]")           # Match protocol
high_sid = query(rule, "SidOption[value=1000001]")         # Match value

# Universal selector
all_nodes = query(rule, "*")                                # All nodes
```

#### Phase 2: Hierarchical Selectors (EXPERIMENTAL)

Navigate AST hierarchy with descendant, child, and sibling selectors:

```python
from surinort_ast.query import query

# Descendant selector (space)
# Find all SidOptions anywhere under Rule nodes
sids = query(rule, "Rule SidOption")

# Child selector (>)
# Find ContentOptions that are direct children of Rule
direct_contents = query(rule, "Rule > ContentOption")

# Adjacent sibling selector (+)
# Find ContentOption immediately after another ContentOption
adjacent = query(rule, "ContentOption + ContentOption")

# General sibling selector (~)
# Find all SidOptions after any ContentOption
following_sids = query(rule, "ContentOption ~ SidOption")

# Combined hierarchical queries
# Find nocase modifiers within ContentOptions
nocase_in_content = query(rule, "ContentOption NocaseModifier")
```

#### Phase 3: Advanced Selectors (EXPERIMENTAL)

Powerful pseudo-classes and attribute operators:

```python
from surinort_ast.query import query

# Pseudo-classes
first_content = query(rule, "ContentOption:first-child")           # First content option
last_sid = query(rule, "SidOption:last-child")                     # Last SID option
rules_with_pcre = query(rule, "Rule:has(PcreOption)")              # Rules containing PCRE
non_alert = query(rule, "Rule:not([action=alert])")                # Non-alert rules

# Attribute operators
high_sids = query(rule, "SidOption[value>1000000]")                # Comparison
low_priority = query(rule, "PriorityOption[value<=2]")             # Less than or equal
web_class = query(rule, "ClasstypeOption[value^='web-']")          # Starts with
exploit_refs = query(rule, "ReferenceOption[url$='exploit']")      # Ends with
admin_msg = query(rule, "MsgOption[text*='admin']")                # Contains

# Combined advanced queries
# Find high-priority web-application rules with PCRE
complex = query(
    rule,
    "Rule:has(ClasstypeOption[value^='web-application']):has(PcreOption) PriorityOption[value<=2]"
)
```

#### Query Performance

- Simple type selectors: O(n) where n = number of nodes
- Attribute filters: O(n * k) where k = attribute check cost
- Target: <10ms for typical rule (~50 nodes)

**See source code documentation in [src/surinort_ast/query/](src/surinort_ast/query/) for complete Query API implementation.**

---

### Analysis Module

Tools for analyzing and optimizing IDS rules without changing detection logic.

#### Performance Estimation

Estimate the performance cost of individual rules:

```python
from surinort_ast import parse_rule
from surinort_ast.analysis import PerformanceEstimator

estimator = PerformanceEstimator()

# Compare two rules
rule1 = parse_rule('alert tcp any any -> any 80 (content:"test"; sid:1;)')
rule2 = parse_rule('alert tcp any any -> any 80 (pcre:"/complex.*regex/i"; sid:2;)')

score1 = estimator.estimate(rule1)  # Lower score (faster)
score2 = estimator.estimate(rule2)  # Higher score (slower due to PCRE)

print(f"Rule 1: {score1:.2f}, Rule 2: {score2:.2f}")
```

#### Rule Optimization

Automatically optimize rules for better performance:

```python
from surinort_ast import parse_rule
from surinort_ast.analysis import RuleOptimizer

optimizer = RuleOptimizer()

rule = parse_rule(
    'alert tcp any any -> any 80 '
    '(pcre:"/test/"; content:"test"; content:"admin"; sid:1;)'
)

result = optimizer.optimize(rule)

if result.was_modified:
    print(f"Total improvement: {result.total_improvement:.1f}%")
    for opt in result.optimizations:
        print(f"  - {opt.description}: {opt.estimated_gain:.1f}% gain")
```

**Optimization Strategies:**
- Fast pattern selection (automatic fast_pattern placement)
- Option reordering (cheaper checks first)
- Redundancy removal (duplicate option elimination)
- Content consolidation (merge adjacent patterns)

#### Coverage Analysis

Analyze rule coverage across a corpus:

```python
from surinort_ast import parse_file
from surinort_ast.analysis import CoverageAnalyzer

rules = parse_file("rules/suricata.rules")

analyzer = CoverageAnalyzer()
report = analyzer.analyze(rules)

print(f"Total rules: {report.total_rules}")
print(f"Protocols covered: {report.protocols}")
print(f"Port coverage: {report.port_coverage}")

# Find coverage gaps
for gap in report.gaps:
    print(f"Gap: {gap.protocol} port {gap.port}")
```

#### Conflict Detection

Detect conflicting rules that may cause unexpected behavior:

```python
from surinort_ast import parse_file
from surinort_ast.analysis import ConflictDetector

rules = parse_file("rules/custom.rules")

detector = ConflictDetector()
conflicts = detector.detect(rules)

for conflict in conflicts:
    print(f"Conflict: {conflict.type}")
    print(f"  Rule 1 (SID {conflict.rule1_sid})")
    print(f"  Rule 2 (SID {conflict.rule2_sid})")
    print(f"  Recommendation: {conflict.recommendation}")
```

---

### Builder Pattern (EXPERIMENTAL)

Fluent API for constructing rules programmatically without manually creating AST nodes.

**WARNING: Builder Pattern is experimental. The API may change in future versions.**

```python
from surinort_ast.builder import RuleBuilder
from surinort_ast.printer import print_rule

# Build complex rule using fluent API
rule = (
    RuleBuilder()
    # Set action and protocol
    .alert()
    .tcp()
    # Configure source and destination
    .source(addr="$HOME_NET", port="any")
    .destination(addr="$EXTERNAL_NET", port=80)
    .direction("->")
    # Add detection options
    .msg("Suspicious Admin Access Attempt")
    .flow("established", "to_server")
    .content(b"GET", http_method=True)
    .content(b"/admin", http_uri=True)
    .content(b"password", nocase=True, offset=100, depth=50)
    .pcre(r"/admin\.php\?.*=/i")
    # Add metadata
    .classtype("web-application-attack")
    .reference("url", "example.com/advisory")
    .metadata("author", "Security Team")
    .metadata("severity", "high")
    # Add identifiers
    .sid(1000001)
    .rev(1)
    .build()
)

# Convert to rule text
print(print_rule(rule))
```

**Builder Features:**
- Fluent, chainable API for all rule components
- Type-safe method signatures with validation
- Automatic option ordering
- Support for all 100+ rule options
- Error checking at build time

**Example Output:**
```
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Suspicious Admin Access Attempt"; flow:established,to_server; content:"GET"; http_method; content:"/admin"; http_uri; content:"password"; nocase; offset:100; depth:50; pcre:"/admin\.php\?.*=/i"; classtype:web-application-attack; reference:url,example.com/advisory; metadata:author Security Team, severity high; sid:1000001; rev:1;)
```

---

### Serialization

Multiple serialization formats for different use cases:

#### JSON Serialization

RFC 8259 compliant JSON with roundtrip support:

```python
from surinort_ast import parse_rule, to_json, from_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Convert to JSON
json_str = to_json(rule)

# Convert back
restored_rule = from_json(json_str)

# Verify roundtrip (lossless)
assert rule == restored_rule
```

**JSON Format:**
```json
{
  "node_type": "Rule",
  "action": "alert",
  "header": {
    "node_type": "Header",
    "protocol": "tcp",
    "src_addr": {...},
    "dst_addr": {...}
  },
  "options": [...]
}
```

#### Protocol Buffers Serialization

Compact binary format for efficient storage and transmission:

```python
from surinort_ast import parse_rule
from surinort_ast.serialization import to_protobuf, from_protobuf

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Serialize to Protocol Buffers
pb_bytes = to_protobuf(rule)

# Deserialize back
restored = from_protobuf(pb_bytes)
```

**Performance Comparison:**

| Format | Size | Serialization | Deserialization |
|--------|------|---------------|-----------------|
| JSON (pretty) | 100% (baseline) | 1.0x | 1.0x |
| JSON (compact) | 65% | 1.1x faster | 1.0x |
| Protocol Buffers | 34% | 2.0x faster | 1.8x faster |

**Size Reduction:**
- 66% smaller than pretty JSON
- 48% smaller than compact JSON

**Use Cases:**
- High-volume rule storage (databases, archives)
- Network transmission (APIs, distributed systems)
- Caching and intermediate representations
- Language-agnostic data exchange

#### Text Serialization

Convert AST back to rule text with configurable formatting:

```python
from surinort_ast import parse_rule
from surinort_ast.printer import print_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Default formatting
text = print_rule(rule)

# Stable/canonical formatting (deterministic output)
canonical = print_rule(rule, stable=True)

# Compact formatting (minimal whitespace)
compact = print_rule(rule, compact=True)
```

#### Streaming API

Memory-efficient processing for large rulesets:

```python
from surinort_ast.streaming import stream_parse_file

# Process 1M+ rules with constant memory usage
for rule, line_num in stream_parse_file("huge-ruleset.rules", buffer_size=1000):
    # Process one rule at a time
    if rule.header.protocol == "http":
        print(f"Line {line_num}: HTTP rule")
```

**Streaming Features:**
- Constant memory usage regardless of file size
- Configurable buffer size for performance tuning
- Line number tracking for error reporting
- Automatic comment and blank line handling
- Support for parallel processing with workers

**Performance:**
- Memory: O(buffer_size) regardless of total file size
- Throughput: ~1,353 rules/second (sequential)
- Can process files larger than available RAM

---

### Validation

#### Syntax Validation

Performed automatically during parsing:

```python
from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError

try:
    rule = parse_rule('alert tcp any any > any 80 (sid:1;)')  # Invalid direction
except ParseError as e:
    print(f"Syntax error: {e}")
```

#### Semantic Validation

Additional validation beyond syntax checking:

```python
from surinort_ast import parse_rule, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Validate rule
diagnostics = validate_rule(rule)

# Check for errors and warnings
errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]

if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error.message}")
```

**Validation Checks:**
- Required options present (sid, rev, msg)
- SID uniqueness
- Protocol-specific option compatibility
- PCRE pattern validity
- Cross-option dependencies

---

## Command-Line Interface

surinort provides seven production-ready commands for rule analysis and transformation:

```bash
surinort --help
```

### Commands

#### 1. parse - Parse and validate rules

```bash
# Parse Suricata rules (sequential)
surinort parse rules/suricata/suricata.rules --dialect suricata

# Parse in parallel (8 workers)
surinort parse rules/snort/snort3-community.rules -d snort3 -w 8

# Parse from stdin
echo 'alert tcp any any -> any 80 (msg:"test"; sid:1;)' | surinort parse -

# Verbose output with AST details
surinort parse rules.rules --verbose
```

**Performance**: Parses 30,000 rules in ~2 seconds

#### 2. fmt - Format and pretty-print rules

```bash
# Format rules (stable output)
surinort fmt rules.rules --dialect suricata

# In-place formatting
surinort fmt rules.rules --in-place

# Check mode (exit 1 if would reformat)
surinort fmt rules.rules --check
```

#### 3. validate - Validate rule syntax and semantics

```bash
# Basic validation
surinort validate rules.rules --dialect suricata

# Strict mode (warnings as errors)
surinort validate rules.rules --strict

# Batch validation
surinort validate rules/*.rules
```

#### 4. to-json - Export rules to JSON

```bash
# Convert to JSON
surinort to-json rules.rules -o rules.json

# Compact output
surinort to-json rules.rules --compact

# Pretty-printed JSON
surinort to-json rules.rules --indent 2
```

#### 5. from-json - Import rules from JSON

```bash
# Convert JSON back to rules
surinort from-json rules.json -o rules.rules

# Roundtrip conversion
surinort to-json original.rules | surinort from-json - > roundtrip.rules
```

#### 6. stats - Analyze rule corpus

```bash
# Get statistics
surinort stats rules/suricata/suricata.rules

# Output:
# Total rules: 30,579
# Actions:
#   alert: 30,579 (100.00%)
# Protocols:
#   http: 30,579 (100.00%)
```

#### 7. schema - Generate JSON Schema

```bash
# Generate schema to file
surinort schema -o schema.json

# Output to stdout
surinort schema
```

---

## Python API

### API Package Structure

surinort-ast provides a modular API organized into functional subpackages:

```
surinort_ast.api/
├── parsing         - Rule parsing functions (parse_rule, parse_file, parse_rules)
├── serialization   - JSON serialization/deserialization (to_json, from_json)
├── validation      - Rule validation functions (validate_rule)
└── printing        - Rule text formatting (print_rule)
```

#### Using Modular API

Import specific functions from functional modules:

```python
# Parsing
from surinort_ast.api.parsing import parse_rule, parse_file, parse_rules

# Serialization
from surinort_ast.api.serialization import to_json, from_json

# Validation
from surinort_ast.api.validation import validate_rule

# Printing
from surinort_ast.api.printing import print_rule

# Parse and serialize
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
json_str = to_json(rule)
restored = from_json(json_str)
text = print_rule(restored)
```

#### Backward Compatibility

The top-level surinort_ast module re-exports all public functions:

```python
# Traditional imports (still supported)
from surinort_ast import parse_rule, to_json, print_rule

# Equivalent to modular imports
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.printing import print_rule

# Both styles work identically
rule = parse_rule('alert tcp any any -> any 80 (sid:1;)')
```

### Core Functions

#### parse_rule()

Parse a single IDS rule into an AST.

**Signature**:
```python
def parse_rule(
    text: str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = True,
    parser: IParser | None = None,
) -> Rule
```

**Parameters**:
- `text` (str): The rule text to parse
- `dialect` (Dialect): Rule dialect - `Dialect.SURICATA`, `Dialect.SNORT2`, or `Dialect.SNORT3` (default: `Dialect.SURICATA`)
- `track_locations` (bool): Enable position tracking in AST nodes (default: `True`). Disable for ~10% performance improvement when location information is not needed.
- `include_raw_text` (bool): Store original rule text in `Rule.raw_text` field (default: `True`). Set to `False` for ~50% memory reduction when raw text not needed.
- `parser` (IParser | None): Optional custom parser implementation (default: `None`). Enables dependency injection for testing, custom implementations, or parser swapping. If `None`, uses default Lark-based parser.

**Returns**:
- `Rule`: Parsed AST node representing the complete rule

**Raises**:
- `ParseError`: If rule syntax is invalid or parsing fails

**Example**:
```python
from surinort_ast import parse_rule
from surinort_ast.core.enums import Dialect

# Parse a Suricata rule
rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)')
print(rule.action)                    # Action.ALERT
print(rule.header.protocol)           # Protocol.TCP
print(rule.header.dst_port)           # Port(value=80)

# Parse a Snort3 rule
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
    dialect=Dialect.SNORT3
)

# Fast parsing without location tracking
rule = parse_rule(rule_text, track_locations=False)

# Memory-efficient parsing without raw text storage
rule = parse_rule(rule_text, include_raw_text=False)

# Dependency injection with custom parser
from surinort_ast.parsing import ParserFactory
custom_parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True)
rule = parse_rule(rule_text, parser=custom_parser)

# Mock parser for testing
class MockParser:
    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
        return mock_rule_ast
rule = parse_rule(rule_text, parser=MockParser())
```

---

#### parse_rules()

Parse multiple rules with error collection.

**Signature**:
```python
def parse_rules(
    texts: Sequence[str],
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = True,
) -> tuple[list[Rule], list[tuple[int, str]]]
```

**Parameters**:
- `texts` (Sequence[str]): List of rule texts to parse
- `dialect` (Dialect): Rule dialect (default: `Dialect.SURICATA`)
- `track_locations` (bool): Enable position tracking (default: `True`). Disable for ~10% performance improvement.
- `include_raw_text` (bool): Store original rule text (default: `True`). Set to `False` for ~50% memory reduction.

**Returns**:
- `tuple[list[Rule], list[tuple[int, str]]]`: Tuple containing:
  - List of successfully parsed `Rule` objects
  - List of errors as tuples of `(index, error_message)`

**Raises**:
- Does not raise on individual parse errors; errors are collected in the returned tuple

**Example**:
```python
from surinort_ast import parse_rules

rules, errors = parse_rules([
    'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
    'invalid rule syntax',
    'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
])

print(f"Successfully parsed {len(rules)} rules")
print(f"Failed to parse {len(errors)} rules")

for idx, error in errors:
    print(f"Rule {idx}: {error}")

# Fast batch parsing
rules, errors = parse_rules(rule_list, track_locations=False)

# Memory-efficient batch parsing
rules, errors = parse_rules(rule_list, include_raw_text=False)
```

---

#### parse_file()

Parse all rules from a file with optional parallel processing.

**Signature**:
```python
def parse_file(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    workers: int | None = None,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
    batch_size: int = 100,
    include_raw_text: bool = True,
    stream: bool = False,
) -> list[Rule]
```

**Parameters**:
- `path` (Path | str): Path to file containing rules (one per line)
- `dialect` (Dialect): Rule dialect (default: `Dialect.SURICATA`)
- `track_locations` (bool): Enable position tracking (default: `True`). Disable for ~10% performance improvement.
- `workers` (int | None): Number of parallel workers (default: `1`). Use `workers=8` for ~8x speedup on multi-core systems.
- `allowed_base` (Path | None): Optional base directory for path validation. If specified, file path must be within this directory. Recommended for untrusted input to prevent path traversal attacks (CWE-22).
- `allow_symlinks` (bool): Whether to allow symlinks (default: `False`). Only enable if you trust the symlink source.
- `batch_size` (int): Number of rules per batch in parallel mode (default: `100`). Larger batches reduce overhead but increase memory per worker. Recommended range: 50-200. Ignored when `workers=1`.
- `include_raw_text` (bool): Store original rule text (default: `True`). Set to `False` for ~50% memory reduction.
- `stream` (bool): Enable streaming mode for memory-efficient processing (default: `False`). Returns an iterator instead of a list.

**Returns**:
- `list[Rule]`: List of parsed Rule AST nodes (or iterator if `stream=True`)

**Raises**:
- `ParseError`: If file cannot be read or parsed, or violates security constraints
- `FileNotFoundError`: If file doesn't exist

**Example**:
```python
from surinort_ast import parse_file
from surinort_ast.core.enums import Dialect
from pathlib import Path

# Parse Suricata rules (sequential)
rules = parse_file("/etc/suricata/rules/local.rules")
print(f"Parsed {len(rules)} rules")

# High-performance parallel parsing
rules = parse_file("large.rules", workers=8, batch_size=150)

# Memory-efficient lightweight mode
rules = parse_file("huge.rules", include_raw_text=False)

# Fast parsing without location tracking
rules = parse_file("rules.rules", track_locations=False)

# Secure parsing with path validation (recommended for untrusted input)
rules = parse_file(
    user_provided_path,
    allowed_base=Path("/safe/rules/directory"),
    allow_symlinks=False
)

# Streaming mode for very large files (constant memory usage)
for rule in parse_file("huge.rules", stream=True):
    process(rule)
```

**Performance Notes**:
- Parallel batching (`workers > 1`): ~40% higher throughput
- Lightweight mode (`include_raw_text=False`): ~50% memory reduction
- No location tracking (`track_locations=False`): ~10% faster parsing
- Combined optimizations: 2-3x overall performance improvement

**Security Notes**:
- Use `allowed_base` parameter when parsing user-provided paths
- Symlinks are rejected by default to prevent path traversal
- Error messages are sanitized to prevent path disclosure (CWE-209)

---

#### validate_rule()

Validate a Rule AST and return diagnostics.

**Signature**:
```python
def validate_rule(rule: Rule) -> list[Diagnostic]
```

**Parameters**:
- `rule` (Rule): Rule AST to validate

**Returns**:
- `list[Diagnostic]`: List of diagnostic messages (errors, warnings, info) found during validation

**Raises**:
- Does not raise exceptions; all issues are returned as diagnostics

**Example**:
```python
from surinort_ast import parse_rule, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test";)')
diagnostics = validate_rule(rule)

# Filter by severity
errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]

if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  {error.code}: {error.message}")

if warnings:
    print("Warnings:")
    for warning in warnings:
        print(f"  {warning.code}: {warning.message}")

# Check for specific validation issues
if not errors:
    print("Rule is valid!")
```

**Validation Checks**:
- Required options present (`sid`, `rev`, `msg`)
- SID uniqueness (when validating multiple rules)
- Protocol-specific option compatibility
- PCRE pattern validity
- Cross-option dependencies

---

#### to_json()

Serialize Rule AST to JSON string.

**Signature**:
```python
def to_json(rule: Rule, indent: int | None = 2) -> str
```

**Parameters**:
- `rule` (Rule): Rule AST to serialize
- `indent` (int | None): JSON indentation level (default: `2`). Set to `None` for compact output.

**Returns**:
- `str`: RFC 8259 compliant JSON string representation

**Raises**:
- `SerializationError`: If serialization fails

**Example**:
```python
from surinort_ast import parse_rule, to_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Pretty-printed JSON (default)
json_str = to_json(rule)
print(json_str)

# Compact JSON (no whitespace)
compact_json = to_json(rule, indent=None)

# Save to file
with open("rule.json", "w") as f:
    f.write(to_json(rule))
```

---

#### from_json()

Deserialize Rule AST from JSON.

**Signature**:
```python
def from_json(data: str | dict[str, Any]) -> Rule
```

**Parameters**:
- `data` (str | dict[str, Any]): JSON string or dictionary to deserialize

**Returns**:
- `Rule`: Deserialized Rule AST

**Raises**:
- `SerializationError`: If deserialization fails or JSON is invalid

**Example**:
```python
from surinort_ast import from_json, to_json

# From JSON string
json_str = '{"action": "alert", "header": {...}, ...}'
rule = from_json(json_str)

# From dictionary
import json
with open("rule.json") as f:
    data = json.load(f)
rule = from_json(data)

# Roundtrip test (lossless conversion)
original = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
json_str = to_json(original)
restored = from_json(json_str)
assert original == restored  # Perfect roundtrip
```

---

#### print_rule()

Convert a Rule AST back to text format.

**Signature**:
```python
def print_rule(rule: Rule, stable: bool = False) -> str
```

**Parameters**:
- `rule` (Rule): Rule AST to convert to text
- `stable` (bool): Use stable/canonical formatting (default: `False`). Stable mode produces deterministic output for version control.

**Returns**:
- `str`: Formatted rule text

**Raises**:
- Does not raise exceptions

**Example**:
```python
from surinort_ast import parse_rule, print_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Default formatting
text = print_rule(rule)
print(text)  # alert tcp any any -> any 80 (msg:"Test"; sid:1;)

# Stable/canonical formatting (deterministic)
canonical = print_rule(rule, stable=True)

# Roundtrip test (text -> AST -> text)
original = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
rule = parse_rule(original)
restored = print_rule(rule)
# Note: whitespace may differ but semantics are identical
```

---

#### parse_file_streaming()

Stream parse rules from a file for memory-efficient processing of large files.

**Signature**:
```python
def parse_file_streaming(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = False,
    batch_size: int | None = None,
    skip_errors: bool = False,
    encoding: str = "utf-8",
) -> Iterator[Rule]
```

**Parameters**:
- `path` (Path | str): Path to file containing rules
- `dialect` (Dialect): Rule dialect (default: `Dialect.SURICATA`)
- `track_locations` (bool): Enable position tracking (default: `True`). Disable for ~10% speedup.
- `include_raw_text` (bool): Store original rule text (default: `False`). Enable only if needed to minimize memory.
- `batch_size` (int | None): If specified, yield `StreamBatch` objects; otherwise yield individual rules
- `skip_errors` (bool): Skip malformed rules instead of including error diagnostics (default: `False`)
- `encoding` (str): File encoding (default: `"utf-8"`)

**Returns**:
- `Iterator[Rule]`: Iterator yielding rules on-demand (if `batch_size` is `None`)
- `Iterator[StreamBatch]`: Iterator yielding batches of rules (if `batch_size` is specified)

**Raises**:
- `ParseError`: If file cannot be read
- `FileNotFoundError`: If file doesn't exist

**Example**:
```python
from surinort_ast import parse_file_streaming

# Stream individual rules (constant memory usage)
for rule in parse_file_streaming("huge.rules"):
    process(rule)  # Process one rule at a time

# Stream batches of rules
for batch in parse_file_streaming("huge.rules", batch_size=1000):
    process_batch(batch.rules)
    print(f"Batch {batch.batch_number}: {batch.success_count} rules")

# Memory-efficient mode (minimal overhead)
for rule in parse_file_streaming(
    "huge.rules",
    include_raw_text=False,
    track_locations=False,
    skip_errors=True
):
    process(rule)
```

**Performance**:
- Constant memory usage (~10-50MB for any file size)
- Throughput: 10k+ rules/second
- Ideal for files >10k rules

---

#### to_json_schema()

Generate JSON Schema for Rule AST.

**Signature**:
```python
def to_json_schema() -> dict[str, Any]
```

**Parameters**:
- None

**Returns**:
- `dict[str, Any]`: JSON Schema dictionary conforming to JSON Schema Draft 2020-12

**Raises**:
- Does not raise exceptions

**Example**:
```python
from surinort_ast import to_json_schema
import json

# Generate schema
schema = to_json_schema()
print(schema["$schema"])  # https://json-schema.org/draft/2020-12/schema

# Save schema to file
with open("rule_schema.json", "w") as f:
    json.dump(schema, f, indent=2)

# Use for validation
from jsonschema import validate
rule_json = to_json(parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)'))
validate(json.loads(rule_json), schema)
```

---

### Common Exceptions

#### ParseError

Raised when rule parsing fails due to syntax errors or invalid input.

**Inheritance**: `Exception` -> `ParseError`

**Common Causes**:
- Invalid rule syntax (missing semicolons, malformed options)
- Unsupported dialect features
- File read errors
- Path traversal attempts (CWE-22)
- Symlink violations

**Example**:
```python
from surinort_ast import parse_rule
from surinort_ast.exceptions import ParseError

try:
    rule = parse_rule('alert tcp any any > any 80 (sid:1;)')  # Invalid direction
except ParseError as e:
    print(f"Parse error: {e}")
    # Handle error gracefully
```

#### SerializationError

Raised when JSON serialization or deserialization fails.

**Inheritance**: `Exception` -> `SerializationError`

**Common Causes**:
- Invalid JSON format
- Corrupted data
- Type mismatches during deserialization
- Missing required fields

**Example**:
```python
from surinort_ast import from_json
from surinort_ast.exceptions import SerializationError

try:
    rule = from_json('{"invalid": "json"}')
except SerializationError as e:
    print(f"Serialization error: {e}")
```

#### ValidationError

Raised when rule validation fails (note: `validate_rule()` returns diagnostics instead of raising).

**Inheritance**: `Exception` -> `ValidationError`

**Common Causes**:
- Missing required options (sid, msg)
- Invalid option combinations
- Protocol-specific constraint violations

**Example**:
```python
# Note: validate_rule() returns diagnostics instead of raising
from surinort_ast import parse_rule, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test";)')
diagnostics = validate_rule(rule)

# Check if validation failed
has_errors = any(d.level == DiagnosticLevel.ERROR for d in diagnostics)
if has_errors:
    print("Validation failed")
```

---

**For complete API reference with advanced features, see [docs/API_GUIDE.md](docs/API_GUIDE.md).**

--

## AST Nodes

### Rule

Top-level AST node representing a complete rule:

```python
from surinort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

print(rule.action)                    # Action.ALERT
print(rule.header.protocol)           # Protocol.TCP
print(rule.header.direction)          # Direction.RIGHT
```

### Address

Address specification (IP/port combination):

```python
# Single IP
Address(addr="192.168.1.1", port=Port(80))

# CIDR
Address(addr="192.168.0.0/16", port=Port("any"))

# Variable
Address(addr="$HOME_NET", port=Port("any"))

# Negated
Address(addr="192.168.1.1", port=Port(80), negated=True)
```

### Port

Port specification:

```python
Port(80)                              # single port
Port("any")                           # any port
Port(PortRange(start=1024, end=65535))  # port range
Port([80, 443, 8080])                 # port list
Port(80, negated=True)                # !80
```

### Option Nodes

Base class for all rule options:

**Common Option Types:**
- **MsgOption**: Message text
- **SidOption**: Signature ID
- **RevOption**: Revision number
- **ContentOption**: Content pattern matching
- **PcreOption**: Perl-compatible regex
- **FlowOption**: Flow direction and state
- **ByteTestOption**: Byte testing operations
- **ReferenceOption**: External references
- **MetadataOption**: Metadata key-value pairs

**For complete AST reference, see [src/surinort_ast/core/nodes.py](src/surinort_ast/core/nodes.py).**

---

## Examples

The [examples/](examples/) directory contains 10 comprehensive, executable examples demonstrating all major features.

### Learning Path

**Beginner (Start Here):**
1. [01_basic_parsing.py](examples/01_basic_parsing.py) - Parse rules and access AST components
2. [02_ast_inspection.py](examples/02_ast_inspection.py) - Traverse and inspect ASTs using visitors
3. [03_modify_rules.py](examples/03_modify_rules.py) - Modify rules using immutable patterns
4. [04_json_serialization.py](examples/04_json_serialization.py) - JSON export/import and roundtrip

**Intermediate:**
5. [05_batch_processing.py](examples/05_batch_processing.py) - Parse and process multiple rules
6. [06_error_handling.py](examples/06_error_handling.py) - Robust error handling strategies
7. [07_custom_visitor.py](examples/07_custom_visitor.py) - Create custom AST visitors

**Advanced:**
8. [08_rule_validation.py](examples/08_rule_validation.py) - Validate rules with custom logic
9. [09_file_processing.py](examples/09_file_processing.py) - Work with rule files efficiently
10. [10_ast_transformation.py](examples/10_ast_transformation.py) - Complex multi-pass transformations

### Quick Start

```bash
cd examples/
python 01_basic_parsing.py
python 02_ast_inspection.py
```

**See the [examples/](examples/) directory for complete example catalog with learning path.**

---

## Migration Guide

### Migrating from Old to New API

The surinort-ast API has been refactored to support dependency injection and modular organization. This guide helps you migrate existing code.

#### Parser Instantiation

**Old approach (still works):**
```python
from surinort_ast import parse_rule, parse_file

# Direct parsing (implementation hidden)
rule = parse_rule('alert tcp any any -> any 80 (sid:1;)')
rules = parse_file("rules.rules")
```

**New approach (recommended):**
```python
from surinort_ast.parsing import LarkRuleParser, ParserFactory
from surinort_ast.api.parsing import parse_rule, parse_file

# Explicit parser creation
parser = LarkRuleParser()
rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

# Or use factory pattern
parser = ParserFactory.create()
rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

# Inject parser into API functions
rule = parse_rule('alert tcp any any -> any 80 (sid:1;)', parser=parser)
```

#### Import Organization

**Old imports:**
```python
from surinort_ast import parse_rule, to_json, print_rule, validate_rule
```

**New modular imports (recommended for clarity):**
```python
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.printing import print_rule
from surinort_ast.api.validation import validate_rule
```

**Backward compatibility:**
Both import styles work identically. The old imports are re-exported from `surinort_ast` for full backward compatibility.

#### Parser Configuration

**Old approach (no configuration):**
```python
from surinort_ast import parse_rule

# No way to configure parser limits
rule = parse_rule('alert tcp any any -> any 80 (sid:1;)')
```

**New approach (configurable):**
```python
from surinort_ast.parsing import ParserFactory, ParserConfig

# Configure resource limits
config = ParserConfig.strict()  # For untrusted input
parser = ParserFactory.create(config=config)
rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')

# Or use permissive config for trusted input
config = ParserConfig.permissive()
parser = ParserFactory.create(config=config)
```

#### Custom Parser Implementations

**Old approach (not supported):**
No way to replace parser implementation.

**New approach (dependency injection):**
```python
from surinort_ast.parsing import IParser, ParserFactory

# Implement custom parser
class MyParser:
    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
        # Custom implementation
        ...
    def parse_file(self, path, encoding="utf-8", skip_errors=True):
        # Custom implementation
        ...

# Register as default
ParserFactory.register_default(MyParser)

# Or inject into specific calls
from surinort_ast.api.parsing import parse_rule
rule = parse_rule('alert tcp any any -> any 80 (sid:1;)', parser=MyParser())
```

#### Protocol-Based Interfaces

**New feature:**
Use Protocol interfaces for type-safe dependency injection:

```python
from surinort_ast.parsing import IParser

def process_rules(parser: IParser) -> None:
    """Accept any parser implementation via Protocol."""
    rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')
    # Type checker verifies parser has required methods
```

**Query module protocols:**
```python
from surinort_ast.query.protocols import (
    SelectorProtocol,
    PseudoSelectorProtocol,
    QueryExecutorProtocol,
)

# Use protocols for custom query components
class CustomSelector:
    def matches(self, node: ASTNode) -> bool:
        # Custom matching logic
        ...
```

### Deprecation Timeline

No features are deprecated. All existing code continues to work:

- Top-level imports (`from surinort_ast import parse_rule`) remain supported
- Direct function calls work unchanged
- No breaking changes to existing APIs

**Recommendation**: New projects should use the modular API structure and dependency injection patterns for better testability and flexibility.

---

## Architecture

### Project Structure

```
surinort-ast/
├── src/surinort_ast/
│   ├── api/                      # Modular public API (new structure)
│   │   ├── __init__.py           # Re-exports all public functions
│   │   ├── parsing.py            # parse_rule, parse_file, parse_rules
│   │   ├── serialization.py      # to_json, from_json
│   │   ├── validation.py         # validate_rule
│   │   ├── printing.py           # print_rule
│   │   └── _internal.py          # Internal helpers
│   ├── api.py                    # Legacy API (re-exports from api/)
│   ├── cli/
│   │   └── main.py               # CLI implementation (7 commands)
│   ├── core/
│   │   ├── diagnostics.py        # Error/warning reporting
│   │   ├── enums.py              # Action, Protocol, Direction enums
│   │   ├── location.py           # Source location tracking
│   │   ├── nodes.py              # AST node definitions (60+ types)
│   │   └── visitor.py            # Visitor pattern for AST traversal
│   ├── exceptions.py             # Custom exceptions
│   ├── parsing/
│   │   ├── __init__.py           # Parser module exports (IParser, ParserFactory, etc.)
│   │   ├── interfaces.py         # IParser protocol interface (dependency inversion)
│   │   ├── factory.py            # ParserFactory for creating parser instances
│   │   ├── lark_parser.py        # LarkRuleParser implementation (default)
│   │   ├── parser.py             # RuleParser (backward compatibility wrapper)
│   │   ├── grammar.lark          # LALR(1) grammar (500+ lines)
│   │   ├── transformer.py        # Parse tree -> AST transformation
│   │   ├── parser_config.py      # ParserConfig with resource limits
│   │   ├── helpers.py            # Parsing helper functions
│   │   └── mixins/               # Transformer mixins
│   ├── printer/
│   │   ├── formatter.py          # Formatting options
│   │   └── text_printer.py       # AST -> text serialization
│   ├── serialization/
│   │   ├── json_serializer.py    # JSON export/import
│   │   ├── protobuf_serializer.py # Protocol Buffers support
│   │   └── schema_generator.py   # JSON Schema generation
│   ├── analysis/                 # Analysis module
│   │   ├── performance.py        # Performance estimation
│   │   ├── optimizer.py          # Rule optimization
│   │   ├── coverage.py           # Coverage analysis
│   │   └── conflicts.py          # Conflict detection
│   ├── query/                    # Query API (EXPERIMENTAL)
│   │   ├── __init__.py           # Query module exports
│   │   ├── protocols.py          # Protocol interfaces (structural typing)
│   │   ├── selectors.py          # Selector implementations
│   │   ├── parser.py             # Selector chain parsing
│   │   └── executor.py           # Query execution engine
│   ├── builder/                  # Builder pattern (EXPERIMENTAL)
│   │   └── rule_builder.py       # Fluent API for rule construction
│   └── streaming/                # Streaming API
│       └── stream_parser.py      # Memory-efficient parsing
├── tests/
│   ├── golden/                   # Real-world rule corpus tests
│   ├── integration/              # Integration tests
│   ├── unit/                     # 804 unit tests (93.42% coverage)
│   └── fuzzing/                  # Fuzz testing
└── examples/                     # 10 comprehensive examples
```

### Architecture Principles

#### Dependency Inversion

The parser architecture follows the Dependency Inversion Principle (SOLID):

- **IParser Protocol**: Abstract interface defining parser contract
- **LarkRuleParser**: Concrete implementation using Lark library
- **ParserFactory**: Factory for creating parser instances
- **Dependency Injection**: API functions accept `parser` parameter

This enables:
- Swapping parser implementations without code changes
- Mock parsers for testing
- Custom optimizations for specific use cases
- Library independence (decoupled from Lark)

```python
# High-level modules depend on abstractions (IParser)
def parse_rule(text: str, parser: IParser | None = None) -> Rule:
    if parser is not None:
        return parser.parse(text)  # Inject custom parser
    # Use default implementation
    return default_parser.parse(text)

# Low-level modules implement abstractions
class LarkRuleParser:  # Implements IParser protocol
    def parse(self, text: str, ...) -> Rule:
        # Lark-specific implementation
        ...
```

#### Protocol-Based Interfaces

Uses Python's Protocol (PEP 544) for structural subtyping:

**Parser Protocols:**
- `IParser`: Main parser interface (parse, parse_file methods)

**Query Protocols:**
- `SelectorProtocol`: Selector matching interface
- `PseudoSelectorProtocol`: Pseudo-selectors with context
- `SelectorChainProtocol`: Selector chain structure
- `ExecutionContextProtocol`: Query execution context
- `QueryExecutorProtocol`: Query executor interface

Benefits:
- Duck typing with type safety
- No runtime dependencies (ABC not required)
- Enables circular dependency resolution
- Type checkers verify protocol compliance

#### Modular API Organization

The `api/` package organizes functions by responsibility:

```python
# Functional modules
api/parsing.py         # Parse rules from text/files
api/serialization.py   # Convert to/from JSON
api/validation.py      # Validate rule correctness
api/printing.py        # Format rules as text

# Each module is self-contained and focused
# Easier to understand, test, and maintain
```

#### Parser Configuration

`ParserConfig` provides resource limits to prevent DoS:

```python
config = ParserConfig(
    max_rule_length=100_000,      # Prevent memory exhaustion
    max_options=1000,              # Prevent parsing complexity attacks
    max_nesting_depth=50,          # Prevent stack overflow
    timeout_seconds=30.0,          # Prevent infinite loops (ReDoS)
    max_input_size=100_000_000,   # Prevent memory exhaustion
)
```

Three presets available:
- `ParserConfig.default()`: Balanced security/performance
- `ParserConfig.strict()`: Maximum protection (untrusted input)
- `ParserConfig.permissive()`: Minimal limits (trusted input)

### Data Flow

```
Rule Text
    │
    ▼
┌─────────┐     Tokens      ┌─────────┐      AST       ┌──────────┐
│  Lexer  │ ──────────────> │ Parser  │ ────────────> │   AST    │
└─────────┘                 └─────────┘                └──────────┘
                                                             │
                                                             ├─> JSON/Protobuf
                                                             ├─> Analysis
                                                             ├─> Query API
                                                             └─> Text Printer
```

---

## Performance

### Benchmarks

Tested on Apple M1 Pro (8 cores):

| Operation | Performance | Notes |
|-----------|-------------|-------|
| Parse (simple) | ~50,000 rules/sec | Single content option |
| Parse (complex) | ~15,000 rules/sec | Multiple PCRE, metadata |
| Parse (30K corpus) | ~2 seconds | Full Suricata ET Open |
| Serialize (Text) | ~80,000 rules/sec | AST to text |
| Serialize (JSON) | ~40,000 rules/sec | AST to JSON |
| Serialize (Protobuf) | ~80,000 rules/sec | AST to protobuf (2x faster than JSON) |
| Validate | ~40,000 rules/sec | Syntax + semantics |
| Roundtrip | ~12,000 rules/sec | Parse + serialize |
| Streaming | ~1,353 rules/sec | Constant memory usage |

**Parallel Processing:**
- Sequential: 1,353 rules/second
- With 8 workers: ~10,800 rules/second (8x speedup)

### Memory Usage

- **Parser overhead**: ~50 bytes per rule
- **AST node**: ~100 bytes per node (average)
- **Complete rule**: ~2-5 KB (AST + metadata)
- **30K ruleset**: ~120 MB in memory
- **Streaming**: O(buffer_size) regardless of file size

### Serialization Size Comparison

| Format | Size | Speed |
|--------|------|-------|
| JSON (pretty) | 100% baseline | 1.0x |
| JSON (compact) | 65% | 1.1x faster |
| Protocol Buffers | 34% | 2.0x faster |

**Protocol Buffers Benefits:**
- 66% size reduction vs pretty JSON
- 2x faster serialization
- 1.8x faster deserialization

### Optimization Tips

```python
# For batch processing, use parallel workers
from surinort_ast import parse_file

rules = parse_file("large.rules", workers=8, batch_size=200)

# For memory-constrained environments, use streaming
from surinort_ast.streaming import stream_parse_file

for rule, line_num in stream_parse_file("huge.rules"):
    # Process rule immediately, constant memory usage
    process(rule)
```

---

## Use Cases

### 1. Security Research - Rule Corpus Analysis

Analyze large rule repositories for threat hunting patterns:

```python
from surinort_ast import parse_file
from collections import Counter

# Parse 30,000+ rules
rules = parse_file("rules/suricata/suricata.rules")

# Analyze protocols
protocols = Counter(r.header.protocol for r in rules)
print(f"Top protocols: {protocols.most_common(5)}")

# Find rules with PCRE
pcre_rules = [r for r in rules if any(
    o.node_type == "PcreOption" for o in r.options
)]
print(f"Rules with PCRE: {len(pcre_rules)}")
```

### 2. CI/CD Integration - Rule Quality Gates

Validate rules in continuous integration pipelines:

```bash
#!/bin/bash
# validate_rules.sh - CI/CD validation script

set -e

# Validate syntax
surinort validate rules/*.rules --strict

# Check formatting
surinort fmt rules/*.rules --check

# Generate statistics
surinort stats rules/*.rules > stats.txt

echo "All validations passed"
```

### 3. Rule Optimization - Performance Improvement

Optimize rules for better IDS performance:

```python
from surinort_ast import parse_file
from surinort_ast.analysis import RuleOptimizer
from surinort_ast.printer import print_rule

rules = parse_file("rules/custom.rules")
optimizer = RuleOptimizer()

optimized = []
for rule in rules:
    result = optimizer.optimize(rule)
    optimized.append(result.optimized)

# Save optimized rules
with open("rules/optimized.rules", "w") as f:
    for rule in optimized:
        f.write(print_rule(rule) + "\n")
```

### 4. Rule Migration - Dialect Conversion

Migrate rules between IDS platforms:

```python
from surinort_ast import parse_file
from surinort_ast.printer import print_rule
from surinort_ast.core.enums import Dialect

# Parse Suricata rules
rules = parse_file("suricata.rules", dialect=Dialect.SURICATA)

# Filter compatible rules (no Suricata-specific options)
compatible = []
suricata_only = {'app-layer-protocol', 'tls.sni', 'dns.query'}

for rule in rules:
    option_names = {opt.node_type for opt in rule.options}
    if not (option_names & suricata_only):
        compatible.append(rule)

# Export for Snort2
with open("snort2_compatible.rules", "w") as f:
    for rule in compatible:
        f.write(print_rule(rule) + "\n")

print(f"Migrated {len(compatible)}/{len(rules)} rules")
```

### 5. Batch Processing - Mass Rule Updates

Update SIDs across large rule sets:

```python
from surinort_ast import parse_file
from surinort_ast.printer import print_rule

# Parse rules
rules = parse_file("rules.rules")

# Update SIDs (add 1000000 offset)
updated_rules = []
for rule in rules:
    new_options = []
    for opt in rule.options:
        if opt.node_type == "SidOption":
            new_opt = opt.model_copy(update={'value': opt.value + 1000000})
            new_options.append(new_opt)
        else:
            new_options.append(opt)

    updated_rule = rule.model_copy(update={'options': new_options})
    updated_rules.append(updated_rule)

# Write updated rules
with open("updated_rules.rules", "w") as f:
    for rule in updated_rules:
        f.write(print_rule(rule) + "\n")
```

---

## Compatibility

### Python Versions

- Python 3.11+
- Python 3.12+
- Python 3.13+
- Python 3.14+

Tested on CPython implementation.

### IDS/IPS Platforms

- **Suricata**: 6.x, 7.x (100% compatibility with 30,579 real rules)
- **Snort 2**: 2.9.x (100% compatibility with 561 real rules)
- **Snort 3**: 3.x (100% compatibility with 4,017 real rules)

**Overall**: 100% compatibility with 35,157 real-world production rules

---

## Development

### Development Setup

```bash
# Clone repository
git clone https://github.com/seifreed/surinort-ast.git
cd surinort-ast

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run linters
ruff check .
mypy .
```

### Code Standards

- **Type hints**: Required for all functions
- **Docstrings**: Google style for public APIs
- **Testing**: Minimum 90% coverage for new code
- **Formatting**: `ruff format` (no configuration needed)
- **Linting**: `ruff check` must pass
- **Line length**: 100 characters

### Project Dependencies

**Core dependencies:**
- lark >= 1.3.1 - LALR(1) parser generator
- pydantic >= 2.12.3 - Data validation with type hints
- typer >= 0.20.0 - Modern CLI framework
- jsonschema >= 4.25.1 - JSON Schema validation

**Optional dependencies:**
- protobuf >= 6.33.0 - Protocol Buffers support
- msgpack >= 1.1.2 - Binary serialization
- rich >= 13.9.4 - Enhanced CLI output
- networkx >= 3.4.2 - Graph analysis

**Development dependencies:**
- pytest >= 8.4.2 - Testing framework
- pytest-cov >= 7.0.0 - Coverage reporting
- ruff >= 0.14.3 - Linting and formatting
- mypy >= 1.18.2 - Type checking
- hypothesis >= 6.144.0 - Property-based testing

---

## Troubleshooting

### Parser and Interface Issues

#### ImportError: cannot import IParser

**Problem:**
```python
from surinort_ast.parsing import IParser
# ImportError: cannot import name 'IParser' from 'surinort_ast.parsing'
```

**Solution:**
Ensure you're using surinort-ast version 1.0.0 or later. The IParser interface was introduced in the recent refactoring.

```bash
pip install --upgrade surinort-ast
```

#### Type checking fails with custom parser

**Problem:**
```python
class MyParser:
    def parse(self, text: str) -> Rule:
        ...

parser: IParser = MyParser()  # Type error: MyParser doesn't implement IParser
```

**Solution:**
Ensure your custom parser implements all required methods from the IParser protocol:

```python
from pathlib import Path
from surinort_ast.parsing import IParser
from surinort_ast.core.nodes import Rule

class MyParser:
    def parse(
        self,
        text: str,
        file_path: str | None = None,  # Required parameter
        line_offset: int = 0,           # Required parameter
    ) -> Rule:
        ...

    def parse_file(
        self,
        path: str | Path,               # Required parameter
        encoding: str = "utf-8",        # Required parameter
        skip_errors: bool = True,       # Required parameter
    ) -> list[Rule]:
        ...

# Now type checker accepts it
parser: IParser = MyParser()
```

#### ParserFactory.register_default() raises TypeError

**Problem:**
```python
ParserFactory.register_default(MyParser)
# TypeError: Parser class must implement IParser protocol. Missing method: parse_file
```

**Solution:**
Your custom parser class must implement both `parse()` and `parse_file()` methods:

```python
class MyParser:
    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        # Implementation
        ...

    def parse_file(self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True) -> list[Rule]:
        # Implementation
        ...

# Now registration works
ParserFactory.register_default(MyParser)
```

#### Parser injection doesn't work

**Problem:**
```python
custom_parser = MyParser()
rule = parse_rule("alert tcp any any -> any 80 (sid:1;)", parser=custom_parser)
# Still uses default parser, not custom_parser
```

**Solution:**
Ensure you're importing from `surinort_ast.api.parsing`, not the legacy `surinort_ast.api`:

```python
# Correct import (supports parser injection)
from surinort_ast.api.parsing import parse_rule

# Legacy import (should still work in 1.0.0+)
from surinort_ast import parse_rule
```

#### ParserConfig validation errors

**Problem:**
```python
config = ParserConfig(max_rule_length=-1)
# ValueError: max_rule_length must be positive
```

**Solution:**
All ParserConfig parameters must be positive (or non-negative for timeout):

```python
config = ParserConfig(
    max_rule_length=10_000,     # Must be > 0
    max_options=100,             # Must be > 0
    max_nesting_depth=20,        # Must be > 0
    timeout_seconds=10.0,        # Must be >= 0 (0 = no timeout)
    max_input_size=10_000_000,  # Must be > 0
)
```

Use presets for validated configurations:
```python
config = ParserConfig.strict()      # Pre-validated strict limits
config = ParserConfig.permissive()  # Pre-validated permissive limits
config = ParserConfig.default()     # Pre-validated default limits
```

#### Protocol interface circular import errors

**Problem:**
```python
from surinort_ast.query.protocols import SelectorProtocol
# ImportError: circular dependency
```

**Solution:**
Protocol interfaces are designed to break circular dependencies. Import from the protocols module:

```python
# Correct: Use protocols module
from surinort_ast.query.protocols import (
    SelectorProtocol,
    PseudoSelectorProtocol,
    QueryExecutorProtocol,
)

# Avoid importing concrete classes when only interface is needed
# from surinort_ast.query.selectors import TypeSelector  # May cause circular import
```

### Common Usage Issues

#### Parse errors with valid rules

**Problem:**
Rules that work in Suricata fail to parse.

**Solution:**
Specify the correct dialect:

```python
from surinort_ast import parse_rule
from surinort_ast.core.enums import Dialect

# Suricata-specific syntax
rule = parse_rule(
    'alert http any any -> any any (http.uri; content:"/admin"; sid:1;)',
    dialect=Dialect.SURICATA
)

# Snort3 syntax
rule = parse_rule(
    'alert tcp any any -> any any (service:http; sid:1;)',
    dialect=Dialect.SNORT3
)
```

#### Memory issues with large rulesets

**Problem:**
Out of memory when parsing large rule files.

**Solution:**
Use streaming mode or lightweight parsing:

```python
from surinort_ast.api.parsing import parse_file

# Streaming mode (constant memory)
for rule in parse_file("huge.rules", stream=True):
    process(rule)

# Lightweight mode (50% memory reduction)
rules = parse_file("huge.rules", include_raw_text=False)

# Combined optimizations
for rule in parse_file("huge.rules", stream=True, include_raw_text=False, track_locations=False):
    process(rule)
```

#### Performance issues with parsing

**Problem:**
Parsing is slower than expected.

**Solution:**
Enable parallel processing and disable unnecessary features:

```python
from surinort_ast.api.parsing import parse_file

# Parallel processing (8 workers)
rules = parse_file("large.rules", workers=8, batch_size=200)

# Disable location tracking (10% faster)
rules = parse_file("large.rules", track_locations=False)

# Combined optimizations (2-3x faster)
rules = parse_file(
    "large.rules",
    workers=8,
    batch_size=200,
    track_locations=False,
    include_raw_text=False
)
```

--

## License

Copyright (C) 2025 Marc Rivero López

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

---

## Acknowledgments

- Suricata and Snort communities for comprehensive documentation
- Open Information Security Foundation (OISF) for Suricata
- Cisco Talos for Snort development
- All contributors to this project

---

## Contact

- **Author**: Marc Rivero López (@seifreed)
- **Email**: mriverolopez@gmail.com
- **GitHub**: https://github.com/seifreed/surinort-ast
- **Issues**: https://github.com/seifreed/surinort-ast/issues
- **Discussions**: https://github.com/seifreed/surinort-ast/discussions

---

## Additional Resources


### Source Code Documentation

**Core API:**
- [src/surinort_ast/api/](src/surinort_ast/api/) - Modular public API package
  - [parsing.py](src/surinort_ast/api/parsing.py) - Rule parsing functions
  - [serialization.py](src/surinort_ast/api/serialization.py) - JSON serialization
  - [validation.py](src/surinort_ast/api/validation.py) - Rule validation
  - [printing.py](src/surinort_ast/api/printing.py) - Rule text formatting

**Parser Architecture:**
- [src/surinort_ast/parsing/](src/surinort_ast/parsing/) - Parser module with dependency inversion
  - [interfaces.py](src/surinort_ast/parsing/interfaces.py) - IParser protocol interface
  - [factory.py](src/surinort_ast/parsing/factory.py) - ParserFactory for creating parsers
  - [lark_parser.py](src/surinort_ast/parsing/lark_parser.py) - LarkRuleParser implementation
  - [parser_config.py](src/surinort_ast/parsing/parser_config.py) - ParserConfig with resource limits
  - [grammar.lark](src/surinort_ast/parsing/grammar.lark) - Complete LALR(1) grammar

**Core Infrastructure:**
- [src/surinort_ast/core/nodes.py](src/surinort_ast/core/nodes.py) - AST node definitions (60+ types)
- [src/surinort_ast/core/enums.py](src/surinort_ast/core/enums.py) - Action, Protocol, Direction enums
- [src/surinort_ast/core/visitor.py](src/surinort_ast/core/visitor.py) - Visitor pattern for AST traversal

**Advanced Features:**
- [src/surinort_ast/analysis/](src/surinort_ast/analysis/) - Rule analysis and optimization modules
- [src/surinort_ast/query/](src/surinort_ast/query/) - Query API (EXPERIMENTAL)
  - [protocols.py](src/surinort_ast/query/protocols.py) - Protocol interfaces for circular dependency resolution
  - [selectors.py](src/surinort_ast/query/selectors.py) - Selector implementations
  - [executor.py](src/surinort_ast/query/executor.py) - Query execution engine
- [src/surinort_ast/builder/](src/surinort_ast/builder/) - Builder pattern (EXPERIMENTAL)
- [src/surinort_ast/streaming/](src/surinort_ast/streaming/) - Streaming API

**Examples:**
- [examples/](examples/) - Complete example catalog with learning path

### Community
- **GitHub Repository**: https://github.com/seifreed/surinort-ast
- **Issue Tracker**: https://github.com/seifreed/surinort-ast/issues

---

**Built for security professionals, researchers, and SOC engineers.**
