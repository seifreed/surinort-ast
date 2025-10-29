# Grammar Specification

Formal EBNF grammar specification for Suricata and Snort IDS/IPS rules.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Notation](#notation)
3. [Complete Grammar](#complete-grammar)
4. [Rule Header Grammar](#rule-header-grammar)
5. [Rule Options Grammar](#rule-options-grammar)
6. [Address Grammar](#address-grammar)
7. [Port Grammar](#port-grammar)
8. [Content Grammar](#content-grammar)
9. [Protocol-Specific Options](#protocol-specific-options)
10. [Grammar Extensions](#grammar-extensions)
11. [Dialect Differences](#dialect-differences)

---

## Introduction

This document provides the complete Extended Backus-Naur Form (EBNF) grammar specification for Suricata and Snort rules. The grammar is designed to be:

- **Complete**: Covers all Suricata 7.x and Snort 2.9.x/3.x syntax
- **Unambiguous**: Deterministic parsing without conflicts
- **Extensible**: Easy to add new keywords and options
- **Formal**: Machine-readable grammar definition

### Grammar Purpose

This grammar serves as:
1. **Parser Implementation Guide**: Formal specification for parser development
2. **Documentation**: Authoritative syntax reference
3. **Validation**: Syntax correctness verification
4. **Testing**: Grammar-based test case generation

---

## Notation

### EBNF Conventions

```ebnf
symbol      ::= definition     (* Production rule *)
'literal'                      (* Terminal literal *)
"string"                       (* String literal *)
[optional]                     (* Optional element *)
{repeated}                     (* Zero or more repetitions *)
{repeated}+                    (* One or more repetitions *)
(grouped)                      (* Grouping *)
option1 | option2              (* Alternative *)
(* comment *)                  (* Grammar comment *)
```

### Terminal Symbols

- **UPPERCASE**: Terminal symbols (tokens)
- **lowercase**: Non-terminal symbols (production rules)
- **'literal'**: Exact character sequences
- **regex**: Regular expression patterns

---

## Complete Grammar

### Top-Level Rule

```ebnf
rule ::= header options

header ::= action protocol source_address direction destination_address

options ::= '(' option_list ')'

option_list ::= option { ';' option }* [';']

option ::= simple_option
         | content_option
         | pcre_option
         | flow_option
         | byte_test_option
         | byte_jump_option
         | reference_option
         | metadata_option
         | threshold_option
         | flowbits_option
         | flowint_option
         | xbits_option
         | http_option
         | dns_option
         | tls_option
         | ssh_option
         | file_option
         | detection_filter_option
```

---

## Rule Header Grammar

### Actions

```ebnf
action ::= 'alert'
         | 'drop'
         | 'reject'
         | 'pass'
         | 'log'
         | 'activate'    (* Snort 2.x only *)
         | 'dynamic'     (* Snort 2.x only *)
         | 'sdrop'       (* Snort 3.x only *)
```

**Description**:
- `alert`: Generate alert and log packet
- `drop`: Block packet and alert (IPS mode)
- `reject`: Block and send RST/ICMP unreachable
- `pass`: Allow packet without logging
- `log`: Log packet without alert

---

### Protocols

```ebnf
protocol ::= 'tcp'
           | 'udp'
           | 'icmp'
           | 'ip'
           | 'http'      (* Suricata *)
           | 'http2'     (* Suricata *)
           | 'ftp'       (* Suricata *)
           | 'tls'       (* Suricata *)
           | 'ssh'       (* Suricata *)
           | 'dns'       (* Suricata *)
           | 'dcerpc'    (* Suricata *)
           | 'dhcp'      (* Suricata *)
           | 'dnp3'      (* Suricata *)
           | 'enip'      (* Suricata *)
           | 'nfs'       (* Suricata *)
           | 'ikev2'     (* Suricata *)
           | 'krb5'      (* Suricata *)
           | 'ntp'       (* Suricata *)
           | 'smb'       (* Suricata *)
           | 'smtp'      (* Suricata *)
           | 'snmp'      (* Suricata *)
           | 'tftp'      (* Suricata *)
```

---

### Direction

```ebnf
direction ::= '->'    (* Unidirectional *)
            | '<>'    (* Bidirectional *)
```

---

## Address Grammar

### Address Specification

```ebnf
source_address ::= address port

destination_address ::= address port

address ::= negation? address_spec

negation ::= '!'

address_spec ::= ip_address
               | ip_cidr
               | ip_range
               | variable
               | 'any'
               | address_group

address_group ::= '[' address_list ']'

address_list ::= address_spec { ',' address_spec }*
```

---

### IP Address Formats

```ebnf
ip_address ::= ipv4_address | ipv6_address

ipv4_address ::= DIGIT{1,3} '.' DIGIT{1,3} '.' DIGIT{1,3} '.' DIGIT{1,3}
               (* 0.0.0.0 to 255.255.255.255 *)

ipv6_address ::= ipv6_full | ipv6_compressed
               (* RFC 4291 format *)

ip_cidr ::= ip_address '/' prefix_length

prefix_length ::= DIGIT{1,2}  (* IPv4: 0-32, IPv6: 0-128 *)

ip_range ::= ip_address '-' ip_address
```

**Examples**:
```
192.168.1.1
192.168.0.0/16
10.0.0.1-10.0.0.255
2001:db8::1
!192.168.1.1
[192.168.1.1,10.0.0.1]
```

---

### Variables

```ebnf
variable ::= '$' IDENTIFIER

IDENTIFIER ::= [A-Z_] [A-Z0-9_]*
```

**Examples**:
```
$HOME_NET
$EXTERNAL_NET
$HTTP_SERVERS
$DNS_SERVERS
```

---

## Port Grammar

### Port Specification

```ebnf
port ::= negation? port_spec

port_spec ::= port_number
            | port_range
            | variable
            | 'any'
            | port_group

port_number ::= DIGIT{1,5}  (* 0-65535 *)

port_range ::= port_number ':' [port_number]
             | ':' port_number

port_group ::= '[' port_list ']'

port_list ::= port_spec { ',' port_spec }*
```

**Examples**:
```
80
443
1024:65535
:1023
!80
[80,443,8080]
$HTTP_PORTS
```

---

## Rule Options Grammar

### General Options

```ebnf
simple_option ::= keyword [':' value]

keyword ::= 'msg'
          | 'sid'
          | 'rev'
          | 'gid'
          | 'classtype'
          | 'priority'
          | 'reference'
          | 'metadata'
          | 'target'
          | 'noalert'
          | 'nolog'

value ::= string
        | integer
        | boolean
        | list
```

---

### Required Options

```ebnf
(* Every rule must have msg and sid *)
msg ::= 'msg' ':' string_value

sid ::= 'sid' ':' integer_value

rev ::= 'rev' ':' integer_value

gid ::= 'gid' ':' integer_value

classtype ::= 'classtype' ':' classtype_name

priority ::= 'priority' ':' integer_value
```

**Examples**:
```
msg:"HTTP GET Request"
sid:1000001
rev:1
gid:1
classtype:web-application-attack
priority:1
```

---

### Reference Option

```ebnf
reference_option ::= 'reference' ':' reference_system ',' reference_id

reference_system ::= 'bugtraq'
                   | 'cve'
                   | 'url'
                   | 'osvdb'
                   | 'mcafee'
                   | string_value
```

**Examples**:
```
reference:cve,2021-44228
reference:url,example.com/advisory
reference:bugtraq,12345
```

---

### Metadata Option

```ebnf
metadata_option ::= 'metadata' ':' metadata_list

metadata_list ::= metadata_pair { ',' metadata_pair }*

metadata_pair ::= key [value]

key ::= identifier

value ::= identifier | string_value | integer_value
```

**Examples**:
```
metadata:policy balanced-ips drop
metadata:created_at 2024-01-15, updated_at 2024-01-20
```

---

## Content Grammar

### Content Option

```ebnf
content_option ::= 'content' ':' content_pattern { ';' content_modifier }*

content_pattern ::= string_value
                  | hex_string
                  | mixed_content

string_value ::= '"' string_chars '"'

hex_string ::= '"' { hex_byte }+ '"'

hex_byte ::= '|' HEX_DIGIT HEX_DIGIT '|'

mixed_content ::= '"' { string_chars | hex_byte }+ '"'
```

**Examples**:
```
content:"admin"
content:"|0d 0a|"
content:"GET |20|/admin"
content:!"excluded"
```

---

### Content Modifiers

```ebnf
content_modifier ::= 'nocase'
                   | 'depth' ':' integer_value
                   | 'offset' ':' integer_value
                   | 'distance' ':' integer_value
                   | 'within' ':' integer_value
                   | 'fast_pattern'
                   | 'fast_pattern' ':' fast_pattern_spec
                   | 'rawbytes'
                   | 'bsize' ':' size_spec
                   | protocol_modifier

fast_pattern_spec ::= 'only'
                    | integer_value ',' integer_value  (* offset, length *)

protocol_modifier ::= 'http_uri'
                    | 'http_raw_uri'
                    | 'http_header'
                    | 'http_raw_header'
                    | 'http_cookie'
                    | 'http_method'
                    | 'http_user_agent'
                    | 'http_client_body'
                    | 'http_server_body'
                    | 'http_stat_code'
                    | 'http_stat_msg'
```

**Examples**:
```
content:"admin"; nocase; http_uri;
content:"password"; depth:100; offset:10;
content:"login"; distance:5; within:20;
content:"malware"; fast_pattern:only;
```

---

### PCRE Option

```ebnf
pcre_option ::= 'pcre' ':' pcre_pattern

pcre_pattern ::= '"' '/' regex '/' modifiers '"'
               | '"' delimiter regex delimiter modifiers '"'

delimiter ::= '/' | '#' | '@' | '!'

modifiers ::= { modifier_char }*

modifier_char ::= 'i'  (* case insensitive *)
                | 's'  (* dot matches newline *)
                | 'm'  (* multi-line *)
                | 'x'  (* extended regex *)
                | 'A'  (* anchor at start *)
                | 'E'  (* end anchor *)
                | 'G'  (* start at end of last match *)
                | 'R'  (* relative match *)
                | 'U'  (* ungreedy *)
                | 'B'  (* match in base64 decoded *)
                | 'P'  (* protocol-specific modifier *)
                | 'H'  (* HTTP modifier *)
                | 'D'  (* HTTP raw modifier *)
                | 'M'  (* HTTP method *)
                | 'C'  (* HTTP cookie *)
                | 'K'  (* HTTP header *)
                | 'S'  (* HTTP stat code *)
                | 'Y'  (* HTTP stat msg *)
                | 'I'  (* HTTP raw header *)
                | 'V'  (* HTTP user agent *)
                | 'W'  (* HTTP raw URI *)
```

**Examples**:
```
pcre:"/admin\\.php/i"
pcre:"/(password|passwd)/i"
pcre:"/eval\s*\([^\)]+\)/is"
pcre:"/\x2f\x61\x64\x6d\x69\x6e/i"
```

---

## Flow Grammar

### Flow Option

```ebnf
flow_option ::= 'flow' ':' flow_spec

flow_spec ::= flow_direction { ',' flow_state }*

flow_direction ::= 'to_client'
                 | 'to_server'
                 | 'from_client'
                 | 'from_server'
                 | 'established'
                 | 'not_established'
                 | 'stateless'

flow_state ::= 'established'
             | 'not_established'
             | 'stateless'
             | 'only_stream'
             | 'no_stream'
             | 'only_frag'
             | 'no_frag'
```

**Examples**:
```
flow:established,to_server
flow:to_client,established
flow:stateless
```

---

### Flowbits Option

```ebnf
flowbits_option ::= 'flowbits' ':' flowbits_action

flowbits_action ::= 'set' ',' flowbits_name
                  | 'isset' ',' flowbits_name
                  | 'isnotset' ',' flowbits_name
                  | 'toggle' ',' flowbits_name
                  | 'unset' ',' flowbits_name
                  | 'noalert'

flowbits_name ::= identifier { '|' identifier }*
```

**Examples**:
```
flowbits:set,http.login
flowbits:isset,http.login
flowbits:noalert
```

---

### Flowint Option

```ebnf
flowint_option ::= 'flowint' ':' flowint_name ',' flowint_action

flowint_action ::= '=' value
                 | '+' '=' value
                 | '-' '=' value
                 | '>' value
                 | '<' value
                 | '>=' value
                 | '<=' value
                 | '==' value
                 | '!=' value
                 | 'isset'
                 | 'isnotset'
```

**Examples**:
```
flowint:http_requests,=,0
flowint:http_requests,+=,1
flowint:http_requests,>,5
```

---

## Byte Operations Grammar

### Byte Test

```ebnf
byte_test_option ::= 'byte_test' ':' bytes_to_extract ',' operator ',' value ',' offset
                     { ',' byte_modifier }*

bytes_to_extract ::= '1' | '2' | '4' | '8' | '10'

operator ::= '<' | '>' | '<=' | '>=' | '=' | '!=' | '&' | '^'

offset ::= integer_value | variable_name

byte_modifier ::= 'relative'
                | 'big'
                | 'little'
                | 'dce'
                | 'string'
                | 'hex'
                | 'dec'
                | 'oct'
                | 'bitmask' ',' hex_value
```

**Examples**:
```
byte_test:4,>,1000,0
byte_test:2,=,80,20,relative
byte_test:4,&,0x80000000,0,big
```

---

### Byte Jump

```ebnf
byte_jump_option ::= 'byte_jump' ':' bytes_to_extract ',' offset
                     { ',' byte_modifier }*

bytes_to_extract ::= '0' | '1' | '2' | '4' | '8'

byte_modifier ::= 'relative'
                | 'multiplier' ',' integer_value
                | 'big'
                | 'little'
                | 'dce'
                | 'string'
                | 'hex'
                | 'dec'
                | 'oct'
                | 'align'
                | 'from_beginning'
                | 'from_end'
                | 'post_offset' ',' integer_value
```

**Examples**:
```
byte_jump:4,0
byte_jump:2,0,relative,multiplier 2
byte_jump:4,0,big,post_offset -4
```

---

### Byte Extract

```ebnf
byte_extract_option ::= 'byte_extract' ':' bytes_to_extract ',' offset ',' variable_name
                        { ',' byte_modifier }*

variable_name ::= identifier
```

**Examples**:
```
byte_extract:2,0,packet_length
byte_extract:4,20,content_size,relative,big
```

---

## Protocol-Specific Options

### HTTP Options

```ebnf
http_option ::= 'http_uri'
              | 'http_raw_uri'
              | 'http_header'
              | 'http_raw_header'
              | 'http_cookie'
              | 'http_user_agent'
              | 'http_method'
              | 'http_client_body'
              | 'http_server_body'
              | 'http_stat_code'
              | 'http_stat_msg'
              | 'http.uri' [';' buffer_options]
              | 'http.method' [';' buffer_options]
              | 'http.header' [';' buffer_options]
              | 'http.cookie' [';' buffer_options]
```

**Examples**:
```
content:"/admin"; http_uri;
pcre:"/admin\.php/i"; http_uri;
http.method; content:"POST";
```

---

### DNS Options

```ebnf
dns_option ::= 'dns_query'
             | 'dns.query' [';' buffer_options]
             | 'dns.opcode' ':' opcode_value
```

**Examples**:
```
content:"malware.com"; dns_query;
dns.opcode:0;
```

---

### TLS Options

```ebnf
tls_option ::= 'tls.sni' [';' buffer_options]
             | 'tls.cert_subject' [';' buffer_options]
             | 'tls.cert_issuer' [';' buffer_options]
             | 'tls.cert_serial' [';' buffer_options]
             | 'tls.cert_fingerprint' [';' buffer_options]
             | 'ssl_version' ':' ssl_version_value
             | 'ssl_state' ':' ssl_state_value
```

**Examples**:
```
tls.sni; content:"malicious.com";
ssl_version:tls1.2;
```

---

### SSH Options

```ebnf
ssh_option ::= 'ssh.proto' [';' buffer_options]
             | 'ssh.software' [';' buffer_options]
             | 'ssh.protoversion' ':' version_value
```

**Examples**:
```
ssh.proto; content:"2.0";
ssh.software; content:"OpenSSH";
```

---

### File Options

```ebnf
file_option ::= 'filestore'
              | 'filemagic' ':' magic_pattern
              | 'filename' ':' filename_pattern
              | 'fileext' ':' extension
              | 'filemd5' ':' md5_hash
              | 'filesha1' ':' sha1_hash
              | 'filesha256' ':' sha256_hash
              | 'filesize' ':' size_spec
```

**Examples**:
```
filestore;
fileext:"exe";
filemd5:!file_hash_list;
filesize:>1048576;
```

---

## Detection Filter Grammar

### Threshold Option

```ebnf
threshold_option ::= 'threshold' ':' threshold_type ',' 'track' ',' track_by
                     ',' 'count' ',' count ',' 'seconds' ',' seconds

threshold_type ::= 'type' 'limit'
                 | 'type' 'threshold'
                 | 'type' 'both'

track_by ::= 'by_src'
           | 'by_dst'
```

**Examples**:
```
threshold:type limit,track by_src,count 1,seconds 60
threshold:type threshold,track by_dst,count 10,seconds 60
```

---

### Detection Filter

```ebnf
detection_filter_option ::= 'detection_filter' ':' 'track' ',' track_by
                            ',' 'count' ',' count ',' 'seconds' ',' seconds
```

**Examples**:
```
detection_filter:track by_src,count 5,seconds 60
```

---

## Grammar Extensions

### Adding Custom Keywords

Custom keywords can be added using the extension mechanism:

```ebnf
custom_option ::= custom_keyword ':' custom_value

custom_keyword ::= identifier  (* User-defined keyword *)

custom_value ::= string_value
               | integer_value
               | list_value
```

**Example Plugin**:
```python
# Register custom keyword
register_keyword(
    name="custom_detect",
    grammar="'custom_detect' ':' string_value",
    node_class=CustomDetectOption
)
```

---

## Dialect Differences

### Suricata-Specific

```ebnf
(* Suricata extends the grammar with: *)
- Application layer protocols (http, dns, tls, etc.)
- Lua scripting: luajit option
- Dataset operations: dataset option
- Transformations: strip_whitespace, compress_whitespace
```

**Examples**:
```
luajit:script.lua;
dataset:set,malicious_ips,type ip,state /var/lib/ips.dat;
```

---

### Snort 2.x-Specific

```ebnf
(* Snort 2.x specific options: *)
- Preprocessor options: preprocessor keyword
- Dynamic rules: dynamicpreprocessor, dynamicengine
```

---

### Snort 3.x-Specific

```ebnf
(* Snort 3.x modernized syntax: *)
- Service-based detection: service option
- Inline normalization: normalize options
- Plugin system: plugin_* options
```

**Examples**:
```
service:http;
so:file solib.so,function detect;
```

---

## Grammar Validation

### Well-Formedness Rules

1. **Required Options**: Every rule must have `msg` and `sid`
2. **Option Ordering**: Some options must appear in specific order
3. **Content Modifiers**: Content modifiers must follow content option
4. **Relative Keywords**: Relative keywords require previous content
5. **Protocol Compatibility**: Protocol-specific options match protocol

---

## Grammar Implementation

### Parser Generator Configuration

```python
# For Lark parser generator
grammar_lark = r"""
    rule: header options

    header: ACTION PROTOCOL address "->" address
          | ACTION PROTOCOL address "<>" address

    address: [NEGATION] addr_spec PORT

    // ... complete grammar
"""
```

### Hand-Written Parser

```python
# Recursive descent parser structure
class Parser:
    def parse_rule(self):
        header = self.parse_header()
        options = self.parse_options()
        return Rule(header, options)

    def parse_header(self):
        action = self.parse_action()
        protocol = self.parse_protocol()
        # ...
```

---

## Testing Grammar

### Grammar Coverage

- **Positive Tests**: Valid rule syntax
- **Negative Tests**: Invalid syntax (should fail)
- **Edge Cases**: Boundary conditions
- **Ambiguity Tests**: Ensure deterministic parsing

**Example Tests**:
```python
# Valid syntax
assert parse("alert tcp any any -> any 80 (msg:\"Test\"; sid:1;)")

# Invalid syntax (should raise ParseError)
with pytest.raises(ParseError):
    parse("alert tcp any any -> any 80 (msg:\"Test\"")  # Missing closing paren

# Edge case
assert parse("alert tcp any any -> any any (msg:\"Any port\"; sid:1;)")
```

---

## References

### Standards
- [Suricata Rule Format Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Snort 2.x Rule Documentation](https://www.snort.org/documents)
- [Snort 3.x Rule Documentation](http://www.snort.org/snort3)
- [EBNF Specification ISO/IEC 14977](https://www.iso.org/standard/26153.html)

### Related Documentation
- [AST Specification](AST_SPEC.md)
- [Parser Implementation](docs/technical/parser-implementation.md)
- [Architecture Overview](ARCHITECTURE.md)

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.
