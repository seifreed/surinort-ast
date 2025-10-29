# AST Specification

Formal specification of the Abstract Syntax Tree (AST) for Suricata/Snort rules with JSON Schema.

---

## Table of Contents

1. [Overview](#overview)
2. [AST Design Principles](#ast-design-principles)
3. [Node Hierarchy](#node-hierarchy)
4. [Core Node Specifications](#core-node-specifications)
5. [JSON Schema](#json-schema)
6. [Node Examples](#node-examples)
7. [Traversal Patterns](#traversal-patterns)
8. [Validation Rules](#validation-rules)
9. [Serialization Format](#serialization-format)

---

## Overview

The `surisnort-ast` AST is a structured representation of Suricata/Snort rules that:

- **Preserves Semantics**: Complete rule information without loss
- **Type-Safe**: Strongly typed nodes with validation
- **Immutable**: Nodes are immutable by default
- **JSON Compatible**: Full JSON serialization/deserialization
- **Position Tracking**: Source location information for error reporting

---

## AST Design Principles

### Immutability

All AST nodes are immutable using Python `dataclasses(frozen=True)`. Modifications create new instances.

```python
# Immutable modification
rule = parse_rule("alert tcp any any -> any 80 (msg:\"Test\"; sid:1;)")
modified = rule.replace(action=Action.DROP)  # Creates new instance
```

### Type Safety

Complete type hints throughout the AST:

```python
@dataclass(frozen=True)
class Rule(ASTNode):
    action: Action
    protocol: Protocol
    source: Address
    destination: Address
    direction: Direction
    options: Options
```

### Position Tracking

Every node tracks source position for error reporting:

```python
@dataclass(frozen=True)
class ASTNode:
    position: Optional[Position] = None

@dataclass
class Position:
    line: int
    column: int
    offset: int
```

---

## Node Hierarchy

```
ASTNode (abstract base)
│
├── Rule
│   ├── action: Action
│   ├── protocol: Protocol
│   ├── source: Address
│   ├── destination: Address
│   ├── direction: Direction
│   └── options: Options
│
├── Address
│   ├── addr: Union[str, List[str]]
│   ├── port: Port
│   └── negated: bool
│
├── Port
│   ├── value: Union[int, str, List[int], PortRange]
│   └── negated: bool
│
├── PortRange
│   ├── start: int
│   └── end: Optional[int]
│
├── Options
│   └── options: List[Option]
│
└── Option (abstract)
    ├── SimpleOption
    │   ├── name: str
    │   └── value: Union[str, int, bool]
    │
    ├── ContentOption
    │   ├── name: str
    │   ├── pattern: Union[str, bytes]
    │   └── modifiers: ContentModifiers
    │
    ├── PCREOption
    │   ├── name: str
    │   ├── pattern: str
    │   └── modifiers: str
    │
    ├── FlowOption
    │   ├── name: str
    │   ├── direction: Optional[str]
    │   └── states: List[str]
    │
    ├── ByteTestOption
    │   ├── name: str
    │   ├── bytes_to_extract: int
    │   ├── operator: str
    │   ├── value: int
    │   ├── offset: int
    │   └── modifiers: List[str]
    │
    ├── ByteJumpOption
    │   ├── name: str
    │   ├── bytes_to_extract: int
    │   ├── offset: int
    │   └── modifiers: List[str]
    │
    ├── ByteExtractOption
    │   ├── name: str
    │   ├── bytes_to_extract: int
    │   ├── offset: int
    │   ├── variable: str
    │   └── modifiers: List[str]
    │
    ├── ReferenceOption
    │   ├── name: str
    │   ├── system: str
    │   └── id: str
    │
    ├── MetadataOption
    │   ├── name: str
    │   └── pairs: Dict[str, Optional[str]]
    │
    ├── ThresholdOption
    │   ├── name: str
    │   ├── type: str
    │   ├── track: str
    │   ├── count: int
    │   └── seconds: int
    │
    ├── FlowbitsOption
    │   ├── name: str
    │   ├── action: str
    │   └── bits: List[str]
    │
    ├── FlowintOption
    │   ├── name: str
    │   ├── variable: str
    │   ├── operator: str
    │   └── value: int
    │
    └── DetectionFilterOption
        ├── name: str
        ├── track: str
        ├── count: int
        └── seconds: int
```

---

## Core Node Specifications

### ASTNode (Base Class)

**Purpose**: Abstract base for all AST nodes.

**Definition**:
```python
@dataclass(frozen=True)
class ASTNode(ABC):
    """Base class for all AST nodes."""

    position: Optional[Position] = None

    @abstractmethod
    def accept(self, visitor: 'Visitor') -> Any:
        """Accept visitor for traversal."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""

    def to_json(self, **kwargs) -> str:
        """Convert to JSON string."""

    def validate(self) -> ValidationResult:
        """Validate node constraints."""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ASTNode':
        """Create node from dictionary."""

    @classmethod
    def from_json(cls, json_str: str) -> 'ASTNode':
        """Create node from JSON string."""
```

---

### Rule Node

**Purpose**: Top-level representation of a complete rule.

**Definition**:
```python
@dataclass(frozen=True)
class Rule(ASTNode):
    """Complete Suricata/Snort rule."""

    action: Action
    protocol: Protocol
    source: Address
    destination: Address
    direction: Direction
    options: Options
    comments: List[Comment] = field(default_factory=list)

    def replace(self, **changes) -> 'Rule':
        """Create modified copy."""
        return dataclasses.replace(self, **changes)

    def get_option(self, name: str) -> Optional[Option]:
        """Get option by name."""
        return self.options.get(name)

    def has_option(self, name: str) -> bool:
        """Check if option exists."""
        return self.options.has(name)

    def serialize(self, style: SerializationStyle = SerializationStyle.STANDARD) -> str:
        """Serialize to rule text."""
        from .serializer import Serializer
        return Serializer(style).serialize(self)
```

**Constraints**:
- Must have at least `msg` and `sid` options
- `sid` must be positive integer
- `action` must be valid Action enum value
- `protocol` must be valid Protocol enum value

---

### Address Node

**Purpose**: Represent source or destination address specification.

**Definition**:
```python
@dataclass(frozen=True)
class Address(ASTNode):
    """Address specification (IP and port)."""

    addr: Union[str, List[str]]
    port: Port
    negated: bool = False

    def is_variable(self) -> bool:
        """Check if address is a variable (starts with $)."""
        return isinstance(self.addr, str) and self.addr.startswith('$')

    def is_any(self) -> bool:
        """Check if address is 'any'."""
        return self.addr == "any"

    def is_group(self) -> bool:
        """Check if address is a group (list)."""
        return isinstance(self.addr, list)

    def is_cidr(self) -> bool:
        """Check if address is CIDR notation."""
        return isinstance(self.addr, str) and '/' in self.addr

    def is_range(self) -> bool:
        """Check if address is a range."""
        return isinstance(self.addr, str) and '-' in self.addr
```

**Valid Formats**:
- Single IP: `"192.168.1.1"`
- CIDR: `"192.168.0.0/16"`
- Range: `"192.168.1.1-192.168.1.255"`
- Variable: `"$HOME_NET"`
- Any: `"any"`
- Group: `["192.168.1.1", "10.0.0.1"]`
- Negated: `negated=True` (represents `!addr`)

---

### Port Node

**Purpose**: Represent port specification.

**Definition**:
```python
@dataclass(frozen=True)
class Port(ASTNode):
    """Port specification."""

    value: Union[int, str, List[int], PortRange]
    negated: bool = False

    def is_any(self) -> bool:
        """Check if port is 'any'."""
        return self.value == "any"

    def is_range(self) -> bool:
        """Check if port is a range."""
        return isinstance(self.value, PortRange)

    def is_group(self) -> bool:
        """Check if port is a group."""
        return isinstance(self.value, list)

    def is_variable(self) -> bool:
        """Check if port is a variable."""
        return isinstance(self.value, str) and self.value.startswith('$')
```

**Valid Formats**:
- Single port: `80`
- Any: `"any"`
- Range: `PortRange(start=1024, end=65535)`
- Open-ended range: `PortRange(start=1024, end=None)` (represents `1024:`)
- Group: `[80, 443, 8080]`
- Variable: `"$HTTP_PORTS"`
- Negated: `negated=True` (represents `!port`)

---

### PortRange Node

**Purpose**: Represent port range.

**Definition**:
```python
@dataclass(frozen=True)
class PortRange(ASTNode):
    """Port range specification."""

    start: int
    end: Optional[int] = None  # None represents open-ended range

    def contains(self, port: int) -> bool:
        """Check if port is in range."""
        if self.end is None:
            return port >= self.start
        return self.start <= port <= self.end

    def __str__(self) -> str:
        """String representation."""
        if self.end is None:
            return f"{self.start}:"
        return f"{self.start}:{self.end}"
```

---

### Options Node

**Purpose**: Container for rule options.

**Definition**:
```python
@dataclass(frozen=True)
class Options(ASTNode):
    """Collection of rule options."""

    options: List[Option]

    def get(self, name: str) -> Optional[Option]:
        """Get first option with given name."""
        for opt in self.options:
            if opt.name == name:
                return opt
        return None

    def get_all(self, name: str) -> List[Option]:
        """Get all options with given name."""
        return [opt for opt in self.options if opt.name == name]

    def has(self, name: str) -> bool:
        """Check if option exists."""
        return self.get(name) is not None

    def filter(self, predicate: Callable[[Option], bool]) -> List[Option]:
        """Filter options by predicate."""
        return [opt for opt in self.options if predicate(opt)]

    def __getitem__(self, name: str) -> Option:
        """Get option by name (raises KeyError if not found)."""
        opt = self.get(name)
        if opt is None:
            raise KeyError(f"Option '{name}' not found")
        return opt
```

---

### Option Nodes

#### SimpleOption

**Purpose**: Simple key-value option.

```python
@dataclass(frozen=True)
class SimpleOption(Option):
    """Simple option with single value."""

    name: str
    value: Union[str, int, bool]

    def serialize(self) -> str:
        if isinstance(self.value, bool):
            return f"{self.name};"
        return f"{self.name}:{self.value};"
```

**Examples**:
- `msg:"HTTP Traffic"` → `SimpleOption(name="msg", value="HTTP Traffic")`
- `sid:1000001` → `SimpleOption(name="sid", value=1000001)`
- `noalert;` → `SimpleOption(name="noalert", value=True)`

---

#### ContentOption

**Purpose**: Content matching with modifiers.

```python
@dataclass(frozen=True)
class ContentOption(Option):
    """Content matching option."""

    name: str
    pattern: Union[str, bytes]
    modifiers: ContentModifiers = field(default_factory=ContentModifiers)
    negated: bool = False

    def serialize(self) -> str:
        neg = "!" if self.negated else ""
        pattern = self._format_pattern(self.pattern)
        mods = self.modifiers.serialize()
        return f"{self.name}:{neg}\"{pattern}\"{mods};"

@dataclass
class ContentModifiers:
    """Content option modifiers."""

    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    fast_pattern: bool = False
    fast_pattern_offset: Optional[int] = None
    fast_pattern_length: Optional[int] = None
    rawbytes: bool = False
    http_uri: bool = False
    http_raw_uri: bool = False
    http_header: bool = False
    http_raw_header: bool = False
    http_cookie: bool = False
    http_user_agent: bool = False
    http_method: bool = False
```

---

#### PCREOption

**Purpose**: Perl-compatible regex patterns.

```python
@dataclass(frozen=True)
class PCREOption(Option):
    """PCRE pattern option."""

    name: str
    pattern: str
    modifiers: str = ""
    negated: bool = False

    def serialize(self) -> str:
        neg = "!" if self.negated else ""
        return f"{self.name}:{neg}\"{self.pattern}{self.modifiers}\";"
```

---

#### FlowOption

**Purpose**: Flow direction and state.

```python
@dataclass(frozen=True)
class FlowOption(Option):
    """Flow option."""

    name: str
    direction: Optional[str] = None  # to_client, to_server, etc.
    states: List[str] = field(default_factory=list)  # established, etc.

    def serialize(self) -> str:
        parts = []
        if self.direction:
            parts.append(self.direction)
        parts.extend(self.states)
        return f"{self.name}:{','.join(parts)};"
```

---

## JSON Schema

Complete JSON Schema for AST serialization:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://github.com/mrivero/surisnort-ast/schema/ast.json",
  "title": "Suricata/Snort Rule AST",
  "type": "object",
  "required": ["node_type", "action", "protocol", "source", "destination", "direction", "options"],
  "properties": {
    "node_type": {
      "type": "string",
      "const": "Rule"
    },
    "action": {
      "type": "string",
      "enum": ["alert", "drop", "reject", "pass", "log", "activate", "dynamic", "sdrop"]
    },
    "protocol": {
      "type": "string",
      "enum": ["tcp", "udp", "icmp", "ip", "http", "http2", "ftp", "tls", "ssh", "dns", "dcerpc", "dhcp", "dnp3", "enip", "nfs", "ikev2", "krb5", "ntp", "smb", "smtp", "snmp", "tftp"]
    },
    "source": {
      "$ref": "#/definitions/Address"
    },
    "destination": {
      "$ref": "#/definitions/Address"
    },
    "direction": {
      "type": "string",
      "enum": ["->", "<>"]
    },
    "options": {
      "$ref": "#/definitions/Options"
    },
    "comments": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/Comment"
      }
    },
    "position": {
      "$ref": "#/definitions/Position"
    }
  },
  "definitions": {
    "Address": {
      "type": "object",
      "required": ["node_type", "addr", "port"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "Address"
        },
        "addr": {
          "oneOf": [
            { "type": "string" },
            {
              "type": "array",
              "items": { "type": "string" }
            }
          ]
        },
        "port": {
          "$ref": "#/definitions/Port"
        },
        "negated": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "Port": {
      "type": "object",
      "required": ["node_type", "value"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "Port"
        },
        "value": {
          "oneOf": [
            { "type": "integer", "minimum": 0, "maximum": 65535 },
            { "type": "string" },
            {
              "type": "array",
              "items": { "type": "integer", "minimum": 0, "maximum": 65535 }
            },
            {
              "$ref": "#/definitions/PortRange"
            }
          ]
        },
        "negated": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "PortRange": {
      "type": "object",
      "required": ["node_type", "start"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "PortRange"
        },
        "start": {
          "type": "integer",
          "minimum": 0,
          "maximum": 65535
        },
        "end": {
          "type": ["integer", "null"],
          "minimum": 0,
          "maximum": 65535
        }
      }
    },
    "Options": {
      "type": "object",
      "required": ["node_type", "options"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "Options"
        },
        "options": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/Option"
          }
        }
      }
    },
    "Option": {
      "oneOf": [
        { "$ref": "#/definitions/SimpleOption" },
        { "$ref": "#/definitions/ContentOption" },
        { "$ref": "#/definitions/PCREOption" },
        { "$ref": "#/definitions/FlowOption" },
        { "$ref": "#/definitions/ByteTestOption" },
        { "$ref": "#/definitions/ByteJumpOption" },
        { "$ref": "#/definitions/ByteExtractOption" },
        { "$ref": "#/definitions/ReferenceOption" },
        { "$ref": "#/definitions/MetadataOption" },
        { "$ref": "#/definitions/ThresholdOption" },
        { "$ref": "#/definitions/FlowbitsOption" },
        { "$ref": "#/definitions/FlowintOption" },
        { "$ref": "#/definitions/DetectionFilterOption" }
      ]
    },
    "SimpleOption": {
      "type": "object",
      "required": ["node_type", "name", "value"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "SimpleOption"
        },
        "name": {
          "type": "string"
        },
        "value": {
          "oneOf": [
            { "type": "string" },
            { "type": "integer" },
            { "type": "boolean" }
          ]
        }
      }
    },
    "ContentOption": {
      "type": "object",
      "required": ["node_type", "name", "pattern"],
      "properties": {
        "node_type": {
          "type": "string",
          "const": "ContentOption"
        },
        "name": {
          "type": "string"
        },
        "pattern": {
          "oneOf": [
            { "type": "string" },
            {
              "type": "string",
              "contentEncoding": "base64"
            }
          ]
        },
        "modifiers": {
          "$ref": "#/definitions/ContentModifiers"
        },
        "negated": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "ContentModifiers": {
      "type": "object",
      "properties": {
        "nocase": { "type": "boolean" },
        "offset": { "type": ["integer", "null"] },
        "depth": { "type": ["integer", "null"] },
        "distance": { "type": ["integer", "null"] },
        "within": { "type": ["integer", "null"] },
        "fast_pattern": { "type": "boolean" },
        "rawbytes": { "type": "boolean" },
        "http_uri": { "type": "boolean" },
        "http_header": { "type": "boolean" },
        "http_cookie": { "type": "boolean" }
      }
    },
    "Position": {
      "type": "object",
      "required": ["line", "column", "offset"],
      "properties": {
        "line": { "type": "integer", "minimum": 1 },
        "column": { "type": "integer", "minimum": 1 },
        "offset": { "type": "integer", "minimum": 0 }
      }
    }
  }
}
```

---

## Node Examples

### Complete Rule Example

**Rule Text**:
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP GET /admin"; flow:established,to_server; content:"GET"; http_method; content:"/admin"; http_uri; nocase; sid:1000001; rev:1;)
```

**AST JSON**:
```json
{
  "node_type": "Rule",
  "action": "alert",
  "protocol": "tcp",
  "source": {
    "node_type": "Address",
    "addr": "$EXTERNAL_NET",
    "port": {
      "node_type": "Port",
      "value": "any",
      "negated": false
    },
    "negated": false
  },
  "destination": {
    "node_type": "Address",
    "addr": "$HOME_NET",
    "port": {
      "node_type": "Port",
      "value": 80,
      "negated": false
    },
    "negated": false
  },
  "direction": "->",
  "options": {
    "node_type": "Options",
    "options": [
      {
        "node_type": "SimpleOption",
        "name": "msg",
        "value": "HTTP GET /admin"
      },
      {
        "node_type": "FlowOption",
        "name": "flow",
        "direction": "to_server",
        "states": ["established"]
      },
      {
        "node_type": "ContentOption",
        "name": "content",
        "pattern": "GET",
        "modifiers": {
          "http_method": true
        }
      },
      {
        "node_type": "ContentOption",
        "name": "content",
        "pattern": "/admin",
        "modifiers": {
          "http_uri": true,
          "nocase": true
        }
      },
      {
        "node_type": "SimpleOption",
        "name": "sid",
        "value": 1000001
      },
      {
        "node_type": "SimpleOption",
        "name": "rev",
        "value": 1
      }
    ]
  }
}
```

---

## Traversal Patterns

### Visitor Pattern

```python
class Visitor(ABC):
    """Abstract visitor."""

    @abstractmethod
    def visit_rule(self, node: Rule) -> Any:
        pass

    @abstractmethod
    def visit_option(self, node: Option) -> Any:
        pass

# Example: Collect all SIDs
class SidCollector(Visitor):
    def __init__(self):
        self.sids = []

    def visit_rule(self, node: Rule) -> None:
        for option in node.options.options:
            option.accept(self)

    def visit_option(self, node: Option) -> None:
        if node.name == "sid":
            self.sids.append(node.value)
```

---

## Validation Rules

### Structural Validation

1. **Required Options**: `msg` and `sid` must be present
2. **SID Range**: SID must be positive integer
3. **Port Range**: Port must be 0-65535
4. **IP Format**: Valid IPv4/IPv6 format
5. **Content Ordering**: Content modifiers follow content

### Semantic Validation

1. **Protocol Compatibility**: HTTP options require HTTP protocol
2. **Flow State**: Flow states compatible with protocol
3. **Relative Keywords**: Distance/within require previous content
4. **PCRE Syntax**: Valid Perl regex
5. **Option Conflicts**: Mutually exclusive options

---

## Serialization Format

### Text Format

Standard Suricata/Snort rule syntax:
```
alert tcp any any -> any 80 (msg:"Test"; sid:1;)
```

### JSON Format

Complete AST as JSON (see examples above).

### YAML Format

```yaml
node_type: Rule
action: alert
protocol: tcp
source:
  node_type: Address
  addr: any
  port:
    node_type: Port
    value: any
destination:
  node_type: Address
  addr: any
  port:
    node_type: Port
    value: 80
direction: "->"
options:
  node_type: Options
  options:
    - node_type: SimpleOption
      name: msg
      value: Test
    - node_type: SimpleOption
      name: sid
      value: 1
```

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.
