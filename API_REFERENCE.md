# API Reference

Complete reference documentation for the `surisnort-ast` public API.

---

## Table of Contents

1. [Public API Overview](#public-api-overview)
2. [Core Functions](#core-functions)
3. [AST Nodes](#ast-nodes)
4. [Parser API](#parser-api)
5. [Serializer API](#serializer-api)
6. [Validator API](#validator-api)
7. [Visitor API](#visitor-api)
8. [Utility Functions](#utility-functions)
9. [Type Definitions](#type-definitions)
10. [Exceptions](#exceptions)
11. [CLI Commands](#cli-commands)

---

## Public API Overview

### Import Paths

```python
# High-level API (recommended)
from surisnort_ast import (
    parse_rule,
    parse_ruleset,
    serialize_rule,
    serialize_ruleset,
    validate_rule,
    validate_ruleset,
)

# AST nodes
from surisnort_ast.nodes import (
    Rule,
    Header,
    Address,
    Port,
    Options,
    Option,
)

# Advanced APIs
from surisnort_ast.parser import Parser
from surisnort_ast.serializer import Serializer
from surisnort_ast.validator import Validator
from surisnort_ast.visitor import Visitor

# Types and exceptions
from surisnort_ast.types import (
    Action,
    Protocol,
    Direction,
    ValidationResult,
)
from surisnort_ast.exceptions import (
    ParseError,
    ValidationError,
    SerializationError,
)
```

### API Stability

- **Stable**: Core functions, AST nodes, standard types
- **Experimental**: Visitor API, advanced transformations
- **Internal**: Parser internals, lexer implementation

---

## Core Functions

### parse_rule()

Parse a single Suricata/Snort rule into an AST.

**Signature**:
```python
def parse_rule(
    rule_text: str,
    *,
    strict: bool = True,
    dialect: Optional[Dialect] = None,
) -> Rule:
```

**Parameters**:
- `rule_text` (str): The rule text to parse
- `strict` (bool): If True, raise on syntax errors; if False, use error recovery (default: True)
- `dialect` (Optional[Dialect]): Force specific dialect (Suricata/Snort), or auto-detect (default: None)

**Returns**:
- `Rule`: Parsed AST representation

**Raises**:
- `ParseError`: If rule syntax is invalid (when strict=True)

**Example**:
```python
from surisnort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)')
print(rule.action)  # Action.ALERT
print(rule.protocol)  # Protocol.TCP
print(rule.destination.port)  # Port(80)
```

**Advanced Example**:
```python
# Non-strict parsing with error recovery
try:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1', strict=False)
except ParseError as e:
    print(f"Recovered from error: {e}")
    print(f"Partial AST available: {e.partial_ast}")
```

---

### parse_ruleset()

Parse multiple rules from a file or string.

**Signature**:
```python
def parse_ruleset(
    rules_text: str,
    *,
    strict: bool = True,
    skip_errors: bool = False,
    dialect: Optional[Dialect] = None,
) -> List[Rule]:
```

**Parameters**:
- `rules_text` (str): Multiple rules separated by newlines
- `strict` (bool): Raise on syntax errors (default: True)
- `skip_errors` (bool): Skip invalid rules and continue (default: False)
- `dialect` (Optional[Dialect]): Force specific dialect

**Returns**:
- `List[Rule]`: List of parsed rules

**Raises**:
- `ParseError`: On invalid syntax (when strict=True and skip_errors=False)

**Example**:
```python
from surisnort_ast import parse_ruleset

rules_text = """
alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)
alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)
"""

rules = parse_ruleset(rules_text)
print(f"Parsed {len(rules)} rules")

# Skip invalid rules
rules = parse_ruleset(rules_text, skip_errors=True)
```

---

### serialize_rule()

Convert an AST rule back to text format.

**Signature**:
```python
def serialize_rule(
    rule: Rule,
    *,
    style: SerializationStyle = SerializationStyle.STANDARD,
    preserve_comments: bool = True,
) -> str:
```

**Parameters**:
- `rule` (Rule): AST rule to serialize
- `style` (SerializationStyle): Formatting style (default: STANDARD)
- `preserve_comments` (bool): Include comments if available (default: True)

**Returns**:
- `str`: Serialized rule text

**Raises**:
- `SerializationError`: If rule is invalid or cannot be serialized

**Example**:
```python
from surisnort_ast import parse_rule, serialize_rule, SerializationStyle

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Standard formatting
print(serialize_rule(rule))
# Output: alert tcp any any -> any 80 (msg:"Test"; sid:1;)

# Pretty formatting
print(serialize_rule(rule, style=SerializationStyle.PRETTY))
# Output:
# alert tcp any any -> any 80 (
#     msg:"Test";
#     sid:1;
# )

# Compact formatting
print(serialize_rule(rule, style=SerializationStyle.COMPACT))
# Output: alert tcp any any->any 80(msg:"Test";sid:1;)
```

---

### serialize_ruleset()

Serialize multiple rules to text.

**Signature**:
```python
def serialize_ruleset(
    rules: List[Rule],
    *,
    style: SerializationStyle = SerializationStyle.STANDARD,
    separator: str = "\n",
) -> str:
```

**Parameters**:
- `rules` (List[Rule]): List of rules to serialize
- `style` (SerializationStyle): Formatting style
- `separator` (str): Separator between rules (default: "\n")

**Returns**:
- `str`: Serialized rules

**Example**:
```python
from surisnort_ast import parse_ruleset, serialize_ruleset

rules = parse_ruleset("""
alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)
alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)
""")

output = serialize_ruleset(rules)
print(output)
```

---

### validate_rule()

Validate rule syntax and semantics.

**Signature**:
```python
def validate_rule(
    rule: Union[str, Rule],
    *,
    level: ValidationLevel = ValidationLevel.STRICT,
) -> ValidationResult:
```

**Parameters**:
- `rule` (Union[str, Rule]): Rule text or AST to validate
- `level` (ValidationLevel): Validation strictness (default: STRICT)

**Returns**:
- `ValidationResult`: Validation result with errors/warnings

**Example**:
```python
from surisnort_ast import validate_rule, ValidationLevel

# Validate rule text
result = validate_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
if result.is_valid:
    print("Rule is valid")
else:
    for error in result.errors:
        print(f"Error: {error}")

# Relaxed validation
result = validate_rule(rule, level=ValidationLevel.RELAXED)
for warning in result.warnings:
    print(f"Warning: {warning}")
```

---

### validate_ruleset()

Validate multiple rules.

**Signature**:
```python
def validate_ruleset(
    rules: Union[str, List[Rule]],
    *,
    level: ValidationLevel = ValidationLevel.STRICT,
    check_duplicates: bool = True,
) -> RulesetValidationResult:
```

**Parameters**:
- `rules` (Union[str, List[Rule]]): Rules text or AST list
- `level` (ValidationLevel): Validation strictness
- `check_duplicates` (bool): Check for duplicate SIDs (default: True)

**Returns**:
- `RulesetValidationResult`: Aggregate validation result

**Example**:
```python
from surisnort_ast import validate_ruleset

result = validate_ruleset("""
alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)
alert tcp any any -> any 80 (msg:"Duplicate"; sid:1;)
""", check_duplicates=True)

print(f"Valid: {result.is_valid}")
print(f"Total errors: {len(result.errors)}")
print(f"Duplicate SIDs: {result.duplicate_sids}")
```

---

## AST Nodes

### Rule

Top-level AST node representing a complete rule.

**Class Definition**:
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
```

**Attributes**:
- `action` (Action): Rule action (alert, drop, reject, pass, log)
- `protocol` (Protocol): Network protocol (tcp, udp, icmp, ip, http, etc.)
- `source` (Address): Source address and port specification
- `destination` (Address): Destination address and port specification
- `direction` (Direction): Traffic direction (unidirectional `->` or bidirectional `<>`)
- `options` (Options): Rule options (msg, sid, content, etc.)
- `comments` (List[Comment]): Attached comments (if preserved)

**Methods**:
```python
def replace(self, **changes) -> Rule:
    """Create modified copy of rule."""

def get_option(self, name: str) -> Optional[Option]:
    """Get option by name."""

def has_option(self, name: str) -> bool:
    """Check if option exists."""

def to_dict(self) -> Dict[str, Any]:
    """Convert to dictionary."""

def serialize(self, style: SerializationStyle = SerializationStyle.STANDARD) -> str:
    """Serialize to rule text."""

def validate(self) -> ValidationResult:
    """Validate rule."""
```

**Example**:
```python
from surisnort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)')

# Access attributes
print(rule.action)  # Action.ALERT
print(rule.protocol)  # Protocol.TCP
print(rule.direction)  # Direction.UNIDIRECTIONAL

# Get option
msg_option = rule.get_option("msg")
print(msg_option.value)  # "Test"

# Modify rule (creates new instance)
modified = rule.replace(action=Action.DROP)
print(modified.action)  # Action.DROP

# Check option existence
if rule.has_option("pcre"):
    print("Rule has PCRE pattern")
```

---

### Address

Address specification (IP/port combination).

**Class Definition**:
```python
@dataclass(frozen=True)
class Address(ASTNode):
    """Address specification in rule header."""

    addr: Union[str, List[str]]  # IP, CIDR, variable, or group
    port: Port
    negated: bool = False
```

**Attributes**:
- `addr` (Union[str, List[str]]): Address(es) - IP, CIDR, variable (`$HOME_NET`), or list
- `port` (Port): Port specification
- `negated` (bool): If True, represents `!addr` (default: False)

**Methods**:
```python
def is_variable(self) -> bool:
    """Check if address is a variable."""

def is_any(self) -> bool:
    """Check if address is 'any'."""

def is_group(self) -> bool:
    """Check if address is a group [...]."""
```

**Example**:
```python
from surisnort_ast.nodes import Address, Port

# Single IP
addr = Address(addr="192.168.1.1", port=Port(80))

# CIDR
addr = Address(addr="192.168.0.0/16", port=Port("any"))

# Variable
addr = Address(addr="$HOME_NET", port=Port("any"))

# Negated
addr = Address(addr="192.168.1.1", port=Port(80), negated=True)

# Group
addr = Address(addr=["192.168.1.1", "10.0.0.1"], port=Port([80, 443]))
```

---

### Port

Port specification.

**Class Definition**:
```python
@dataclass(frozen=True)
class Port(ASTNode):
    """Port specification."""

    value: Union[int, str, List[int], PortRange]
    negated: bool = False
```

**Attributes**:
- `value` (Union[int, str, List[int], PortRange]): Port(s) - single, "any", list, or range
- `negated` (bool): If True, represents `!port`

**Methods**:
```python
def is_any(self) -> bool:
    """Check if port is 'any'."""

def is_range(self) -> bool:
    """Check if port is a range."""

def is_group(self) -> bool:
    """Check if port is a group."""
```

**Example**:
```python
from surisnort_ast.nodes import Port, PortRange

# Single port
port = Port(80)

# Any port
port = Port("any")

# Port range
port = Port(PortRange(start=1024, end=65535))

# Port group
port = Port([80, 443, 8080])

# Negated
port = Port(80, negated=True)  # !80
```

---

### Options

Collection of rule options.

**Class Definition**:
```python
@dataclass(frozen=True)
class Options(ASTNode):
    """Collection of rule options."""

    options: List[Option]
```

**Methods**:
```python
def get(self, name: str) -> Optional[Option]:
    """Get option by name."""

def has(self, name: str) -> bool:
    """Check if option exists."""

def filter(self, predicate: Callable[[Option], bool]) -> List[Option]:
    """Filter options by predicate."""

def get_all(self, name: str) -> List[Option]:
    """Get all options with given name (for multi-value options)."""
```

**Example**:
```python
from surisnort_ast import parse_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

options = rule.options

# Get specific option
msg = options.get("msg")
print(msg.value)  # "Test"

# Check existence
if options.has("content"):
    print("Rule has content match")

# Get all content options
contents = options.get_all("content")
for content in contents:
    print(content.value)
```

---

### Option (Abstract Base)

Base class for all rule options.

**Class Definition**:
```python
@dataclass(frozen=True)
class Option(ASTNode, ABC):
    """Abstract base for rule options."""

    name: str

    @abstractmethod
    def serialize(self) -> str:
        """Serialize option to text."""
```

**Derived Classes**:
- `SimpleOption`: Simple key:value options (msg, sid, rev, etc.)
- `ContentOption`: Content matching with modifiers
- `PCREOption`: Perl-compatible regex patterns
- `FlowOption`: Flow direction and state
- `ByteTestOption`: Byte testing operations
- `ByteJumpOption`: Byte jumping operations
- `ReferenceOption`: External references
- `MetadataOption`: Metadata key-value pairs

---

### SimpleOption

Simple key-value option.

**Class Definition**:
```python
@dataclass(frozen=True)
class SimpleOption(Option):
    """Simple option with single value."""

    value: Union[str, int, bool]
```

**Example**:
```python
from surisnort_ast.nodes import SimpleOption

# String value
opt = SimpleOption(name="msg", value="HTTP Traffic")

# Integer value
opt = SimpleOption(name="sid", value=1000001)

# Boolean flag
opt = SimpleOption(name="noalert", value=True)
```

---

### ContentOption

Content matching option with modifiers.

**Class Definition**:
```python
@dataclass(frozen=True)
class ContentOption(Option):
    """Content matching option."""

    pattern: Union[str, bytes]
    modifiers: ContentModifiers = field(default_factory=ContentModifiers)
```

**ContentModifiers**:
```python
@dataclass
class ContentModifiers:
    """Content option modifiers."""

    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None
    fast_pattern: bool = False
    http_uri: bool = False
    http_header: bool = False
    http_cookie: bool = False
    http_method: bool = False
```

**Example**:
```python
from surisnort_ast.nodes import ContentOption, ContentModifiers

# Simple content
opt = ContentOption(name="content", pattern="admin")

# Content with modifiers
opt = ContentOption(
    name="content",
    pattern="admin",
    modifiers=ContentModifiers(
        nocase=True,
        offset=10,
        depth=100,
        http_uri=True
    )
)

# Hex content
opt = ContentOption(name="content", pattern=b"\x3a\x2f\x2f")
```

---

### PCREOption

Perl-compatible regex option.

**Class Definition**:
```python
@dataclass(frozen=True)
class PCREOption(Option):
    """PCRE pattern option."""

    pattern: str
    modifiers: str = ""
```

**Example**:
```python
from surisnort_ast.nodes import PCREOption

# Basic PCRE
opt = PCREOption(name="pcre", pattern="/admin/i")

# PCRE with modifiers
opt = PCREOption(name="pcre", pattern="/\/login\.php/", modifiers="iU")
```

---

## Parser API

### Parser Class

Low-level parser interface for advanced use cases.

**Class Definition**:
```python
class Parser:
    """Low-level rule parser."""

    def __init__(
        self,
        strict: bool = True,
        dialect: Optional[Dialect] = None,
    ):
        """Initialize parser."""

    def parse(self, text: str) -> Rule:
        """Parse rule text."""

    def parse_header(self) -> Header:
        """Parse rule header only."""

    def parse_options(self) -> Options:
        """Parse rule options only."""
```

**Example**:
```python
from surisnort_ast.parser import Parser

parser = Parser(strict=True)
rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
```

---

## Serializer API

### Serializer Class

Low-level serialization interface.

**Class Definition**:
```python
class Serializer:
    """AST to text serializer."""

    def __init__(
        self,
        style: SerializationStyle = SerializationStyle.STANDARD,
        indent: int = 4,
    ):
        """Initialize serializer."""

    def serialize(self, rule: Rule) -> str:
        """Serialize rule to text."""

    def serialize_header(self, rule: Rule) -> str:
        """Serialize header only."""

    def serialize_options(self, options: Options) -> str:
        """Serialize options only."""
```

**SerializationStyle**:
```python
class SerializationStyle(Enum):
    """Serialization formatting styles."""

    COMPACT = "compact"      # Minimal whitespace
    STANDARD = "standard"    # Standard formatting
    PRETTY = "pretty"        # Multi-line with indentation
```

**Example**:
```python
from surisnort_ast import parse_rule
from surisnort_ast.serializer import Serializer, SerializationStyle

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

serializer = Serializer(style=SerializationStyle.PRETTY, indent=2)
output = serializer.serialize(rule)
print(output)
```

---

## Validator API

### Validator Class

Rule validation interface.

**Class Definition**:
```python
class Validator:
    """Rule validator."""

    def __init__(
        self,
        level: ValidationLevel = ValidationLevel.STRICT,
    ):
        """Initialize validator."""

    def validate(self, rule: Rule) -> ValidationResult:
        """Validate single rule."""

    def validate_syntax(self, rule: Rule) -> ValidationResult:
        """Validate syntax only."""

    def validate_semantics(self, rule: Rule) -> ValidationResult:
        """Validate semantics only."""
```

**ValidationLevel**:
```python
class ValidationLevel(Enum):
    """Validation strictness levels."""

    RELAXED = "relaxed"    # Warnings only
    STANDARD = "standard"  # Common errors
    STRICT = "strict"      # All checks
```

**ValidationResult**:
```python
@dataclass
class ValidationResult:
    """Validation result."""

    is_valid: bool
    errors: List[ValidationError]
    warnings: List[ValidationWarning]
```

**Example**:
```python
from surisnort_ast import parse_rule
from surisnort_ast.validator import Validator, ValidationLevel

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

validator = Validator(level=ValidationLevel.STRICT)
result = validator.validate(rule)

if not result.is_valid:
    for error in result.errors:
        print(f"Error: {error.message} at {error.position}")
```

---

## Visitor API

### Visitor Pattern

Base visitor for AST traversal.

**Class Definition**:
```python
class Visitor(ABC):
    """Abstract visitor for AST traversal."""

    @abstractmethod
    def visit_rule(self, node: Rule) -> Any:
        """Visit Rule node."""

    @abstractmethod
    def visit_option(self, node: Option) -> Any:
        """Visit Option node."""

    def generic_visit(self, node: ASTNode) -> Any:
        """Fallback visitor."""
```

**Example: Custom Visitor**:
```python
from surisnort_ast.visitor import Visitor
from surisnort_ast.nodes import Rule, Option

class SidCollector(Visitor):
    """Collect all SIDs from rules."""

    def __init__(self):
        self.sids = []

    def visit_rule(self, node: Rule) -> None:
        for option in node.options.options:
            option.accept(self)

    def visit_option(self, node: Option) -> None:
        if node.name == "sid":
            self.sids.append(node.value)

# Usage
from surisnort_ast import parse_ruleset

rules = parse_ruleset("""
alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
""")

collector = SidCollector()
for rule in rules:
    rule.accept(collector)

print(collector.sids)  # [1, 2]
```

---

## Utility Functions

### normalize_rule()

Normalize rule formatting.

**Signature**:
```python
def normalize_rule(rule: Union[str, Rule]) -> str:
```

**Example**:
```python
from surisnort_ast.utils import normalize_rule

rule = 'alert   tcp any    any->any 80(msg:"Test";sid:1;)'
normalized = normalize_rule(rule)
print(normalized)
# Output: alert tcp any any -> any 80 (msg:"Test"; sid:1;)
```

---

### extract_sids()

Extract all SIDs from rules.

**Signature**:
```python
def extract_sids(rules: Union[str, List[Rule]]) -> Set[int]:
```

**Example**:
```python
from surisnort_ast.utils import extract_sids

sids = extract_sids("""
alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
""")
print(sids)  # {1, 2}
```

---

### compare_rules()

Compare two rules for equivalence.

**Signature**:
```python
def compare_rules(
    rule1: Union[str, Rule],
    rule2: Union[str, Rule],
    *,
    ignore_metadata: bool = False,
) -> bool:
```

**Example**:
```python
from surisnort_ast.utils import compare_rules

rule1 = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
rule2 = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

# Exact comparison
print(compare_rules(rule1, rule2))  # False

# Ignore metadata (rev, reference, etc.)
print(compare_rules(rule1, rule2, ignore_metadata=True))  # True
```

---

## Type Definitions

### Action

Rule action enumeration.

```python
class Action(Enum):
    """Rule actions."""

    ALERT = "alert"
    DROP = "drop"
    REJECT = "reject"
    PASS = "pass"
    LOG = "log"
```

---

### Protocol

Network protocol enumeration.

```python
class Protocol(Enum):
    """Network protocols."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
```

---

### Direction

Traffic direction enumeration.

```python
class Direction(Enum):
    """Traffic direction."""

    UNIDIRECTIONAL = "->"  # One-way
    BIDIRECTIONAL = "<>"   # Both directions
```

---

### Dialect

IDS/IPS dialect enumeration.

```python
class Dialect(Enum):
    """Rule dialect."""

    SURICATA = "suricata"
    SNORT2 = "snort2"
    SNORT3 = "snort3"
```

---

## Exceptions

### ParseError

Raised when rule parsing fails.

**Class Definition**:
```python
class ParseError(Exception):
    """Rule parsing error."""

    def __init__(
        self,
        message: str,
        position: Optional[Position] = None,
        partial_ast: Optional[Rule] = None,
    ):
        self.message = message
        self.position = position
        self.partial_ast = partial_ast
```

**Attributes**:
- `message` (str): Error description
- `position` (Optional[Position]): Error location (line, column)
- `partial_ast` (Optional[Rule]): Partially parsed AST (if available)

**Example**:
```python
from surisnort_ast import parse_rule
from surisnort_ast.exceptions import ParseError

try:
    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"')
except ParseError as e:
    print(f"Parse error: {e.message}")
    print(f"At line {e.position.line}, column {e.position.column}")
```

---

### ValidationError

Raised when rule validation fails.

**Class Definition**:
```python
class ValidationError(Exception):
    """Rule validation error."""

    def __init__(
        self,
        message: str,
        rule: Optional[Rule] = None,
        option: Optional[Option] = None,
    ):
        self.message = message
        self.rule = rule
        self.option = option
```

---

### SerializationError

Raised when AST serialization fails.

**Class Definition**:
```python
class SerializationError(Exception):
    """AST serialization error."""

    def __init__(
        self,
        message: str,
        node: Optional[ASTNode] = None,
    ):
        self.message = message
        self.node = node
```

---

## CLI Commands

### surisnort-ast parse

Parse rules and display AST.

**Usage**:
```bash
surisnort-ast parse [OPTIONS] [FILE]
```

**Options**:
- `-o, --output`: Output format (text, json, yaml, tree)
- `--strict/--no-strict`: Strict parsing mode
- `--dialect`: Force dialect (suricata, snort2, snort3)

**Example**:
```bash
# Parse and display as JSON
surisnort-ast parse rules.rules --output json

# Parse with error recovery
surisnort-ast parse rules.rules --no-strict

# Parse from stdin
cat rules.rules | surisnort-ast parse -
```

---

### surisnort-ast validate

Validate rule syntax and semantics.

**Usage**:
```bash
surisnort-ast validate [OPTIONS] [FILE]
```

**Options**:
- `--level`: Validation level (relaxed, standard, strict)
- `--check-duplicates`: Check for duplicate SIDs
- `--format`: Output format (text, json)

**Example**:
```bash
# Validate rules
surisnort-ast validate rules.rules

# Strict validation with duplicate checks
surisnort-ast validate rules.rules --level strict --check-duplicates
```

---

### surisnort-ast format

Format rules consistently.

**Usage**:
```bash
surisnort-ast format [OPTIONS] [FILE]
```

**Options**:
- `--style`: Format style (compact, standard, pretty)
- `--indent`: Indentation width (for pretty style)
- `-i, --in-place`: Modify file in place

**Example**:
```bash
# Pretty-print rules
surisnort-ast format rules.rules --style pretty

# Format in place
surisnort-ast format rules.rules --style standard -i
```

---

### surisnort-ast convert

Convert between formats.

**Usage**:
```bash
surisnort-ast convert [OPTIONS] [FILE]
```

**Options**:
- `--from`: Input format (rules, json, yaml)
- `--to`: Output format (rules, json, yaml)

**Example**:
```bash
# Rules to JSON
surisnort-ast convert rules.rules --from rules --to json > rules.json

# JSON to rules
surisnort-ast convert rules.json --from json --to rules > rules.rules
```

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](LICENSE) for full details.
