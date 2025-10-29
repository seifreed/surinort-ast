# Architecture Overview

This document describes the architectural design, implementation decisions, and internal structure of `surisnort-ast`.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [System Architecture](#system-architecture)
3. [Component Overview](#component-overview)
4. [Data Flow](#data-flow)
5. [AST Design](#ast-design)
6. [Parser Architecture](#parser-architecture)
7. [Serialization Strategy](#serialization-strategy)
8. [Extensibility Model](#extensibility-model)
9. [Performance Considerations](#performance-considerations)
10. [Design Decisions](#design-decisions)
11. [Future Architecture](#future-architecture)

---

## Design Philosophy

### Core Principles

1. **Formal Specification First**: Grammar and AST are formally specified before implementation
2. **Correctness Over Speed**: Prioritize parsing accuracy and AST fidelity
3. **Bidirectional Lossless**: Parse to AST and serialize back without information loss
4. **Extensible by Design**: Support custom keywords and rule options without core changes
5. **Type Safety**: Comprehensive type hints throughout the codebase
6. **Separation of Concerns**: Clear boundaries between parsing, AST, validation, and serialization

### Design Goals

- **Completeness**: Support 100% of Suricata/Snort rule syntax
- **Maintainability**: Clean architecture that scales with grammar complexity
- **Testability**: Every component independently testable
- **Documentation**: Self-documenting code with comprehensive external docs
- **Performance**: Handle production rulesets (10,000+ rules) efficiently

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                        │
│  ┌──────────────────────┐     ┌──────────────────────────┐  │
│  │   Python API         │     │   CLI (Click)            │  │
│  └──────────────────────┘     └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Core Components                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Parser  │  │   AST    │  │Serializer│  │Validator │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Foundation Layer                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Grammar  │  │  Lexer   │  │  Types   │  │ Utilities│    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Component Interactions

```
Rule Text
    │
    ▼
┌─────────┐     Tokens      ┌─────────┐      AST       ┌──────────┐
│  Lexer  │ ──────────────> │ Parser  │ ────────────> │   AST    │
└─────────┘                 └─────────┘                └──────────┘
                                                             │
                                                             │
                                                             ▼
┌──────────────┐   Validation   ┌──────────┐    Rule Text  │
│  Validator   │ <───────────── │   AST    │ <─────────────┘
└──────────────┘                └──────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │ Serializer   │
                              └──────────────┘
                                     │
                                     ▼
                                Rule Text
```

---

## Component Overview

### 1. Lexer (`lexer.py`)

**Responsibility**: Tokenize raw rule text into lexical tokens.

**Implementation**:
- Hand-written lexer for maximum control and performance
- Token types defined in `TokenType` enum
- Handles quoted strings, escape sequences, variables, and operators
- Position tracking for error reporting

**Token Categories**:
- Keywords: `alert`, `drop`, `tcp`, `udp`, `http`, etc.
- Operators: `->`, `<>`, `!`, `[`, `]`, `:`, `;`
- Literals: IP addresses, port numbers, strings, hex strings
- Identifiers: Variables (`$HOME_NET`), keywords

### 2. Grammar (`grammar.py`)

**Responsibility**: Formal EBNF grammar specification.

**Structure**:
```python
@dataclass
class Grammar:
    """Formal grammar definition for Suricata/Snort rules."""

    productions: Dict[str, Production]
    terminals: Dict[str, Terminal]
    start_symbol: str
```

**Grammar Representation**:
- Production rules as Python data structures
- Terminal symbols with regex patterns
- Grammar validation on initialization
- Export to EBNF notation

### 3. Parser (`parser.py`)

**Responsibility**: Transform token stream into AST.

**Architecture**:
- **Type**: Recursive descent parser with backtracking
- **Strategy**: Top-down predictive parsing
- **Error Recovery**: Synchronization on rule boundaries
- **Lookahead**: 1-token lookahead (LL(1) where possible)

**Parser Structure**:
```python
class Parser:
    def parse_rule(self) -> Rule:
        """Entry point: parse complete rule."""

    def parse_header(self) -> Header:
        """Parse rule header (action proto src -> dst)."""

    def parse_options(self) -> Options:
        """Parse rule options (content, sid, etc.)."""

    def parse_address(self) -> Address:
        """Parse address specification (IP, CIDR, range)."""

    def parse_port(self) -> Port:
        """Parse port specification (single, range, list)."""
```

**Error Handling**:
- `ParserError` with line/column information
- Error recovery strategies for malformed rules
- Detailed error messages with context

### 4. AST (`nodes.py`)

**Responsibility**: Structured representation of parsed rules.

**Design Pattern**: Composite Pattern

**Node Hierarchy**:
```
ASTNode (abstract base)
├── Rule
├── Header
│   ├── Action
│   ├── Protocol
│   ├── Address
│   └── Port
├── Options
│   └── Option (abstract)
│       ├── SimpleOption
│       ├── ContentOption
│       ├── PCREOption
│       ├── FlowOption
│       └── ... (specialized options)
└── Expressions
    ├── Literal
    ├── Variable
    └── Group
```

**Node Characteristics**:
- Immutable by default (use `replace()` for modifications)
- Type-safe with dataclasses
- JSON serializable
- Position information for error reporting
- Visitor pattern support

### 5. Serializer (`serializer.py`)

**Responsibility**: Convert AST back to rule text.

**Architecture**:
- Visitor pattern traversal
- Maintains formatting preferences (indent, spacing)
- Preserves comments (when captured during parsing)
- Validates AST before serialization

**Serialization Modes**:
- **Compact**: Minimal whitespace
- **Pretty**: Formatted with indentation
- **Preserve**: Maintains original formatting (when available)

### 6. Validator (`validator.py`)

**Responsibility**: Semantic validation of rules.

**Validation Layers**:

1. **Syntactic Validation**: Performed during parsing
2. **Semantic Validation**: Post-parse checks
3. **Context Validation**: Cross-rule dependencies

**Validation Checks**:
- Required options present (`sid`, `msg`)
- Option compatibility (protocol-specific options)
- Port/address format validity
- PCRE syntax correctness
- Content modifier compatibility
- Flow keyword validity

### 7. Types (`types.py`)

**Responsibility**: Type definitions and enums.

**Contents**:
- Enums: `Action`, `Protocol`, `Direction`
- Type aliases: `IPAddress`, `PortSpec`, `ContentModifiers`
- Data classes: `Position`, `Range`, `ValidationResult`

### 8. CLI (`cli.py`)

**Responsibility**: Command-line interface.

**Implementation**: Click framework

**Commands**:
- `parse`: Parse rules and display AST
- `validate`: Validate rule syntax/semantics
- `format`: Pretty-print rules
- `convert`: Convert between formats (text, JSON, YAML)
- `analyze`: Rule analysis and statistics

---

## Data Flow

### Parsing Flow

```
Input: 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
                    │
                    ▼
            ┌──────────────┐
            │    Lexer     │
            └──────────────┘
                    │
                    ▼
Tokens: [ALERT, TCP, ANY, ANY, ARROW, ANY, INT(80),
         LPAREN, MSG, COLON, STRING("Test"), SEMICOLON, ...]
                    │
                    ▼
            ┌──────────────┐
            │    Parser    │
            └──────────────┘
                    │
                    ▼
AST:
Rule(
  action=Action.ALERT,
  protocol=Protocol.TCP,
  source=Address(addr="any", port=Port("any")),
  destination=Address(addr="any", port=Port(80)),
  direction=Direction.UNIDIRECTIONAL,
  options=Options([
    SimpleOption(name="msg", value="Test"),
    SimpleOption(name="sid", value=1)
  ])
)
```

### Serialization Flow

```
AST (Rule object)
        │
        ▼
┌────────────────┐
│  Serializer    │
│  (Visitor)     │
└────────────────┘
        │
        ▼
Text Fragments:
["alert", "tcp", "any", "any", "->", "any", "80",
 "(", "msg:\"Test\"", ";", "sid:1", ";", ")"]
        │
        ▼
Join with spaces
        │
        ▼
'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
```

---

## AST Design

### Design Principles

1. **Immutability**: AST nodes are immutable (use `dataclasses(frozen=True)`)
2. **Type Safety**: Fully typed with Python type hints
3. **JSON Compatible**: All nodes serialize to/from JSON
4. **Position Tracking**: Every node tracks source position
5. **Visitor Pattern**: Support for AST traversal and transformation

### Node Structure

```python
@dataclass(frozen=True)
class ASTNode:
    """Base class for all AST nodes."""

    position: Optional[Position] = None

    def accept(self, visitor: 'Visitor') -> Any:
        """Accept visitor for traversal."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""

    def validate(self) -> ValidationResult:
        """Validate node constraints."""
```

### Example: Rule Node

```python
@dataclass(frozen=True)
class Rule(ASTNode):
    """Complete rule AST node."""

    action: Action
    protocol: Protocol
    source: Address
    destination: Address
    direction: Direction
    options: Options

    def replace(self, **changes) -> 'Rule':
        """Create modified copy."""
        return dataclasses.replace(self, **changes)
```

### AST Traversal

**Visitor Pattern Implementation**:

```python
class Visitor(ABC):
    """Abstract visitor for AST traversal."""

    @abstractmethod
    def visit_rule(self, node: Rule) -> Any:
        pass

    @abstractmethod
    def visit_option(self, node: Option) -> Any:
        pass
```

**Example Visitor**:

```python
class CountSidsVisitor(Visitor):
    """Count unique SIDs in ruleset."""

    def __init__(self):
        self.sids = set()

    def visit_rule(self, node: Rule) -> None:
        for option in node.options:
            if option.name == "sid":
                self.sids.add(option.value)
```

---

## Parser Architecture

### Parsing Strategy

**Type**: Recursive Descent Parser

**Characteristics**:
- Top-down parsing
- One-token lookahead (LL(1))
- Hand-written for control and performance
- Backtracking for ambiguous constructs

### Parser State

```python
@dataclass
class ParserState:
    """Parser state management."""

    tokens: List[Token]
    position: int
    errors: List[ParserError]

    def peek(self) -> Token:
        """Look at current token without consuming."""

    def consume(self, expected: TokenType) -> Token:
        """Consume token of expected type."""

    def match(self, *types: TokenType) -> bool:
        """Check if current token matches any type."""
```

### Error Recovery

**Strategy**: Panic Mode Recovery

1. **Synchronization Points**: Rule boundaries (`;` at top level)
2. **Error Tokens**: Insert synthetic tokens to continue parsing
3. **Error Aggregation**: Collect multiple errors before failing

**Example**:
```python
def parse_rule_safe(self) -> Optional[Rule]:
    """Parse rule with error recovery."""
    try:
        return self.parse_rule()
    except ParserError as e:
        self.errors.append(e)
        self.synchronize()  # Skip to next rule
        return None
```

### Grammar Ambiguity Resolution

**Challenge**: Distinguish between variables and literals.

**Solution**: Context-sensitive lexing.

```python
# Variable in address position
$HOME_NET  →  Variable("HOME_NET")

# Literal in other contexts
$1         →  Literal(1)  # In PCRE backreference
```

---

## Serialization Strategy

### Serialization Architecture

```python
class Serializer:
    """Convert AST to rule text."""

    def __init__(self, style: SerializationStyle):
        self.style = style

    def serialize_rule(self, rule: Rule) -> str:
        """Serialize complete rule."""

    def serialize_header(self, header: Header) -> str:
        """Serialize rule header."""

    def serialize_options(self, options: Options) -> str:
        """Serialize rule options."""
```

### Formatting Styles

**Compact**:
```
alert tcp any any->any 80(msg:"Test";sid:1;)
```

**Standard** (default):
```
alert tcp any any -> any 80 (msg:"Test"; sid:1;)
```

**Pretty**:
```
alert tcp any any -> any 80 (
    msg:"Test";
    sid:1;
    rev:1;
)
```

### Comment Preservation

**Challenge**: Standard AST doesn't capture comments.

**Solution**: Attach comments to nearest AST node.

```python
@dataclass
class Rule(ASTNode):
    comments: List[Comment] = field(default_factory=list)
```

---

## Extensibility Model

### Adding New Keywords

**Step 1**: Define grammar production.

```python
# In grammar.py
grammar.add_production(
    "new_keyword",
    "NEW_KEYWORD COLON value SEMICOLON"
)
```

**Step 2**: Create AST node.

```python
# In nodes.py
@dataclass(frozen=True)
class NewKeywordOption(Option):
    value: str
```

**Step 3**: Add parser method.

```python
# In parser.py
def parse_new_keyword(self) -> NewKeywordOption:
    self.consume(TokenType.NEW_KEYWORD)
    self.consume(TokenType.COLON)
    value = self.parse_value()
    self.consume(TokenType.SEMICOLON)
    return NewKeywordOption(value=value)
```

**Step 4**: Register with option parser.

```python
# In parser.py
OPTION_PARSERS = {
    "new_keyword": parse_new_keyword,
    # ... existing options
}
```

### Plugin System (Future)

```python
class KeywordPlugin(Protocol):
    """Protocol for keyword plugins."""

    keyword: str
    node_class: Type[Option]

    def parse(self, parser: Parser) -> Option:
        """Parse keyword from token stream."""

    def serialize(self, node: Option) -> str:
        """Serialize node to text."""

    def validate(self, node: Option) -> ValidationResult:
        """Validate node."""
```

---

## Performance Considerations

### Optimization Strategies

1. **Lexer Performance**:
   - Single-pass tokenization
   - Minimal backtracking
   - Compiled regex patterns cached

2. **Parser Performance**:
   - One-token lookahead (no multi-token lookahead)
   - Memoization for repeated parsing (packrat parsing)
   - Early exit on syntax errors

3. **Memory Efficiency**:
   - Immutable AST nodes (shared structure)
   - Interned strings for common values
   - Lazy evaluation of computed properties

4. **Serialization Performance**:
   - String builder pattern (avoid concatenation)
   - Pre-allocated buffers for large rulesets
   - Batch serialization of multiple rules

### Benchmarking

**Performance Targets**:
- Parse: 50,000 simple rules/second
- Serialize: 80,000 rules/second
- Validate: 40,000 rules/second
- Memory: <2KB per rule AST

**Profiling Points**:
```python
# In parser.py
@profile
def parse_rule(self) -> Rule:
    with Timer("parse_rule"):
        # parsing logic
```

---

## Design Decisions

### Why Recursive Descent Parser?

**Alternatives Considered**:
- Parser generators (PLY, Lark, ANTLR)
- Parser combinators (pyparsing)
- PEG parsers (parsimonious)

**Decision**: Hand-written recursive descent

**Rationale**:
- Full control over error messages
- Better performance for simple grammars
- No external dependencies
- Easier to debug and maintain
- Direct mapping from grammar to code

### Why Immutable AST?

**Alternatives Considered**:
- Mutable AST nodes
- Copy-on-write semantics

**Decision**: Immutable nodes with `replace()`

**Rationale**:
- Thread-safe by default
- Prevents accidental mutations
- Easier to reason about transformations
- Supports structural sharing (memory efficient)
- Aligns with functional programming principles

### Why Dataclasses?

**Alternatives Considered**:
- Plain classes with `__init__`
- attrs library
- Pydantic models

**Decision**: Standard library dataclasses

**Rationale**:
- No external dependencies
- Native Python 3.7+ support
- Type hint integration
- `frozen=True` for immutability
- Good performance

### Why Not Parser Generator?

**Trade-offs**:

**Parser Generator (Lark, ANTLR)**:
- Pros: Declarative grammar, less code
- Cons: Learning curve, debugging difficulty, external dependency

**Hand-written Parser**:
- Pros: Full control, better errors, no dependencies
- Cons: More code, manual maintenance

**Decision**: Hand-written for this project's needs.

---

## Future Architecture

### Planned Enhancements

1. **Incremental Parsing**:
   - Parse only changed rules in large files
   - Maintain parse cache with invalidation

2. **Parallel Processing**:
   - Parse multiple rules concurrently
   - Thread-safe AST operations

3. **AST Optimization**:
   - Compact AST representation
   - Lazy node evaluation
   - Structure sharing across similar rules

4. **Query Language**:
   - XPath-like queries on AST
   - Pattern matching on rule structure

5. **Advanced Validation**:
   - Cross-rule analysis (duplicate SIDs)
   - Performance impact estimation
   - Security best practice checks

### Extensibility Improvements

1. **Plugin Architecture**:
   - Dynamic keyword loading
   - Custom validation rules
   - Third-party serializers

2. **Transform Pipeline**:
   - Composable AST transformations
   - Rule optimization passes
   - Dialect conversion

---

## References

### Internal Documentation
- [Grammar Specification](GRAMMAR.md)
- [AST Specification](AST_SPEC.md)
- [API Reference](API_REFERENCE.md)

### External Resources
- [Suricata Rule Format](https://suricata.readthedocs.io/en/latest/rules/index.html)
- [Snort Rule Format](https://www.snort.org/documents)
- [Recursive Descent Parsing](https://en.wikipedia.org/wiki/Recursive_descent_parser)
- [Visitor Pattern](https://en.wikipedia.org/wiki/Visitor_pattern)

---

## License

Copyright (C) 2025 Marc Rivero López

This documentation is licensed under the GNU General Public License v3.0.

See [LICENSE](../LICENSE) for full details.
