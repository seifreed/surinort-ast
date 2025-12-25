# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Shared pytest fixtures and configuration for surinort-ast test suite.

This module provides reusable fixtures for testing the IDS rule parser
using real rule data from the rules/ directory.
"""

from pathlib import Path

import pytest
from lark import Lark

# Import core modules
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing.transformer import RuleTransformer
from surinort_ast.printer.text_printer import TextPrinter
from surinort_ast.serialization.json_serializer import JSONSerializer

# ============================================================================
# Path Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture(scope="session")
def rules_dir(project_root: Path) -> Path:
    """Return rules directory containing real IDS rules."""
    return project_root / "rules"


@pytest.fixture(scope="session")
def suricata_rules_file(rules_dir: Path) -> Path:
    """Return path to Suricata rules file (30,579 active rules)."""
    return rules_dir / "suricata" / "suricata.rules"


@pytest.fixture(scope="session")
def snort29_rules_file(rules_dir: Path) -> Path:
    """Return path to Snort 2.9 community rules (561 active rules, 3,468 commented)."""
    return rules_dir / "snort" / "snort29-community-rules" / "community-rules" / "community.rules"


@pytest.fixture(scope="session")
def snort3_rules_file(rules_dir: Path) -> Path:
    """Return path to Snort 3 community rules (4,017 active rules)."""
    return (
        rules_dir
        / "snort"
        / "snort3-community-rules"
        / "snort3-community-rules"
        / "snort3-community.rules"
    )


@pytest.fixture(scope="session")
def fixtures_dir(project_root: Path) -> Path:
    """Return test fixtures directory."""
    return project_root / "tests" / "fixtures"


# ============================================================================
# Parser Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def grammar_file(project_root: Path) -> Path:
    """Return path to Lark grammar file."""
    return project_root / "src" / "surinort_ast" / "parsing" / "grammar.lark"


@pytest.fixture(scope="session")
def lark_parser(grammar_file: Path) -> Lark:
    """
    Create Lark parser instance (reused across session for performance).

    This fixture uses real Lark parser with actual grammar file.
    """
    with open(grammar_file, encoding="utf-8") as f:
        grammar_content = f.read()

    # Use Earley parser for maximum compatibility with complex grammar
    return Lark(
        grammar_content,
        parser="earley",
        propagate_positions=True,
        maybe_placeholders=False,
    )


@pytest.fixture
def transformer() -> RuleTransformer:
    """Create fresh RuleTransformer instance for each test."""
    return RuleTransformer()


@pytest.fixture
def text_printer() -> TextPrinter:
    """Create TextPrinter instance for converting AST to text."""
    return TextPrinter()


@pytest.fixture
def json_serializer() -> JSONSerializer:
    """Create JSONSerializer instance for JSON serialization."""
    return JSONSerializer()


# ============================================================================
# Sample Rule Fixtures
# ============================================================================


@pytest.fixture
def simple_rule_text() -> str:
    """Simple HTTP detection rule."""
    return 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'


@pytest.fixture
def complex_rule_text() -> str:
    """Complex rule with multiple content matches and modifiers."""
    return (
        "alert http $EXTERNAL_NET any -> $HOME_NET any "
        '(msg:"ET MALWARE Possible CobaltStrike Malleable C2 Profile"; '
        'flow:established,to_server; http.method; content:"POST"; '
        'http.uri; content:"/api/v1/"; depth:8; pcre:"/\\/api\\/v1\\/[a-z]{8,12}$/"; '
        'http.header; content:"Accept|3a| */*"; content:"User-Agent|3a| Mozilla/5.0"; '
        "classtype:trojan-activity; sid:2027452; rev:2; metadata:created_at 2019_06_10;)"
    )


@pytest.fixture
def malformed_rule_text() -> str:
    """Malformed rule for error recovery testing."""
    return 'alert tcp any any -> any 80 (msg:"Missing semicolon" sid:999)'


@pytest.fixture
def multiline_rule_text() -> str:
    """Multi-line rule (realistic format)."""
    return """alert tcp any any -> any 443 (
    msg:"TLS Suspicious Certificate";
    flow:established,to_server;
    tls.sni; content:"malicious.com"; nocase;
    tls.cert_subject; content:"CN=Fake";
    classtype:bad-unknown;
    sid:3000001;
    rev:1;
)"""


# ============================================================================
# Real Rule Sample Fixtures
# ============================================================================


@pytest.fixture(scope="session")
def suricata_sample_rules(suricata_rules_file: Path) -> list[str]:
    """
    Load first 100 non-comment lines from Suricata rules.

    Returns real rules for testing, skipping comments and empty lines.
    """
    rules = []
    with open(suricata_rules_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
                if len(rules) >= 100:
                    break
    return rules


@pytest.fixture(scope="session")
def snort_sample_rules(snort29_rules_file: Path) -> list[str]:
    """
    Load first 50 non-comment lines from Snort rules.

    Returns real rules for testing, skipping comments and empty lines.
    """
    rules = []
    with open(snort29_rules_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(line)
                if len(rules) >= 50:
                    break
    return rules


# ============================================================================
# Utility Functions
# ============================================================================


def parse_rule(rule_text: str, lark_parser: Lark, transformer: RuleTransformer) -> Rule:
    """
    Parse a single rule text to AST.

    Helper function for tests to parse rules using real parser.

    Args:
        rule_text: Rule text to parse
        lark_parser: Lark parser instance
        transformer: AST transformer

    Returns:
        Parsed Rule AST node
    """
    parse_tree = lark_parser.parse(rule_text)
    result = transformer.transform(parse_tree)

    # Handle single rule or list of rules
    if isinstance(result, list):
        return result[0] if result else None
    return result


def count_rules_in_file(file_path: Path) -> int:
    """
    Count non-comment, non-empty lines in a rule file.

    Args:
        file_path: Path to rule file

    Returns:
        Number of actual rules (excluding comments/empty lines)
    """
    count = 0
    with open(file_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                count += 1
    return count


# ============================================================================
# Pytest Configuration
# ============================================================================


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "golden: marks golden tests with real rule files")
    config.addinivalue_line("markers", "fuzzing: marks property-based fuzzing tests")
