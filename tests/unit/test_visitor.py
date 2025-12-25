# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for AST visitor and transformer patterns.

Tests visitor pattern implementation with real AST traversal.
NO MOCKS - all tests use actual visitor execution on real AST nodes.
"""

from lark import Lark

from surinort_ast.core.nodes import ContentOption, IPAddress, MsgOption, SidOption
from surinort_ast.core.visitor import ASTTransformer, ASTVisitor, ASTWalker
from surinort_ast.parsing.transformer import RuleTransformer


class SIDCollector(ASTVisitor[list[int]]):
    """Test visitor that collects all SID values."""

    def __init__(self):
        super().__init__()
        self.sids = []

    def visit_SidOption(self, node: SidOption) -> list[int]:
        """Collect SID value."""
        self.sids.append(node.value)
        return self.sids

    def default_return(self) -> list[int]:
        """Return collected SIDs."""
        return self.sids


class MessageCollector(ASTVisitor[list[str]]):
    """Test visitor that collects all message texts."""

    def __init__(self):
        super().__init__()
        self.messages = []

    def visit_MsgOption(self, node: MsgOption) -> list[str]:
        """Collect message text."""
        self.messages.append(node.text)
        return self.messages

    def default_return(self) -> list[str]:
        """Return collected messages."""
        return self.messages


class TestVisitorPattern:
    """Test ASTVisitor pattern."""

    def test_collect_single_sid(self, lark_parser: Lark, transformer: RuleTransformer):
        """Collect SID from single rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1000001; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Visit with SID collector
        collector = SIDCollector()
        collector.visit(rule)

        assert len(collector.sids) == 1
        assert 1000001 in collector.sids

    def test_collect_messages(self, lark_parser: Lark, transformer: RuleTransformer):
        """Collect message texts."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Message"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Visit with message collector
        collector = MessageCollector()
        collector.visit(rule)

        assert len(collector.messages) == 1
        assert "Test Message" in collector.messages

    def test_visit_multiple_rules(self, lark_parser: Lark, transformer: RuleTransformer):
        """Visit multiple rules."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
            'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
        ]

        rules = []
        for rule_text in rules_text:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Collect SIDs from all rules
        collector = SIDCollector()
        for rule in rules:
            collector.visit(rule)

        assert len(collector.sids) == 3
        assert collector.sids == [1, 2, 3]


class SIDIncrementer(ASTTransformer):
    """Test transformer that increments all SIDs by a value."""

    def __init__(self, increment: int = 1000000):
        super().__init__()
        self.increment = increment

    def visit_SidOption(self, node: SidOption) -> SidOption:
        """Increment SID value."""
        return node.model_copy(update={"value": node.value + self.increment})


class IPReplacer(ASTTransformer):
    """Test transformer that replaces IP addresses."""

    def __init__(self, old_ip: str, new_ip: str):
        super().__init__()
        self.old_ip = old_ip
        self.new_ip = new_ip

    def visit_IPAddress(self, node: IPAddress) -> IPAddress:
        """Replace IP address."""
        if node.value == self.old_ip:
            return node.model_copy(update={"value": self.new_ip})
        return node


class TestTransformerPattern:
    """Test ASTTransformer pattern."""

    def test_increment_sid(self, lark_parser: Lark, transformer: RuleTransformer):
        """Transform rule by incrementing SID."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        # Find original SID
        original_sid = next(
            (o.value for o in original_rule.options if isinstance(o, SidOption)), None
        )
        assert original_sid == 1

        # Transform
        incrementer = SIDIncrementer(increment=1000000)
        new_rule = incrementer.visit(original_rule)

        # Find new SID
        new_sid = next((o.value for o in new_rule.options if isinstance(o, SidOption)), None)
        assert new_sid == 1000001

        # Original unchanged
        original_sid_after = next(
            (o.value for o in original_rule.options if isinstance(o, SidOption)), None
        )
        assert original_sid_after == 1

    def test_replace_ip_address(self, lark_parser: Lark, transformer: RuleTransformer):
        """Transform rule by replacing IP address."""
        rule_text = 'alert tcp 192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        # Verify original IP
        assert isinstance(original_rule.header.src_addr, IPAddress)
        assert original_rule.header.src_addr.value == "192.168.1.1"

        # Transform
        replacer = IPReplacer(old_ip="192.168.1.1", new_ip="10.0.0.1")
        new_rule = replacer.visit(original_rule)

        # Verify new IP
        assert isinstance(new_rule.header.src_addr, IPAddress)
        assert new_rule.header.src_addr.value == "10.0.0.1"

        # Original unchanged
        assert original_rule.header.src_addr.value == "192.168.1.1"

    def test_transform_multiple_nodes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Transform multiple nodes in one pass."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        # Transform with large increment
        incrementer = SIDIncrementer(increment=5000000)
        new_rule = incrementer.visit(original_rule)

        # Check transformation
        original_sid = next(
            (o.value for o in original_rule.options if isinstance(o, SidOption)), None
        )
        new_sid = next((o.value for o in new_rule.options if isinstance(o, SidOption)), None)

        assert original_sid == 1
        assert new_sid == 5000001


class NodeCounter(ASTWalker):
    """Test walker that counts nodes."""

    def __init__(self):
        super().__init__()
        self.count = 0

    def generic_visit(self, node):
        """Count each node visited."""
        self.count += 1
        super().generic_visit(node)


class TestWalkerPattern:
    """Test ASTWalker pattern."""

    def test_count_nodes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Count all nodes in AST."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Walk and count
        counter = NodeCounter()
        counter.walk(rule)

        # Should have counted multiple nodes (rule, header, options, addresses, ports)
        assert counter.count > 0

    def test_walk_complex_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Walk complex rule with many nodes."""
        rule_text = 'alert http any any -> any any (msg:"Complex"; flow:established,to_server; http.method; content:"POST"; sid:2000001; rev:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Walk
        counter = NodeCounter()
        counter.walk(rule)

        # Complex rule should have many nodes
        assert counter.count > 5


class TestVisitorIntegration:
    """Test visitor integration with real rules."""

    def test_collect_all_sids_from_fixtures(
        self, lark_parser: Lark, transformer: RuleTransformer, fixtures_dir
    ):
        """Collect all SIDs from fixture rules."""
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        rules = []
        with open(simple_rules_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parse_tree = lark_parser.parse(line)
                rule = transformer.transform(parse_tree)[0]
                rules.append(rule)

        # Collect all SIDs
        collector = SIDCollector()
        for rule in rules:
            collector.visit(rule)

        # Should have collected multiple SIDs
        assert len(collector.sids) > 0
        # All SIDs should be unique (in fixture)
        assert len(set(collector.sids)) == len(collector.sids)

    def test_transform_fixture_rules(
        self, lark_parser: Lark, transformer: RuleTransformer, fixtures_dir
    ):
        """Transform all fixture rules."""
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        rules = []
        with open(simple_rules_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parse_tree = lark_parser.parse(line)
                rule = transformer.transform(parse_tree)[0]
                rules.append(rule)

        # Transform all rules (increment SIDs)
        incrementer = SIDIncrementer(increment=9000000)
        transformed_rules = [incrementer.visit(rule) for rule in rules]

        # All SIDs should be incremented
        for original, transformed in zip(rules, transformed_rules, strict=False):
            original_sid = next(
                (o.value for o in original.options if isinstance(o, SidOption)), None
            )
            transformed_sid = next(
                (o.value for o in transformed.options if isinstance(o, SidOption)), None
            )

            if original_sid is not None:
                assert transformed_sid == original_sid + 9000000


class TestCustomVisitors:
    """Test custom visitor implementations."""

    class ContentPatternCollector(ASTVisitor[list[bytes]]):
        """Collect all content patterns."""

        def __init__(self):
            super().__init__()
            self.patterns = []

        def visit_ContentOption(self, node: ContentOption) -> list[bytes]:
            """Collect content pattern."""
            self.patterns.append(node.pattern)
            return self.patterns

        def default_return(self) -> list[bytes]:
            """Return patterns."""
            return self.patterns

    def test_collect_content_patterns(self, lark_parser: Lark, transformer: RuleTransformer):
        """Collect content patterns from rule."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; content:"POST"; sid:1;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Collect patterns
        collector = self.ContentPatternCollector()
        collector.visit(rule)

        assert len(collector.patterns) >= 1
        assert b"GET" in collector.patterns or b"POST" in collector.patterns
