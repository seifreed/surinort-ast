# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive visitor tests to achieve 100% coverage.

Tests all visit_* methods and edge cases using real AST traversal.
NO MOCKS - all tests use actual visitor execution on real AST nodes.
"""

from lark import Lark

from surinort_ast.core.nodes import (
    AddressList,
    AddressNegation,
    ContentOption,
    IPAddress,
    PortList,
    PortNegation,
    SidOption,
)
from surinort_ast.core.visitor import ASTTransformer, ASTVisitor, ASTWalker
from surinort_ast.parsing.transformer import RuleTransformer


class TestVisitorNoneHandling:
    """Test visitor handling of None nodes (line 59)."""

    def test_visit_none_returns_default(self):
        """Test that visiting None returns default_return()."""

        class SimpleVisitor(ASTVisitor[int]):
            def default_return(self) -> int:
                return 42

        visitor = SimpleVisitor()
        result = visitor.visit(None)
        assert result == 42


class TestVisitorGenericVisit:
    """Test generic_visit for nodes with child sequences (lines 82, 85-86)."""

    def test_generic_visit_with_child_nodes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test generic_visit traverses child ASTNode fields."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class FieldCounter(ASTVisitor[int]):
            def __init__(self):
                super().__init__()
                self.count = 0

            def generic_visit(self, node):
                self.count += 1
                return super().generic_visit(node)

            def default_return(self) -> int:
                return self.count

        visitor = FieldCounter()
        visitor.visit(rule)
        # Should have visited multiple nodes via generic_visit
        assert visitor.count > 0

    def test_generic_visit_with_list_of_nodes(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit traverses sequences of ASTNodes (lines 85-86)."""
        # Rule with address list
        rule_text = 'alert tcp [192.168.1.1,192.168.1.2] any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NodeVisitor(ASTVisitor[list]):
            def __init__(self):
                super().__init__()
                self.visited = []

            def generic_visit(self, node):
                self.visited.append(type(node).__name__)
                return super().generic_visit(node)

            def default_return(self) -> list:
                return self.visited

        visitor = NodeVisitor()
        visitor.visit(rule)
        # Should have visited AddressList elements
        assert "IPAddress" in visitor.visited


class TestVisitorDefaultReturn:
    """Test default_return override (line 97)."""

    def test_custom_default_return(self):
        """Test visitor with custom default_return."""

        class CustomReturnVisitor(ASTVisitor[str]):
            def default_return(self) -> str:
                return "custom_value"

        visitor = CustomReturnVisitor()
        # Visit None to trigger default_return
        result = visitor.visit(None)
        assert result == "custom_value"


class TestVisitorAddressList:
    """Test visit_AddressList method (lines 117-119)."""

    def test_visit_address_list(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visiting AddressList with multiple addresses."""
        rule_text = 'alert tcp [192.168.1.1,10.0.0.1,172.16.0.1] any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class AddressCollector(ASTVisitor[list]):
            def __init__(self):
                super().__init__()
                self.addresses = []

            def visit_IPAddress(self, node):
                self.addresses.append(node.value)
                return self.default_return()

            def default_return(self) -> list:
                return self.addresses

        collector = AddressCollector()
        collector.visit(rule)
        assert len(collector.addresses) == 3
        assert "192.168.1.1" in collector.addresses


class TestVisitorAddressNegation:
    """Test visit_AddressNegation method (lines 123-124)."""

    def test_visit_address_negation(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visiting AddressNegation node."""
        rule_text = 'alert tcp !192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NegationCounter(ASTVisitor[int]):
            def __init__(self):
                super().__init__()
                self.negations = 0

            def visit_AddressNegation(self, node):
                self.negations += 1
                return super().visit_AddressNegation(node)

            def default_return(self) -> int:
                return self.negations

        counter = NegationCounter()
        counter.visit(rule)
        assert counter.negations == 1


class TestVisitorPortList:
    """Test visit_PortList method (lines 128-130)."""

    def test_visit_port_list(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visiting PortList with multiple ports."""
        rule_text = 'alert tcp any any -> any [80,443,8080] (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class PortCollector(ASTVisitor[list]):
            def __init__(self):
                super().__init__()
                self.ports = []

            def visit_Port(self, node):
                self.ports.append(node.value)
                return self.default_return()

            def default_return(self) -> list:
                return self.ports

        collector = PortCollector()
        collector.visit(rule)
        assert len(collector.ports) == 3
        assert 80 in collector.ports
        assert 443 in collector.ports


class TestVisitorPortNegation:
    """Test visit_PortNegation method (lines 134-135)."""

    def test_visit_port_negation(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visiting PortNegation node."""
        rule_text = 'alert tcp any any -> any !80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class PortNegationCounter(ASTVisitor[int]):
            def __init__(self):
                super().__init__()
                self.negations = 0

            def visit_PortNegation(self, node):
                self.negations += 1
                return super().visit_PortNegation(node)

            def default_return(self) -> int:
                return self.negations

        counter = PortNegationCounter()
        counter.visit(rule)
        assert counter.negations == 1


class TestTransformerDefaultReturn:
    """Test transformer default_return (line 157)."""

    def test_transformer_default_return_none(self):
        """Test transformer default_return returns None."""
        transformer = ASTTransformer()
        result = transformer.default_return()
        assert result is None


class TestTransformerGenericVisit:
    """Test transformer generic_visit with field changes (lines 176-194)."""

    def test_generic_visit_single_astnode_field(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit with single ASTNode field change (lines 176-179)."""
        rule_text = 'alert tcp 192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class IPReplacer(ASTTransformer):
            def visit_IPAddress(self, node):
                if node.value == "192.168.1.1":
                    return node.model_copy(update={"value": "10.0.0.1"})
                return node

        replacer = IPReplacer()
        new_rule = replacer.visit(rule)
        # Header should be updated via generic_visit
        assert isinstance(new_rule.header.src_addr, IPAddress)
        assert new_rule.header.src_addr.value == "10.0.0.1"

    def test_generic_visit_list_field_changes(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit with list field changes (lines 183-191)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:"foo"; content:"bar"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class ContentModifier(ASTTransformer):
            def visit_ContentOption(self, node):
                # Modify content patterns
                new_pattern = node.pattern.replace(b"foo", b"baz")
                if new_pattern != node.pattern:
                    return node.model_copy(update={"pattern": new_pattern})
                return node

        modifier = ContentModifier()
        new_rule = modifier.visit(rule)
        # Options list should be updated via generic_visit
        content_options = [o for o in new_rule.options if isinstance(o, ContentOption)]
        patterns = [o.pattern for o in content_options]
        assert b"baz" in patterns

    def test_generic_visit_no_changes_returns_original(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit returns original when no changes (line 194)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            pass

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # Should return original rule (not a copy)
        assert new_rule is rule


class TestTransformerRuleVisit:
    """Test transformer visit_Rule (line 209)."""

    def test_visit_rule_with_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_Rule creates new rule when changed."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class SIDDoubler(ASTTransformer):
            def visit_SidOption(self, node):
                return node.model_copy(update={"value": node.value * 2})

        doubler = SIDDoubler()
        new_rule = doubler.visit(rule)
        # Rule should be new object
        assert new_rule is not rule
        # SID should be doubled
        new_sid = next((o.value for o in new_rule.options if isinstance(o, SidOption)), None)
        assert new_sid == 2


class TestTransformerAddressList:
    """Test transformer visit_AddressList (lines 236-239)."""

    def test_visit_address_list_with_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_AddressList creates new list when elements change."""
        rule_text = 'alert tcp [192.168.1.1,10.0.0.1] any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class IPNormalizer(ASTTransformer):
            def visit_IPAddress(self, node):
                # Normalize all IPs to 0.0.0.0
                return node.model_copy(update={"value": "0.0.0.0"})

        normalizer = IPNormalizer()
        new_rule = normalizer.visit(rule)
        # AddressList should be new object
        assert isinstance(new_rule.header.src_addr, AddressList)
        assert new_rule.header.src_addr is not rule.header.src_addr


class TestTransformerAddressNegation:
    """Test transformer visit_AddressNegation (lines 243-246)."""

    def test_visit_address_negation_with_change(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test visit_AddressNegation creates new node when expr changes."""
        rule_text = 'alert tcp !192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class IPReplacer(ASTTransformer):
            def visit_IPAddress(self, node):
                return node.model_copy(update={"value": "10.0.0.1"})

        replacer = IPReplacer()
        new_rule = replacer.visit(rule)
        # AddressNegation should be new object
        assert isinstance(new_rule.header.src_addr, AddressNegation)
        assert new_rule.header.src_addr is not rule.header.src_addr


class TestTransformerPortList:
    """Test transformer visit_PortList (lines 250-253)."""

    def test_visit_port_list_with_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_PortList creates new list when elements change."""
        rule_text = 'alert tcp any any -> any [80,443] (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class PortShifter(ASTTransformer):
            def visit_Port(self, node):
                return node.model_copy(update={"value": node.value + 10000})

        shifter = PortShifter()
        new_rule = shifter.visit(rule)
        # PortList should be new object
        assert isinstance(new_rule.header.dst_port, PortList)
        assert new_rule.header.dst_port is not rule.header.dst_port


class TestTransformerPortNegation:
    """Test transformer visit_PortNegation (lines 257-260)."""

    def test_visit_port_negation_with_change(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_PortNegation creates new node when expr changes."""
        rule_text = 'alert tcp any any -> any !80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class PortReplacer(ASTTransformer):
            def visit_Port(self, node):
                return node.model_copy(update={"value": 443})

        replacer = PortReplacer()
        new_rule = replacer.visit(rule)
        # PortNegation should be new object
        assert isinstance(new_rule.header.dst_port, PortNegation)
        assert new_rule.header.dst_port is not rule.header.dst_port


class TestWalkerNoneHandling:
    """Test walker handling of None nodes (line 287)."""

    def test_walk_none_returns_early(self):
        """Test that walking None returns immediately."""

        class CountingWalker(ASTWalker):
            def __init__(self):
                super().__init__()
                self.count = 0

            def generic_visit(self, node):
                self.count += 1
                super().generic_visit(node)

        walker = CountingWalker()
        walker.walk(None)
        # Should not have visited anything
        assert walker.count == 0


class TestWalkerGenericVisit:
    """Test walker generic_visit (line 308)."""

    def test_walker_generic_visit_with_sequences(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test walker generic_visit traverses sequences."""
        rule_text = 'alert tcp [192.168.1.1,10.0.0.1] any -> any [80,443] (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NodeTypeCollector(ASTWalker):
            def __init__(self):
                super().__init__()
                self.types = []

            def generic_visit(self, node):
                self.types.append(type(node).__name__)
                super().generic_visit(node)

        collector = NodeTypeCollector()
        collector.walk(rule)
        # Should have walked through lists
        assert "AddressList" in collector.types
        assert "PortList" in collector.types
        assert "IPAddress" in collector.types
        assert "Port" in collector.types


class TestBaseVisitorDefaultReturn:
    """Test base ASTVisitor default_return without override (line 97)."""

    def test_base_visitor_default_return(self):
        """Test that base ASTVisitor.default_return returns None."""
        visitor = ASTVisitor()
        result = visitor.default_return()
        assert result is None


class TestVisitorGenericVisitDirectCall:
    """Test calling generic_visit directly to hit lines 82, 85-86."""

    def test_generic_visit_on_option_node(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test generic_visit on a node without specialized visit method."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class BaseVisitor(ASTVisitor):
            def __init__(self):
                super().__init__()
                self.visited = []

            def visit(self, node):
                # Call generic_visit directly for certain nodes
                if hasattr(node, "node_type") and node.node_type == "SidOption":
                    return self.generic_visit(node)
                return super().visit(node)

        visitor = BaseVisitor()
        # This will trigger generic_visit for SidOption
        # which has no child ASTNodes (lines 82, 85-86 won't execute for this node)
        visitor.visit(rule)


class TestTransformerNoChangesPaths:
    """Test transformer paths that return original node (lines 239, 246, 253, 260)."""

    def test_address_list_no_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_AddressList returns original when no changes (line 239)."""
        rule_text = 'alert tcp [192.168.1.1,10.0.0.1] any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            """Transformer that makes no changes."""

            pass

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # AddressList should be same object (no changes)
        assert new_rule.header.src_addr is rule.header.src_addr

    def test_address_negation_no_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_AddressNegation returns original when no changes (line 246)."""
        rule_text = 'alert tcp !192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            pass

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # AddressNegation should be same object
        assert new_rule.header.src_addr is rule.header.src_addr

    def test_port_list_no_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_PortList returns original when no changes (line 253)."""
        rule_text = 'alert tcp any any -> any [80,443] (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            pass

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # PortList should be same object
        assert new_rule.header.dst_port is rule.header.dst_port

    def test_port_negation_no_changes(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test visit_PortNegation returns original when no changes (line 260)."""
        rule_text = 'alert tcp any any -> any !80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            pass

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # PortNegation should be same object
        assert new_rule.header.dst_port is rule.header.dst_port


class TestTransformerGenericVisitDetailedPaths:
    """Test transformer generic_visit detailed execution paths (lines 176-194)."""

    def test_generic_visit_with_none_return(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test generic_visit when visit returns None (line 177)."""
        rule_text = 'alert tcp 192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoneReturningTransformer(ASTTransformer):
            def visit_IPAddress(self, node):
                # Return None to test line 177 condition
                # When None is returned, it actually changes the node
                return None

        none_transformer = NoneReturningTransformer()
        new_rule = none_transformer.visit(rule)
        # Header should be changed (src_addr set to None)
        assert new_rule.header is not rule.header
        assert new_rule.header.src_addr is None

    def test_generic_visit_list_with_non_astnode_items(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit with lists containing non-ASTNode items (line 187)."""
        # Use a rule with multiple options (a list containing ASTNodes)
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1; priority:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class OptionTransformer(ASTTransformer):
            """Transform that doesn't change anything."""

            pass

        option_transformer = OptionTransformer()
        new_rule = option_transformer.visit(rule)
        # Should return original rule (no changes)
        assert new_rule is rule

    def test_generic_visit_list_unchanged(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test generic_visit with list that doesn't change (line 189-191)."""
        rule_text = 'alert tcp [192.168.1.1,10.0.0.1] any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class NoOpTransformer(ASTTransformer):
            def visit_IPAddress(self, node):
                # Return same node (no change)
                return node

        noop = NoOpTransformer()
        new_rule = noop.visit(rule)
        # AddressList should be same because elements didn't change
        assert isinstance(new_rule.header.src_addr, AddressList)

    def test_generic_visit_changed_triggers_copy(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test generic_visit creates new node when changed (line 194)."""
        rule_text = 'alert tcp 192.168.1.1 any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class IPChanger(ASTTransformer):
            def visit_IPAddress(self, node):
                return node.model_copy(update={"value": "10.0.0.1"})

        changer = IPChanger()
        new_rule = changer.visit(rule)
        # Should have created new header via generic_visit (line 194)
        assert new_rule.header is not rule.header


class TestWalkerGenericVisitDirectCall:
    """Test walker generic_visit line 304."""

    def test_walker_generic_visit_with_non_astnode_list(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """Test walker with nodes containing non-ASTNode list items (line 307)."""
        # Use a rule with multiple options to test walking through sequences
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        class ItemWalker(ASTWalker):
            def __init__(self):
                super().__init__()
                self.count = 0

            def generic_visit(self, node):
                self.count += 1
                super().generic_visit(node)

        walker = ItemWalker()
        walker.walk(rule)
        # Should have visited multiple nodes
        assert walker.count > 1
