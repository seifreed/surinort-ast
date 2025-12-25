# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for public API.

Tests the complete public API workflow with real data.
NO MOCKS - all tests use real parser, printer, and serializer.
"""

import pytest

# Note: These imports may need adjustment based on actual API structure
# from surinort_ast import parse_rule, print_rule, to_json, from_json


@pytest.mark.integration
class TestPublicAPI:
    """Test public API functions (if they exist)."""

    def test_end_to_end_workflow(self, lark_parser, transformer, text_printer, json_serializer):
        """Test complete workflow: parse -> modify -> print -> serialize."""
        rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1; classtype:web-application-attack;)'

        # Step 1: Parse
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Verify parsing
        from surinort_ast.core.nodes import Action, Protocol, Rule

        assert isinstance(rule, Rule)
        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP

        # Step 2: Print
        printed = text_printer.print_rule(rule)
        assert "alert" in printed
        assert "tcp" in printed
        assert "msg:" in printed

        # Step 3: Serialize to JSON
        json_str = json_serializer.to_json(rule)
        assert len(json_str) > 0
        assert '"action"' in json_str or '"data"' in json_str

        # Step 4: Deserialize
        restored_rule = json_serializer.from_json(json_str)
        assert isinstance(restored_rule, Rule)
        assert restored_rule.action == rule.action

        # Step 5: Re-parse printed output
        parse_tree2 = lark_parser.parse(printed)
        rule2 = transformer.transform(parse_tree2)[0]
        assert rule2.action == rule.action

    def test_parse_print_roundtrip(self, lark_parser, transformer, text_printer):
        """Test parse -> print -> parse roundtrip."""
        original_text = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP POST Request"; flow:established,to_server; http.method; content:"POST"; sid:2000001; rev:1;)'

        # Parse
        parse_tree1 = lark_parser.parse(original_text)
        rule1 = transformer.transform(parse_tree1)[0]

        # Print
        printed = text_printer.print_rule(rule1)

        # Parse again
        parse_tree2 = lark_parser.parse(printed)
        rule2 = transformer.transform(parse_tree2)[0]

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert rule1.header.direction == rule2.header.direction

    def test_json_roundtrip(self, lark_parser, transformer, json_serializer):
        """Test parse -> JSON -> restore workflow."""
        rule_text = 'alert tcp any any -> any 443 (msg:"HTTPS Traffic"; flow:established; sid:3000001; rev:1;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        rule1 = transformer.transform(parse_tree)[0]

        # To JSON
        json_str = json_serializer.to_json(rule1)

        # From JSON
        rule2 = json_serializer.from_json(json_str)

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert len(rule1.options) == len(rule2.options)

    def test_parse_multiple_rules_from_file(self, lark_parser, transformer, fixtures_dir):
        """Test parsing multiple rules from file."""
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        rules = []
        with open(simple_rules_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parse_tree = lark_parser.parse(line)
                result = transformer.transform(parse_tree)
                if isinstance(result, list) and len(result) > 0:
                    rules.append(result[0])

        # Should have parsed multiple rules
        assert len(rules) > 0

        # All should be Rule instances
        from surinort_ast.core.nodes import Rule

        assert all(isinstance(r, Rule) for r in rules)

        # All should have SID
        from surinort_ast.core.nodes import SidOption

        for rule in rules:
            sid_opt = next((o for o in rule.options if isinstance(o, SidOption)), None)
            assert sid_opt is not None
            assert sid_opt.value > 0


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling in integration scenarios."""

    def test_invalid_rule_raises_error(self, lark_parser):
        """Invalid rules should raise appropriate errors."""
        from lark.exceptions import LarkError

        invalid_rule = 'invalid_action tcp any any -> any 80 (msg:"Test"; sid:1;)'

        with pytest.raises(LarkError):
            lark_parser.parse(invalid_rule)

    def test_malformed_json_raises_error(self, json_serializer):
        """Malformed JSON should raise error."""
        import json

        malformed_json = '{"incomplete": '

        with pytest.raises(json.JSONDecodeError):
            json_serializer.from_json(malformed_json)


@pytest.mark.integration
class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_batch_process_rules(self, lark_parser, transformer, suricata_sample_rules):
        """Batch process multiple real rules."""
        from surinort_ast.core.nodes import Rule

        parsed_rules = []

        for rule_text in suricata_sample_rules[:50]:  # Process first 50
            try:
                parse_tree = lark_parser.parse(rule_text)
                result = transformer.transform(parse_tree)
                if isinstance(result, list) and len(result) > 0:
                    parsed_rules.append(result[0])
            except Exception:
                # Skip rules that fail
                pass

        # Should have parsed most rules
        assert len(parsed_rules) >= 40  # At least 80% success

        # All should be valid Rules
        assert all(isinstance(r, Rule) for r in parsed_rules)

    def test_transform_rule_sids(self, lark_parser, transformer):
        """Transform rules by modifying SIDs."""
        from surinort_ast.core.nodes import SidOption
        from surinort_ast.core.visitor import ASTTransformer

        class SIDIncrementer(ASTTransformer):
            def __init__(self, increment: int):
                super().__init__()
                self.increment = increment

            def visit_SidOption(self, node: SidOption) -> SidOption:
                return node.model_copy(update={"value": node.value + self.increment})

        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        original_rule = transformer.transform(parse_tree)[0]

        # Transform
        incrementer = SIDIncrementer(increment=1000000)
        new_rule = incrementer.visit(original_rule)

        # Verify transformation
        original_sid = next(
            (o.value for o in original_rule.options if isinstance(o, SidOption)), None
        )
        new_sid = next((o.value for o in new_rule.options if isinstance(o, SidOption)), None)

        assert original_sid == 1
        assert new_sid == 1000001

    def test_extract_statistics(self, lark_parser, transformer, fixtures_dir):
        """Extract statistics from rules."""
        from surinort_ast.core.nodes import ClasstypeOption
        from surinort_ast.core.visitor import ASTVisitor

        class RuleStats(ASTVisitor[dict]):
            def __init__(self):
                super().__init__()
                self.stats = {
                    "total": 0,
                    "with_classtype": 0,
                    "protocols": {},
                    "actions": {},
                }

            def visit_Rule(self, node):
                self.stats["total"] += 1

                # Count protocol
                protocol = node.header.protocol.value
                self.stats["protocols"][protocol] = self.stats["protocols"].get(protocol, 0) + 1

                # Count action
                action = node.action.value
                self.stats["actions"][action] = self.stats["actions"].get(action, 0) + 1

                # Check for classtype
                has_classtype = any(isinstance(o, ClasstypeOption) for o in node.options)
                if has_classtype:
                    self.stats["with_classtype"] += 1

                return super().visit_Rule(node)

            def default_return(self):
                return self.stats

        # Parse fixture rules
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        stats_collector = RuleStats()
        with open(simple_rules_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    parse_tree = lark_parser.parse(line)
                    rule = transformer.transform(parse_tree)[0]
                    stats_collector.visit(rule)
                except Exception:
                    pass

        stats = stats_collector.stats

        # Should have collected stats
        assert stats["total"] > 0
        assert len(stats["protocols"]) > 0
        assert len(stats["actions"]) > 0

        print("\nRule Statistics:")
        print(f"  Total rules: {stats['total']}")
        print(f"  With classtype: {stats['with_classtype']}")
        print(f"  Protocols: {stats['protocols']}")
        print(f"  Actions: {stats['actions']}")
