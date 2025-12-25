"""
Query API Phase 2/3 Examples - Advanced Features

Demonstrates hierarchical navigation, union selectors, comparison operators,
string operators, and pseudo-selectors.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from surinort_ast import parse_rule
from surinort_ast.query import query, query_all, query_exists

# ============================================================================
# Phase 2: Hierarchical Navigation
# ============================================================================

print("=" * 70)
print("PHASE 2: HIERARCHICAL NAVIGATION")
print("=" * 70)

# Example 1: Descendant Combinator (space) - Match at any depth
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1000001;)')

# Find all SidOptions under Rule (at any depth)
results = query(rule, "Rule SidOption")
print("\n1. Descendant Combinator: 'Rule SidOption'")
print(f"   Found {len(results)} matches")
print(f"   SID value: {results[0].value if results else 'N/A'}")

# Example 2: Child Combinator (>) - Match direct children only
results = query(rule, "Rule > Header")
print("\n2. Child Combinator: 'Rule > Header'")
print(f"   Found {len(results)} matches")
print(f"   Protocol: {results[0].protocol if results else 'N/A'}")

# Example 3: Adjacent Sibling (+) - Match immediately following sibling
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)')
results = query(rule, "SidOption + RevOption")
print("\n3. Adjacent Sibling: 'SidOption + RevOption'")
print(f"   Found {len(results)} matches")
print(f"   Rev value: {results[0].value if results else 'N/A'}")

# Example 4: General Sibling (~) - Match any following sibling
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"A"; content:"B"; sid:1;)')
results = query(rule, "MsgOption ~ ContentOption")
print("\n4. General Sibling: 'MsgOption ~ ContentOption'")
print(f"   Found {len(results)} ContentOptions following MsgOption")

# Example 5: Complex hierarchical chain
rule = parse_rule('alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"HTTP"; sid:1;)')
results = query(rule, "Rule > Header AnyPort")
print("\n5. Complex Chain: 'Rule > Header AnyPort'")
print(f"   Found {len(results)} AnyPort nodes under Header which is child of Rule")

# ============================================================================
# Phase 2: Union Selectors (OR Logic)
# ============================================================================

print("\n" + "=" * 70)
print("PHASE 2: UNION SELECTORS (OR LOGIC)")
print("=" * 70)

# Example 6: Simple union - Find either ContentOption OR PcreOption
rule = parse_rule(
    'alert tcp any any -> any 80 (msg:"Test"; content:"admin"; pcre:"/test/"; sid:1;)'
)
results = query(rule, "ContentOption, PcreOption")
print("\n6. Simple Union: 'ContentOption, PcreOption'")
print(f"   Found {len(results)} matches (content or pcre)")
for r in results:
    print(f"   - {r.node_type}")

# Example 7: Union with attributes
rules = [
    parse_rule("alert tcp any any -> any 80 (sid:1;)"),
    parse_rule("drop tcp any any -> any 445 (sid:2;)"),
    parse_rule("pass tcp any any -> any 443 (sid:3;)"),
]
results = query_all(rules, "Rule[action=alert], Rule[action=drop]")
print("\n7. Union with Attributes: 'Rule[action=alert], Rule[action=drop]'")
print(f"   Found {len(results)} rules (alert or drop)")
for r in results:
    print(f"   - {r.action}")

# Example 8: Union of complex chains
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"A"; content:"B"; sid:1;)')
results = query(rule, "Rule > MsgOption, Rule > ContentOption")
print("\n8. Union of Chains: 'Rule > MsgOption, Rule > ContentOption'")
print(f"   Found {len(results)} matches")

# ============================================================================
# Phase 3: Comparison Operators
# ============================================================================

print("\n" + "=" * 70)
print("PHASE 3: COMPARISON OPERATORS")
print("=" * 70)

# Example 9: Greater than (>)
rule = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")
results = query(rule, "SidOption[value>1000000]")
print("\n9. Greater Than: 'SidOption[value>1000000]'")
print(f"   Found {len(results)} SIDs greater than 1000000")
print(f"   SID: {results[0].value if results else 'N/A'}")

# Example 10: Less than (<)
rule = parse_rule("alert tcp any any -> any 80 (priority:1; sid:1;)")
results = query(rule, "PriorityOption[value<3]")
print("\n10. Less Than: 'PriorityOption[value<3]'")
print(f"    Found {len(results)} priority values less than 3")

# Example 11: Greater than or equal (>=)
rule = parse_rule("alert tcp any any -> any 80 (sid:1000; rev:5;)")
results = query(rule, "RevOption[value>=5]")
print("\n11. Greater or Equal: 'RevOption[value>=5]'")
print(f"    Found {len(results)} rev values >= 5")

# Example 12: Less than or equal (<=)
rule = parse_rule("alert tcp any any -> any 80 (priority:2; sid:1;)")
results = query(rule, "PriorityOption[value<=2]")
print("\n12. Less or Equal: 'PriorityOption[value<=2]'")
print(f"    Found {len(results)} priority values <= 2")

# Example 13: Not equal (!=)
rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
results = query(rule, "SidOption[value!=999]")
print("\n13. Not Equal: 'SidOption[value!=999]'")
print(f"    Found {len(results)} SIDs not equal to 999")

# ============================================================================
# Phase 3: String Operators
# ============================================================================

print("\n" + "=" * 70)
print("PHASE 3: STRING OPERATORS")
print("=" * 70)

# Example 14: Contains (*=)
rule = parse_rule('alert tcp any any -> any 80 (msg:"SQL Injection Attack"; sid:1;)')
results = query(rule, 'MsgOption[text*="Injection"]')
print("\n14. Contains: 'MsgOption[text*=\"Injection\"]'")
print(f"    Found {len(results)} messages containing 'Injection'")
print(f"    Message: {results[0].text if results else 'N/A'}")

# Example 15: Starts with (^=)
rule = parse_rule('alert tcp any any -> any 80 (msg:"MALWARE-CNC Botnet"; sid:1;)')
results = query(rule, 'MsgOption[text^="MALWARE"]')
print("\n15. Starts With: 'MsgOption[text^=\"MALWARE\"]'")
print(f"    Found {len(results)} messages starting with 'MALWARE'")

# Example 16: Ends with ($=)
rule = parse_rule('alert tcp any any -> any 80 (msg:"Attack detected"; sid:1;)')
results = query(rule, 'MsgOption[text$="detected"]')
print("\n16. Ends With: 'MsgOption[text$=\"detected\"]'")
print(f"    Found {len(results)} messages ending with 'detected'")

# ============================================================================
# Phase 3: Pseudo-Selectors
# ============================================================================

print("\n" + "=" * 70)
print("PHASE 3: PSEUDO-SELECTORS")
print("=" * 70)

# Example 17: :has() - Match nodes containing specific descendants
rule = parse_rule('alert tcp any any -> any 80 (content:"admin"; pcre:"/test/"; sid:1;)')
results = query(rule, "Rule:has(PcreOption)")
print("\n17. :has() - 'Rule:has(PcreOption)'")
print(f"    Found {len(results)} rules containing PCRE patterns")

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
results = query(rule, "Rule:has(ContentOption)")
print(f"    Found {len(results)} rules containing content patterns (this rule has none)")

# Example 18: :not() - Negation
rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
results = query(rule, "Rule:not([action=drop])")
print("\n18. :not() - 'Rule:not([action=drop])'")
print(f"    Found {len(results)} rules that are NOT drop rules")

# Example 19: :empty - Match nodes with no children
rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
results = query(rule, "SidOption:empty")
print("\n19. :empty - 'SidOption:empty'")
print(f"    Found {len(results)} empty nodes (SidOption has no children)")

# Example 20: :not-empty - Match nodes with children
results = query(rule, "Rule:not-empty")
print("\n20. :not-empty - 'Rule:not-empty'")
print(f"    Found {len(results)} non-empty nodes (Rule has children)")

# ============================================================================
# Real-World Complex Queries
# ============================================================================

print("\n" + "=" * 70)
print("REAL-WORLD COMPLEX QUERIES")
print("=" * 70)

# Example 21: Find high-priority alert rules with PCRE
rules = [
    parse_rule(
        'alert tcp any any -> any 80 (msg:"HTTP Attack"; priority:1; pcre:"/admin/"; sid:1000001;)'
    ),
    parse_rule(
        'alert tcp any any -> any 443 (msg:"HTTPS Attack"; priority:2; content:"login"; sid:1000002;)'
    ),
    parse_rule('drop tcp any any -> any 445 (msg:"SMB Block"; priority:1; sid:1000003;)'),
]

results = query_all(rules, "Rule[action=alert] PriorityOption[value<=2]")
print("\n21. High-Priority Alerts: 'Rule[action=alert] PriorityOption[value<=2]'")
print(f"    Found {len(results)} high-priority alert rules")

# Example 22: Find rules with specific message patterns and high SIDs
results = query_all(rules, 'Rule:has(MsgOption[text*="Attack"]) SidOption[value>1000000]')
print("\n22. Attack Rules with High SIDs")
print(f"    Found {len(results)} rules")

# Example 23: Find rules with either PCRE or multiple content options
rule_with_contents = parse_rule(
    'alert tcp any any -> any 80 (msg:"Multi-pattern"; '
    'content:"admin"; content:"login"; content:"password"; sid:1;)'
)
results = query(rule_with_contents, "ContentOption, PcreOption")
print("\n23. PCRE or Content Options: 'ContentOption, PcreOption'")
print(f"    Found {len(results)} pattern matching options")

# Example 24: Complex hierarchical query with unions
results = query_all(
    rules, "Rule[action=alert] > Header[protocol=tcp], Rule[action=drop] > Header[protocol=tcp]"
)
print("\n24. TCP Rules (Alert or Drop)")
print(f"    Found {len(results)} TCP headers")

# Example 25: Existence checks with complex conditions
has_pcre = query_exists(rules[0], "Rule:has(PcreOption)")
has_high_priority = query_exists(rules[0], "PriorityOption[value=1]")
print("\n25. Existence Checks on First Rule:")
print(f"    Has PCRE: {has_pcre}")
print(f"    Has priority=1: {has_high_priority}")

print("\n" + "=" * 70)
print("Examples completed successfully!")
print("=" * 70)
