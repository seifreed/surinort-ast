"""
Query API Demo - Demonstrates Phase 1 MVP functionality.

Shows how to use CSS-style selectors to query Snort/Suricata rule AST nodes.

Licensed under GNU General Public License v3.0
"""

from surinort_ast import parse_rule
from surinort_ast.query import query, query_exists, query_first

# Example 1: Basic Type Selectors
print("=== Example 1: Basic Type Selectors ===")
rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1000001;)')

# Find all ContentOption nodes
content_options = query(rule, "ContentOption")
print(f"Found {len(content_options)} ContentOption nodes")
for opt in content_options:
    print(f"  - pattern: {opt.pattern}")

# Find SidOption
sid_options = query(rule, "SidOption")
print(f"Found {len(sid_options)} SidOption nodes")
if sid_options:
    print(f"  - SID value: {sid_options[0].value}")

print()

# Example 2: Attribute Selectors
print("=== Example 2: Attribute Selectors ===")

# Find rules with action=alert
rule_alert = parse_rule("alert tcp any any -> any 80 (sid:1;)")
rule_drop = parse_rule("drop tcp any any -> any 80 (sid:2;)")

alert_matches = query(rule_alert, "Rule[action=alert]")
print(f"Alert rule matched: {len(alert_matches) > 0}")

drop_matches = query(rule_drop, "Rule[action=drop]")
print(f"Drop rule matched: {len(drop_matches) > 0}")

# Find specific SID values
rule_with_sid = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")
high_sid = query(rule_with_sid, "SidOption[value=1000001]")
print(f"Found SID 1000001: {len(high_sid) > 0}")

print()

# Example 3: Combined Type + Attribute Selectors
print("=== Example 3: Combined Selectors ===")

# Find Header with specific protocol
tcp_rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
headers = query(tcp_rule, "Header[protocol=tcp]")
print(f"Found TCP header: {len(headers) > 0}")

udp_rule = parse_rule("alert udp any any -> any 53 (sid:2;)")
udp_headers = query(udp_rule, "Header[protocol=udp]")
print(f"Found UDP header: {len(udp_headers) > 0}")

print()

# Example 4: query_first() - Get First Match
print("=== Example 4: query_first() ===")

rule_multi = parse_rule(
    'alert tcp any any -> any 80 (content:"A"; content:"B"; content:"C"; sid:1;)'
)

# Get first ContentOption
first_content = query_first(rule_multi, "ContentOption")
if first_content:
    print(f"First content pattern: {first_content.pattern}")

# Get SID (typically only one per rule)
sid = query_first(rule_multi, "SidOption")
if sid:
    print(f"Rule SID: {sid.value}")

print()

# Example 5: query_exists() - Check Existence
print("=== Example 5: query_exists() ===")

rule_with_pcre = parse_rule('alert tcp any any -> any 80 (pcre:"/test/i"; sid:1;)')
rule_without_pcre = parse_rule('alert tcp any any -> any 80 (content:"test"; sid:2;)')

# Check if rules have PCRE
has_pcre_1 = query_exists(rule_with_pcre, "PcreOption")
has_pcre_2 = query_exists(rule_without_pcre, "PcreOption")

print(f"Rule 1 has PCRE: {has_pcre_1}")
print(f"Rule 2 has PCRE: {has_pcre_2}")

# Check if rule has specific option types
has_content = query_exists(rule_with_pcre, "ContentOption")
has_sid = query_exists(rule_with_pcre, "SidOption")

print(f"Rule has content: {has_content}")
print(f"Rule has SID: {has_sid}")

print()

# Example 6: Universal Selector
print("=== Example 6: Universal Selector ===")

rule_simple = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

# Match all nodes (descendants)
all_nodes = query(rule_simple, "*")
node_types = {n.node_type for n in all_nodes}

print(f"Total nodes found: {len(all_nodes)}")
print(f"Node types: {sorted(node_types)}")

print()

# Example 7: Complex Rule Analysis
print("=== Example 7: Complex Rule Analysis ===")

complex_rule = parse_rule(
    "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
    '(msg:"HTTP Admin Access"; '
    "flow:established,to_server; "
    'content:"GET"; http_method; '
    'content:"/admin"; http_uri; '
    'pcre:"/\\/admin\\/[a-z]+/i"; '
    "sid:1000001; rev:2;)"
)

# Analyze rule components
print("Rule Analysis:")
print(f"  - Has PCRE: {query_exists(complex_rule, 'PcreOption')}")
print(f"  - Has Content: {query_exists(complex_rule, 'ContentOption')}")
print(f"  - Has Flow: {query_exists(complex_rule, 'FlowOption')}")

# Count content options
content_count = len(query(complex_rule, "ContentOption"))
print(f"  - Content options: {content_count}")

# Get SID and Rev
sid = query_first(complex_rule, "SidOption")
rev = query_first(complex_rule, "RevOption")

if sid:
    print(f"  - SID: {sid.value}")
if rev:
    print(f"  - Rev: {rev.value}")

# Check rule action and protocol
is_alert = query_exists(complex_rule, "Rule[action=alert]")
is_tcp = query_exists(complex_rule, "Header[protocol=tcp]")

print(f"  - Is alert rule: {is_alert}")
print(f"  - Is TCP: {is_tcp}")

print()

# Example 8: String Attributes with Spaces
print("=== Example 8: String Attributes ===")

rule_msg = parse_rule('alert tcp any any -> any 80 (msg:"Test Message"; sid:1;)')

# Find message with specific text (use quotes for strings with spaces)
msg_exact = query(rule_msg, 'MsgOption[text="Test Message"]')
print(f"Found exact message match: {len(msg_exact) > 0}")

# Single word values don't need quotes
sid_match = query(rule_msg, "SidOption[value=1]")
print(f"Found SID=1: {len(sid_match) > 0}")

print()
print("=== Query API Demo Complete ===")
