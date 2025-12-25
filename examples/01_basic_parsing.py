#!/usr/bin/env python3
"""
Basic Parsing Examples for surinort-ast

This example demonstrates the fundamental parsing capabilities of surinort-ast,
showing how to parse IDS/IPS rules and access basic AST components.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import Action, Direction, Protocol, parse_rule


def example_1_simple_parsing():
    """Parse a simple Suricata rule and access basic components."""
    print("=" * 70)
    print("Example 1: Simple Rule Parsing")
    print("=" * 70)

    # Parse a basic HTTP detection rule
    rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic Detected"; sid:1000001; rev:1;)'

    print(f"\nInput rule:\n{rule_text}\n")

    # Parse the rule
    rule = parse_rule(rule_text)

    # Access rule components
    print("Parsed rule components:")
    print(f"  Action: {rule.action}")
    print(f"  Protocol: {rule.header.protocol}")
    print(f"  Direction: {rule.header.direction}")
    print(f"  Source Address: {rule.header.src_addr}")
    print(f"  Source Port: {rule.header.src_port}")
    print(f"  Destination Address: {rule.header.dst_addr}")
    print(f"  Destination Port: {rule.header.dst_port}")
    print(f"  Number of options: {len(rule.options)}")

    # Type checking - all fields are properly typed
    assert rule.action == Action.ALERT
    assert rule.header.protocol == Protocol.TCP
    assert rule.header.direction == Direction.TO

    print("\nParsing successful!")


def example_2_accessing_options():
    """Parse a rule and iterate through its options."""
    print("\n" + "=" * 70)
    print("Example 2: Accessing Rule Options")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 443 (msg:"TLS Traffic"; flow:established,to_server; sid:1000002; rev:1; classtype:protocol-command-decode;)'

    print(f"\nInput rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    print("Rule options:")
    for i, option in enumerate(rule.options, 1):
        print(f"  {i}. {option.node_type}")

        # Access specific option types
        if option.node_type == "MsgOption":
            print(f"     Message: {option.text}")
        elif option.node_type == "SidOption":
            print(f"     SID: {option.value}")
        elif option.node_type == "RevOption":
            print(f"     Revision: {option.value}")
        elif option.node_type == "ClasstypeOption":
            print(f"     Classtype: {option.value}")
        elif option.node_type == "FlowOption":
            print(f"     Flow directions: {[d.value for d in option.directions]}")
            print(f"     Flow states: {[s.value for s in option.states]}")


def example_3_different_protocols():
    """Parse rules with different protocols."""
    print("\n" + "=" * 70)
    print("Example 3: Different Protocol Rules")
    print("=" * 70)

    rules = [
        'alert tcp any any -> any 22 (msg:"SSH Traffic"; sid:1;)',
        'alert udp any any -> any 53 (msg:"DNS Query"; sid:2;)',
        'alert http any any -> any any (msg:"HTTP Request"; sid:3;)',
        'alert tls any any -> any any (msg:"TLS Connection"; sid:4;)',
    ]

    for rule_text in rules:
        rule = parse_rule(rule_text)
        print(f"\nProtocol: {rule.header.protocol.value:8s} -> {rule_text[:50]}...")


def example_4_different_actions():
    """Parse rules with different actions."""
    print("\n" + "=" * 70)
    print("Example 4: Different Rule Actions")
    print("=" * 70)

    rules = [
        ('alert tcp any any -> any 80 (msg:"Alert on HTTP"; sid:1;)', "Generate alert"),
        ('drop tcp any any -> any 80 (msg:"Block HTTP"; sid:2;)', "Drop packet silently"),
        ('reject tcp any any -> any 80 (msg:"Reject HTTP"; sid:3;)', "Drop and send RST"),
        ('pass tcp any any -> any 80 (msg:"Allow HTTP"; sid:4;)', "Explicitly allow"),
    ]

    print("\nSupported actions:")
    for rule_text, description in rules:
        rule = parse_rule(rule_text)
        print(f"  {rule.action.value:6s} - {description}")


def example_5_complex_addresses_and_ports():
    """Parse rules with complex address and port specifications."""
    print("\n" + "=" * 70)
    print("Example 5: Complex Addresses and Ports")
    print("=" * 70)

    rules = [
        'alert tcp 192.168.1.0/24 any -> any 80 (msg:"From internal network"; sid:1;)',
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Using variables"; sid:2;)',
        'alert tcp !192.168.1.1 any -> any [80,443,8080] (msg:"Multiple ports"; sid:3;)',
        'alert tcp any any -> any 1024:65535 (msg:"High ports"; sid:4;)',
    ]

    print("\nAddress and port examples:")
    for rule_text in rules:
        try:
            rule = parse_rule(rule_text)
            print(
                f"\n  Source: {rule.header.src_addr.node_type:20s} Port: {rule.header.src_port.node_type}"
            )
            print(
                f"  Dest:   {rule.header.dst_addr.node_type:20s} Port: {rule.header.dst_port.node_type}"
            )
            # Get the message to understand what this rule does
            for opt in rule.options:
                if opt.node_type == "MsgOption":
                    print(f"  Purpose: {opt.text}")
        except Exception as e:
            print(f"  Error: {e}")


def example_6_accessing_raw_text():
    """Access the original raw text of a parsed rule."""
    print("\n" + "=" * 70)
    print("Example 6: Accessing Raw Rule Text")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 80 (msg:"Example Rule"; sid:1; rev:1;)'

    rule = parse_rule(rule_text)

    print(f"\nOriginal text stored: {rule.raw_text}")
    print(f"Matches input: {rule.raw_text == rule_text}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Basic Parsing Examples")
    print("=" * 70)
    print("\nThis script demonstrates basic parsing capabilities of surinort-ast.")
    print("Each example shows different aspects of rule parsing.\n")

    try:
        example_1_simple_parsing()
        example_2_accessing_options()
        example_3_different_protocols()
        example_4_different_actions()
        example_5_complex_addresses_and_ports()
        example_6_accessing_raw_text()

        print("\n" + "=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
