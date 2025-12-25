"""
Demonstration of the RuleBuilder API for programmatic rule construction.

This example showcases various ways to build IDS rules using the fluent
builder pattern, without parsing text.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from surinort_ast.builder import RuleBuilder
from surinort_ast.printer.text_printer import TextPrinter


def example_1_basic_http_rule() -> None:
    """Example 1: Basic HTTP detection rule."""
    print("=" * 80)
    print("Example 1: Basic HTTP Detection Rule")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .http()
        .source_ip("$EXTERNAL_NET")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port("$HTTP_PORTS")
        .msg("HTTP GET request detected")
        .content(b"GET", http_method=True)
        .sid(1000001)
        .rev(1)
        .classtype("web-application-activity")
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_2_advanced_http_rule() -> None:
    """Example 2: Advanced HTTP rule with multiple content matches."""
    print("=" * 80)
    print("Example 2: Advanced HTTP Rule with Multiple Content Matches")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .http()
        .source_ip("$EXTERNAL_NET")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port("$HTTP_PORTS")
        .msg("Potential SQL injection attempt")
        .flow_builder()
        .established()
        .to_server()
        .done()
        .content_builder()
        .pattern(b"POST")
        .http_method()
        .done()
        .content_builder()
        .pattern(b"' OR '1'='1")
        .http_uri()
        .done()
        .pcre(r"/(union|select|insert|update|delete)/i", flags="i")
        .classtype("web-application-attack")
        .priority(1)
        .reference("url", "https://owasp.org/www-community/attacks/SQL_Injection")
        .sid(1000002)
        .rev(2)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_3_dns_exfiltration() -> None:
    """Example 3: DNS exfiltration detection with threshold."""
    print("=" * 80)
    print("Example 3: DNS Exfiltration Detection with Threshold")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .dns()
        .source_ip("$HOME_NET")
        .source_port("any")
        .dest_ip("any")
        .dest_port(53)
        .msg("Potential DNS tunneling detected")
        .buffer_select("dns_query")
        .content(b".suspicious-domain.com")
        .threshold_builder()
        .threshold_type("limit")
        .track("by_src")
        .count(10)
        .seconds(60)
        .done()
        .classtype("policy-violation")
        .priority(2)
        .metadata(("created_at", "2025-01-01"), ("updated_at", "2025-01-15"))
        .sid(1000003)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_4_tls_sni_detection() -> None:
    """Example 4: TLS SNI-based malware C2 detection."""
    print("=" * 80)
    print("Example 4: TLS SNI-Based Malware C2 Detection")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tls()
        .source_ip("$HOME_NET")
        .source_port("any")
        .dest_ip("$EXTERNAL_NET")
        .dest_port(443)
        .msg("Known malware C2 server in TLS SNI")
        .flow_builder()
        .established()
        .to_server()
        .done()
        .buffer_select("tls.sni")
        .content(b"malicious-c2.example.com")
        .flowbits("set", "tls.malware_c2_detected")
        .classtype("trojan-activity")
        .priority(1)
        .reference("url", "https://example.com/threat-intel/ioc-12345")
        .metadata(("malware_family", "Zeus"), ("severity", "critical"))
        .sid(1000004)
        .rev(3)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_5_ssh_brute_force() -> None:
    """Example 5: SSH brute force detection with detection filter."""
    print("=" * 80)
    print("Example 5: SSH Brute Force Detection")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("$EXTERNAL_NET")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port(22)
        .msg("SSH brute force attempt detected")
        .flow_builder()
        .established()
        .to_server()
        .done()
        .content(b"SSH-")
        .detection_filter("by_src", 5, 60)
        .classtype("attempted-admin")
        .priority(1)
        .sid(1000005)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_6_file_extraction() -> None:
    """Example 6: File extraction with filestore option."""
    print("=" * 80)
    print("Example 6: Malicious File Extraction")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .http()
        .source_ip("any")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port("$HTTP_PORTS")
        .msg("Potential malicious executable download")
        .flow_builder()
        .established()
        .to_client()
        .done()
        .buffer_select("file_data")
        .content(b"MZ")
        .filestore(direction="response", scope="file")
        .classtype("trojan-activity")
        .priority(1)
        .sid(1000006)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_7_byte_operations() -> None:
    """Example 7: Advanced byte operations for protocol analysis."""
    print("=" * 80)
    print("Example 7: Advanced Byte Operations")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("any")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port("any")
        .msg("Suspicious protocol with length field manipulation")
        .content(b"\x00\x00")
        .byte_extract(2, 0, "pkt_len")
        .byte_test(2, ">", 1000, 0)
        .byte_jump(4, 0, flags=["relative"])
        .classtype("protocol-command-decode")
        .sid(1000007)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_8_lua_scripting() -> None:
    """Example 8: Using Lua scripting for complex detection."""
    print("=" * 80)
    print("Example 8: Lua Scripting for Complex Detection")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("any")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port(80)
        .msg("Complex payload analysis via Lua")
        .content(b"PAYLOAD")
        .lua("custom_analysis.lua")
        .classtype("misc-activity")
        .sid(1000008)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_9_ip_ranges_and_ports() -> None:
    """Example 9: Complex IP ranges and port specifications."""
    print("=" * 80)
    print("Example 9: Complex IP Ranges and Port Specifications")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("[192.168.1.0/24,10.0.0.0/8]")
        .source_port("[80,443,8080:8090]")
        .dest_ip("!$HOME_NET")
        .dest_port("[1024:65535]")
        .msg("Outbound connection from internal network")
        .classtype("policy-violation")
        .sid(1000009)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_10_bidirectional_rule() -> None:
    """Example 10: Bidirectional rule for peer-to-peer detection."""
    print("=" * 80)
    print("Example 10: Bidirectional Rule for P2P Detection")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("$HOME_NET")
        .source_port("any")
        .bidirectional()
        .dest_ip("any")
        .dest_port("any")
        .msg("Potential P2P protocol detected")
        .content(b"BitTorrent")
        .classtype("policy-violation")
        .priority(3)
        .sid(1000010)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_11_snort2_dialect() -> None:
    """Example 11: Building Snort2-specific rule."""
    print("=" * 80)
    print("Example 11: Snort2-Specific Rule")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("any")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port(80)
        .msg("Snort2 compatible rule")
        .content(b"exploit")
        .classtype("attempted-admin")
        .sid(2000001)
        .rev(1)
        .dialect("snort2")
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_12_drop_rule() -> None:
    """Example 12: DROP action for inline IPS mode."""
    print("=" * 80)
    print("Example 12: DROP Rule for Inline IPS")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .drop()
        .tcp()
        .source_ip("$EXTERNAL_NET")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port("[445,135,139]")
        .msg("Blocking SMB/NetBIOS from external network")
        .flow_builder()
        .to_server()
        .done()
        .classtype("attempted-admin")
        .priority(1)
        .sid(3000001)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def example_13_tag_option() -> None:
    """Example 13: Using tag option for session logging."""
    print("=" * 80)
    print("Example 13: Tag Option for Session Logging")
    print("=" * 80)

    rule = (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("$EXTERNAL_NET")
        .source_port("any")
        .dest_ip("$HOME_NET")
        .dest_port(80)
        .msg("Suspicious activity - tagging session")
        .content(b"malicious_payload")
        .tag("session", 300, "seconds")
        .classtype("trojan-activity")
        .sid(1000013)
        .rev(1)
        .build()
    )

    printer = TextPrinter()
    print("\nGenerated rule:")
    print(printer.print_rule(rule))
    print()


def main() -> None:
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "SURINORT-AST BUILDER DEMO" + " " * 33 + "║")
    print("║" + " " * 16 + "Programmatic IDS Rule Construction" + " " * 28 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    examples = [
        example_1_basic_http_rule,
        example_2_advanced_http_rule,
        example_3_dns_exfiltration,
        example_4_tls_sni_detection,
        example_5_ssh_brute_force,
        example_6_file_extraction,
        example_7_byte_operations,
        example_8_lua_scripting,
        example_9_ip_ranges_and_ports,
        example_10_bidirectional_rule,
        example_11_snort2_dialect,
        example_12_drop_rule,
        example_13_tag_option,
    ]

    for i, example in enumerate(examples, 1):
        try:
            example()
            if i < len(examples):
                print("\n")
        except Exception as e:
            print(f"Error in example {i}: {e}")
            import traceback

            traceback.print_exc()

    print("=" * 80)
    print("All examples completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    main()
