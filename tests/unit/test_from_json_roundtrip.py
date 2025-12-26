"""
Test roundtrip functionality for from-json command.

Tests that rules can be properly serialized to JSON and deserialized back
with all option content preserved.

This test was added to prevent regression of the bug where from-json
was outputting generic "option" placeholders instead of actual option content.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from surinort_ast import from_json, parse_rule, print_rule, to_json


class TestFromJsonRoundtrip:
    """Test JSON serialization/deserialization roundtrip."""

    def test_simple_rule_roundtrip(self) -> None:
        """Test roundtrip with simple rule."""
        original = 'alert tcp any any -> any 443 (msg:"HTTPS Traffic"; sid:1000; rev:1;)'

        # Parse original
        parsed = parse_rule(original)

        # Convert to JSON
        json_str = to_json(parsed)

        # Deserialize from JSON
        deserialized = from_json(json_str)

        # Print the deserialized rule
        output = print_rule(deserialized)

        # Verify options are preserved (not generic "option" placeholders)
        assert 'msg:"HTTPS Traffic"' in output
        assert "sid:1000" in output
        assert "rev:1" in output
        assert "option;" not in output.lower()

    def test_complex_rule_roundtrip(self) -> None:
        """Test roundtrip with complex rule containing multiple option types."""
        original = (
            "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
            '(msg:"HTTP GET Request"; content:"GET"; nocase; '
            'pcre:"/^GET\\s+/"; flow:established,to_server; '
            "sid:2000; rev:2; classtype:web-application-attack; priority:2;)"
        )

        # Parse original
        parsed = parse_rule(original)

        # Convert to JSON
        json_str = to_json(parsed)

        # Deserialize from JSON
        deserialized = from_json(json_str)

        # Print the deserialized rule
        output = print_rule(deserialized)

        # Verify all option types are preserved
        assert 'msg:"HTTP GET Request"' in output
        assert 'content:"GET"' in output
        assert "nocase;" in output
        assert "pcre:" in output
        assert "flow:" in output
        assert "sid:2000" in output
        assert "rev:2" in output
        assert "classtype:web-application-attack" in output
        assert "priority:2" in output
        assert "option;" not in output.lower()

    def test_content_option_roundtrip(self) -> None:
        """Test that ContentOption is properly serialized/deserialized."""
        original = 'alert tcp any any -> any any (msg:"Test"; content:"HTTP/1.1"; sid:3000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Roundtrip
        json_str = to_json(parsed)
        deserialized = from_json(json_str)
        output = print_rule(deserialized)

        # Verify content is preserved
        assert 'content:"HTTP/1.1"' in output
        assert "option;" not in output.lower()

    def test_pcre_option_roundtrip(self) -> None:
        """Test that PcreOption is properly serialized/deserialized."""
        original = 'alert tcp any any -> any any (msg:"Test"; pcre:"/test/i"; sid:4000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Roundtrip
        json_str = to_json(parsed)
        deserialized = from_json(json_str)
        output = print_rule(deserialized)

        # Verify pcre is preserved
        assert 'pcre:"/test/i"' in output
        assert "option;" not in output.lower()

    def test_flow_option_roundtrip(self) -> None:
        """Test that FlowOption is properly serialized/deserialized."""
        original = 'alert tcp any any -> any any (msg:"Test"; flow:established,to_server; sid:5000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Roundtrip
        json_str = to_json(parsed)
        deserialized = from_json(json_str)
        output = print_rule(deserialized)

        # Verify flow is preserved
        assert "flow:" in output
        assert "established" in output
        assert "to_server" in output
        assert "option;" not in output.lower()

    def test_metadata_option_roundtrip(self) -> None:
        """Test that MetadataOption is properly serialized/deserialized."""
        original = 'alert tcp any any -> any any (msg:"Test"; metadata:author John, created 2024; sid:6000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Roundtrip
        json_str = to_json(parsed)
        deserialized = from_json(json_str)
        output = print_rule(deserialized)

        # Verify metadata is preserved
        assert "metadata:" in output
        assert "author John" in output
        assert "created 2024" in output
        assert "option;" not in output.lower()

    def test_discriminator_field_in_json(self) -> None:
        """Test that the 'type' discriminator field is present in JSON."""
        original = 'alert tcp any any -> any any (msg:"Test"; sid:7000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Convert to JSON
        json_str = to_json(parsed)

        # Verify type discriminator is in JSON
        assert '"type":"MsgOption"' in json_str or '"type": "MsgOption"' in json_str
        assert '"type":"SidOption"' in json_str or '"type": "SidOption"' in json_str
        assert '"type":"RevOption"' in json_str or '"type": "RevOption"' in json_str

    def test_all_option_types_have_discriminator(self) -> None:
        """Test that all option instances have the 'type' field."""
        original = 'alert tcp any any -> any any (msg:"Test"; sid:8000; rev:1;)'

        # Parse
        parsed = parse_rule(original)

        # Verify all options have type field
        for opt in parsed.options:
            assert hasattr(opt, "type")
            assert opt.type is not None
            assert opt.type == opt.__class__.__name__
