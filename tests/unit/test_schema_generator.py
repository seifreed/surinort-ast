# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for JSON Schema generator.

Tests schema generation with real Pydantic models and JSON Schema validation.
NO MOCKS - all tests use actual schema generation.
"""

import json

from surinort_ast.serialization.schema_generator import (
    SchemaGenerator,
    generate_envelope_schema,
    generate_schema,
    generate_schema_json,
)
from surinort_ast.version import __ast_version__, __version__


class TestSchemaGenerator:
    """Test SchemaGenerator class."""

    def test_default_initialization(self):
        """Test generator with default parameters."""
        generator = SchemaGenerator()

        assert generator.include_examples is True
        assert generator.ref_template == "#/$defs/{model}"

    def test_custom_initialization(self):
        """Test generator with custom parameters."""
        generator = SchemaGenerator(include_examples=False, ref_template="#/definitions/{model}")

        assert generator.include_examples is False
        assert generator.ref_template == "#/definitions/{model}"

    def test_generate_schema_structure(self):
        """Test that generated schema has required structure."""
        generator = SchemaGenerator()
        schema = generator.generate_schema()

        # Should be a dictionary
        assert isinstance(schema, dict)

        # Should have title
        assert "title" in schema
        assert "Surinort" in schema["title"]

        # Should have description
        assert "description" in schema
        assert len(schema["description"]) > 0

        # Should have comment with version info
        assert "$comment" in schema
        assert __version__ in schema["$comment"]
        assert __ast_version__ in schema["$comment"]

    def test_generate_schema_with_examples(self):
        """Test schema generation includes examples."""
        generator = SchemaGenerator(include_examples=True)
        schema = generator.generate_schema()

        # Should have examples
        assert "examples" in schema
        assert isinstance(schema["examples"], list)
        assert len(schema["examples"]) > 0

        # Example should have rule structure
        example = schema["examples"][0]
        assert "action" in example
        assert "header" in example
        assert "options" in example

    def test_generate_schema_without_examples(self):
        """Test schema generation without examples."""
        generator = SchemaGenerator(include_examples=False)
        schema = generator.generate_schema()

        # Should not have examples
        assert "examples" not in schema

    def test_generate_schema_custom_title(self):
        """Test schema generation with custom title."""
        generator = SchemaGenerator()
        custom_title = "My Custom Schema"
        schema = generator.generate_schema(title=custom_title)

        assert schema["title"] == custom_title

    def test_generate_schema_custom_description(self):
        """Test schema generation with custom description."""
        generator = SchemaGenerator()
        custom_desc = "This is my custom description."
        schema = generator.generate_schema(description=custom_desc)

        assert schema["description"] == custom_desc

    def test_generate_schema_json_is_valid_json(self):
        """Test that generate_schema_json produces valid JSON."""
        generator = SchemaGenerator()
        schema_json = generator.generate_schema_json()

        # Should be valid JSON
        parsed = json.loads(schema_json)
        assert isinstance(parsed, dict)
        assert "title" in parsed

    def test_generate_schema_json_with_indent(self):
        """Test schema JSON generation with custom indentation."""
        generator = SchemaGenerator()

        # Compact
        compact = generator.generate_schema_json(indent=None)
        assert "\n" not in compact or compact.count("\n") < 10

        # Pretty
        pretty = generator.generate_schema_json(indent=4)
        assert "\n" in pretty
        assert pretty.count("\n") > 10

    def test_generate_schema_json_kwargs(self):
        """Test that kwargs are passed to json.dumps."""
        generator = SchemaGenerator()

        # Test with custom kwargs
        schema_json = generator.generate_schema_json(indent=2, sort_keys=False)

        # Should still be valid JSON
        parsed = json.loads(schema_json)
        assert isinstance(parsed, dict)

    def test_generate_examples_structure(self):
        """Test that _generate_examples produces valid structure."""
        generator = SchemaGenerator()
        examples = generator._generate_examples()

        assert isinstance(examples, list)
        assert len(examples) > 0

        # Each example should have rule fields
        for example in examples:
            assert "action" in example
            assert "header" in example
            assert "options" in example
            assert "dialect" in example


class TestEnvelopeSchema:
    """Test envelope schema generation."""

    def test_generate_envelope_schema_structure(self):
        """Test envelope schema has correct structure."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        # Should be a dictionary
        assert isinstance(envelope, dict)

        # Should have JSON Schema metadata
        assert "$schema" in envelope
        assert "json-schema.org" in envelope["$schema"]

        # Should have title and description
        assert "title" in envelope
        assert "description" in envelope

        # Should have required fields
        assert "required" in envelope
        assert "ast_version" in envelope["required"]
        assert "timestamp" in envelope["required"]
        assert "count" in envelope["required"]
        assert "data" in envelope["required"]

        # Should have properties
        assert "properties" in envelope
        props = envelope["properties"]

        assert "ast_version" in props
        assert "timestamp" in props
        assert "count" in props
        assert "data" in props

    def test_envelope_ast_version_property(self):
        """Test ast_version property in envelope schema."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        ast_version_prop = envelope["properties"]["ast_version"]

        # Should have correct type
        assert ast_version_prop["type"] == "string"

        # Should have pattern
        assert "pattern" in ast_version_prop

        # Should have examples
        assert "examples" in ast_version_prop
        assert __ast_version__ in ast_version_prop["examples"]

    def test_envelope_timestamp_property(self):
        """Test timestamp property in envelope schema."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        timestamp_prop = envelope["properties"]["timestamp"]

        # Should be string with date-time format
        assert timestamp_prop["type"] == "string"
        assert timestamp_prop["format"] == "date-time"

    def test_envelope_count_property(self):
        """Test count property in envelope schema."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        count_prop = envelope["properties"]["count"]

        # Should be integer with minimum
        assert count_prop["type"] == "integer"
        assert count_prop["minimum"] == 1

    def test_envelope_data_property(self):
        """Test data property has oneOf for single/multiple rules."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        data_prop = envelope["properties"]["data"]

        # Should have oneOf
        assert "oneOf" in data_prop
        assert len(data_prop["oneOf"]) == 2

        # Should reference Rule definition
        assert any("$ref" in option for option in data_prop["oneOf"])

    def test_envelope_has_defs(self):
        """Test envelope includes $defs from rule schema."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        # Should have $defs
        assert "$defs" in envelope
        assert isinstance(envelope["$defs"], dict)

    def test_envelope_custom_title_description(self):
        """Test envelope with custom title and description."""
        generator = SchemaGenerator()
        custom_title = "My Envelope"
        custom_desc = "My envelope description"

        envelope = generator.generate_envelope_schema(title=custom_title, description=custom_desc)

        assert envelope["title"] == custom_title
        assert envelope["description"] == custom_desc

    def test_envelope_comment_has_version(self):
        """Test envelope comment includes version info."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        assert "$comment" in envelope
        assert __version__ in envelope["$comment"]


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_generate_schema_function(self):
        """Test generate_schema convenience function."""
        schema = generate_schema()

        assert isinstance(schema, dict)
        assert "title" in schema
        assert "examples" in schema  # Default includes examples

    def test_generate_schema_function_no_examples(self):
        """Test generate_schema without examples."""
        schema = generate_schema(include_examples=False)

        assert isinstance(schema, dict)
        assert "examples" not in schema

    def test_generate_schema_function_custom_params(self):
        """Test generate_schema with custom parameters."""
        title = "Custom Title"
        desc = "Custom Description"
        schema = generate_schema(title=title, description=desc, include_examples=False)

        assert schema["title"] == title
        assert schema["description"] == desc
        assert "examples" not in schema

    def test_generate_schema_json_function(self):
        """Test generate_schema_json convenience function."""
        schema_json = generate_schema_json()

        # Should be valid JSON
        parsed = json.loads(schema_json)
        assert isinstance(parsed, dict)
        assert "title" in parsed

    def test_generate_schema_json_function_compact(self):
        """Test generate_schema_json with compact output."""
        compact = generate_schema_json(indent=None)

        # Should be compact
        assert "\n" not in compact or compact.count("\n") < 10

        # Should be valid JSON
        parsed = json.loads(compact)
        assert isinstance(parsed, dict)

    def test_generate_schema_json_function_kwargs(self):
        """Test generate_schema_json with additional kwargs."""
        schema_json = generate_schema_json(indent=2, ensure_ascii=True)

        # Should be valid JSON
        parsed = json.loads(schema_json)
        assert isinstance(parsed, dict)

    def test_generate_envelope_schema_function(self):
        """Test generate_envelope_schema convenience function."""
        envelope = generate_envelope_schema()

        assert isinstance(envelope, dict)
        assert "required" in envelope
        assert "properties" in envelope

    def test_generate_envelope_schema_function_custom(self):
        """Test generate_envelope_schema with custom parameters."""
        title = "Custom Envelope"
        desc = "Custom envelope description"
        envelope = generate_envelope_schema(title=title, description=desc)

        assert envelope["title"] == title
        assert envelope["description"] == desc


class TestSchemaValidation:
    """Test that generated schemas are valid JSON Schema."""

    def test_schema_has_valid_structure(self):
        """Test generated schema is structurally valid."""
        generator = SchemaGenerator()
        schema = generator.generate_schema()

        # Should be serializable to JSON
        json_str = json.dumps(schema)
        parsed = json.loads(json_str)

        # Should preserve structure
        assert parsed["title"] == schema["title"]
        assert parsed["description"] == schema["description"]

    def test_envelope_schema_has_valid_structure(self):
        """Test envelope schema is structurally valid."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        # Should be serializable to JSON
        json_str = json.dumps(envelope)
        parsed = json.loads(json_str)

        # Should preserve structure
        assert parsed["title"] == envelope["title"]
        assert len(parsed["required"]) == len(envelope["required"])

    def test_schema_examples_are_valid(self):
        """Test that schema examples have valid structure."""
        generator = SchemaGenerator()
        schema = generator.generate_schema()

        if "examples" in schema:
            for example in schema["examples"]:
                # Each example should have required rule fields
                assert "action" in example
                assert "header" in example
                assert "options" in example
                assert "dialect" in example

                # Header should have required fields
                header = example["header"]
                assert "protocol" in header
                assert "src_addr" in header
                assert "dst_addr" in header


class TestCustomRefTemplate:
    """Test custom ref template."""

    def test_custom_ref_template(self):
        """Test schema generation with custom ref template."""
        generator = SchemaGenerator(ref_template="#/definitions/{model}")
        schema = generator.generate_schema()

        # Schema should still be generated
        assert isinstance(schema, dict)
        assert "title" in schema

    def test_envelope_uses_default_refs(self):
        """Test that envelope schema uses #/$defs/ regardless of ref_template."""
        generator = SchemaGenerator(ref_template="#/custom/{model}")
        envelope = generator.generate_envelope_schema()

        # Envelope always uses #/$defs/
        data_prop = envelope["properties"]["data"]
        refs = []
        for option in data_prop["oneOf"]:
            if "$ref" in option:
                refs.append(option["$ref"])

        # Should use #/$defs/
        assert any("#/$defs/" in ref for ref in refs)


class TestSchemaVersionInfo:
    """Test version information in schemas."""

    def test_schema_contains_version_comment(self):
        """Test that schema contains version in comment."""
        generator = SchemaGenerator()
        schema = generator.generate_schema()

        assert "$comment" in schema
        comment = schema["$comment"]

        # Should contain version info
        assert "surinort-ast" in comment
        assert "v" in comment or "version" in comment.lower()

    def test_envelope_contains_version_comment(self):
        """Test that envelope contains version in comment."""
        generator = SchemaGenerator()
        envelope = generator.generate_envelope_schema()

        assert "$comment" in envelope
        comment = envelope["$comment"]

        # Should contain version info
        assert "surinort-ast" in comment

    def test_version_info_is_current(self):
        """Test that version info matches current version."""
        generator = SchemaGenerator()
        schema = generator.generate_schema()

        comment = schema["$comment"]

        # Should contain current versions
        assert __version__ in comment
        assert __ast_version__ in comment
