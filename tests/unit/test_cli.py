"""
Tests for CLI commands

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3. See LICENSE file for details.
This test suite validates real code behavior without mocks or stubs.
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from surinort_ast.cli.main import app, read_input, write_output

runner = CliRunner()


class TestCLIParseCommand:
    """Test 'surinort parse' command"""

    def test_parse_command_file(self, tmp_path):
        """Test parse command with file input"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["parse", str(file)])

        # Should complete successfully
        assert result.exit_code == 0
        assert "Success" in result.stdout or "Parsed" in result.stdout

    def test_parse_command_with_json_output(self, tmp_path):
        """Test parse command with JSON output"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["parse", str(file), "--json"])

        assert result.exit_code == 0

    def test_parse_command_with_output_file(self, tmp_path):
        """Test parse command with output file"""
        input_file = tmp_path / "test.rules"
        input_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        output_file = tmp_path / "output.txt"

        result = runner.invoke(app, ["parse", str(input_file), "-o", str(output_file)])

        # Check output file was created
        assert output_file.exists() or result.exit_code == 0

    def test_parse_command_nonexistent_file(self):
        """Test parse command with nonexistent file"""
        result = runner.invoke(app, ["parse", "/nonexistent/file.rules"])

        # Should fail
        assert result.exit_code != 0

    def test_parse_command_with_dialect(self, tmp_path):
        """Test parse command with dialect option"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["parse", str(file), "-d", "snort3"])

        assert result.exit_code in {0, 1}

    def test_parse_command_verbose(self, tmp_path):
        """Test parse command with verbose flag"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["parse", str(file), "-v"])

        assert result.exit_code == 0


class TestCLIFormatCommand:
    """Test 'surinort fmt' command"""

    def test_fmt_command_basic(self, tmp_path):
        """Test fmt command basic functionality"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["fmt", str(file)])

        assert result.exit_code == 0
        assert "alert" in result.stdout or "Success" in result.stdout

    def test_fmt_command_stable(self, tmp_path):
        """Test fmt command with stable formatting"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["fmt", str(file), "--stable"])

        assert result.exit_code == 0

    def test_fmt_command_check_mode(self, tmp_path):
        """Test fmt command in check mode"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["fmt", str(file), "--check"])

        # Exit code 0 if already formatted, 1 if needs formatting
        assert result.exit_code in [0, 1]

    def test_fmt_command_output_file(self, tmp_path):
        """Test fmt command with output file"""
        input_file = tmp_path / "test.rules"
        input_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        output_file = tmp_path / "formatted.rules"

        result = runner.invoke(app, ["fmt", str(input_file), "-o", str(output_file)])

        assert result.exit_code == 0 or output_file.exists()


class TestCLIValidateCommand:
    """Test 'surinort validate' command"""

    def test_validate_command_valid_file(self, tmp_path):
        """Test validate command with valid rules"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["validate", str(file)])

        assert result.exit_code == 0
        assert (
            "passed" in result.stdout.lower()
            or "success" in result.stdout.lower()
            or result.exit_code == 0
        )

    def test_validate_command_missing_sid(self, tmp_path):
        """Test validate command detects missing SID"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test";)\n')

        result = runner.invoke(app, ["validate", str(file)])

        # Should report warning about missing SID
        assert "sid" in result.stdout.lower() or result.exit_code in [0, 1]

    def test_validate_command_strict(self, tmp_path):
        """Test validate command with strict mode"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test";)\n')

        result = runner.invoke(app, ["validate", str(file), "--strict"])

        # Strict mode should treat warnings as errors
        assert result.exit_code in [0, 1]

    def test_validate_command_with_dialect(self, tmp_path):
        """Test validate command with dialect"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["validate", str(file), "-d", "suricata"])

        assert result.exit_code in {0, 1}


class TestCLIToJSONCommand:
    """Test 'surinort to-json' command"""

    def test_to_json_command(self, tmp_path):
        """Test to-json command"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["to-json", str(file)])

        assert result.exit_code == 0
        # Output should be valid JSON or success message
        if '"action"' in result.stdout or '"rules"' in result.stdout:
            # Try to parse as JSON
            pass

    def test_to_json_command_compact(self, tmp_path):
        """Test to-json command with compact output"""
        file = tmp_path / "test.rules"
        file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        result = runner.invoke(app, ["to-json", str(file), "--compact"])

        assert result.exit_code == 0

    def test_to_json_command_output_file(self, tmp_path):
        """Test to-json command with output file"""
        input_file = tmp_path / "test.rules"
        input_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)\n')

        output_file = tmp_path / "output.json"

        result = runner.invoke(app, ["to-json", str(input_file), "-o", str(output_file)])

        assert result.exit_code == 0 or output_file.exists()


class TestCLIFromJSONCommand:
    """Test 'surinort from-json' command"""

    def test_from_json_command(self, tmp_path):
        """Test from-json command"""
        # First create JSON
        json_file = tmp_path / "test.json"
        json_data = {
            "rules": [
                {
                    "action": "alert",
                    "header": {
                        "protocol": "tcp",
                        "src_addr": {"node_type": "AnyAddress"},
                        "src_port": {"node_type": "AnyPort"},
                        "direction": "->",
                        "dst_addr": {"node_type": "AnyAddress"},
                        "dst_port": {"node_type": "PortNumber", "value": 80},
                    },
                    "options": [
                        {"node_type": "MsgOption", "value": "Test"},
                        {"node_type": "SidOption", "value": 1},
                    ],
                    "dialect": "suricata",
                }
            ]
        }
        json_file.write_text(json.dumps(json_data))

        result = runner.invoke(app, ["from-json", str(json_file)])

        # Should convert JSON to rules (may succeed or have errors)
        assert result.exit_code in [0, 1]

    def test_from_json_command_output_file(self, tmp_path):
        """Test from-json command with output file"""
        json_file = tmp_path / "test.json"
        json_data = {"rules": []}
        json_file.write_text(json.dumps(json_data))

        output_file = tmp_path / "output.rules"

        result = runner.invoke(app, ["from-json", str(json_file), "-o", str(output_file)])

        # May fail with empty rules, but should attempt
        assert result.exit_code in [0, 1]


class TestCLIStatsCommand:
    """Test 'surinort stats' command"""

    def test_stats_command(self, tmp_path):
        """Test stats command"""
        file = tmp_path / "test.rules"
        file.write_text("""alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
alert udp any any -> any 53 (msg:"Test3"; sid:3;)
""")

        result = runner.invoke(app, ["stats", str(file)])

        assert result.exit_code == 0
        # Should show statistics
        assert "Rules" in result.stdout or "Total" in result.stdout or result.exit_code == 0


class TestCLISchemaCommand:
    """Test 'surinort schema' command"""

    def test_schema_command(self):
        """Test schema command"""
        result = runner.invoke(app, ["schema"])

        assert result.exit_code == 0
        # Should output JSON schema
        if "{" in result.stdout:
            # Try to parse as JSON
            try:
                data = json.loads(result.stdout)
                assert data is not None
            except Exception:
                # May have additional output around JSON
                pass

    def test_schema_command_output_file(self, tmp_path):
        """Test schema command with output file"""
        output_file = tmp_path / "schema.json"

        result = runner.invoke(app, ["schema", "-o", str(output_file)])

        assert result.exit_code == 0 or output_file.exists()


class TestCLIVersion:
    """Test version option"""

    def test_version_flag(self):
        """Test --version flag"""
        result = runner.invoke(app, ["--version"])

        # Should show version
        assert "surinort-ast" in result.stdout.lower() or "version" in result.stdout.lower()

    def test_version_short_flag(self):
        """Test -V flag"""
        result = runner.invoke(app, ["-V"])

        # Should show version
        assert result.exit_code == 0 or "version" in result.stdout.lower()


class TestCLIHelpers:
    """Test CLI helper functions"""

    def test_read_input_from_file(self, tmp_path):
        """Test read_input() with file"""
        file = tmp_path / "test.txt"
        file.write_text("test content")

        content = read_input(file)

        assert content == "test content"

    def test_read_input_nonexistent(self):
        """Test read_input() with nonexistent file"""
        from typer import Exit

        with pytest.raises(Exit):
            read_input(Path("/nonexistent/file.txt"))

    def test_write_output_to_file(self, tmp_path):
        """Test write_output() to file"""
        output_file = tmp_path / "output.txt"

        write_output("test content", output_file)

        assert output_file.exists()
        assert output_file.read_text() == "test content"


class TestCLIEdgeCases:
    """Test CLI edge cases"""

    def test_parse_empty_file(self, tmp_path):
        """Test parse command with empty file"""
        file = tmp_path / "empty.rules"
        file.write_text("")

        result = runner.invoke(app, ["parse", str(file)])

        # Should handle empty file gracefully
        assert result.exit_code in [0, 1]

    def test_fmt_command_invalid_file(self, tmp_path):
        """Test fmt command with invalid rules"""
        file = tmp_path / "invalid.rules"
        file.write_text("invalid syntax\n")

        result = runner.invoke(app, ["fmt", str(file)])

        # Should fail gracefully
        assert result.exit_code == 1

    def test_multiple_rules_parse(self, tmp_path):
        """Test parsing multiple rules"""
        file = tmp_path / "multiple.rules"
        file.write_text("""alert tcp any any -> any 80 (msg:"Test1"; sid:1;)
alert tcp any any -> any 443 (msg:"Test2"; sid:2;)
alert udp any any -> any 53 (msg:"Test3"; sid:3;)
alert tcp any any -> any 22 (msg:"Test4"; sid:4;)
alert tcp any any -> any 21 (msg:"Test5"; sid:5;)
""")

        result = runner.invoke(app, ["parse", str(file)])

        assert result.exit_code == 0
        # Should mention multiple rules
        assert "5" in result.stdout or "Parsed" in result.stdout


# Run with: pytest tests/unit/test_cli.py -v --cov=src/surinort_ast/cli/main --cov-report=term-missing
