"""
Security tests for surinort-ast API module.

Tests path validation (CWE-22) and error message sanitization (CWE-209)
in the public API functions.

Licensed under GNU General Public License v3.0
Author: Marc Rivero Lopez | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from surinort_ast.api import parse_file
from surinort_ast.api._internal import _sanitize_path_for_error, _validate_file_path
from surinort_ast.exceptions import ParseError


class TestPathSanitization:
    """Tests for _sanitize_path_for_error function (CWE-209)"""

    def test_sanitize_removes_directory_path(self, tmp_path):
        """Full paths should be reduced to filename only"""
        deep_path = tmp_path / "level1" / "level2" / "level3" / "file.rules"

        sanitized = _sanitize_path_for_error(deep_path)

        assert sanitized == "file.rules"
        assert "level1" not in sanitized
        assert "level2" not in sanitized
        assert "level3" not in sanitized
        assert str(tmp_path) not in sanitized

    def test_sanitize_preserves_filename(self, tmp_path):
        """Filename should be preserved"""
        file_path = tmp_path / "important_rules.txt"

        sanitized = _sanitize_path_for_error(file_path)

        assert sanitized == "important_rules.txt"

    def test_sanitize_handles_absolute_paths(self):
        """Absolute paths should be reduced to basename"""
        path = Path("/etc/suricata/rules/local.rules")

        sanitized = _sanitize_path_for_error(path)

        assert sanitized == "local.rules"
        assert "/etc" not in sanitized
        assert "suricata" not in sanitized

    def test_sanitize_handles_relative_paths(self):
        """Relative paths should be reduced to basename"""
        path = Path("../../../sensitive/data/file.txt")

        sanitized = _sanitize_path_for_error(path)

        assert sanitized == "file.txt"
        assert ".." not in sanitized
        assert "sensitive" not in sanitized


class TestPathValidation:
    """Tests for _validate_file_path function (CWE-22)"""

    def test_valid_absolute_path_no_restrictions(self, tmp_path):
        """Valid absolute path with no restrictions should work"""
        test_file = tmp_path / "rules.txt"
        test_file.write_text("content")

        result = _validate_file_path(test_file)

        assert result.exists()
        assert result.is_absolute()

    def test_relative_path_resolved_to_absolute(self, tmp_path):
        """Relative paths should be resolved to absolute"""
        original_dir = Path.cwd()
        try:
            os.chdir(tmp_path)
            relative = Path("test.rules")
            relative.write_text("content")

            result = _validate_file_path(relative)

            assert result.is_absolute()
            assert result.exists()
        finally:
            os.chdir(original_dir)

    def test_path_traversal_rejected_with_allowed_base(self, tmp_path):
        """Path traversal attempts should be rejected when allowed_base is set"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Create target outside safe directory
        outside = tmp_path / "sensitive.txt"
        outside.write_text("secret")

        # Attempt traversal
        traversal_path = base_dir / ".." / "sensitive.txt"

        with pytest.raises(ParseError, match="Path outside allowed directory"):
            _validate_file_path(traversal_path, allowed_base=base_dir)

    def test_absolute_path_outside_allowed_base_rejected(self, tmp_path):
        """Absolute paths outside allowed_base should be rejected"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        outside = tmp_path / "outside.txt"
        outside.write_text("outside")

        with pytest.raises(ParseError, match="Path outside allowed directory"):
            _validate_file_path(outside, allowed_base=base_dir)

    def test_symlink_rejected_by_default(self, tmp_path):
        """Symlinks should be rejected by default"""
        target = tmp_path / "target.txt"
        target.write_text("content")

        symlink = tmp_path / "link.txt"
        symlink.symlink_to(target)

        with pytest.raises(ParseError, match="Symlinks not allowed"):
            _validate_file_path(symlink, allow_symlinks=False)

    def test_symlink_allowed_when_enabled(self, tmp_path):
        """Symlinks should work when explicitly allowed"""
        target = tmp_path / "target.txt"
        target.write_text("content")

        symlink = tmp_path / "link.txt"
        symlink.symlink_to(target)

        result = _validate_file_path(symlink, allow_symlinks=True)

        assert result.exists()

    def test_symlink_escaping_base_rejected(self, tmp_path):
        """Symlinks pointing outside allowed_base should be rejected"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        outside_target = tmp_path / "outside.txt"
        outside_target.write_text("outside")

        symlink = base_dir / "link.txt"
        symlink.symlink_to(outside_target)

        # Even with allow_symlinks=True, should reject if target is outside base
        with pytest.raises(ParseError, match="Path outside allowed directory"):
            _validate_file_path(symlink, allowed_base=base_dir, allow_symlinks=True)

    def test_path_within_allowed_base_works(self, tmp_path):
        """Valid paths within allowed_base should work"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        safe_file = base_dir / "file.txt"
        safe_file.write_text("content")

        result = _validate_file_path(safe_file, allowed_base=base_dir)

        assert result.exists()
        assert result.is_relative_to(base_dir.resolve())

    def test_subdirectory_within_allowed_base_works(self, tmp_path):
        """Files in subdirectories of allowed_base should work"""
        base_dir = tmp_path / "safe"
        subdir = base_dir / "subdir"
        subdir.mkdir(parents=True)

        safe_file = subdir / "file.txt"
        safe_file.write_text("content")

        result = _validate_file_path(safe_file, allowed_base=base_dir)

        assert result.exists()
        assert result.is_relative_to(base_dir.resolve())

    def test_multiple_parent_traversal_rejected(self, tmp_path):
        """Multiple .. sequences should be caught"""
        base_dir = tmp_path / "level1" / "level2" / "level3"
        base_dir.mkdir(parents=True)

        outside = tmp_path / "secret.txt"
        outside.write_text("secret")

        # Try to escape multiple levels
        traversal_path = base_dir / ".." / ".." / ".." / ".." / "secret.txt"

        with pytest.raises(ParseError, match="Path outside allowed directory"):
            _validate_file_path(traversal_path, allowed_base=base_dir)

    def test_invalid_path_raises_parse_error(self):
        """Invalid paths should raise ParseError with sanitized message"""
        # Create a path that will fail resolution on most systems
        # Note: Python 3.14+ raises ValueError for null bytes, which we also catch
        invalid = Path("\x00invalid\x00path")

        with pytest.raises((ParseError, ValueError)):
            _validate_file_path(invalid)

    def test_error_message_is_sanitized(self, tmp_path):
        """Error messages should not expose full paths"""
        base_dir = tmp_path / "some" / "deep" / "nested" / "directory"
        base_dir.mkdir(parents=True)

        outside = tmp_path / "outside.txt"
        outside.write_text("content")

        with pytest.raises(ParseError) as exc_info:
            _validate_file_path(outside, allowed_base=base_dir)

        error_msg = str(exc_info.value)
        # Should contain filename only
        assert "outside.txt" in error_msg
        # Should NOT contain directory structure
        assert "deep" not in error_msg
        assert "nested" not in error_msg


class TestParseFileSecureAPI:
    """Tests for parse_file with security features"""

    def test_parse_file_with_allowed_base(self, tmp_path):
        """parse_file should respect allowed_base parameter"""
        base_dir = tmp_path / "rules"
        base_dir.mkdir()

        rules_file = base_dir / "test.rules"
        rules_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Should work with allowed_base
        rules = parse_file(rules_file, allowed_base=base_dir)

        assert len(rules) == 1
        assert rules[0].header.protocol.value == "tcp"

    def test_parse_file_rejects_traversal_with_allowed_base(self, tmp_path):
        """parse_file should reject path traversal when allowed_base is set"""
        base_dir = tmp_path / "rules"
        base_dir.mkdir()

        # File outside allowed base
        outside = tmp_path / "outside.rules"
        outside.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        with pytest.raises(ParseError, match="Path outside allowed directory"):
            parse_file(outside, allowed_base=base_dir)

    def test_parse_file_rejects_symlinks_by_default(self, tmp_path):
        """parse_file should reject symlinks by default"""
        target = tmp_path / "target.rules"
        target.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        symlink = tmp_path / "link.rules"
        symlink.symlink_to(target)

        with pytest.raises(ParseError, match="Symlinks not allowed"):
            parse_file(symlink)

    def test_parse_file_allows_symlinks_when_enabled(self, tmp_path):
        """parse_file should allow symlinks when explicitly enabled"""
        target = tmp_path / "target.rules"
        target.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        symlink = tmp_path / "link.rules"
        symlink.symlink_to(target)

        rules = parse_file(symlink, allow_symlinks=True)

        assert len(rules) == 1

    def test_parse_file_error_messages_are_sanitized(self, tmp_path):
        """parse_file error messages should not expose full paths"""
        deep_path = tmp_path / "level1" / "level2" / "level3"
        deep_path.mkdir(parents=True)

        nonexistent = deep_path / "nonexistent.rules"

        with pytest.raises(FileNotFoundError) as exc_info:
            parse_file(nonexistent)

        error_msg = str(exc_info.value)
        # Should contain filename
        assert "nonexistent.rules" in error_msg
        # Should NOT contain directory structure
        assert "level1" not in error_msg
        assert "level2" not in error_msg
        assert str(tmp_path) not in error_msg

    def test_parse_file_parallel_errors_sanitized(self, tmp_path):
        """Parallel parsing errors should also be sanitized"""
        deep_path = tmp_path / "secure" / "rules" / "directory"
        deep_path.mkdir(parents=True)

        rules_file = deep_path / "bad.rules"
        # Write one invalid rule and one valid rule to avoid "no rules parsed" error
        rules_file.write_text(
            'alert tcp any any -> any 80 (msg:"Valid"; sid:1;)\ninvalid rule syntax here'
        )

        # Parse will succeed but with errors for invalid lines
        rules = parse_file(rules_file, workers=2)

        # Should have parsed the valid rule
        assert len(rules) >= 1

        # Now test with all invalid rules to check error sanitization
        all_invalid = deep_path / "all_bad.rules"
        all_invalid.write_text("invalid rule 1\ninvalid rule 2")

        with pytest.raises(ParseError) as exc_info:
            parse_file(all_invalid, workers=2)

        error_msg = str(exc_info.value)
        # Should contain filename
        assert "all_bad.rules" in error_msg
        # Should NOT contain full directory path
        assert "secure" not in error_msg
        assert str(tmp_path) not in error_msg

    def test_parse_file_sequential_errors_sanitized(self, tmp_path):
        """Sequential parsing errors should also be sanitized"""
        deep_path = tmp_path / "private" / "rules"
        deep_path.mkdir(parents=True)

        rules_file = deep_path / "malformed.rules"
        # Write invalid rule
        rules_file.write_text("this is not a valid rule")

        with pytest.raises(ParseError) as exc_info:
            parse_file(rules_file, workers=1)

        error_msg = str(exc_info.value)
        # Should contain filename
        assert "malformed.rules" in error_msg
        # Should NOT contain directory structure
        assert "private" not in error_msg
        assert str(tmp_path) not in error_msg

    def test_parse_file_without_allowed_base_accepts_any_path(self, tmp_path):
        """When allowed_base is None, any valid path should work"""
        rules_file = tmp_path / "test.rules"
        rules_file.write_text('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        # Should work without restrictions
        rules = parse_file(rules_file)

        assert len(rules) == 1


class TestSecurityDocumentation:
    """Tests to ensure security features are properly documented"""

    def test_validate_file_path_has_security_docs(self):
        """_validate_file_path should document security features"""
        from surinort_ast.api import _internal

        docstring = _internal._validate_file_path.__doc__

        assert "CWE-22" in docstring
        assert "Path Traversal" in docstring or "traversal" in docstring
        assert "security" in docstring.lower() or "Security" in docstring

    def test_parse_file_has_security_docs(self):
        """parse_file should document security parameters"""
        from surinort_ast.api import parsing

        docstring = parsing.parse_file.__doc__

        assert "allowed_base" in docstring
        assert "allow_symlinks" in docstring
        assert "security" in docstring.lower() or "Security" in docstring

    def test_sanitize_path_has_security_docs(self):
        """_sanitize_path_for_error should document CWE-209"""
        from surinort_ast.api import _internal

        docstring = _internal._sanitize_path_for_error.__doc__

        assert "CWE-209" in docstring
        assert "Information Exposure" in docstring or "information" in docstring.lower()
