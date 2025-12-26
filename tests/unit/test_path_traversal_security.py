"""
Security tests for path traversal vulnerability (CWE-22) fix.

Tests validate_file_path() function's security features:
- Symlink detection and rejection
- Path traversal prevention via .. sequences
- Absolute path restrictions
- Directory sandboxing with allowed_base
- Error message sanitization

Licensed under GNU General Public License v3.0
Author: Marc Rivero Lopez | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from surinort_ast.cli.main import validate_file_path


class TestValidateFilePathSecurity:
    """Security tests for validate_file_path function"""

    def test_basic_valid_path(self, tmp_path):
        """Valid paths should work normally"""
        test_file = tmp_path / "rules.txt"
        test_file.write_text("content")

        result = validate_file_path(test_file, must_exist=True)

        assert result.exists()
        assert result.is_absolute()

    def test_relative_path_traversal_attack(self, tmp_path):
        """Path traversal with .. should be rejected when allowed_base is set"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Create a file outside the safe directory
        outside_file = tmp_path / "sensitive.txt"
        outside_file.write_text("sensitive data")

        # Attempt to access file outside base via .. traversal
        traversal_path = base_dir / ".." / "sensitive.txt"

        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(traversal_path, must_exist=True, allowed_base=base_dir)

    def test_absolute_path_outside_allowed_base(self, tmp_path):
        """Absolute paths outside allowed_base should be rejected"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Create file outside base directory
        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("outside content")

        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(outside_file, must_exist=True, allowed_base=base_dir)

    def test_symlink_attack_detection(self, tmp_path):
        """Symlinks to sensitive files should be rejected by default"""
        # Create a sensitive file
        sensitive = tmp_path / "sensitive.txt"
        sensitive.write_text("secret data")

        # Create symlink pointing to sensitive file
        symlink = tmp_path / "innocent_looking_file.txt"
        symlink.symlink_to(sensitive)

        with pytest.raises(ValueError, match="Symlinks not allowed"):
            validate_file_path(symlink, must_exist=True, allow_symlinks=False)

    def test_symlink_allowed_when_explicitly_enabled(self, tmp_path):
        """Symlinks should work when allow_symlinks=True"""
        target = tmp_path / "target.txt"
        target.write_text("content")

        symlink = tmp_path / "link.txt"
        symlink.symlink_to(target)

        result = validate_file_path(symlink, must_exist=True, allow_symlinks=True)

        # Should resolve to actual target
        assert result.exists()

    def test_symlink_escaping_allowed_base(self, tmp_path):
        """Symlinks pointing outside allowed_base should be rejected"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Create target outside safe directory
        outside_target = tmp_path / "outside.txt"
        outside_target.write_text("outside content")

        # Create symlink inside safe directory pointing outside
        symlink = base_dir / "link.txt"
        symlink.symlink_to(outside_target)

        # Even with allow_symlinks=True, should reject if resolved path is outside base
        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(symlink, must_exist=True, allowed_base=base_dir, allow_symlinks=True)

    def test_multiple_parent_directory_traversal(self, tmp_path):
        """Multiple .. sequences should be caught"""
        base_dir = tmp_path / "level1" / "level2" / "level3"
        base_dir.mkdir(parents=True)

        # Try to escape multiple levels
        outside_file = tmp_path / "secret.txt"
        outside_file.write_text("secret")

        traversal_path = base_dir / ".." / ".." / ".." / ".." / "secret.txt"

        # When must_exist=True and path doesn't resolve, we get "Invalid path" error
        # When must_exist=False, we can check directory constraint
        with pytest.raises(ValueError, match=r"(Path outside allowed directory|Invalid path)"):
            validate_file_path(traversal_path, must_exist=False, allowed_base=base_dir)

    def test_path_inside_allowed_base_works(self, tmp_path):
        """Valid paths inside allowed_base should work"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        safe_file = base_dir / "file.txt"
        safe_file.write_text("safe content")

        result = validate_file_path(safe_file, must_exist=True, allowed_base=base_dir)

        assert result.exists()
        assert result.is_relative_to(base_dir.resolve())

    def test_subdirectory_inside_allowed_base_works(self, tmp_path):
        """Files in subdirectories of allowed_base should work"""
        base_dir = tmp_path / "safe"
        subdir = base_dir / "subdir"
        subdir.mkdir(parents=True)

        safe_file = subdir / "file.txt"
        safe_file.write_text("content")

        result = validate_file_path(safe_file, must_exist=True, allowed_base=base_dir)

        assert result.exists()
        assert result.is_relative_to(base_dir.resolve())

    def test_error_message_sanitization_hides_full_path(self, tmp_path):
        """Error messages should not leak full paths"""
        nonexistent = tmp_path / "some" / "deep" / "path" / "file.txt"

        with pytest.raises(ValueError) as exc_info:
            validate_file_path(nonexistent, must_exist=True)

        error_msg = str(exc_info.value)
        # Should only contain filename, not full path
        assert "file.txt" in error_msg
        assert str(tmp_path) not in error_msg
        assert "deep" not in error_msg

    def test_nonexistent_file_with_must_exist_false(self, tmp_path):
        """Non-existent files should work with must_exist=False"""
        nonexistent = tmp_path / "nonexistent.txt"

        result = validate_file_path(nonexistent, must_exist=False)

        assert result.is_absolute()
        assert not result.exists()

    def test_allowed_base_nonexistent_rejects_path(self, tmp_path):
        """Nonexistent allowed_base still provides security by rejecting paths outside it"""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        invalid_base = tmp_path / "nonexistent_base"

        # Even if base doesn't exist, path validation still works (rejects path outside base)
        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(test_file, must_exist=True, allowed_base=invalid_base)

    def test_etc_passwd_attack_absolute_path(self, tmp_path):
        """Direct access to /etc/passwd should be rejected with allowed_base"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Attempt to access system file
        etc_passwd = Path("/etc/passwd")

        if etc_passwd.exists():
            with pytest.raises(ValueError, match="Path outside allowed directory"):
                validate_file_path(etc_passwd, must_exist=True, allowed_base=base_dir)

    def test_windows_drive_letter_attack(self, tmp_path):
        """Windows absolute paths should be rejected with allowed_base"""
        if os.name != "nt":
            pytest.skip("Windows-specific test")

        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Try to access C:\Windows\System32
        system32 = Path("C:/Windows/System32/notepad.exe")

        if system32.exists():
            with pytest.raises(ValueError, match="Path outside allowed directory"):
                validate_file_path(system32, must_exist=True, allowed_base=base_dir)

    def test_null_byte_injection(self, tmp_path):
        """Null byte injection attempts should be handled"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Python's Path should handle this, but test to be sure
        try:
            malicious_path = base_dir / "file.txt\x00../../etc/passwd"
            result = validate_file_path(malicious_path, must_exist=False, allowed_base=base_dir)
            # If it doesn't raise, verify it's still within base
            assert result.is_relative_to(base_dir.resolve())
        except (ValueError, OSError):
            # Expected - null bytes should cause error
            pass

    def test_unicode_normalization_attack(self, tmp_path):
        """Unicode normalization attacks should not bypass validation"""
        base_dir = tmp_path / "safe"
        base_dir.mkdir()

        # Unicode dots (U+2024, U+2025, etc.) should not be treated as ..
        # Python's Path normalizes these, but test to ensure
        safe_file = base_dir / "file\u2024\u2024.txt"
        safe_file.write_text("content")

        result = validate_file_path(safe_file, must_exist=True, allowed_base=base_dir)
        assert result.is_relative_to(base_dir.resolve())

    def test_no_allowed_base_allows_any_path(self, tmp_path):
        """When allowed_base is None, any valid path should work"""
        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        # Should work without allowed_base restriction
        result = validate_file_path(test_file, must_exist=True, allowed_base=None)

        assert result.exists()
        assert result.is_absolute()

    def test_allowed_base_can_be_same_as_file_parent(self, tmp_path):
        """File's parent directory can be used as allowed_base"""
        base_dir = tmp_path / "base"
        base_dir.mkdir()

        test_file = base_dir / "file.txt"
        test_file.write_text("content")

        result = validate_file_path(test_file, must_exist=True, allowed_base=base_dir)

        assert result.exists()

    def test_case_sensitivity_on_case_insensitive_fs(self, tmp_path):
        """Path validation should work correctly on case-insensitive filesystems"""
        base_dir = tmp_path / "Base"
        base_dir.mkdir()

        test_file = base_dir / "File.txt"
        test_file.write_text("content")

        # Try with different case
        mixed_case_path = tmp_path / "base" / "file.txt"

        # Should work on case-insensitive FS (macOS, Windows)
        # Should fail on case-sensitive FS (Linux) if file doesn't exist
        try:
            result = validate_file_path(mixed_case_path, must_exist=True, allowed_base=base_dir)
            assert result.exists()
        except ValueError:
            # Expected on case-sensitive filesystem
            pass


class TestLuaDirPathTraversalProtection:
    """Test that Lua directory validation is protected against path traversal"""

    def test_lua_script_path_traversal_blocked(self, tmp_path):
        """Lua scripts with path traversal should be rejected"""
        base_dir = tmp_path / "lua_scripts"
        base_dir.mkdir()

        # Create a sensitive file outside lua directory
        sensitive = tmp_path / "sensitive.lua"
        sensitive.write_text("-- secret code")

        # Attempt path traversal
        traversal_path = base_dir / ".." / "sensitive.lua"

        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(traversal_path, must_exist=True, allowed_base=base_dir)

    def test_lua_script_absolute_path_blocked(self, tmp_path):
        """Absolute paths to Lua scripts outside base should be rejected"""
        base_dir = tmp_path / "lua_scripts"
        base_dir.mkdir()

        outside_script = tmp_path / "outside.lua"
        outside_script.write_text("-- outside")

        with pytest.raises(ValueError, match="Path outside allowed directory"):
            validate_file_path(outside_script, must_exist=True, allowed_base=base_dir)

    def test_lua_script_valid_path_works(self, tmp_path):
        """Valid Lua script paths should work"""
        base_dir = tmp_path / "lua_scripts"
        base_dir.mkdir()

        valid_script = base_dir / "my_script.lua"
        valid_script.write_text("-- valid lua")

        result = validate_file_path(
            valid_script,
            must_exist=True,
            allowed_base=base_dir,
            allow_symlinks=True,
        )

        assert result.exists()
        assert result.is_relative_to(base_dir.resolve())
