"""
Migration Examples: Old API → New API

This file demonstrates how to migrate from top-level imports to
the new modular API structure in surinort-ast.

Both patterns work in v1.1.0+, but the modular approach is recommended
for production code.

Author: Marc Rivero López
License: GNU General Public License v3.0
"""

from __future__ import annotations

# =============================================================================
# Example 1: Simple Rule Parsing
# =============================================================================

print("Example 1: Simple Rule Parsing")
print("-" * 70)

# OLD (v1.0.x - still works in v1.1.0+)
# This is the top-level import pattern
"""
from surinort_ast import parse_rule

rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
rule = parse_rule(rule_text)
print(f"Action: {rule.header.action}")
"""

# NEW (v1.1.0+ - recommended)
# This is the modular import pattern
from surinort_ast.api.parsing import parse_rule

rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
rule = parse_rule(rule_text)
print(f"Action: {rule.header.action}")
print(f"Protocol: {rule.header.protocol}")
print()

# =============================================================================
# Example 2: JSON Serialization
# =============================================================================

print("Example 2: JSON Serialization")
print("-" * 70)

# OLD (top-level imports)
"""
from surinort_ast import parse_rule, to_json, from_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
json_str = to_json(rule)
restored_rule = from_json(json_str)
"""

# NEW (modular imports - explicit categories)
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import from_json, to_json

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
json_str = to_json(rule)
restored_rule = from_json(json_str)
print(f"Original SID: {rule.options.sid}")
print(f"Restored SID: {restored_rule.options.sid}")
print(f"Serialization successful: {rule.options.sid == restored_rule.options.sid}")
print()

# =============================================================================
# Example 3: Multi-Function Import
# =============================================================================

print("Example 3: Multi-Function Import")
print("-" * 70)

# OLD (single import line)
"""
from surinort_ast import parse_rule, to_json, validate_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
diagnostics = validate_rule(rule)
json_output = to_json(rule)
"""

# NEW (multiple modular imports - better organization)
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.serialization import to_json
from surinort_ast.api.validation import validate_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
diagnostics = validate_rule(rule)
json_output = to_json(rule)

print(f"Rule parsed: {rule.options.sid}")
print(f"Validation diagnostics: {len(diagnostics)} issues")
print(f"JSON output length: {len(json_output)} chars")
print()

# =============================================================================
# Example 4: File Parsing
# =============================================================================

print("Example 4: File Parsing (Conceptual)")
print("-" * 70)

# OLD
"""
from surinort_ast import parse_file

rules = parse_file("rules.rules")
print(f"Parsed {len(rules)} rules")
"""

# NEW
"""
from surinort_ast.api.parsing import parse_file

rules = parse_file("rules.rules")
print(f"Parsed {len(rules)} rules")
"""

print("File parsing example (would require actual file)")
print()

# =============================================================================
# Example 5: Validation and Printing
# =============================================================================

print("Example 5: Validation and Printing")
print("-" * 70)

# OLD
"""
from surinort_ast import parse_rule, validate_rule, print_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
diagnostics = validate_rule(rule)
formatted = print_rule(rule)
"""

# NEW
from surinort_ast.api.parsing import parse_rule
from surinort_ast.api.printing import print_rule
from surinort_ast.api.validation import validate_rule

rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
diagnostics = validate_rule(rule)
formatted = print_rule(rule)

print(f"Formatted rule:\n{formatted}")
print(f"Validation diagnostics: {len(diagnostics)}")
print()

# =============================================================================
# Example 6: Advanced - Batch Processing
# =============================================================================

print("Example 6: Advanced - Batch Processing")
print("-" * 70)

# OLD
"""
from surinort_ast import parse_rules, to_json

rule_texts = [
    'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
    'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    'alert tcp any any -> any 22 (msg:"SSH"; sid:3;)',
]

rules, errors = parse_rules(rule_texts)
json_list = [to_json(r) for r in rules]
"""

# NEW (explicit, organized)
from surinort_ast.api.parsing import parse_rules
from surinort_ast.api.serialization import to_json

rule_texts = [
    'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
    'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
    'alert tcp any any -> any 22 (msg:"SSH"; sid:3;)',
]

rules, errors = parse_rules(rule_texts)
json_list = [to_json(r) for r in rules]

print(f"Batch parsed {len(rules)} rules")
print(f"Errors: {len(errors)}")
print(f"Serialized {len(json_list)} rules to JSON")
print()

# =============================================================================
# Example 7: All API Categories
# =============================================================================

print("Example 7: Using All API Categories")
print("-" * 70)

# NEW (shows all modular imports organized by category)
from surinort_ast.api.parsing import parse_rule, parse_rules
from surinort_ast.api.printing import print_rule
from surinort_ast.api.serialization import from_json, to_json, to_json_schema
from surinort_ast.api.validation import validate_rule

# Parse
rule = parse_rule('alert tcp any any -> any 80 (msg:"Complete example"; sid:999;)')

# Validate
diagnostics = validate_rule(rule)

# Serialize
json_str = to_json(rule)
schema = to_json_schema()

# Print
formatted = print_rule(rule)

# Deserialize
restored = from_json(json_str)

print(f"✓ Parsed rule SID: {rule.options.sid}")
print(f"✓ Validation issues: {len(diagnostics)}")
print(f"✓ JSON length: {len(json_str)} chars")
print(f"✓ Schema generated: {len(schema)} chars")
print(f"✓ Formatted output: {len(formatted)} chars")
print(f"✓ Round-trip successful: {rule.options.sid == restored.options.sid}")
print()

# =============================================================================
# Example 8: Convenience Import (Still Supported)
# =============================================================================

print("Example 8: Top-Level Convenience Import (Still Works)")
print("-" * 70)

# This pattern still works and is fine for quick scripts, REPL usage, etc.
# For production code, prefer the modular imports shown above.
from surinort_ast import parse_rule as quick_parse

quick_rule = quick_parse('alert tcp any any -> any 80 (msg:"Quick test"; sid:1000;)')
print(f"Quick parse successful: {quick_rule.options.sid}")
print()

# =============================================================================
# Summary
# =============================================================================

print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print("✓ Both import patterns work in surinort-ast v1.1.0+")
print("✓ Modular imports are recommended for production code")
print("✓ Top-level imports are fine for scripts and REPL usage")
print("✓ No breaking changes - migrate at your own pace")
print()
print("Benefits of modular imports:")
print("  1. Explicit dependencies - clear what you're using")
print("  2. Better IDE support - clearer auto-completion")
print("  3. Easier code review - obvious which APIs are used")
print("  4. Future-proof - guaranteed long-term support")
print("  5. Organized - functions grouped by category")
print()
print("Migration resources:")
print("  - Migration strategy: docs/API_MIGRATION_STRATEGY.md")
print("  - Migration checklist: docs/MIGRATION_CHECKLIST.md")
print("  - Automated tool: tools/migrate_imports.py")
print("  - LibCST codemod: tools/codemods/api_migration.py")
print()
print("=" * 70)
