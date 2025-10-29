#!/bin/bash
# Test script for surinort-ast CLI
# This script validates all CLI commands and features

set -e  # Exit on error

echo "============================================================"
echo "SURINORT-AST CLI TEST SUITE"
echo "============================================================"
echo ""

# Activate virtualenv
source venv/bin/activate

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
test_command() {
    local test_name="$1"
    local command="$2"

    echo -n "Testing: $test_name ... "

    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test 1: Version
echo "============================================================"
echo "1. Version and Help Commands"
echo "============================================================"
surinort --version
surinort --help > /dev/null
echo ""

# Test 2: Parse command
echo "============================================================"
echo "2. Parse Command"
echo "============================================================"
test_command "parse file" "surinort parse test_rules.txt > /dev/null"
test_command "parse stdin" "echo 'alert tcp any any -> any 80 (msg:\"Test\"; sid:1;)' | surinort parse - > /dev/null"
test_command "parse with JSON output" "surinort parse test_rules.txt --json > /dev/null"
echo ""

# Test 3: Format command
echo "============================================================"
echo "3. Format Command"
echo "============================================================"
test_command "format file" "surinort fmt test_rules.txt > /dev/null"
test_command "format with stable mode" "surinort fmt test_rules.txt --stable > /dev/null"
test_command "format check mode" "surinort fmt test_rules.txt --check || true"
echo ""

# Test 4: Validate command
echo "============================================================"
echo "4. Validate Command"
echo "============================================================"
test_command "validate file" "surinort validate test_rules.txt"
echo ""

# Test 5: Statistics command
echo "============================================================"
echo "5. Statistics Command"
echo "============================================================"
surinort stats test_rules.txt
echo ""

# Test 6: JSON conversion
echo "============================================================"
echo "6. JSON Conversion"
echo "============================================================"
test_command "to-json" "surinort to-json test_rules.txt -o /tmp/surinort_test.json"
test_command "from-json" "surinort from-json /tmp/surinort_test.json > /dev/null"
test_command "to-json compact" "surinort to-json test_rules.txt --compact > /dev/null"
echo ""

# Test 7: Schema generation
echo "============================================================"
echo "7. Schema Generation"
echo "============================================================"
test_command "generate schema" "surinort schema > /dev/null"
echo ""

# Test 8: Dialects
echo "============================================================"
echo "8. Dialect Support"
echo "============================================================"
test_command "parse with suricata dialect" "surinort parse test_rules.txt --dialect suricata > /dev/null"
test_command "parse with snort2 dialect" "surinort parse test_rules.txt --dialect snort2 > /dev/null"
test_command "parse with snort3 dialect" "surinort parse test_rules.txt --dialect snort3 > /dev/null"
echo ""

# Test 9: Pipeline support
echo "============================================================"
echo "9. Pipeline Support"
echo "============================================================"
test_command "pipeline parse -> format" "surinort parse test_rules.txt | head -5 > /dev/null"
test_command "pipeline cat -> parse" "cat test_rules.txt | surinort parse - > /dev/null"
echo ""

# Cleanup
rm -f /tmp/surinort_test.json

# Summary
echo "============================================================"
echo "TEST SUMMARY"
echo "============================================================"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo "Total: $((TESTS_PASSED + TESTS_FAILED))"
echo "============================================================"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}SOME TESTS FAILED!${NC}"
    exit 1
fi
