#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright Pionix GmbH and Contributors to EVerest

# EVerest Auth Security Test Runner
# This script builds and runs the security-focused tests for the Auth module

set -e

# Configuration
BUILD_DIR="build"
TEST_TARGET="everest-core_auth_tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../../" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== EVerest Auth Security Test Runner ===${NC}"
echo "Project Root: $PROJECT_ROOT"
echo "Build Directory: $BUILD_DIR"
echo "Test Target: $TEST_TARGET"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}Build directory not found. Creating and configuring...${NC}"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    cd ..
fi

# Build the project
echo -e "${BLUE}Building Auth tests...${NC}"
if cmake --build "$BUILD_DIR" --target "$TEST_TARGET" -j$(nproc 2>/dev/null || echo 4); then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Find the test executable
TEST_EXECUTABLE="$BUILD_DIR/tests/modules/EVSE/Auth/tests/$TEST_TARGET"

if [ ! -f "$TEST_EXECUTABLE" ]; then
    echo -e "${RED}✗ Test executable not found at: $TEST_EXECUTABLE${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}=== Running Security Tests ===${NC}"

# Function to run tests with a filter
run_test_category() {
    local category="$1"
    local filter="$2"
    local description="$3"
    
    echo ""
    echo -e "${YELLOW}--- $description ---${NC}"
    
    if "$TEST_EXECUTABLE" --gtest_filter="$filter" --gtest_color=yes; then
        echo -e "${GREEN}✓ $category tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $category tests failed${NC}"
        return 1
    fi
}

# Run different categories of security tests
TEST_RESULTS=()

# Individual security test categories
run_test_category "SQL Injection" "*sql_injection*" "SQL Injection Protection Tests"
TEST_RESULTS+=($?)

run_test_category "XSS Protection" "*xss_protection*" "Cross-Site Scripting Protection Tests"
TEST_RESULTS+=($?)

run_test_category "Input Validation" "*input_validation*" "Input Validation Edge Cases"
TEST_RESULTS+=($?)

run_test_category "DoS Protection" "*flooding*" "Denial of Service Protection Tests"
TEST_RESULTS+=($?)

run_test_category "Race Conditions" "*race_condition*" "Concurrent Access Protection Tests"
TEST_RESULTS+=($?)

run_test_category "Master Pass Security" "*master_pass*" "Master Pass Security Tests"
TEST_RESULTS+=($?)

run_test_category "Session Security" "*timeout*:*unauthorized*" "Session and Transaction Security"
TEST_RESULTS+=($?)

run_test_category "Performance" "*performance*" "Performance Under Security Load"
TEST_RESULTS+=($?)

# Run all security tests together
echo ""
echo -e "${BLUE}=== Running All Security Tests ===${NC}"
if "$TEST_EXECUTABLE" --gtest_filter="*Security*" --gtest_color=yes; then
    echo -e "${GREEN}✓ All security tests completed${NC}"
    ALL_TESTS_RESULT=0
else
    echo -e "${RED}✗ Some security tests failed${NC}"
    ALL_TESTS_RESULT=1
fi

# Summary
echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"

FAILED_TESTS=0
for result in "${TEST_RESULTS[@]}"; do
    if [ "$result" -ne 0 ]; then
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
done

TOTAL_CATEGORIES=${#TEST_RESULTS[@]}
PASSED_CATEGORIES=$((TOTAL_CATEGORIES - FAILED_TESTS))

echo "Test Categories: $PASSED_CATEGORIES/$TOTAL_CATEGORIES passed"

if [ $FAILED_TESTS -eq 0 ] && [ $ALL_TESTS_RESULT -eq 0 ]; then
    echo -e "${GREEN}🛡️  All security tests passed! System appears secure against tested attack vectors.${NC}"
    exit 0
else
    echo -e "${RED}⚠️  Some security tests failed. Review the output above for details.${NC}"
    echo -e "${YELLOW}📋 Consider investigating any failed security tests as they may indicate vulnerabilities.${NC}"
    exit 1
fi