#!/bin/bash

# EVerest Auth Module Security Test Runner
# This script runs the comprehensive fraud scenario tests

echo "EVerest Auth Security Test Suite"
echo "==============================="
echo ""
echo "WARNING: This test suite demonstrates security vulnerabilities."
echo "Only run in controlled test environments!"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install required packages
echo "Installing required Python packages..."
pip install -q asyncio

# Run the security tests
echo ""
echo "Starting security test execution..."
echo "=================================="

python3 test_fraud_scenarios.py

# Check if report was generated
if [ -f "auth_security_test_report.json" ]; then
    echo ""
    echo "Test completed successfully!"
    echo "Report generated: auth_security_test_report.json"
    echo ""
    echo "Summary of report:"
    python3 -c "
import json
with open('auth_security_test_report.json', 'r') as f:
    report = json.load(f)
    summary = report['test_summary']
    print(f'Total tests: {summary[\"total_tests\"]}')
    print(f'Passed: {summary[\"passed\"]}')
    print(f'Failed: {summary[\"failed\"]}')
    print(f'Success rate: {summary[\"success_rate\"]:.1f}%')
    
    # Show critical failures
    failed_tests = [t for t in report['test_results'] if not t['success']]
    if failed_tests:
        print(f'\\nCRITICAL VULNERABILITIES FOUND: {len(failed_tests)}')
        for test in failed_tests[:5]:  # Show first 5
            print(f'  - {test[\"test_name\"]}: {test[\"details\"]}')
    else:
        print('\\nNo critical vulnerabilities detected.')
"
else
    echo "Error: Test report was not generated. Check for errors above."
    exit 1
fi

# Deactivate virtual environment
deactivate

echo ""
echo "Test execution completed."
echo "Review the detailed report for security recommendations."