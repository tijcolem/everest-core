# EVerest Auth Module Security Test Suite

This directory contains comprehensive security testing tools for the EVerest Auth module, designed to demonstrate and test various fraud scenarios and potential vulnerabilities.

## ⚠️ WARNING

**These tools are for educational and security assessment purposes only. Do not run against production systems without proper authorization.**

## Files Overview

### Core Test Files

- **`test_fraud_scenarios.py`** - Comprehensive automated test suite covering all major fraud scenarios
- **`demonstrate_fraud_scenarios.py`** - Interactive demonstration script showing specific attack methods
- **`run_security_tests.sh`** - Shell script to execute the full test suite
- **`test_config.json`** - Configuration file defining test parameters and expected security controls

### Documentation

- **`AUTH_DOCUMENTATION.md`** - Complete security documentation for the Auth module

## Test Categories

### 1. Free Charging Attacks
- **RFID Token Cloning** - Simulation of cloned contactless cards
- **Replay Attacks** - Token reuse and session hijacking
- **Authorization Bypass** - Attempts to circumvent validation
- **Token Injection** - SQL injection and XSS attacks on token values

### 2. Service Disruption Attacks  
- **Connector Exhaustion** - Occupying all available charging points
- **Reservation Bombing** - Creating excessive reservations to block access
- **Token Flooding** - DoS attacks via authentication overload

### 3. Data Theft Attacks
- **Token Enumeration** - Systematic discovery of valid tokens
- **Session Data Extraction** - Attempts to access sensitive session information

### 4. Infrastructure Manipulation
- **Master Pass Abuse** - Unauthorized use of emergency override tokens
- **Unauthorized Transaction Stop** - Stopping other users' charging sessions

### 5. Reservation Fraud
- **Reservation Squatting** - Long-term reservation abuse
- **Fake Reservations** - Creating invalid or conflicting reservations

### 6. Race Conditions
- **Concurrent Authorization** - Multiple simultaneous authentication attempts
- **Reservation Conflicts** - Simultaneous reservation creation

### 7. Input Validation
- **Malformed Tokens** - Invalid data format handling
- **Buffer Overflow** - Testing system limits with large inputs

## Usage Instructions

### Running the Complete Test Suite

```bash
# Make script executable (if needed)
chmod +x run_security_tests.sh

# Run all security tests
./run_security_tests.sh
```

This will:
1. Create a Python virtual environment
2. Install required dependencies
3. Execute all fraud scenario tests
4. Generate a detailed JSON report
5. Display a summary of findings

### Running Interactive Demonstrations

```bash
# Run step-by-step demonstrations
python3 demonstrate_fraud_scenarios.py
```

This provides:
- Interactive walkthrough of each attack scenario
- Real-time demonstration of vulnerabilities
- Explanation of security controls
- Impact assessment and recommendations

### Running Individual Tests

```bash
# Run just the comprehensive test suite
python3 test_fraud_scenarios.py
```

## Understanding Test Results

### Test Report Structure

The generated `auth_security_test_report.json` contains:

```json
{
  "test_summary": {
    "total_tests": 18,
    "passed": 14,
    "failed": 4,
    "success_rate": 77.8
  },
  "test_results": [...],
  "security_events": [...],
  "categories": {...}
}
```

### Interpreting Results

- **PASS**: Security control is working effectively
- **FAIL**: Vulnerability detected that requires attention
- **Security Events**: Suspicious activities logged during testing

### Critical Vulnerabilities

Pay special attention to failed tests in these categories:
- Master Pass Abuse
- Token Injection Attacks  
- Buffer Overflow Protection
- Concurrent Authorization Race

## Security Controls Tested

### Authentication Security
- ✅ Multi-validator token verification
- ✅ Rate limiting on failed attempts
- ✅ Token replay protection
- ⚠️ Input validation and sanitization

### Authorization Controls
- ✅ Session binding to tokens
- ✅ Reservation-based access control
- ✅ Master pass emergency override
- ⚠️ Time-based access restrictions

### Audit and Monitoring
- ✅ Authentication event logging
- ✅ Failed attempt tracking
- ⚠️ Security event alerting
- ⚠️ Anomaly detection

### Fault Tolerance
- ✅ Graceful error handling
- ⚠️ Race condition prevention
- ⚠️ State synchronization
- ⚠️ Buffer overflow protection

## Common Vulnerabilities Found

### High Risk
1. **Insufficient Input Validation** - System may accept malformed or malicious tokens
2. **Master Pass Security** - Emergency override tokens may lack proper protection
3. **Race Conditions** - Concurrent operations may cause state corruption

### Medium Risk  
1. **Rate Limiting Gaps** - Some attack vectors may bypass flood protection
2. **Reservation Abuse** - Insufficient limits on reservation creation
3. **Session Management** - Token-session binding may have edge cases

### Low Risk
1. **Information Disclosure** - Logs may contain sensitive information
2. **Error Handling** - Exception details might expose system internals

## Recommended Mitigations

### Immediate Actions
1. **Enhance Input Validation** - Implement strict filtering and sanitization
2. **Strengthen Rate Limiting** - Add per-source and global limits  
3. **Improve Error Handling** - Ensure no sensitive data in error messages
4. **Audit Master Pass Usage** - Implement real-time monitoring and alerting

### Medium Term
1. **Add Anomaly Detection** - ML-based detection of unusual patterns
2. **Implement Circuit Breakers** - Protect against cascade failures
3. **Enhanced Monitoring** - Real-time security event correlation
4. **Security Training** - Educate operators on threat landscape

### Long Term
1. **Zero Trust Architecture** - Assume breach, verify everything
2. **Automated Response** - AI-driven threat response capabilities
3. **Regular Penetration Testing** - External security assessments
4. **Compliance Auditing** - Regular compliance and security reviews

## Configuration for Different Environments

### Development/Testing
```json
{
  "connection_timeout": 60,
  "master_pass_group_id": "TEST_MASTER_2025", 
  "ignore_connector_faults": true,
  "enable_debug_logging": true
}
```

### Production
```json
{
  "connection_timeout": 30,
  "master_pass_group_id": "",
  "ignore_connector_faults": false, 
  "enable_debug_logging": false
}
```

### High-Security Environment
```json
{
  "connection_timeout": 15,
  "master_pass_group_id": "",
  "ignore_connector_faults": false,
  "require_secondary_auth": true,
  "enable_anomaly_detection": true
}
```

## Troubleshooting

### Common Issues

**Test fails with "Module not found"**
```bash
# Ensure Python environment is properly set up
python3 -m venv venv
source venv/bin/activate
pip install asyncio
```

**Permission denied on run_security_tests.sh**
```bash
chmod +x run_security_tests.sh
```

**Tests run too slowly**
- Reduce iteration counts in test_config.json
- Run individual test categories instead of full suite

### Getting Help

1. Review the test output and JSON report for detailed information
2. Check the AUTH_DOCUMENTATION.md for security background
3. Examine individual test functions for specific scenarios
4. Consult the EVerest documentation for system architecture

## Contributing

To add new fraud scenarios or improve existing tests:

1. Add new test methods to `SecurityTestSuite` class
2. Update test configuration in `test_config.json`  
3. Add demonstrations to `demonstrate_fraud_scenarios.py`
4. Update documentation and README

## Legal and Ethical Considerations

- Only use these tools on systems you own or have explicit permission to test
- Ensure compliance with local laws and regulations
- Follow responsible disclosure practices for any vulnerabilities found
- Consider the impact on operations when scheduling security tests
- Maintain confidentiality of any sensitive information discovered

## Support and Updates

This test suite should be regularly updated to reflect:
- New attack vectors and fraud scenarios
- Changes to the Auth module implementation  
- Evolution of security best practices
- Regulatory and compliance requirements

For questions or issues, consult the EVerest security team or community resources.