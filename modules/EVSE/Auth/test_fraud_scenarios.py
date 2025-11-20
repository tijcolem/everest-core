#!/usr/bin/env python3
"""
EVerest Auth Module Security Test Suite

This test suite demonstrates various fraud use case scenarios and security
vulnerabilities that could affect the EVerest Auth module. These tests are
designed for educational and security assessment purposes.

WARNING: These tests should only be run in controlled test environments.
Do not run against production systems.

Author: Security Assessment Team
Date: November 2025
"""

import asyncio
import json
import time
import uuid
import hashlib
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AuthorizationStatus(Enum):
    ACCEPTED = "Accepted"
    REJECTED = "Rejected"
    UNKNOWN = "Unknown"
    NOT_AT_THIS_LOCATION = "NotAtThisLocation"
    NOT_AT_THIS_TIME = "NotAtThisTime"

class TokenType(Enum):
    RFID = "RFID"
    ISO15118 = "ISO15118"
    CENTRAL = "Central"
    LOCAL = "Local"
    REMOTE = "Remote"

@dataclass
class IdToken:
    value: str
    type: TokenType

@dataclass
class ProvidedIdToken:
    id_token: IdToken
    authorization_type: TokenType
    connectors: Optional[List[int]] = None
    parent_id_token: Optional[IdToken] = None
    prevalidated: bool = False

@dataclass
class ValidationResult:
    authorization_status: AuthorizationStatus
    parent_id_token: Optional[IdToken] = None
    evse_ids: Optional[List[int]] = None
    reservation_id: Optional[int] = None

@dataclass
class Reservation:
    id: int
    evse_id: Optional[int]
    id_token: str
    parent_id_token: Optional[str]
    expiry_time: datetime

class MockAuthHandler:
    """
    Mock implementation of the Auth module for testing security scenarios.
    This simulates the behavior of the actual AuthHandler for testing purposes.
    """
    
    def __init__(self):
        self.evses = {1: {"available": True, "transaction_active": False, "identifier": None},
                     2: {"available": True, "transaction_active": False, "identifier": None},
                     3: {"available": True, "transaction_active": False, "identifier": None}}
        self.reservations: Dict[int, Reservation] = {}
        self.tokens_in_process = set()
        self.master_pass_group_id = "MASTER_PASS_2025"
        self.connection_timeout = 60
        self.active_sessions: Dict[int, Dict] = {}
        self.failed_attempts: Dict[str, int] = {}
        self.security_events: List[Dict] = []
        
    def log_security_event(self, event_type: str, details: Dict):
        """Log security events for analysis"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "details": details
        }
        self.security_events.append(event)
        logger.warning(f"SECURITY EVENT: {event_type} - {details}")
    
    def validate_token(self, token: ProvidedIdToken) -> ValidationResult:
        """Simulate token validation with various security checks"""
        
        # Simulate network delay
        time.sleep(0.1)
        
        # Check for suspicious patterns
        if self._is_suspicious_token(token):
            self.log_security_event("SUSPICIOUS_TOKEN", {
                "token": token.id_token.value[:8] + "***",
                "type": token.authorization_type.value
            })
            return ValidationResult(AuthorizationStatus.REJECTED)
        
        # Simulate different validation scenarios
        if token.id_token.value.startswith("VALID_"):
            return ValidationResult(AuthorizationStatus.ACCEPTED)
        elif token.id_token.value.startswith("CLONED_"):
            return ValidationResult(AuthorizationStatus.REJECTED)
        elif token.id_token.value.startswith("MASTER_"):
            return ValidationResult(
                AuthorizationStatus.ACCEPTED,
                parent_id_token=IdToken(self.master_pass_group_id, TokenType.CENTRAL)
            )
        else:
            return ValidationResult(AuthorizationStatus.UNKNOWN)
    
    def _is_suspicious_token(self, token: ProvidedIdToken) -> bool:
        """Detect potentially fraudulent tokens"""
        
        # Rate limiting check
        token_key = token.id_token.value
        current_time = time.time()
        
        # Reset failed attempts older than 5 minutes
        cutoff_time = current_time - 300
        self.failed_attempts = {k: v for k, v in self.failed_attempts.items() 
                               if v > cutoff_time}
        
        # Check for too many attempts
        if token_key in self.failed_attempts:
            attempts = sum(1 for t in self.failed_attempts.values() 
                          if current_time - t < 60)  # Last minute
            if attempts > 5:
                return True
        
        # Check for known attack patterns
        if any(pattern in token_key for pattern in ["../", "<script>", "DROP TABLE"]):
            return True
            
        return False
    
    def process_token(self, token: ProvidedIdToken) -> str:
        """Main token processing logic with security controls"""
        
        try:
            # Check if token already in process
            if token.id_token.value in self.tokens_in_process:
                return "ALREADY_IN_PROCESS"
            
            self.tokens_in_process.add(token.id_token.value)
            
            # Validate token
            validation_result = self.validate_token(token)
            
            if validation_result.authorization_status == AuthorizationStatus.REJECTED:
                self._record_failed_attempt(token.id_token.value)
                return "REJECTED"
            
            # Check for master pass
            if (validation_result.parent_id_token and 
                validation_result.parent_id_token.value == self.master_pass_group_id):
                return self._handle_master_pass(token)
            
            # Check for active transactions to stop
            evse_with_transaction = self._find_active_transaction(token.id_token.value)
            if evse_with_transaction:
                return self._stop_transaction(evse_with_transaction, token)
            
            # Find available EVSE
            available_evse = self._select_available_evse(token)
            if not available_evse:
                return "NO_CONNECTOR_AVAILABLE"
            
            # Start new session
            return self._start_session(available_evse, token, validation_result)
            
        finally:
            self.tokens_in_process.discard(token.id_token.value)
    
    def _record_failed_attempt(self, token_value: str):
        """Record failed authentication attempts"""
        self.failed_attempts[token_value] = time.time()
        self.log_security_event("FAILED_AUTH_ATTEMPT", {"token": token_value[:8] + "***"})
    
    def _handle_master_pass(self, token: ProvidedIdToken) -> str:
        """Handle master pass operations"""
        self.log_security_event("MASTER_PASS_USED", {
            "token": token.id_token.value[:8] + "***",
            "active_sessions": len(self.active_sessions)
        })
        
        # Stop all active transactions
        stopped_count = 0
        for evse_id in self.active_sessions.copy():
            self._stop_transaction(evse_id, token)
            stopped_count += 1
            
        return f"MASTER_PASS_STOPPED_{stopped_count}_SESSIONS"
    
    def _find_active_transaction(self, token_value: str) -> Optional[int]:
        """Find EVSE with active transaction for this token"""
        for evse_id, session in self.active_sessions.items():
            if session.get("token") == token_value:
                return evse_id
        return None
    
    def _select_available_evse(self, token: ProvidedIdToken) -> Optional[int]:
        """Select available EVSE using configured algorithm"""
        
        # Check reservations first
        for reservation in self.reservations.values():
            if (reservation.id_token == token.id_token.value and
                reservation.expiry_time > datetime.now()):
                if reservation.evse_id and self.evses[reservation.evse_id]["available"]:
                    return reservation.evse_id
        
        # Find first available EVSE
        for evse_id, evse in self.evses.items():
            if evse["available"] and not evse["transaction_active"]:
                return evse_id
        
        return None
    
    def _start_session(self, evse_id: int, token: ProvidedIdToken, 
                      validation_result: ValidationResult) -> str:
        """Start a new charging session"""
        
        session_id = str(uuid.uuid4())
        self.active_sessions[evse_id] = {
            "session_id": session_id,
            "token": token.id_token.value,
            "start_time": datetime.now(),
            "validation_result": validation_result
        }
        
        self.evses[evse_id]["transaction_active"] = True
        self.evses[evse_id]["identifier"] = token.id_token.value
        
        return f"ACCEPTED_EVSE_{evse_id}_SESSION_{session_id[:8]}"
    
    def _stop_transaction(self, evse_id: int, token: ProvidedIdToken) -> str:
        """Stop an active transaction"""
        
        if evse_id in self.active_sessions:
            session = self.active_sessions.pop(evse_id)
            self.evses[evse_id]["transaction_active"] = False
            self.evses[evse_id]["identifier"] = None
            
            return f"STOPPED_EVSE_{evse_id}_SESSION_{session['session_id'][:8]}"
        
        return "NO_ACTIVE_TRANSACTION"
    
    def create_reservation(self, reservation: Reservation) -> str:
        """Create a new reservation"""
        
        # Check for conflicts
        if reservation.evse_id:
            existing = [r for r in self.reservations.values() 
                       if r.evse_id == reservation.evse_id and r.expiry_time > datetime.now()]
            if existing:
                return "CONFLICTING_RESERVATION"
        
        self.reservations[reservation.id] = reservation
        return f"RESERVATION_CREATED_{reservation.id}"
    
    def cancel_reservation(self, reservation_id: int) -> str:
        """Cancel an existing reservation"""
        if reservation_id in self.reservations:
            del self.reservations[reservation_id]
            return f"RESERVATION_CANCELLED_{reservation_id}"
        return "RESERVATION_NOT_FOUND"

class SecurityTestSuite:
    """
    Comprehensive security test suite for EVerest Auth module fraud scenarios.
    """
    
    def __init__(self):
        self.auth_handler = MockAuthHandler()
        self.test_results = []
        
    def log_test_result(self, test_name: str, success: bool, details: str):
        """Log test results"""
        result = {
            "test_name": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        status = "PASS" if success else "FAIL"
        logger.info(f"[{status}] {test_name}: {details}")
    
    async def run_all_tests(self):
        """Run all security test scenarios"""
        
        logger.info("=== Starting EVerest Auth Security Test Suite ===")
        
        # Test categories
        await self.test_free_charging_attacks()
        await self.test_service_disruption_attacks()
        await self.test_data_theft_attacks()
        await self.test_infrastructure_manipulation()
        await self.test_reservation_fraud()
        await self.test_race_conditions()
        await self.test_input_validation()
        
        # Generate report
        self.generate_report()
    
    async def test_free_charging_attacks(self):
        """Test scenarios where attackers attempt free charging"""
        
        logger.info("\n=== Testing Free Charging Attack Scenarios ===")
        
        # Test 1: RFID Token Cloning
        await self._test_rfid_cloning()
        
        # Test 2: Replay Attack
        await self._test_replay_attack()
        
        # Test 3: Authorization Bypass
        await self._test_authorization_bypass()
        
        # Test 4: Token Injection
        await self._test_token_injection()
    
    async def _test_rfid_cloning(self):
        """Simulate RFID token cloning attack"""
        
        # First, establish a legitimate token
        legitimate_token = ProvidedIdToken(
            id_token=IdToken("VALID_USER_12345", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        result = self.auth_handler.process_token(legitimate_token)
        if "ACCEPTED" in result:
            logger.info("Legitimate token accepted, session established")
        
        # Now simulate cloned token usage
        cloned_token = ProvidedIdToken(
            id_token=IdToken("CLONED_USER_12345", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        result = self.auth_handler.process_token(cloned_token)
        success = "REJECTED" in result
        
        self.log_test_result(
            "RFID Token Cloning Attack",
            success,
            f"Cloned token result: {result}"
        )
    
    async def _test_replay_attack(self):
        """Test token replay attack scenario"""
        
        # Use the same token multiple times rapidly
        token = ProvidedIdToken(
            id_token=IdToken("REPLAY_TOKEN_999", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        results = []
        for _ in range(10):
            result = self.auth_handler.process_token(token)
            results.append(result)
            await asyncio.sleep(0.1)  # Small delay between attempts
        
        # Should see protection against rapid reuse
        success = results.count("ALREADY_IN_PROCESS") > 0 or results.count("REJECTED") > 5
        
        self.log_test_result(
            "Token Replay Attack",
            success,
            f"Replay attempts blocked: {results}"
        )
    
    async def _test_authorization_bypass(self):
        """Test attempts to bypass authorization"""
        
        # Test with malformed token
        bypass_token = ProvidedIdToken(
            id_token=IdToken("BYPASS_../admin", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        result = self.auth_handler.process_token(bypass_token)
        success = "REJECTED" in result
        
        self.log_test_result(
            "Authorization Bypass Attempt",
            success,
            f"Bypass attempt result: {result}"
        )
    
    async def _test_token_injection(self):
        """Test SQL injection style attacks on token values"""
        
        injection_tokens = [
            "'; DROP TABLE tokens; --",
            "<script>alert('xss')</script>",
            "../../etc/passwd",
            "admin'/**/OR/**/1=1#"
        ]
        
        blocked_count = 0
        for injection in injection_tokens:
            token = ProvidedIdToken(
                id_token=IdToken(injection, TokenType.RFID),
                authorization_type=TokenType.RFID
            )
            
            result = self.auth_handler.process_token(token)
            if "REJECTED" in result:
                blocked_count += 1
        
        success = blocked_count == len(injection_tokens)
        
        self.log_test_result(
            "Token Injection Attacks",
            success,
            f"Blocked {blocked_count}/{len(injection_tokens)} injection attempts"
        )
    
    async def test_service_disruption_attacks(self):
        """Test denial of service scenarios"""
        
        logger.info("\n=== Testing Service Disruption Attacks ===")
        
        await self._test_connector_exhaustion()
        await self._test_reservation_bombing()
        await self._test_token_flooding()
    
    async def _test_connector_exhaustion(self):
        """Test exhausting all available connectors"""
        
        # Start sessions on all connectors
        sessions_started = 0
        for i in range(5):  # Try more than available connectors
            token = ProvidedIdToken(
                id_token=IdToken(f"EXHAUST_TOKEN_{i}", TokenType.RFID),
                authorization_type=TokenType.RFID
            )
            
            result = self.auth_handler.process_token(token)
            if "ACCEPTED" in result:
                sessions_started += 1
        
        # Try one more - should be rejected
        final_token = ProvidedIdToken(
            id_token=IdToken("FINAL_TOKEN", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        result = self.auth_handler.process_token(final_token)
        success = "NO_CONNECTOR_AVAILABLE" in result
        
        self.log_test_result(
            "Connector Exhaustion Attack",
            success,
            f"Started {sessions_started} sessions, final attempt: {result}"
        )
    
    async def _test_reservation_bombing(self):
        """Test creating excessive reservations"""
        
        reservations_created = 0
        for i in range(100):  # Try to create many reservations
            reservation = Reservation(
                id=i + 1000,
                evse_id=random.choice([1, 2, 3]),
                id_token=f"BOMB_TOKEN_{i}",
                parent_id_token=None,
                expiry_time=datetime.now() + timedelta(hours=1)
            )
            
            result = self.auth_handler.create_reservation(reservation)
            if "CREATED" in result:
                reservations_created += 1
            elif "CONFLICTING" in result:
                break  # Expected protection
        
        success = reservations_created < 50  # Should have some limit
        
        self.log_test_result(
            "Reservation Bombing Attack",
            success,
            f"Created {reservations_created} reservations before blocking"
        )
    
    async def _test_token_flooding(self):
        """Test flooding system with tokens"""
        
        start_time = time.time()
        processed_count = 0
        rejected_count = 0
        
        # Send many tokens rapidly
        for i in range(100):
            token = ProvidedIdToken(
                id_token=IdToken(f"FLOOD_TOKEN_{i}_{random.randint(1000, 9999)}", TokenType.RFID),
                authorization_type=TokenType.RFID
            )
            
            result = self.auth_handler.process_token(token)
            processed_count += 1
            
            if "REJECTED" in result:
                rejected_count += 1
            
            # Very small delay to simulate rapid requests
            await asyncio.sleep(0.01)
        
        elapsed_time = time.time() - start_time
        
        # System should implement rate limiting
        success = rejected_count > processed_count * 0.5  # At least 50% should be rejected
        
        self.log_test_result(
            "Token Flooding Attack",
            success,
            f"Processed {processed_count} tokens in {elapsed_time:.2f}s, rejected {rejected_count}"
        )
    
    async def test_data_theft_attacks(self):
        """Test data exfiltration scenarios"""
        
        logger.info("\n=== Testing Data Theft Attack Scenarios ===")
        
        await self._test_token_enumeration()
        await self._test_session_data_extraction()
    
    async def _test_token_enumeration(self):
        """Test systematic token enumeration"""
        
        valid_tokens_found = 0
        
        # Try systematic enumeration
        for i in range(100):
            token_value = f"ENUM_{i:04d}"
            token = ProvidedIdToken(
                id_token=IdToken(token_value, TokenType.RFID),
                authorization_type=TokenType.RFID
            )
            
            result = self.auth_handler.process_token(token)
            if "ACCEPTED" in result:
                valid_tokens_found += 1
                logger.warning(f"Found valid token during enumeration: {token_value}")
        
        # Should have rate limiting to prevent enumeration
        success = valid_tokens_found < 5
        
        self.log_test_result(
            "Token Enumeration Attack",
            success,
            f"Found {valid_tokens_found} valid tokens during enumeration"
        )
    
    async def _test_session_data_extraction(self):
        """Test attempts to extract session data"""
        
        # Start a legitimate session
        token = ProvidedIdToken(
            id_token=IdToken("VALID_SESSION_USER", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        self.auth_handler.process_token(token)
        
        # Check if sensitive data is exposed in logs or responses
        sensitive_data_exposed = False
        
        # Check security events for data leakage
        for event in self.auth_handler.security_events:
            if any(sensitive in str(event) for sensitive in ["password", "key", "secret"]):
                sensitive_data_exposed = True
                break
        
        success = not sensitive_data_exposed
        
        self.log_test_result(
            "Session Data Extraction",
            success,
            f"Sensitive data exposure detected: {sensitive_data_exposed}"
        )
    
    async def test_infrastructure_manipulation(self):
        """Test infrastructure control attacks"""
        
        logger.info("\n=== Testing Infrastructure Manipulation Attacks ===")
        
        await self._test_master_pass_abuse()
        await self._test_unauthorized_stop()
    
    async def _test_master_pass_abuse(self):
        """Test master pass token abuse"""
        
        # First start some legitimate sessions
        for i in range(2):
            token = ProvidedIdToken(
                id_token=IdToken(f"LEGIT_USER_{i}", TokenType.RFID),
                authorization_type=TokenType.RFID
            )
            self.auth_handler.process_token(token)
        
        # Try to use master pass
        master_token = ProvidedIdToken(
            id_token=IdToken("FAKE_MASTER_PASS", TokenType.CENTRAL),
            authorization_type=TokenType.CENTRAL
        )
        
        result = self.auth_handler.process_token(master_token)
        
        # Should log the master pass usage
        master_events = [e for e in self.auth_handler.security_events 
                        if e.get("type") == "MASTER_PASS_USED"]
        
        success = len(master_events) > 0 or "REJECTED" in result
        
        self.log_test_result(
            "Master Pass Abuse",
            success,
            f"Master pass attempt result: {result}, events logged: {len(master_events)}"
        )
    
    async def _test_unauthorized_stop(self):
        """Test unauthorized transaction stopping"""
        
        # Start a session with one token
        start_token = ProvidedIdToken(
            id_token=IdToken("VICTIM_USER_001", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        self.auth_handler.process_token(start_token)
        
        # Try to stop with different token
        stop_token = ProvidedIdToken(
            id_token=IdToken("ATTACKER_TOKEN", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        stop_result = self.auth_handler.process_token(stop_token)
        
        # Should not be able to stop someone else's session
        success = "STOPPED" not in stop_result or "NO_ACTIVE_TRANSACTION" in stop_result
        
        self.log_test_result(
            "Unauthorized Transaction Stop",
            success,
            f"Unauthorized stop attempt: {stop_result}"
        )
    
    async def test_reservation_fraud(self):
        """Test reservation-related fraud scenarios"""
        
        logger.info("\n=== Testing Reservation Fraud Scenarios ===")
        
        await self._test_reservation_squatting()
        await self._test_fake_reservations()
    
    async def _test_reservation_squatting(self):
        """Test long-term reservation squatting"""
        
        # Create reservations far in the future
        future_reservations = 0
        for i in range(10):
            reservation = Reservation(
                id=2000 + i,
                evse_id=random.choice([1, 2, 3]),
                id_token=f"SQUATTER_{i}",
                parent_id_token=None,
                expiry_time=datetime.now() + timedelta(days=365)  # 1 year future
            )
            
            result = self.auth_handler.create_reservation(reservation)
            if "CREATED" in result:
                future_reservations += 1
        
        # System should limit future reservations
        success = future_reservations < 5
        
        self.log_test_result(
            "Reservation Squatting",
            success,
            f"Created {future_reservations} long-term reservations"
        )
    
    async def _test_fake_reservations(self):
        """Test creation of fake/invalid reservations"""
        
        # Try reservations with invalid parameters
        invalid_attempts = [
            Reservation(-1, 1, "INVALID_ID", None, datetime.now() + timedelta(hours=1)),
            Reservation(3001, 999, "INVALID_EVSE", None, datetime.now() + timedelta(hours=1)),
            Reservation(3002, 1, "", None, datetime.now() + timedelta(hours=1)),  # Empty token
            Reservation(3003, 1, "VALID_TOKEN", None, datetime.now() - timedelta(hours=1))  # Past expiry
        ]
        
        rejected_count = 0
        for reservation in invalid_attempts:
            result = self.auth_handler.create_reservation(reservation)
            if "CREATED" not in result:
                rejected_count += 1
        
        success = rejected_count == len(invalid_attempts)
        
        self.log_test_result(
            "Fake Reservation Creation",
            success,
            f"Rejected {rejected_count}/{len(invalid_attempts)} invalid reservations"
        )
    
    async def test_race_conditions(self):
        """Test race condition vulnerabilities"""
        
        logger.info("\n=== Testing Race Condition Vulnerabilities ===")
        
        await self._test_concurrent_authorization()
        await self._test_reservation_race()
    
    async def _test_concurrent_authorization(self):
        """Test concurrent authorization of same token"""
        
        token = ProvidedIdToken(
            id_token=IdToken("CONCURRENT_TOKEN", TokenType.RFID),
            authorization_type=TokenType.RFID
        )
        
        # Launch concurrent authorization attempts
        tasks = []
        for _ in range(10):
            task = asyncio.create_task(self._async_token_process(token))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should see protection against concurrent processing
        already_processing = sum(1 for r in results if "ALREADY_IN_PROCESS" in str(r))
        accepted = sum(1 for r in results if "ACCEPTED" in str(r))
        
        success = already_processing > 0 and accepted <= 1
        
        self.log_test_result(
            "Concurrent Authorization Race",
            success,
            f"Concurrent results - Already processing: {already_processing}, Accepted: {accepted}"
        )
    
    async def _async_token_process(self, token: ProvidedIdToken) -> str:
        """Async wrapper for token processing"""
        await asyncio.sleep(0.01)  # Small delay to simulate async processing
        return self.auth_handler.process_token(token)
    
    async def _test_reservation_race(self):
        """Test concurrent reservation creation"""
        
        # Multiple tasks trying to reserve same connector        
        tasks = []
        for i in range(5):
            reservation = Reservation(
                id=4000 + i,
                evse_id=1,  # Same EVSE
                id_token=f"RACE_TOKEN_{i}",
                parent_id_token=None,
                expiry_time=datetime.now() + timedelta(hours=1)
            )
            task = asyncio.create_task(self._async_reservation_create(reservation))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle conflicts properly
        created = sum(1 for r in results if "CREATED" in str(r))
        conflicted = sum(1 for r in results if "CONFLICTING" in str(r))
        
        success = created <= 1 and conflicted > 0
        
        self.log_test_result(
            "Reservation Race Condition",
            success,
            f"Race results - Created: {created}, Conflicted: {conflicted}"
        )
    
    async def _async_reservation_create(self, reservation: Reservation) -> str:
        """Async wrapper for reservation creation"""
        await asyncio.sleep(0.01)  # Small delay to simulate async processing
        return self.auth_handler.create_reservation(reservation)
    
    async def test_input_validation(self):
        """Test input validation vulnerabilities"""
        
        logger.info("\n=== Testing Input Validation Vulnerabilities ===")
        
        await self._test_malformed_tokens()
        await self._test_buffer_overflow()
    
    async def _test_malformed_tokens(self):
        """Test handling of malformed token data"""
        
        malformed_tokens = [
            None,
            "",
            "A" * 1000,  # Very long token
            "\x00\x01\x02\x03",  # Binary data
            "正常なトークン",  # Unicode characters
            "token\nwith\nnewlines"
        ]
        
        handled_safely = 0
        for malformed in malformed_tokens:
            try:
                if malformed is None:
                    continue  # Skip None case for this test
                    
                token = ProvidedIdToken(
                    id_token=IdToken(malformed, TokenType.RFID),
                    authorization_type=TokenType.RFID
                )
                
                result = self.auth_handler.process_token(token)
                if "REJECTED" in result:
                    handled_safely += 1
                    
            except Exception as e:
                logger.warning(f"Exception handling malformed token: {e}")
        
        success = handled_safely >= len(malformed_tokens) - 1  # Minus None case
        
        self.log_test_result(
            "Malformed Token Handling",
            success,
            f"Safely handled {handled_safely} malformed tokens"
        )
    
    async def _test_buffer_overflow(self):
        """Test potential buffer overflow conditions"""
        
        # Test with extremely long inputs
        overflow_attempts = [
            "X" * 10000,  # Very long token
            "OVERFLOW_" + "A" * 5000,
            "B" * 100000
        ]
        
        no_crashes = True
        for overflow_data in overflow_attempts:
            try:
                token = ProvidedIdToken(
                    id_token=IdToken(overflow_data, TokenType.RFID),
                    authorization_type=TokenType.RFID
                )
                
                self.auth_handler.process_token(token)
                # Should handle gracefully, not crash
                
            except Exception as e:
                logger.error(f"Potential buffer overflow vulnerability: {e}")
                no_crashes = False
        
        success = no_crashes
        
        self.log_test_result(
            "Buffer Overflow Protection",
            success,
            f"System handled overflow attempts safely: {no_crashes}"
        )
    
    def generate_report(self):
        """Generate comprehensive security test report"""
        
        logger.info("\n=== SECURITY TEST REPORT ===")
        
        passed = sum(1 for r in self.test_results if r["success"])
        total = len(self.test_results)
        
        logger.info(f"Total Tests: {total}")
        logger.info(f"Passed: {passed}")
        logger.info(f"Failed: {total - passed}")
        logger.info(f"Success Rate: {passed/total*100:.1f}%")
        
        # Group by test category
        categories = {}
        for result in self.test_results:
            test_name = result["test_name"]
            category = test_name.split()[0]  # First word as category
            if category not in categories:
                categories[category] = {"passed": 0, "total": 0}
            categories[category]["total"] += 1
            if result["success"]:
                categories[category]["passed"] += 1
        
        logger.info("\n=== Results by Category ===")
        for category, stats in categories.items():
            rate = stats["passed"] / stats["total"] * 100
            logger.info(f"{category}: {stats['passed']}/{stats['total']} ({rate:.1f}%)")
        
        # Failed tests detail
        failed_tests = [r for r in self.test_results if not r["success"]]
        if failed_tests:
            logger.info("\n=== Failed Tests (Security Vulnerabilities Found) ===")
            for test in failed_tests:
                logger.warning(f"VULNERABILITY: {test['test_name']} - {test['details']}")
        
        # Security events summary
        logger.info(f"\n=== Security Events Detected: {len(self.auth_handler.security_events)} ===")
        event_types = {}
        for event in self.auth_handler.security_events:
            event_type = event["type"]
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        for event_type, count in event_types.items():
            logger.info(f"{event_type}: {count}")
        
        # Generate JSON report
        report = {
            "test_summary": {
                "total_tests": total,
                "passed": passed,
                "failed": total - passed,
                "success_rate": passed/total*100
            },
            "test_results": self.test_results,
            "security_events": self.auth_handler.security_events,
            "categories": categories,
            "timestamp": datetime.now().isoformat()
        }
        
        with open("auth_security_test_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info("\nDetailed report saved to: auth_security_test_report.json")

async def main():
    """Main test execution function"""
    
    print("EVerest Auth Module Security Test Suite")
    print("======================================")
    print("WARNING: This test suite demonstrates security vulnerabilities.")
    print("Only run in controlled test environments!")
    print()
    
    # Initialize test suite
    test_suite = SecurityTestSuite()
    
    # Run all tests
    await test_suite.run_all_tests()
    
    print("\n=== Test Suite Completed ===")
    print("Review the generated report for detailed results.")

if __name__ == "__main__":
    asyncio.run(main())