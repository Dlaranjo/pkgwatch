"""
Tests for error classification module.

Tests cover classification of transient vs permanent errors
for DLQ retry decision logic.
"""

from shared.error_classification import (
    PERMANENT_PATTERNS,
    TRANSIENT_PATTERNS,
    classify_error,
)


class TestClassifyError:
    """Tests for classify_error function."""

    # --- Permanent Error Tests ---

    def test_404_error_is_permanent(self):
        """404 errors should not be retried."""
        assert classify_error("HTTP 404: Package not found") == "permanent"

    def test_not_found_is_permanent(self):
        """'not found' messages should not be retried."""
        assert classify_error("Package does not exist in registry") == "permanent"

    def test_does_not_exist_is_permanent(self):
        """'does not exist' messages should not be retried."""
        assert classify_error("The requested resource does not exist") == "permanent"

    def test_malformed_is_permanent(self):
        """Malformed requests should not be retried."""
        assert classify_error("Malformed package name") == "permanent"

    def test_forbidden_is_permanent(self):
        """Forbidden errors should not be retried."""
        assert classify_error("403 Forbidden: Access denied") == "permanent"

    def test_unauthorized_is_permanent(self):
        """Unauthorized errors should not be retried."""
        assert classify_error("401 Unauthorized: Invalid token") == "permanent"

    def test_path_traversal_is_permanent(self):
        """Path traversal attempts should not be retried."""
        assert classify_error("Security error: path traversal detected") == "permanent"

    def test_package_name_too_long_is_permanent(self):
        """Package name validation failures should not be retried."""
        assert classify_error("Invalid: package name too long") == "permanent"

    def test_empty_package_name_is_permanent(self):
        """Empty package name errors should not be retried."""
        assert classify_error("Validation failed: empty package name") == "permanent"

    # --- Transient Error Tests ---

    def test_timeout_is_transient(self):
        """Timeout errors are worth retrying."""
        assert classify_error("Request timeout after 30s") == "transient"

    def test_timed_out_is_transient(self):
        """'timed out' messages are worth retrying."""
        assert classify_error("Connection timed out") == "transient"

    def test_503_is_transient(self):
        """503 Service Unavailable should be retried."""
        assert classify_error("HTTP 503: Service temporarily unavailable") == "transient"

    def test_502_is_transient(self):
        """502 Bad Gateway should be retried."""
        assert classify_error("HTTP 502: Bad Gateway") == "transient"

    def test_504_is_transient(self):
        """504 Gateway Timeout should be retried."""
        assert classify_error("HTTP 504: Gateway Timeout") == "transient"

    def test_rate_limit_is_transient(self):
        """Rate limit errors are worth retrying later."""
        assert classify_error("GitHub API rate limit exceeded") == "transient"

    def test_too_many_requests_is_transient(self):
        """429 Too Many Requests should be retried."""
        assert classify_error("429: Too many requests") == "transient"

    def test_connection_error_is_transient(self):
        """Connection errors are transient."""
        assert classify_error("Failed to establish connection") == "transient"

    def test_connection_reset_is_transient(self):
        """Connection reset errors are transient."""
        assert classify_error("Connection reset by peer") == "transient"

    def test_connection_refused_is_transient(self):
        """Connection refused errors are transient."""
        assert classify_error("Connection refused by server") == "transient"

    def test_unavailable_is_transient(self):
        """Service unavailable messages are transient."""
        assert classify_error("Registry unavailable") == "transient"

    def test_temporarily_unavailable_is_transient(self):
        """Temporarily unavailable messages are transient."""
        assert classify_error("Service temporarily unavailable, try again") == "transient"

    def test_service_unavailable_is_transient(self):
        """Service unavailable errors are transient."""
        assert classify_error("503 Service Unavailable") == "transient"

    # --- Unknown Error Tests ---

    def test_empty_message_returns_unknown(self):
        """Empty error message should return unknown."""
        assert classify_error("") == "unknown"

    def test_none_message_returns_unknown(self):
        """None error message should return unknown."""
        assert classify_error(None) == "unknown"

    def test_generic_error_returns_unknown(self):
        """Unclassified errors should return unknown."""
        assert classify_error("Something went wrong") == "unknown"

    def test_numeric_only_message_returns_unknown(self):
        """Numeric-only messages should return unknown."""
        assert classify_error("12345") == "unknown"

    def test_unknown_exception_type_returns_unknown(self):
        """Unknown exception types should return unknown."""
        assert classify_error("SomeRandomException: unexpected state") == "unknown"

    # --- Case Insensitivity Tests ---

    def test_case_insensitive_timeout(self):
        """Classification should be case insensitive for timeout."""
        assert classify_error("TIMEOUT ERROR") == "transient"
        assert classify_error("Timeout Error") == "transient"
        assert classify_error("TimeOut") == "transient"

    def test_case_insensitive_not_found(self):
        """Classification should be case insensitive for not found."""
        assert classify_error("NOT FOUND") == "permanent"
        assert classify_error("Not Found") == "permanent"
        # "NotFound" without space doesn't match "not found" pattern
        assert classify_error("NotFound") == "unknown"

    def test_case_insensitive_forbidden(self):
        """Classification should be case insensitive for forbidden."""
        assert classify_error("FORBIDDEN") == "permanent"
        assert classify_error("Forbidden access") == "permanent"

    # --- Priority Tests (Permanent checked first) ---

    def test_permanent_takes_priority_over_transient(self):
        """When both patterns match, permanent should win."""
        # A 404 that also mentions 'temporarily' should still be permanent
        result = classify_error("404 Not found - temporarily cached")
        assert result == "permanent"

    def test_not_found_with_connection_is_permanent(self):
        """Not found errors take priority even with connection mentioned."""
        result = classify_error("Connection to registry: package not found")
        assert result == "permanent"

    # --- Pattern Coverage Tests ---

    def test_all_transient_patterns_recognized(self):
        """Verify all TRANSIENT_PATTERNS are recognized."""
        for pattern in TRANSIENT_PATTERNS:
            error_msg = f"Error with {pattern} in message"
            result = classify_error(error_msg)
            # Should be transient unless it also matches a permanent pattern
            assert result in ("transient", "permanent"), f"Pattern '{pattern}' not recognized"

    def test_all_permanent_patterns_recognized(self):
        """Verify all PERMANENT_PATTERNS are recognized."""
        for pattern in PERMANENT_PATTERNS:
            error_msg = f"Error: {pattern}"
            result = classify_error(error_msg)
            assert result == "permanent", f"Pattern '{pattern}' not recognized as permanent"

    # --- Edge Cases ---

    def test_whitespace_only_returns_unknown(self):
        """Whitespace-only message should return unknown."""
        assert classify_error("   ") == "unknown"

    def test_partial_pattern_match(self):
        """Partial pattern matches should still classify correctly."""
        # '503' is a pattern, so '503abc' should match
        assert classify_error("status503error") == "transient"

    def test_unicode_in_error_message(self):
        """Unicode characters should not break classification."""
        assert classify_error("Connection timeout \u2014 retrying") == "transient"
        assert classify_error("Package \u2018test\u2019 not found") == "permanent"

    def test_very_long_error_message(self):
        """Long error messages should still be classified."""
        long_prefix = "x" * 10000
        assert classify_error(f"{long_prefix} - timeout error") == "transient"
        assert classify_error(f"{long_prefix} - 404 not found") == "permanent"

    def test_multiline_error_message(self):
        """Multiline error messages should be handled."""
        multiline = "HTTP Error\n503 Service Unavailable\nTry again later"
        assert classify_error(multiline) == "transient"

    def test_error_with_only_number_like_pattern(self):
        """Error messages with status codes embedded in text."""
        assert classify_error("Received status 502 from upstream") == "transient"
        assert classify_error("Error code 404 returned") == "permanent"

    def test_error_with_stacktrace(self):
        """Error messages containing stack traces should still classify."""
        error = (
            "Traceback (most recent call last):\n"
            '  File "handler.py", line 42, in process\n'
            "requests.exceptions.ConnectionError: connection reset by peer"
        )
        assert classify_error(error) == "transient"

    def test_error_with_json_body(self):
        """Error messages containing JSON should still classify."""
        error = '{"status": 503, "message": "Service Unavailable"}'
        assert classify_error(error) == "transient"

    def test_mixed_case_permanent_patterns(self):
        """All permanent patterns should match case-insensitively."""
        assert classify_error("PATH TRAVERSAL attempt detected") == "permanent"
        assert classify_error("EMPTY PACKAGE NAME") == "permanent"
        assert classify_error("Package Name Too Long: exceeded 256 chars") == "permanent"

    def test_error_classification_is_deterministic(self):
        """Same error message should always produce same classification."""
        error = "Connection timeout after 30s"
        results = {classify_error(error) for _ in range(100)}
        assert len(results) == 1
        assert results.pop() == "transient"


# =============================================================================
# INTEGRATION WITH DLQ RETRY LOGIC
# =============================================================================


class TestErrorClassificationRetryIntegration:
    """Tests verifying error classification drives correct retry behavior."""

    def test_all_transient_patterns_would_allow_retry(self):
        """Every transient pattern should result in a classification that allows retry."""
        for pattern in TRANSIENT_PATTERNS:
            # Build a message that only matches this transient pattern
            msg = f"Specific error: {pattern} occurred"
            result = classify_error(msg)
            # Should be transient (or permanent if pattern also matches permanent)
            assert result in ("transient", "permanent"), f"Pattern '{pattern}' classified as '{result}'"

    def test_all_permanent_patterns_would_block_retry(self):
        """Every permanent pattern should result in classification that blocks retry."""
        for pattern in PERMANENT_PATTERNS:
            msg = f"Error: {pattern}"
            result = classify_error(msg)
            assert result == "permanent", f"Pattern '{pattern}' was '{result}', expected 'permanent'"

    def test_empty_string_returns_unknown(self):
        """Empty string should return unknown."""
        assert classify_error("") == "unknown"

    def test_none_returns_unknown(self):
        """None should return unknown."""
        assert classify_error(None) == "unknown"

    def test_numeric_status_codes_classified_correctly(self):
        """HTTP status codes should be classified as expected."""
        assert classify_error("HTTP 404") == "permanent"
        assert classify_error("HTTP 502") == "transient"
        assert classify_error("HTTP 503") == "transient"
        assert classify_error("HTTP 504") == "transient"
        assert classify_error("HTTP 200") == "unknown"  # Success code not classified
        assert classify_error("HTTP 400") == "unknown"  # 400 not in patterns
