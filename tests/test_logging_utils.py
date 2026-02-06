"""
Tests for structured logging utilities module.

Tests cover JSON formatting, request ID correlation,
and standardized log methods for API and external calls.
"""

import json
import logging
import os
import uuid
from io import StringIO
from unittest.mock import patch

from shared.logging_utils import (
    StructuredFormatter,
    configure_structured_logging,
    log_api_request,
    log_external_call,
    request_id_var,
    set_request_id,
)


class TestStructuredFormatter:
    """Tests for StructuredFormatter class."""

    def test_format_produces_valid_json(self):
        """Formatter should produce valid JSON output."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)

        # Should be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_format_includes_required_fields(self):
        """Formatter should include timestamp, level, logger, message."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=10,
            msg="Warning message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert "timestamp" in parsed
        assert parsed["level"] == "WARNING"
        assert parsed["logger"] == "test.logger"
        assert parsed["message"] == "Warning message"

    def test_format_includes_request_id_from_context(self):
        """Formatter should include request_id from context variable."""
        formatter = StructuredFormatter()

        # Set request ID in context
        test_request_id = "req-12345"
        token = request_id_var.set(test_request_id)

        try:
            record = logging.LogRecord(
                name="test.logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test",
                args=(),
                exc_info=None,
            )

            result = formatter.format(record)
            parsed = json.loads(result)

            assert parsed["request_id"] == test_request_id
        finally:
            request_id_var.reset(token)

    def test_format_includes_lambda_function_name(self):
        """Formatter should include AWS_LAMBDA_FUNCTION_NAME env var."""
        formatter = StructuredFormatter()

        with patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"}):
            record = logging.LogRecord(
                name="test.logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test",
                args=(),
                exc_info=None,
            )

            result = formatter.format(record)
            parsed = json.loads(result)

            assert parsed["function_name"] == "test-function"

    def test_format_includes_extra_fields(self):
        """Formatter should include extra fields passed to log call."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )
        # Add extra fields
        record.user_id = "user_123"
        record.package_name = "lodash"

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["user_id"] == "user_123"
        assert parsed["package_name"] == "lodash"

    def test_format_excludes_standard_record_fields(self):
        """Formatter should not duplicate standard LogRecord fields."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        # These internal fields should not appear
        assert "levelno" not in parsed
        assert "pathname" not in parsed
        assert "lineno" not in parsed
        assert "funcName" not in parsed
        assert "process" not in parsed
        assert "thread" not in parsed

    def test_format_includes_exception_info(self):
        """Formatter should include exception traceback when present."""
        formatter = StructuredFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]
        assert "Test error" in parsed["exception"]

    def test_format_handles_non_serializable_extra(self):
        """Formatter should handle non-JSON-serializable extra values."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test",
            args=(),
            exc_info=None,
        )
        # Add non-serializable value
        record.complex_obj = lambda x: x  # Lambdas aren't JSON serializable

        # Should not raise, uses default=str
        result = formatter.format(record)
        parsed = json.loads(result)

        # Lambda should be converted to string representation
        assert "complex_obj" in parsed
        assert "function" in parsed["complex_obj"]

    def test_format_handles_message_with_args(self):
        """Formatter should correctly format messages with arguments."""
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Processing package %s with score %d",
            args=("lodash", 85),
            exc_info=None,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["message"] == "Processing package lodash with score 85"


class TestConfigureStructuredLogging:
    """Tests for configure_structured_logging function."""

    def test_returns_root_logger(self):
        """Should return the root logger."""
        logger = configure_structured_logging()
        assert logger is logging.getLogger()

    def test_sets_log_level(self):
        """Should set specified log level."""
        logger = configure_structured_logging(level=logging.DEBUG)
        assert logger.level == logging.DEBUG

        # Reset
        configure_structured_logging(level=logging.INFO)

    def test_removes_existing_handlers(self):
        """Should remove existing handlers before adding new one."""
        root = logging.getLogger()

        # Add some handlers
        root.addHandler(logging.StreamHandler())
        root.addHandler(logging.StreamHandler())
        initial_count = len(root.handlers)
        assert initial_count >= 2

        configure_structured_logging()

        # Should have exactly 1 handler now
        assert len(root.handlers) == 1

    def test_adds_structured_formatter(self):
        """Should add handler with StructuredFormatter."""
        logger = configure_structured_logging()

        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, StructuredFormatter)

    def test_default_level_is_info(self):
        """Default log level should be INFO."""
        logger = configure_structured_logging()
        assert logger.level == logging.INFO


class TestSetRequestId:
    """Tests for set_request_id function."""

    def test_extracts_api_gateway_request_id(self):
        """Should extract requestId from API Gateway event."""
        event = {"requestContext": {"requestId": "api-gw-req-123"}}

        result = set_request_id(event)

        assert result == "api-gw-req-123"
        assert request_id_var.get() == "api-gw-req-123"

    def test_extracts_x_request_id_header_lowercase(self):
        """Should extract x-request-id header (lowercase)."""
        event = {"requestContext": {}, "headers": {"x-request-id": "header-req-456"}}

        result = set_request_id(event)

        assert result == "header-req-456"
        assert request_id_var.get() == "header-req-456"

    def test_extracts_x_request_id_header_camelcase(self):
        """Should extract X-Request-Id header (camelCase)."""
        event = {"requestContext": {}, "headers": {"X-Request-Id": "header-req-789"}}

        result = set_request_id(event)

        assert result == "header-req-789"
        assert request_id_var.get() == "header-req-789"

    def test_api_gateway_id_takes_priority(self):
        """API Gateway requestId should take priority over header."""
        event = {"requestContext": {"requestId": "api-gw-priority"}, "headers": {"x-request-id": "header-ignored"}}

        result = set_request_id(event)

        assert result == "api-gw-priority"

    def test_generates_uuid_when_no_id_found(self):
        """Should generate UUID when no request ID is found."""
        event = {}

        result = set_request_id(event)

        # Should be a valid UUID
        uuid.UUID(result)  # Raises if invalid
        assert request_id_var.get() == result

    def test_handles_none_headers(self):
        """Should handle None headers gracefully."""
        event = {"requestContext": {}, "headers": None}

        result = set_request_id(event)

        # Should generate UUID
        uuid.UUID(result)

    def test_handles_missing_request_context(self):
        """Should handle missing requestContext."""
        event = {"headers": {"x-request-id": "fallback-header"}}

        result = set_request_id(event)

        assert result == "fallback-header"

    def test_sets_context_variable(self):
        """Should set the context variable for later access."""
        event = {"requestContext": {"requestId": "ctx-test-123"}}

        set_request_id(event)

        # Verify it's accessible from context
        assert request_id_var.get() == "ctx-test-123"


class TestLogApiRequest:
    """Tests for log_api_request function."""

    def test_logs_request_at_info_level(self, caplog):
        """Should log API request at INFO level."""
        logger = logging.getLogger("test.api")

        with caplog.at_level(logging.INFO):
            log_api_request(
                logger,
                method="GET",
                path="/api/v1/packages/npm/lodash",
                status_code=200,
                latency_ms=45.5,
            )

        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == logging.INFO

    def test_formats_message_correctly(self, caplog):
        """Should format message as 'METHOD path -> status'."""
        logger = logging.getLogger("test.api")

        with caplog.at_level(logging.INFO):
            log_api_request(
                logger,
                method="POST",
                path="/api/v1/scan",
                status_code=201,
                latency_ms=100.0,
            )

        assert "POST /api/v1/scan -> 201" in caplog.text

    def test_includes_extra_fields(self, caplog):
        """Should include structured extra fields."""
        logger = logging.getLogger("test.api")

        with caplog.at_level(logging.INFO):
            log_api_request(
                logger,
                method="GET",
                path="/test",
                status_code=200,
                latency_ms=50.0,
                user_id="user_123",
            )

        record = caplog.records[0]
        assert record.http_method == "GET"
        assert record.path == "/test"
        assert record.status_code == 200
        assert record.latency_ms == 50.0
        assert record.user_id == "user_123"

    def test_anonymous_user_id_when_none(self, caplog):
        """Should use 'anonymous' when user_id is None."""
        logger = logging.getLogger("test.api")

        with caplog.at_level(logging.INFO):
            log_api_request(
                logger,
                method="GET",
                path="/test",
                status_code=200,
                latency_ms=10.0,
                user_id=None,
            )

        record = caplog.records[0]
        assert record.user_id == "anonymous"


class TestLogExternalCall:
    """Tests for log_external_call function."""

    def test_successful_call_logged_at_info(self, caplog):
        """Successful external calls should be logged at INFO level."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.INFO):
            log_external_call(
                logger,
                service="github",
                operation="get_repo",
                success=True,
                latency_ms=250.0,
            )

        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == logging.INFO

    def test_failed_call_logged_at_warning(self, caplog):
        """Failed external calls should be logged at WARNING level."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.WARNING):
            log_external_call(
                logger,
                service="npm",
                operation="get_package",
                success=False,
                latency_ms=5000.0,
                error="Timeout after 5s",
            )

        assert len(caplog.records) == 1
        assert caplog.records[0].levelno == logging.WARNING

    def test_formats_success_message(self, caplog):
        """Should format success message correctly."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.INFO):
            log_external_call(
                logger,
                service="deps.dev",
                operation="fetch_dependencies",
                success=True,
                latency_ms=150.0,
            )

        assert "External call to deps.dev: fetch_dependencies -> success" in caplog.text

    def test_formats_failure_message(self, caplog):
        """Should format failure message correctly."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.WARNING):
            log_external_call(
                logger,
                service="pypi",
                operation="get_metadata",
                success=False,
                latency_ms=30000.0,
            )

        assert "External call to pypi: get_metadata -> failed" in caplog.text

    def test_includes_extra_fields(self, caplog):
        """Should include structured extra fields."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.INFO):
            log_external_call(
                logger,
                service="github",
                operation="get_commits",
                success=True,
                latency_ms=500.0,
            )

        record = caplog.records[0]
        assert record.service == "github"
        assert record.operation == "get_commits"
        assert record.success is True
        assert record.latency_ms == 500.0

    def test_includes_error_when_provided(self, caplog):
        """Should include error field when provided."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.WARNING):
            log_external_call(
                logger,
                service="npm",
                operation="get_downloads",
                success=False,
                latency_ms=100.0,
                error="Rate limit exceeded",
            )

        record = caplog.records[0]
        assert record.error == "Rate limit exceeded"

    def test_error_is_none_when_not_provided(self, caplog):
        """Error field should be None when not provided."""
        logger = logging.getLogger("test.external")

        with caplog.at_level(logging.INFO):
            log_external_call(
                logger,
                service="github",
                operation="get_repo",
                success=True,
                latency_ms=200.0,
            )

        record = caplog.records[0]
        assert record.error is None


class TestIntegration:
    """Integration tests for structured logging components working together."""

    def test_full_logging_flow(self):
        """Test complete flow: configure -> set request ID -> log."""
        # Capture output
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(StructuredFormatter())

        logger = logging.getLogger("integration.test")
        logger.handlers = []
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Set request ID
        event = {"requestContext": {"requestId": "integration-req-123"}}
        set_request_id(event)

        # Log a message
        logger.info("Integration test message", extra={"custom_field": "value"})

        # Parse output
        output = stream.getvalue()
        parsed = json.loads(output)

        assert parsed["request_id"] == "integration-req-123"
        assert parsed["message"] == "Integration test message"
        assert parsed["custom_field"] == "value"
        assert parsed["level"] == "INFO"
