"""
Tests for response utilities module.

Tests cover CORS headers, JSON serialization, and response formatting helpers.
"""

import json
from decimal import Decimal

import pytest


class TestGetCorsHeaders:
    """Tests for get_cors_headers function."""

    def test_returns_cors_headers_for_allowed_prod_origin(self):
        """Should return CORS headers for allowed production origin."""
        from shared.response_utils import get_cors_headers

        result = get_cors_headers("https://pkgwatch.dev")

        assert result["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"
        assert "Access-Control-Allow-Methods" in result
        assert "Access-Control-Allow-Headers" in result
        assert result["Access-Control-Allow-Credentials"] == "true"

    def test_returns_empty_dict_for_disallowed_origin(self):
        """Should return empty dict for non-allowed origin."""
        from shared.response_utils import get_cors_headers

        result = get_cors_headers("https://malicious-site.com")

        assert result == {}

    def test_returns_empty_dict_for_none_origin(self):
        """Should return empty dict when origin is None."""
        from shared.response_utils import get_cors_headers

        result = get_cors_headers(None)

        assert result == {}


class TestDecimalDefault:
    """Tests for decimal_default JSON serializer."""

    def test_converts_integer_decimal_to_int(self):
        """Should convert integer Decimal to int."""
        from shared.response_utils import decimal_default

        result = decimal_default(Decimal("42"))

        assert result == 42
        assert isinstance(result, int)

    def test_converts_float_decimal_to_float(self):
        """Should convert non-integer Decimal to float."""
        from shared.response_utils import decimal_default

        result = decimal_default(Decimal("3.14"))

        assert result == 3.14
        assert isinstance(result, float)

    def test_raises_type_error_for_non_decimal(self):
        """Should raise TypeError for non-Decimal types."""
        from shared.response_utils import decimal_default

        with pytest.raises(TypeError) as exc_info:
            decimal_default({"not": "a decimal"})

        assert "dict" in str(exc_info.value)
        assert "not JSON serializable" in str(exc_info.value)


class TestJsonResponse:
    """Tests for json_response function."""

    def test_creates_basic_json_response(self):
        """Should create response with correct structure."""
        from shared.response_utils import json_response

        result = json_response(200, {"key": "value"})

        assert result["statusCode"] == 200
        assert result["headers"]["Content-Type"] == "application/json"
        assert json.loads(result["body"]) == {"key": "value"}

    def test_includes_additional_headers(self):
        """Should merge additional headers into response."""
        from shared.response_utils import json_response

        custom_headers = {
            "X-Custom-Header": "custom-value",
            "Cache-Control": "no-store",
        }

        result = json_response(200, {"data": "test"}, headers=custom_headers)

        assert result["headers"]["Content-Type"] == "application/json"
        assert result["headers"]["X-Custom-Header"] == "custom-value"
        assert result["headers"]["Cache-Control"] == "no-store"

    def test_serializes_decimals_in_body(self):
        """Should correctly serialize Decimal values in body."""
        from shared.response_utils import json_response

        result = json_response(200, {"score": Decimal("85.5"), "count": Decimal("100")})

        body = json.loads(result["body"])
        assert body["score"] == 85.5
        assert body["count"] == 100


class TestErrorResponse:
    """Tests for error_response function."""

    def test_creates_error_with_code_and_message(self):
        """Should create error response with proper structure."""
        from shared.response_utils import error_response

        result = error_response(400, "invalid_input", "Missing required field")

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_input"
        assert body["error"]["message"] == "Missing required field"

    def test_includes_custom_headers(self):
        """Should include custom headers in error response."""
        from shared.response_utils import error_response

        result = error_response(
            500,
            "server_error",
            "Internal error",
            headers={"X-Request-Id": "req-12345"},
        )

        assert result["headers"]["X-Request-Id"] == "req-12345"

    def test_includes_retry_after_header(self):
        """Should include Retry-After header when specified."""
        from shared.response_utils import error_response

        result = error_response(429, "rate_limited", "Too many requests", retry_after=60)

        assert result["headers"]["Retry-After"] == "60"

    def test_includes_cors_headers_for_allowed_origin(self):
        """Should include CORS headers when origin is allowed."""
        from shared.response_utils import error_response

        result = error_response(
            400,
            "bad_request",
            "Invalid input",
            origin="https://pkgwatch.dev",
        )

        assert (
            result["headers"]["Access-Control-Allow-Origin"]
            == "https://pkgwatch.dev"
        )


class TestSuccessResponse:
    """Tests for success_response function."""

    def test_creates_success_with_data(self):
        """Should create success response with data."""
        from shared.response_utils import success_response

        result = success_response({"package": "lodash", "score": 85})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"
        assert body["score"] == 85

    def test_uses_custom_status_code(self):
        """Should allow custom status code."""
        from shared.response_utils import success_response

        result = success_response({"created": True}, status_code=201)

        assert result["statusCode"] == 201

    def test_includes_custom_headers(self):
        """Should include custom headers in success response."""
        from shared.response_utils import success_response

        result = success_response({"data": "test"}, headers={"X-Cache-Status": "HIT"})

        assert result["headers"]["X-Cache-Status"] == "HIT"

    def test_includes_cors_headers_for_allowed_origin(self):
        """Should include CORS headers when origin is allowed."""
        from shared.response_utils import success_response

        result = success_response(
            {"data": "test"}, origin="https://pkgwatch.dev"
        )

        assert (
            result["headers"]["Access-Control-Allow-Origin"]
            == "https://pkgwatch.dev"
        )


class TestRedirectResponse:
    """Tests for redirect_response function."""

    def test_creates_redirect_with_location(self):
        """Should create redirect response with Location header."""
        from shared.response_utils import redirect_response

        result = redirect_response("https://pkgwatch.dev/dashboard")

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/dashboard"
        assert result["body"] == ""

    def test_uses_custom_status_code(self):
        """Should allow 301 permanent redirect."""
        from shared.response_utils import redirect_response

        result = redirect_response("https://new-url.com", status_code=301)

        assert result["statusCode"] == 301

    def test_includes_custom_headers(self):
        """Should include custom headers (e.g., Set-Cookie)."""
        from shared.response_utils import redirect_response

        result = redirect_response(
            "https://pkgwatch.dev/dashboard",
            headers={
                "Set-Cookie": "session=abc123; HttpOnly; Secure",
                "Cache-Control": "no-store",
            },
        )

        assert result["headers"]["Set-Cookie"] == "session=abc123; HttpOnly; Secure"
        assert result["headers"]["Cache-Control"] == "no-store"
        assert result["headers"]["Location"] == "https://pkgwatch.dev/dashboard"
