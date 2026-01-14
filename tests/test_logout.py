"""Tests for POST /auth/logout endpoint."""

import json
import os
import sys

import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions"))


class TestLogoutHandler:
    """Test logout endpoint."""

    @mock_aws
    def test_logout_clears_session_cookie(self, api_gateway_event):
        """Logout should set cookie with Max-Age=0."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "Set-Cookie" in result["headers"]
        cookie = result["headers"]["Set-Cookie"]
        assert cookie.startswith("session=;")  # Cookie name must match auth_callback.py
        assert "Max-Age=0" in cookie
        assert "Path=/" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie  # Must match auth_callback.py

    @mock_aws
    def test_logout_returns_success_message(self, api_gateway_event):
        """Logout should return success message."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["message"] == "Logged out successfully"

    @mock_aws
    def test_logout_includes_cors_headers_for_allowed_origin(self, api_gateway_event):
        """Logout should include CORS headers for allowed origins."""
        from api.logout import handler

        api_gateway_event["headers"]["origin"] = "https://pkgwatch.laranjo.dev"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # CORS headers should be present for allowed origin
        assert "Access-Control-Allow-Origin" in result["headers"]
        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.laranjo.dev"

    @mock_aws
    def test_logout_no_cors_for_disallowed_origin(self, api_gateway_event):
        """Logout should not include CORS headers for disallowed origins."""
        from api.logout import handler

        api_gateway_event["headers"]["origin"] = "https://malicious-site.com"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # CORS should not include the malicious origin
        assert result["headers"].get("Access-Control-Allow-Origin") != "https://malicious-site.com"

    @mock_aws
    def test_logout_handles_missing_headers(self, api_gateway_event):
        """Logout should handle missing headers gracefully."""
        from api.logout import handler

        api_gateway_event["headers"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "Set-Cookie" in result["headers"]
