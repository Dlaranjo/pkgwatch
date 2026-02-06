"""Tests for POST /auth/logout endpoint."""

import json
import os
import sys

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

        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # CORS headers should be present for allowed origin
        assert "Access-Control-Allow-Origin" in result["headers"]
        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"

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


class TestLogoutCookieAttributes:
    """Tests for cookie attribute security."""

    @mock_aws
    def test_cookie_path_is_root(self, api_gateway_event):
        """Cookie Path should be / to clear from all paths."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        # Path must be / to ensure cookie is cleared site-wide
        assert "Path=/" in cookie

    @mock_aws
    def test_cookie_is_httponly(self, api_gateway_event):
        """Cookie must have HttpOnly flag to prevent XSS access."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        assert "HttpOnly" in cookie

    @mock_aws
    def test_cookie_is_secure(self, api_gateway_event):
        """Cookie must have Secure flag for HTTPS-only transmission."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        assert "Secure" in cookie

    @mock_aws
    def test_cookie_samesite_strict(self, api_gateway_event):
        """Cookie must have SameSite=Strict for CSRF protection."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        assert "SameSite=Strict" in cookie

    @mock_aws
    def test_cookie_value_is_empty(self, api_gateway_event):
        """Cookie value should be empty after logout."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        # Cookie should start with session=; (empty value followed by semicolon)
        assert cookie.startswith("session=;")

    @mock_aws
    def test_cookie_max_age_zero(self, api_gateway_event):
        """Cookie Max-Age must be 0 to expire immediately."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        assert "Max-Age=0" in cookie


class TestLogoutCors:
    """Tests for CORS handling on logout."""

    @mock_aws
    def test_cors_for_production_origin(self, api_gateway_event):
        """Should include CORS headers for production origin."""
        from api.logout import handler

        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"
        assert result["headers"]["Access-Control-Allow-Credentials"] == "true"

    @mock_aws
    def test_cors_uppercase_origin_header(self, api_gateway_event):
        """Should handle uppercase Origin header."""
        from api.logout import handler

        api_gateway_event["headers"]["Origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"

    @mock_aws
    def test_cors_excludes_unauthorized_origin(self, api_gateway_event):
        """Should not allow CORS from unauthorized origins."""
        from api.logout import handler

        api_gateway_event["headers"]["origin"] = "https://attacker.com"

        result = handler(api_gateway_event, {})

        # Should succeed but without CORS for attacker origin
        assert result["statusCode"] == 200
        assert result["headers"].get("Access-Control-Allow-Origin") != "https://attacker.com"

    @mock_aws
    def test_no_origin_no_cors(self, api_gateway_event):
        """Should not include CORS headers when no origin is provided."""
        from api.logout import handler

        # No origin header
        api_gateway_event["headers"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # CORS headers should not be present when no origin
        assert result["headers"].get("Access-Control-Allow-Origin") is None


class TestLogoutEdgeCases:
    """Tests for edge cases and unusual inputs."""

    @mock_aws
    def test_logout_with_empty_headers_dict(self, api_gateway_event):
        """Should handle empty headers dictionary."""
        from api.logout import handler

        api_gateway_event["headers"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "Set-Cookie" in result["headers"]

    @mock_aws
    def test_logout_with_existing_session_cookie(self, api_gateway_event):
        """Should clear even when a session cookie already exists in request."""
        from api.logout import handler

        api_gateway_event["headers"]["Cookie"] = "session=old_session_value"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # Should still set the clear cookie
        assert "Set-Cookie" in result["headers"]
        assert "Max-Age=0" in result["headers"]["Set-Cookie"]

    @mock_aws
    def test_logout_with_multiple_cookies(self, api_gateway_event):
        """Should work when request has multiple cookies."""
        from api.logout import handler

        api_gateway_event["headers"]["Cookie"] = "session=abc123; other=value; tracking=xyz"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        cookie = result["headers"]["Set-Cookie"]
        # Should only clear the session cookie
        assert cookie.startswith("session=;")

    @mock_aws
    def test_logout_content_type_is_json(self, api_gateway_event):
        """Response should have JSON content type."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        assert result["headers"]["Content-Type"] == "application/json"

    @mock_aws
    def test_logout_body_is_valid_json(self, api_gateway_event):
        """Response body should be valid JSON."""
        from api.logout import handler

        result = handler(api_gateway_event, {})

        # Should not raise JSONDecodeError
        body = json.loads(result["body"])
        assert isinstance(body, dict)


class TestLogoutIdempotency:
    """Tests for logout idempotency and repeated calls."""

    @mock_aws
    def test_logout_is_idempotent(self, api_gateway_event):
        """Calling logout multiple times should always succeed."""
        from api.logout import handler

        # First logout
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Second logout (already logged out)
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 200

        # Both should return same response structure
        assert json.loads(result1["body"]) == json.loads(result2["body"])

    @mock_aws
    def test_logout_without_prior_session(self, api_gateway_event):
        """Logout should succeed even if user was never logged in."""
        from api.logout import handler

        # No session cookie in request
        api_gateway_event["headers"] = {"origin": "https://pkgwatch.dev"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["message"] == "Logged out successfully"

    @mock_aws
    def test_logout_with_invalid_session(self, api_gateway_event):
        """Logout should succeed even with invalid/corrupt session cookie."""
        from api.logout import handler

        api_gateway_event["headers"]["Cookie"] = "session=invalid.garbage.token"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # Should still clear the cookie
        assert "Max-Age=0" in result["headers"]["Set-Cookie"]


class TestLogoutDevCors:
    """Tests for development CORS when enabled."""

    @mock_aws
    def test_dev_cors_when_enabled(self, api_gateway_event):
        """Should allow localhost origins when ALLOW_DEV_CORS is true."""
        # Note: This requires ALLOW_DEV_CORS=true env var
        # Save original and set dev mode
        original = os.environ.get("ALLOW_DEV_CORS")
        os.environ["ALLOW_DEV_CORS"] = "true"

        try:
            # Reload module to pick up env var change
            import importlib

            import shared.response_utils
            importlib.reload(shared.response_utils)

            from api.logout import handler

            api_gateway_event["headers"]["origin"] = "http://localhost:4321"

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 200
            assert result["headers"].get("Access-Control-Allow-Origin") == "http://localhost:4321"
        finally:
            # Restore original
            if original:
                os.environ["ALLOW_DEV_CORS"] = original
            else:
                os.environ.pop("ALLOW_DEV_CORS", None)
            # Reload again to restore
            import importlib

            import shared.response_utils
            importlib.reload(shared.response_utils)
