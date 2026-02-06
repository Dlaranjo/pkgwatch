"""
Tests for the health check endpoint.
"""

import json


class TestHealthEndpoint:
    """Tests for GET /health endpoint."""

    def test_returns_200(self):
        """Health endpoint should return 200."""
        from api.health import handler

        result = handler({}, {})

        assert result["statusCode"] == 200

    def test_returns_healthy_status(self):
        """Health endpoint should return healthy status."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert body["status"] == "healthy"

    def test_returns_version(self):
        """Health endpoint should return version."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert "version" in body
        assert body["version"] == "1.0.0"

    def test_returns_timestamp(self):
        """Health endpoint should return timestamp."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert "timestamp" in body

    def test_returns_json_content_type(self):
        """Health endpoint should return JSON content type."""
        from api.health import handler

        result = handler({}, {})

        assert result["headers"]["Content-Type"] == "application/json"

    def test_returns_no_cache_header(self):
        """Health endpoint should not be cached."""
        from api.health import handler

        result = handler({}, {})

        assert result["headers"]["Cache-Control"] == "no-cache"

    def test_response_body_is_valid_json(self):
        """Health endpoint body must be parseable as JSON."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert isinstance(body, dict)

    def test_response_has_exactly_three_fields(self):
        """Health endpoint body should have exactly status, version, timestamp."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert set(body.keys()) == {"status", "version", "timestamp"}

    def test_timestamp_is_iso_format(self):
        """Health endpoint timestamp should be ISO 8601 format."""
        from datetime import datetime

        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        # Should not raise ValueError
        ts = datetime.fromisoformat(body["timestamp"].replace("Z", "+00:00"))
        assert ts is not None

    def test_status_value_is_healthy(self):
        """Health endpoint status should be exactly 'healthy'."""
        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert body["status"] == "healthy"

    def test_version_is_semver_format(self):
        """Health endpoint version should look like semver."""
        import re

        from api.health import handler

        result = handler({}, {})
        body = json.loads(result["body"])

        assert re.match(r"^\d+\.\d+\.\d+", body["version"])

    def test_handles_event_with_request_context(self):
        """Health endpoint should work with a full API Gateway event."""
        from api.health import handler

        event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {
                "requestId": "test-request-id-123",
                "identity": {"sourceIp": "127.0.0.1"},
            },
        }
        result = handler(event, {})

        assert result["statusCode"] == 200
