"""
Tests for GET /packages/{ecosystem}/{name} endpoint.
"""

import json
import os

import pytest
from moto import mock_aws


class TestGetPackageHandler:
    """Tests for the get_package Lambda handler."""

    @mock_aws
    def test_returns_package_with_valid_api_key(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return package health data for authenticated request."""
        # Set env vars before import
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"
        assert body["ecosystem"] == "npm"
        assert body["health_score"] == 85
        assert body["risk_level"] == "LOW"

    @mock_aws
    def test_returns_package_in_demo_mode(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return package data for demo (unauthenticated) request."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key - should use demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "lodash"
        assert result["headers"].get("X-Demo-Mode") == "true"

    @mock_aws
    def test_returns_404_for_unknown_package(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return 404 for packages not in database."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "package_not_found"

    @mock_aws
    def test_returns_400_for_invalid_ecosystem(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should return 400 for unsupported ecosystem."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "pypi", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"

    @mock_aws
    def test_returns_400_for_missing_name(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 400 when package name is missing."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_parameter"

    @mock_aws
    def test_decodes_url_encoded_package_name(
        self, seeded_api_keys_table, seeded_packages_table, mock_dynamodb, api_gateway_event
    ):
        """Should decode URL-encoded scoped package names."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        # Add a scoped package
        packages_table = mock_dynamodb.Table("dephealth-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#@babel/core",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "@babel/core",
                "health_score": 90,
                "risk_level": "LOW",
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        # URL-encoded @babel/core
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "%40babel%2Fcore"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["package"] == "@babel/core"

    @mock_aws
    def test_rate_limit_headers_in_response(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should include rate limit headers in response."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-RateLimit-Limit" in result["headers"]
        assert "X-RateLimit-Remaining" in result["headers"]

    @mock_aws
    def test_increments_usage_for_authenticated_requests(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Should increment usage counter for authenticated requests."""
        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        # Make two requests
        handler(api_gateway_event, {})
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # Check that usage was incremented (remaining should be less)
        remaining = int(result["headers"]["X-RateLimit-Remaining"])
        limit = int(result["headers"]["X-RateLimit-Limit"])
        assert remaining < limit

    @mock_aws
    def test_returns_429_when_authenticated_limit_exceeded(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return 429 when authenticated user exceeds monthly limit."""
        import hashlib

        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        # Create a user that's already at their limit
        table = mock_dynamodb.Table("dephealth-api-keys")
        test_key = "dh_overlimit1234567890"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_overlimit",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "overlimit@example.com",
                "tier": "free",
                "requests_this_month": 5000,  # Already at free tier limit
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "rate_limit_exceeded"
        assert "Retry-After" in result["headers"]
        assert result["headers"]["X-RateLimit-Remaining"] == "0"
        assert "upgrade_url" in body["error"]

    @mock_aws
    def test_returns_429_when_demo_limit_exceeded(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should return 429 when demo mode IP exceeds hourly limit."""
        from datetime import datetime, timezone

        os.environ["PACKAGES_TABLE"] = "dephealth-packages"
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        # Seed demo rate limit data to exceed the limit
        table = mock_dynamodb.Table("dephealth-api-keys")
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%d-%H")
        client_ip = "127.0.0.1"

        table.put_item(
            Item={
                "pk": f"demo#{client_ip}",
                "sk": f"hour#{current_hour}",
                "requests": 21,  # Over the 20/hour demo limit
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key - should use demo mode with rate-limited IP

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        body = json.loads(result["body"])
        assert body["error"]["code"] == "demo_rate_limit_exceeded"
        assert "Retry-After" in result["headers"]
        assert result["headers"]["X-RateLimit-Remaining"] == "0"
        assert "signup_url" in body["error"]
