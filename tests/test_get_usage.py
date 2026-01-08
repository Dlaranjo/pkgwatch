"""
Tests for GET /usage endpoint.
"""

import json
import os

import pytest
from moto import mock_aws


class TestGetUsageHandler:
    """Tests for the get_usage Lambda handler."""

    @mock_aws
    def test_returns_usage_for_valid_api_key(self, seeded_api_keys_table, api_gateway_event):
        """Should return usage statistics for valid API key."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "free"
        assert body["usage"]["requests_this_month"] == 0
        assert body["usage"]["monthly_limit"] == 5000
        assert body["usage"]["remaining"] == 5000
        assert "reset" in body
        assert "limits_by_tier" in body

    @mock_aws
    def test_returns_401_for_invalid_api_key(self, mock_dynamodb, api_gateway_event):
        """Should return 401 for invalid API key."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = "dh_invalid_key"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"

    @mock_aws
    def test_returns_401_without_api_key(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when API key is missing."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_usage import handler

        # No API key header
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_calculates_correct_remaining_quota(self, seeded_api_keys_table, api_gateway_event):
        """Should calculate remaining quota correctly after usage."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table, test_key = seeded_api_keys_table

        # Simulate some usage
        import hashlib
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.update_item(
            Key={"pk": "user_test123", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 1500},
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["usage"]["requests_this_month"] == 1500
        assert body["usage"]["remaining"] == 3500
        assert body["usage"]["usage_percentage"] == 30.0

    @mock_aws
    def test_includes_rate_limit_headers(self, seeded_api_keys_table, api_gateway_event):
        """Should include rate limit headers in response."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "X-RateLimit-Limit" in result["headers"]
        assert "X-RateLimit-Remaining" in result["headers"]
        assert result["headers"]["X-RateLimit-Limit"] == "5000"

    @mock_aws
    def test_shows_correct_tier_limits(self, seeded_api_keys_table, api_gateway_event):
        """Should show all tier limits in response."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        limits = body["limits_by_tier"]
        assert limits["free"] == 5000
        assert limits["starter"] == 25000
        assert limits["pro"] == 100000
        assert limits["business"] == 500000
