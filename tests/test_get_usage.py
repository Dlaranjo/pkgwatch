"""
Tests for GET /usage endpoint.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

from moto import mock_aws


class TestGetUsageHandler:
    """Tests for the get_usage Lambda handler."""

    @mock_aws
    def test_returns_usage_for_valid_api_key(self, seeded_api_keys_table, api_gateway_event):
        """Should return usage statistics for valid API key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

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
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = "pw_invalid_key"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"

    @mock_aws
    def test_returns_401_without_api_key(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when API key is missing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        # No API key header
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_calculates_correct_remaining_quota(self, seeded_api_keys_table, api_gateway_event):
        """Should calculate remaining quota correctly after usage."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

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
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

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
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

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


class TestGetUsageApiKeyVariants:
    """Tests for API key header variations."""

    @mock_aws
    def test_accepts_uppercase_x_api_key_header(self, seeded_api_keys_table, api_gateway_event):
        """Should accept uppercase X-API-Key header."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["X-API-Key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_accepts_lowercase_x_api_key_header(self, seeded_api_keys_table, api_gateway_event):
        """Should accept lowercase x-api-key header."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_returns_401_for_empty_api_key(self, mock_dynamodb, api_gateway_event):
        """Should return 401 for empty API key string."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = ""

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_returns_401_for_key_without_prefix(self, mock_dynamodb, api_gateway_event):
        """Should return 401 for API key without pw_ prefix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = "invalid_no_prefix_12345"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401


class TestGetUsageUserMetaAggregation:
    """Tests for USER_META aggregation logic."""

    @mock_aws
    def test_uses_user_meta_requests_when_available(self, mock_dynamodb, api_gateway_event):
        """Should use USER_META.requests_this_month when available."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_test_user_meta_key"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Create API key record with per-key usage of 100
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "meta@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "email_verified": True,
            }
        )

        # Create USER_META with aggregated usage of 500
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": "USER_META",
                "requests_this_month": 500,
                "key_count": 1,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should use USER_META value (500) not per-key value (100)
        assert body["usage"]["requests_this_month"] == 500
        assert body["usage"]["remaining"] == 4500

    @mock_aws
    def test_falls_back_to_per_key_when_no_user_meta(self, seeded_api_keys_table, api_gateway_event):
        """Should fall back to per-key usage when USER_META doesn't exist."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table, test_key = seeded_api_keys_table

        # Update per-key usage (no USER_META exists from seeded fixture)
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.update_item(
            Key={"pk": "user_test123", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 250},
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should use per-key value since no USER_META
        assert body["usage"]["requests_this_month"] == 250


class TestGetUsageTierLimits:
    """Tests for different tier limits."""

    @mock_aws
    def test_starter_tier_limits(self, mock_dynamodb, api_gateway_event):
        """Should return correct limits for starter tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_starter_tier_test"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "requests_this_month": 0,
                "email_verified": True,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "starter"
        assert body["usage"]["monthly_limit"] == 25000

    @mock_aws
    def test_pro_tier_limits(self, mock_dynamodb, api_gateway_event):
        """Should return correct limits for pro tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_pro_tier_test"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_pro",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pro@example.com",
                "tier": "pro",
                "requests_this_month": 50000,
                "email_verified": True,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "pro"
        assert body["usage"]["monthly_limit"] == 100000
        assert body["usage"]["remaining"] == 50000

    @mock_aws
    def test_business_tier_limits(self, mock_dynamodb, api_gateway_event):
        """Should return correct limits for business tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_business_tier_test"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_business",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "business@example.com",
                "tier": "business",
                "requests_this_month": 0,
                "email_verified": True,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "business"
        assert body["usage"]["monthly_limit"] == 500000


class TestGetUsageEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @mock_aws
    def test_usage_at_limit(self, seeded_api_keys_table, api_gateway_event):
        """Should show zero remaining when usage equals limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table, test_key = seeded_api_keys_table

        # Set usage exactly at limit
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.update_item(
            Key={"pk": "user_test123", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 5000},  # Free tier limit
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["usage"]["remaining"] == 0
        assert body["usage"]["usage_percentage"] == 100.0

    @mock_aws
    def test_usage_over_limit(self, seeded_api_keys_table, api_gateway_event):
        """Should clamp remaining to zero when usage exceeds limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table, test_key = seeded_api_keys_table

        # Set usage over the limit (can happen with bonus credits or race conditions)
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.update_item(
            Key={"pk": "user_test123", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 6000},  # Over free tier limit
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Remaining should be clamped to 0, not negative
        assert body["usage"]["remaining"] == 0
        assert body["usage"]["usage_percentage"] == 120.0

    @mock_aws
    def test_decimal_values_serialized_correctly(self, mock_dynamodb, api_gateway_event):
        """Should serialize Decimal values from DynamoDB correctly."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_decimal_test"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Use Decimal as DynamoDB returns
        table.put_item(
            Item={
                "pk": "user_decimal",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "decimal@example.com",
                "tier": "free",
                "requests_this_month": Decimal("1234"),
                "email_verified": True,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        # Should not raise serialization error
        body = json.loads(result["body"])
        assert body["usage"]["requests_this_month"] == 1234

    @mock_aws
    def test_cache_control_header_present(self, seeded_api_keys_table, api_gateway_event):
        """Should include Cache-Control no-store header to prevent caching."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "Cache-Control" in result["headers"]
        assert "no-store" in result["headers"]["Cache-Control"]
        assert "no-cache" in result["headers"]["Cache-Control"]


class TestGetUsageBillingCycle:
    """Tests for billing cycle reset date calculation."""

    @mock_aws
    def test_free_tier_reset_first_of_month(self, seeded_api_keys_table, api_gateway_event):
        """Free tier users should reset on first of next month."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Check reset date is first of next month
        reset_date = datetime.fromisoformat(body["reset"]["date"].replace("Z", "+00:00"))
        assert reset_date.day == 1

    @mock_aws
    def test_paid_tier_reset_uses_billing_cycle(self, mock_dynamodb, api_gateway_event):
        """Paid tier users should reset based on billing cycle end."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_paid_billing_test"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Set billing cycle end to a specific date
        billing_end = int(datetime(2026, 2, 15, tzinfo=timezone.utc).timestamp())

        table.put_item(
            Item={
                "pk": "user_paid_billing",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "paid@example.com",
                "tier": "pro",
                "requests_this_month": 0,
                "current_period_end": billing_end,
                "email_verified": True,
            }
        )

        # Also create USER_META with current_period_end
        table.put_item(
            Item={
                "pk": "user_paid_billing",
                "sk": "USER_META",
                "requests_this_month": 0,
                "current_period_end": billing_end,
            }
        )

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Reset date should match billing cycle end
        reset_date = datetime.fromisoformat(body["reset"]["date"].replace("Z", "+00:00"))
        assert reset_date.day == 15
        assert reset_date.month == 2

    @mock_aws
    def test_reset_seconds_calculation(self, seeded_api_keys_table, api_gateway_event):
        """Should calculate seconds until reset correctly."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Seconds until reset should be positive
        assert body["reset"]["seconds_until_reset"] > 0


class TestGetUsageErrorHandling:
    """Tests for error handling scenarios."""

    @mock_aws
    def test_handles_dynamodb_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 on DynamoDB errors."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"]["x-api-key"] = "pw_valid_looking_key"

        # Force an error by patching validate_api_key to raise
        with patch("api.get_usage.validate_api_key") as mock_validate:
            mock_validate.side_effect = Exception("DynamoDB error")

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_null_headers(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when headers are None (no API key present)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_usage import handler

        api_gateway_event["headers"] = None

        result = handler(api_gateway_event, {})

        # With null headers, api_key is None so validate_api_key returns None → 401
        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"
