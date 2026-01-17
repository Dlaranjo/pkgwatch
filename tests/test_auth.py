"""
Tests for authentication and API key management.

Security-critical code - high coverage required.
"""

import hashlib
import os

import pytest
from moto import mock_aws


@pytest.fixture
def auth_table(mock_dynamodb):
    """Ensure the API keys table exists."""
    return mock_dynamodb


class TestValidateApiKey:
    """Tests for validate_api_key function."""

    @mock_aws
    def test_valid_key_returns_user_info(self, aws_credentials, mock_dynamodb):
        """Valid API key should return user info."""
        # Import inside test to ensure moto is active
        from shared.auth import generate_api_key, validate_api_key

        # Generate a key first
        user_id = "user_123"
        api_key = generate_api_key(user_id, tier="pro", email="test@example.com")

        # Validate the key
        result = validate_api_key(api_key)

        assert result is not None
        assert result["user_id"] == user_id
        assert result["tier"] == "pro"
        assert result["monthly_limit"] == 100000  # pro tier limit
        assert result["requests_this_month"] == 0

    @mock_aws
    def test_invalid_key_returns_none(self, aws_credentials, mock_dynamodb):
        """Invalid API key should return None."""
        from shared.auth import validate_api_key

        result = validate_api_key("pw_invalid_key_that_doesnt_exist")

        assert result is None

    @mock_aws
    def test_missing_key_returns_none(self, aws_credentials, mock_dynamodb):
        """Missing/empty API key should return None."""
        from shared.auth import validate_api_key

        assert validate_api_key(None) is None
        assert validate_api_key("") is None

    @mock_aws
    def test_wrong_prefix_returns_none(self, aws_credentials, mock_dynamodb):
        """Key without 'pw_' prefix should return None."""
        from shared.auth import validate_api_key

        assert validate_api_key("wrong_prefix_key") is None
        assert validate_api_key("sk_live_123") is None

    @mock_aws
    def test_very_long_key_handled(self, aws_credentials, mock_dynamodb):
        """Very long key should not crash."""
        from shared.auth import validate_api_key

        long_key = "pw_" + "x" * 10000
        result = validate_api_key(long_key)

        assert result is None  # Should not crash, just return None


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    @mock_aws
    def test_generates_valid_key_format(self, aws_credentials, mock_dynamodb):
        """Generated key should have correct format."""
        from shared.auth import generate_api_key

        api_key = generate_api_key("user_123", tier="free")

        assert api_key.startswith("pw_")
        assert len(api_key) > 10

    @mock_aws
    def test_keys_are_unique(self, aws_credentials, mock_dynamodb):
        """Each generated key should be unique."""
        from shared.auth import generate_api_key

        keys = [generate_api_key(f"user_{i}") for i in range(10)]

        # All keys should be unique
        assert len(set(keys)) == 10

    @mock_aws
    def test_tier_stored_correctly(self, aws_credentials, mock_dynamodb):
        """Tier should be stored and retrievable."""
        from shared.auth import generate_api_key, validate_api_key

        for tier in ["free", "starter", "pro", "business"]:
            api_key = generate_api_key(f"user_{tier}", tier=tier)
            result = validate_api_key(api_key)

            assert result["tier"] == tier

    @mock_aws
    def test_key_suffix_stored_correctly(self, aws_credentials, mock_dynamodb):
        """Key suffix should be stored for dashboard display."""
        import boto3
        from boto3.dynamodb.conditions import Key
        from shared.auth import generate_api_key

        api_key = generate_api_key("user_suffix_test", tier="free")
        expected_suffix = api_key[-8:]

        # Query DynamoDB directly to verify key_suffix is stored
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        response = table.query(
            KeyConditionExpression=Key("pk").eq("user_suffix_test"),
        )

        items = response.get("Items", [])
        assert len(items) == 1

        stored_suffix = items[0].get("key_suffix")
        assert stored_suffix == expected_suffix, \
            f"Stored key_suffix '{stored_suffix}' should match actual suffix '{expected_suffix}'"


class TestIncrementUsage:
    """Tests for increment_usage function."""

    @mock_aws
    def test_increments_counter(self, aws_credentials, mock_dynamodb):
        """Usage counter should increment."""
        from shared.auth import generate_api_key, increment_usage, validate_api_key

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        # Increment usage
        new_count = increment_usage(user["user_id"], user["key_hash"])

        assert new_count == 1

        # Increment again
        new_count = increment_usage(user["user_id"], user["key_hash"])

        assert new_count == 2

    @mock_aws
    def test_increment_by_custom_amount(self, aws_credentials, mock_dynamodb):
        """Should support custom increment amounts."""
        from shared.auth import generate_api_key, increment_usage, validate_api_key

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        # Increment by 10 (batch operation)
        new_count = increment_usage(user["user_id"], user["key_hash"], count=10)

        assert new_count == 10

    @mock_aws
    def test_usage_persists(self, aws_credentials, mock_dynamodb):
        """Usage should be visible in validate_api_key."""
        from shared.auth import generate_api_key, increment_usage, validate_api_key

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        # Increment
        increment_usage(user["user_id"], user["key_hash"], count=5)

        # Validate again and check usage
        user_updated = validate_api_key(api_key)

        assert user_updated["requests_this_month"] == 5


class TestTierLimits:
    """Tests for tier limit enforcement."""

    @mock_aws
    def test_tier_limits_correct(self, aws_credentials, mock_dynamodb):
        """Each tier should have correct monthly limit."""
        from shared.constants import TIER_LIMITS
        from shared.auth import generate_api_key, validate_api_key

        expected_limits = {
            "free": 5000,
            "starter": 25000,
            "pro": 100000,
            "business": 500000,
        }

        for tier, expected_limit in expected_limits.items():
            api_key = generate_api_key(f"user_{tier}", tier=tier)
            user = validate_api_key(api_key)

            assert user["monthly_limit"] == expected_limit

        # Also check TIER_LIMITS constant matches
        assert TIER_LIMITS == expected_limits


class TestUpdateTier:
    """Tests for update_tier function."""

    @mock_aws
    def test_update_tier_changes_limit(self, aws_credentials, mock_dynamodb):
        """Updating tier should change monthly limit."""
        from shared.auth import generate_api_key, update_tier, validate_api_key

        api_key = generate_api_key("user_123", tier="free")
        user = validate_api_key(api_key)

        assert user["monthly_limit"] == 5000

        # Upgrade to pro
        update_tier(user["user_id"], user["key_hash"], "pro")

        user_updated = validate_api_key(api_key)

        assert user_updated["tier"] == "pro"
        assert user_updated["monthly_limit"] == 100000

    @mock_aws
    def test_invalid_tier_raises_error(self, aws_credentials, mock_dynamodb):
        """Invalid tier should raise ValueError."""
        from shared.auth import generate_api_key, update_tier, validate_api_key

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        with pytest.raises(ValueError, match="Invalid tier"):
            update_tier(user["user_id"], user["key_hash"], "invalid_tier")


class TestRevokeApiKey:
    """Tests for revoke_api_key function."""

    @mock_aws
    def test_revoke_deletes_key(self, aws_credentials, mock_dynamodb):
        """Revoking a key should make it invalid."""
        from shared.auth import generate_api_key, revoke_api_key, validate_api_key

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        # Key works before revocation
        assert user is not None

        # Revoke
        revoke_api_key(user["user_id"], user["key_hash"])

        # Key no longer works
        result = validate_api_key(api_key)
        assert result is None


class TestResetMonthlyUsage:
    """Tests for reset_monthly_usage function."""

    @mock_aws
    def test_reset_clears_counter(self, aws_credentials, mock_dynamodb):
        """Reset should clear the monthly counter."""
        from shared.auth import (
            generate_api_key,
            increment_usage,
            reset_monthly_usage,
            validate_api_key,
        )

        api_key = generate_api_key("user_123")
        user = validate_api_key(api_key)

        # Use some quota
        increment_usage(user["user_id"], user["key_hash"], count=100)

        user_before = validate_api_key(api_key)
        assert user_before["requests_this_month"] == 100

        # Reset
        reset_monthly_usage(user["user_id"], user["key_hash"])

        user_after = validate_api_key(api_key)
        assert user_after["requests_this_month"] == 0


class TestUserLevelRateLimiting:
    """Tests for user-level rate limiting (USER_META.requests_this_month).

    Rate limiting is enforced at the user level to prevent gaming via key deletion.
    """

    @mock_aws
    def test_check_and_increment_uses_user_meta(self, aws_credentials, mock_dynamodb):
        """check_and_increment_usage should update USER_META, not per-key counter."""
        from shared.auth import generate_api_key, check_and_increment_usage, validate_api_key
        import boto3

        # Generate a key
        user_id = "user_meta_test"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # Make some requests
        for _ in range(5):
            allowed, _ = check_and_increment_usage(user["user_id"], user["key_hash"], 5000)
            assert allowed

        # Check USER_META has the count
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        meta = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert "Item" in meta
        assert meta["Item"]["requests_this_month"] == 5

    @mock_aws
    def test_rate_limit_shared_across_keys(self, aws_credentials, mock_dynamodb):
        """Rate limit should be enforced across all keys for a user."""
        from shared.auth import generate_api_key, check_and_increment_usage, validate_api_key

        user_id = "user_multikey"

        # Create USER_META first (normally done by create_api_key.py)
        import boto3
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        table.put_item(Item={"pk": user_id, "sk": "USER_META", "key_count": 0, "requests_this_month": 0})

        # Generate two keys
        key1 = generate_api_key(user_id, tier="free")
        key2 = generate_api_key(user_id, tier="free")

        user1 = validate_api_key(key1)
        user2 = validate_api_key(key2)

        # Use key1 for 3 requests
        for _ in range(3):
            allowed, count = check_and_increment_usage(user1["user_id"], user1["key_hash"], 5)
            assert allowed

        # Use key2 for 2 more requests (should work, total = 5)
        allowed, count = check_and_increment_usage(user2["user_id"], user2["key_hash"], 5)
        assert allowed
        assert count == 4

        allowed, count = check_and_increment_usage(user2["user_id"], user2["key_hash"], 5)
        assert allowed
        assert count == 5

        # Now both keys should be rate limited
        allowed, count = check_and_increment_usage(user1["user_id"], user1["key_hash"], 5)
        assert not allowed
        assert count == 5

        allowed, count = check_and_increment_usage(user2["user_id"], user2["key_hash"], 5)
        assert not allowed
        assert count == 5

    @mock_aws
    def test_batch_increment_uses_user_meta(self, aws_credentials, mock_dynamodb):
        """check_and_increment_usage_batch should also use USER_META."""
        from shared.auth import generate_api_key, check_and_increment_usage_batch, validate_api_key
        import boto3

        user_id = "user_batch_test"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # Batch increment by 10
        allowed, count = check_and_increment_usage_batch(
            user["user_id"], user["key_hash"], 5000, count=10
        )
        assert allowed
        assert count == 10

        # Check USER_META
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        meta = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert meta["Item"]["requests_this_month"] == 10

    @mock_aws
    def test_batch_limit_enforced_at_user_level(self, aws_credentials, mock_dynamodb):
        """Batch increment should be limited by user-level usage."""
        from shared.auth import generate_api_key, check_and_increment_usage, check_and_increment_usage_batch, validate_api_key
        import boto3

        user_id = "user_batch_limit"

        # Initialize USER_META
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        table.put_item(Item={"pk": user_id, "sk": "USER_META", "key_count": 0, "requests_this_month": 0})

        # Create two keys
        key1 = generate_api_key(user_id, tier="free")
        key2 = generate_api_key(user_id, tier="free")

        user1 = validate_api_key(key1)
        user2 = validate_api_key(key2)

        # Use key1 to consume 8 of 10 requests
        for _ in range(8):
            allowed, _ = check_and_increment_usage(user1["user_id"], user1["key_hash"], 10)
            assert allowed

        # Try batch of 5 with key2 - should fail (would exceed 10)
        allowed, count = check_and_increment_usage_batch(user2["user_id"], user2["key_hash"], 10, count=5)
        assert not allowed
        assert count == 8

        # Batch of 2 should work
        allowed, count = check_and_increment_usage_batch(user2["user_id"], user2["key_hash"], 10, count=2)
        assert allowed
        assert count == 10

    @mock_aws
    def test_user_meta_auto_created_on_first_request(self, aws_credentials, mock_dynamodb):
        """USER_META should be auto-created with count=1 on first rate-limited request."""
        from shared.auth import generate_api_key, check_and_increment_usage, validate_api_key
        import boto3

        user_id = "user_auto_create"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # USER_META shouldn't exist yet (generate_api_key doesn't create it)
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        meta_before = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert "Item" not in meta_before

        # First request should auto-create USER_META
        allowed, count = check_and_increment_usage(user["user_id"], user["key_hash"], 5000)
        assert allowed
        assert count == 1

        # Verify USER_META was created
        meta_after = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert "Item" in meta_after
        assert meta_after["Item"]["requests_this_month"] == 1

    @mock_aws
    def test_revoke_key_preserves_user_usage(self, aws_credentials, mock_dynamodb):
        """Revoking a key should NOT reset USER_META.requests_this_month."""
        from shared.auth import generate_api_key, check_and_increment_usage, validate_api_key, revoke_api_key
        import boto3

        user_id = "user_revoke_test"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META with initial usage
        table.put_item(Item={
            "pk": user_id,
            "sk": "USER_META",
            "key_count": 2,
            "requests_this_month": 100,
        })

        # Create two keys
        key1 = generate_api_key(user_id, tier="free")
        key2 = generate_api_key(user_id, tier="free")
        user1 = validate_api_key(key1)
        user2 = validate_api_key(key2)

        # Use some more quota
        for _ in range(50):
            check_and_increment_usage(user1["user_id"], user1["key_hash"], 5000)

        # Usage should now be 150
        meta_before = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert meta_before["Item"]["requests_this_month"] == 150

        # Revoke key1
        revoke_api_key(user1["user_id"], user1["key_hash"])

        # Usage should STILL be 150 (not reset!)
        meta_after = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert meta_after["Item"]["requests_this_month"] == 150

    @mock_aws
    def test_new_key_inherits_user_rate_limit(self, aws_credentials, mock_dynamodb):
        """A newly created key should be rate-limited if user is already at limit."""
        from shared.auth import generate_api_key, check_and_increment_usage, validate_api_key
        import boto3

        user_id = "user_inherit_limit"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META at limit
        table.put_item(Item={
            "pk": user_id,
            "sk": "USER_META",
            "key_count": 1,
            "requests_this_month": 5000,  # At free tier limit
        })

        # Create first key
        key1 = generate_api_key(user_id, tier="free")
        user1 = validate_api_key(key1)

        # Create second key
        key2 = generate_api_key(user_id, tier="free")
        user2 = validate_api_key(key2)

        # Both keys should be rate-limited immediately
        allowed1, _ = check_and_increment_usage(user1["user_id"], user1["key_hash"], 5000)
        allowed2, _ = check_and_increment_usage(user2["user_id"], user2["key_hash"], 5000)

        assert not allowed1
        assert not allowed2
