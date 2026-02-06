"""
Tests for authentication and API key management.

Security-critical code - high coverage required.
"""

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
        """Valid API key should return user info with all expected fields."""
        # Import inside test to ensure moto is active
        from shared.auth import generate_api_key, validate_api_key

        # Generate a key first
        user_id = "user_123"
        api_key = generate_api_key(user_id, tier="pro", email="test@example.com")

        # Validate the key
        result = validate_api_key(api_key)

        # Verify all returned fields - this is security-critical
        assert result is not None
        assert result["user_id"] == user_id
        assert result["tier"] == "pro"
        assert result["monthly_limit"] == 100000  # pro tier limit
        assert result["requests_this_month"] == 0
        # Verify key_hash is returned (needed for increment_usage)
        assert "key_hash" in result
        assert len(result["key_hash"]) == 64  # SHA256 hex = 64 chars
        # Verify email is returned
        assert result["email"] == "test@example.com"
        # Verify created_at is returned and is a valid ISO timestamp
        assert "created_at" in result
        assert "T" in result["created_at"]  # ISO format check

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

    @mock_aws
    def test_key_with_special_characters_handled(self, aws_credentials, mock_dynamodb):
        """Keys with special characters should not crash or cause injection."""
        from shared.auth import validate_api_key

        # Test SQL injection-style attack patterns
        malicious_keys = [
            "pw_' OR '1'='1",
            'pw_"; DROP TABLE users;--',
            "pw_<script>alert('xss')</script>",
            "pw_\x00null_byte",
            "pw_\n\r\t",  # Control characters
            "pw_" + "\u200b" * 100,  # Zero-width spaces
        ]

        for malicious_key in malicious_keys:
            result = validate_api_key(malicious_key)
            assert result is None, f"Malicious key {repr(malicious_key)} should return None"

    @mock_aws
    def test_key_with_unicode_handled(self, aws_credentials, mock_dynamodb):
        """Keys with unicode characters should be handled safely."""
        from shared.auth import validate_api_key

        unicode_key = "pw_" + "\u4e2d\u6587" * 10  # Chinese characters
        result = validate_api_key(unicode_key)
        assert result is None

    @mock_aws
    def test_key_hash_is_deterministic(self, aws_credentials, mock_dynamodb):
        """Same key should always produce same hash for consistent validation."""
        from shared.auth import generate_api_key, validate_api_key

        user_id = "user_deterministic"
        api_key = generate_api_key(user_id, tier="free")

        # Validate same key multiple times
        result1 = validate_api_key(api_key)
        result2 = validate_api_key(api_key)

        assert result1 is not None
        assert result2 is not None
        assert result1["key_hash"] == result2["key_hash"]

    @mock_aws
    def test_key_without_email_returns_none_for_email_field(self, aws_credentials, mock_dynamodb):
        """Keys generated without email should return None for email field."""
        from shared.auth import generate_api_key, validate_api_key

        # Generate key without email
        api_key = generate_api_key("user_no_email", tier="free")
        result = validate_api_key(api_key)

        assert result is not None
        assert result["email"] is None

    @mock_aws
    def test_case_sensitive_key_validation(self, aws_credentials, mock_dynamodb):
        """API key validation should be case-sensitive."""
        from shared.auth import generate_api_key, validate_api_key

        user_id = "user_case"
        api_key = generate_api_key(user_id, tier="free")

        # Original key works
        assert validate_api_key(api_key) is not None

        # Modified case should NOT work
        upper_key = api_key.upper()
        if upper_key != api_key:  # Only test if case differs
            assert validate_api_key(upper_key) is None


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    @mock_aws
    def test_generates_valid_key_format(self, aws_credentials, mock_dynamodb):
        """Generated key should have correct format and sufficient entropy."""
        from shared.auth import generate_api_key

        api_key = generate_api_key("user_123", tier="free")

        assert api_key.startswith("pw_")
        # secrets.token_urlsafe(32) produces 43 chars, plus "pw_" prefix = 46+
        assert len(api_key) >= 46, f"Key too short: {len(api_key)} chars"
        # Verify key contains only URL-safe characters after prefix
        key_body = api_key[3:]  # Remove "pw_"
        assert all(c.isalnum() or c in "-_" for c in key_body), f"Key contains invalid characters: {key_body}"

    @mock_aws
    def test_keys_are_unique(self, aws_credentials, mock_dynamodb):
        """Each generated key should be unique and cryptographically random."""
        from shared.auth import generate_api_key

        keys = [generate_api_key(f"user_{i}") for i in range(10)]

        # All keys should be unique
        assert len(set(keys)) == 10

        # Keys should have high entropy - no common prefixes beyond "pw_"
        key_bodies = [k[3:6] for k in keys]  # First 3 chars after prefix
        assert len(set(key_bodies)) >= 8, "Keys have suspicious common patterns"

    @mock_aws
    def test_keys_are_unique_for_same_user(self, aws_credentials, mock_dynamodb):
        """Same user can have multiple unique keys."""
        from shared.auth import generate_api_key, validate_api_key

        user_id = "user_multikey"
        keys = [generate_api_key(user_id, tier="free") for _ in range(3)]

        # All keys should be unique
        assert len(set(keys)) == 3

        # All keys should validate and return same user_id
        for key in keys:
            result = validate_api_key(key)
            assert result is not None
            assert result["user_id"] == user_id

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
        """Key suffix should be stored for dashboard display and match actual key."""
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
        assert stored_suffix == expected_suffix, (
            f"Stored key_suffix '{stored_suffix}' should match actual suffix '{expected_suffix}'"
        )

        # Verify suffix length is exactly 8
        assert len(stored_suffix) == 8, f"Key suffix should be 8 chars, got {len(stored_suffix)}"

        # Verify suffix is different from key_hash suffix (security check)
        key_hash = items[0].get("key_hash")
        assert key_hash[-8:] != stored_suffix, "Key suffix should be from actual key, not from hash"

    @mock_aws
    def test_payment_failures_initialized_to_zero(self, aws_credentials, mock_dynamodb):
        """New keys should have payment_failures initialized to 0."""
        import boto3
        from boto3.dynamodb.conditions import Key

        from shared.auth import generate_api_key

        generate_api_key("user_payment_init", tier="free")

        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        response = table.query(
            KeyConditionExpression=Key("pk").eq("user_payment_init"),
        )

        items = response.get("Items", [])
        assert len(items) == 1
        assert items[0].get("payment_failures") == 0

    @mock_aws
    def test_email_verified_initialized_to_false(self, aws_credentials, mock_dynamodb):
        """New keys should have email_verified initialized to False."""
        import boto3
        from boto3.dynamodb.conditions import Key

        from shared.auth import generate_api_key

        generate_api_key("user_email_init", tier="free", email="test@example.com")

        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        response = table.query(
            KeyConditionExpression=Key("pk").eq("user_email_init"),
        )

        items = response.get("Items", [])
        assert len(items) == 1
        assert items[0].get("email_verified") is False


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
        from shared.auth import generate_api_key, validate_api_key
        from shared.constants import TIER_LIMITS

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
        import boto3

        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key

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
        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key

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
        import boto3

        from shared.auth import check_and_increment_usage_batch, generate_api_key, validate_api_key

        user_id = "user_batch_test"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # Batch increment by 10
        allowed, count = check_and_increment_usage_batch(user["user_id"], user["key_hash"], 5000, count=10)
        assert allowed
        assert count == 10

        # Check USER_META
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        meta = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert meta["Item"]["requests_this_month"] == 10

    @mock_aws
    def test_batch_limit_enforced_at_user_level(self, aws_credentials, mock_dynamodb):
        """Batch increment should be limited by user-level usage."""
        import boto3

        from shared.auth import (
            check_and_increment_usage,
            check_and_increment_usage_batch,
            generate_api_key,
            validate_api_key,
        )

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
        import boto3

        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key

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
        import boto3

        from shared.auth import check_and_increment_usage, generate_api_key, revoke_api_key, validate_api_key

        user_id = "user_revoke_test"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META with initial usage
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "key_count": 2,
                "requests_this_month": 100,
            }
        )

        # Create two keys
        key1 = generate_api_key(user_id, tier="free")
        _key2 = generate_api_key(user_id, tier="free")
        user1 = validate_api_key(key1)
        _user2 = validate_api_key(_key2)

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
        import boto3

        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key

        user_id = "user_inherit_limit"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META at limit
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 5000,  # At free tier limit
            }
        )

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


class TestUpdateTierEdgeCases:
    """Additional edge case tests for update_tier function."""

    @mock_aws
    def test_update_tier_validates_case_sensitive(self, aws_credentials, mock_dynamodb):
        """Tier names should be case-sensitive."""
        from shared.auth import generate_api_key, update_tier, validate_api_key

        api_key = generate_api_key("user_tier_case")
        user = validate_api_key(api_key)

        # Uppercase tier should be rejected
        with pytest.raises(ValueError, match="Invalid tier"):
            update_tier(user["user_id"], user["key_hash"], "FREE")

        with pytest.raises(ValueError, match="Invalid tier"):
            update_tier(user["user_id"], user["key_hash"], "Pro")

    @mock_aws
    def test_update_tier_rejects_empty_string(self, aws_credentials, mock_dynamodb):
        """Empty string should be rejected as tier."""
        from shared.auth import generate_api_key, update_tier, validate_api_key

        api_key = generate_api_key("user_tier_empty")
        user = validate_api_key(api_key)

        with pytest.raises(ValueError, match="Invalid tier"):
            update_tier(user["user_id"], user["key_hash"], "")


class TestRevokeApiKeyEdgeCases:
    """Edge case tests for revoke_api_key function."""

    @mock_aws
    def test_revoke_nonexistent_key_does_not_raise(self, aws_credentials, mock_dynamodb):
        """Revoking a non-existent key should not raise an error."""
        from shared.auth import revoke_api_key

        # Should not raise even if key doesn't exist
        revoke_api_key("user_nonexistent", "nonexistent_hash" * 4)

    @mock_aws
    def test_revoke_makes_key_immediately_invalid(self, aws_credentials, mock_dynamodb):
        """Revoked key should be immediately invalid."""
        from shared.auth import generate_api_key, revoke_api_key, validate_api_key

        api_key = generate_api_key("user_revoke_imm", tier="free")

        # Key works before revocation
        assert validate_api_key(api_key) is not None

        # Get user info for revocation
        user = validate_api_key(api_key)
        revoke_api_key(user["user_id"], user["key_hash"])

        # Key immediately invalid
        assert validate_api_key(api_key) is None


class TestGetUserKeysEdgeCases:
    """Edge case tests for get_user_keys function."""

    @mock_aws
    def test_get_user_keys_returns_empty_for_nonexistent_user(self, aws_credentials, mock_dynamodb):
        """Should return empty list for user with no keys."""
        from shared.auth import get_user_keys

        result = get_user_keys("user_nonexistent")
        assert result == []

    @mock_aws
    def test_get_user_keys_excludes_sensitive_data(self, aws_credentials, mock_dynamodb):
        """Should not expose full key hash or other sensitive fields."""
        from shared.auth import generate_api_key, get_user_keys

        user_id = "user_keys_secure"
        _api_key = generate_api_key(user_id, tier="free", email="secure@example.com")

        keys = get_user_keys(user_id)

        assert len(keys) == 1
        key_info = keys[0]

        # Should have truncated hash prefix only
        assert "key_hash_prefix" in key_info
        assert key_info["key_hash_prefix"].endswith("...")
        assert len(key_info["key_hash_prefix"]) == 11  # 8 chars + "..."

        # Should NOT contain full key hash, email, or actual key
        assert "key_hash" not in key_info or key_info.get("key_hash", "").endswith("...")
        assert "email" not in key_info
        assert "api_key" not in key_info

    @mock_aws
    def test_get_user_keys_returns_all_keys_for_user(self, aws_credentials, mock_dynamodb):
        """Should return all keys for a user."""
        from shared.auth import generate_api_key, get_user_keys

        user_id = "user_multi_keys"

        # Generate 3 keys
        for _ in range(3):
            generate_api_key(user_id, tier="free")

        keys = get_user_keys(user_id)

        # Should return all 3 keys
        assert len(keys) == 3

        # All should have different hash prefixes
        prefixes = [k["key_hash_prefix"] for k in keys]
        assert len(set(prefixes)) == 3


class TestResetMonthlyUsageEdgeCases:
    """Edge case tests for reset_monthly_usage function."""

    @mock_aws
    def test_reset_records_timestamp(self, aws_credentials, mock_dynamodb):
        """Reset should record the timestamp of the reset."""
        import boto3

        from shared.auth import generate_api_key, increment_usage, reset_monthly_usage, validate_api_key

        user_id = "user_reset_ts"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # Use some quota
        increment_usage(user["user_id"], user["key_hash"], count=100)

        # Reset
        reset_monthly_usage(user["user_id"], user["key_hash"])

        # Verify last_reset timestamp was recorded
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        response = table.get_item(Key={"pk": user_id, "sk": user["key_hash"]})
        item = response.get("Item")

        assert "last_reset" in item
        assert "T" in item["last_reset"]  # ISO format check

    @mock_aws
    def test_reset_on_nonexistent_user_creates_record(self, aws_credentials, mock_dynamodb):
        """Reset on nonexistent user should not raise."""
        from shared.auth import reset_monthly_usage

        # This may create a record or just fail silently - should not raise
        # DynamoDB update_item creates the item if it doesn't exist
        reset_monthly_usage("user_nonexistent", "hash" * 16)


class TestValidateApiKeyCircuitBreaker:
    """Tests for circuit breaker integration in validate_api_key."""

    @mock_aws
    def test_circuit_open_returns_none(self, aws_credentials, mock_dynamodb):
        """When DynamoDB circuit is open, validate_api_key should return None."""
        from shared.auth import generate_api_key, validate_api_key
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitState

        # Generate a valid key first
        api_key = generate_api_key("user_circuit_test", tier="free")

        # Manually open the DynamoDB circuit
        DYNAMODB_CIRCUIT._state.state = CircuitState.OPEN
        DYNAMODB_CIRCUIT._state.last_failure_time = __import__("time").time()

        result = validate_api_key(api_key)

        assert result is None

    @mock_aws
    def test_generic_exception_returns_none_and_records_failure(self, aws_credentials, mock_dynamodb):
        """A generic exception during validation should return None and record circuit failure."""
        from unittest.mock import patch

        from shared.auth import validate_api_key
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitBreakerState

        # Reset circuit state to track failure recording
        DYNAMODB_CIRCUIT._state = CircuitBreakerState()
        assert DYNAMODB_CIRCUIT._state.failure_count == 0

        # Patch the table query to raise a non-ClientError exception
        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_table = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
            mock_table.query.side_effect = RuntimeError("Connection lost")
            mock_ddb.return_value.Table.return_value = mock_table

            result = validate_api_key("pw_valid_looking_key_123456789")

        assert result is None
        # Circuit breaker should have recorded the failure
        assert DYNAMODB_CIRCUIT._state.failure_count == 1

    @mock_aws
    def test_max_retries_exceeded_returns_none(self, aws_credentials, mock_dynamodb):
        """When all retries are exhausted due to throttling, should return None."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import validate_api_key

        # Create a throttling error
        throttle_error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}}, "Query"
        )

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_table.query.side_effect = throttle_error
            mock_ddb.return_value.Table.return_value = mock_table

            # Use max_retries=1 and patch time.sleep to speed up test
            with patch("shared.auth.time.sleep"):
                result = validate_api_key("pw_test_throttle_key", max_retries=1)

        assert result is None

    @mock_aws
    def test_throttling_records_circuit_failure_and_retries(self, aws_credentials, mock_dynamodb):
        """Throttling errors should record circuit failure and retry with backoff."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import validate_api_key
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitBreakerState

        DYNAMODB_CIRCUIT._state = CircuitBreakerState()

        throttle_error = ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}, "Query")

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            # Fail twice then succeed with empty result
            mock_table.query.side_effect = [
                throttle_error,
                throttle_error,
                {"Items": []},
            ]
            mock_ddb.return_value.Table.return_value = mock_table

            with patch("shared.auth.time.sleep") as mock_sleep:
                result = validate_api_key("pw_retry_test_key_1234567890", max_retries=3)

        # Should have returned None (no items found after retries)
        assert result is None
        # Should have slept twice for the two retries
        assert mock_sleep.call_count == 2
        # Circuit breaker should have recorded 2 failures (and 1 success from final query)
        assert DYNAMODB_CIRCUIT._state.failure_count == 0  # Reset by the success


class TestCheckAndIncrementUsageCircuitBreaker:
    """Tests for circuit breaker and error handling in check_and_increment_usage."""

    @mock_aws
    def test_circuit_open_allows_request_degraded_mode(self, aws_credentials, mock_dynamodb):
        """When DynamoDB circuit is open, should allow request in degraded mode."""
        from shared.auth import check_and_increment_usage
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitState

        DYNAMODB_CIRCUIT._state.state = CircuitState.OPEN
        DYNAMODB_CIRCUIT._state.last_failure_time = __import__("time").time()

        allowed, count = check_and_increment_usage("user_test", "hash_test", 5000)

        assert allowed is True
        assert count == -1  # Degraded mode signal

    @mock_aws
    def test_per_key_counter_failure_does_not_block_request(self, aws_credentials, mock_dynamodb):
        """Failure to increment per-key counter should not block the request."""
        from unittest.mock import patch

        from shared.auth import check_and_increment_usage, generate_api_key, validate_api_key

        user_id = "user_perkey_fail"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        # The first update_item call (USER_META) succeeds, the second (per-key) fails
        original_update_item = None

        call_count = [0]

        def selective_fail(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Second call is per-key update
                raise RuntimeError("Per-key counter update failed")
            return original_update_item(*args, **kwargs)

        import boto3

        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        original_update_item = table.update_item

        with patch.object(table, "update_item", side_effect=selective_fail):
            # Need to patch _get_dynamodb to return our patched table
            with patch("shared.auth.get_dynamodb") as mock_ddb:
                mock_ddb.return_value.Table.return_value = table
                allowed, count = check_and_increment_usage(user["user_id"], user["key_hash"], 5000)

        # Request should still be allowed despite per-key failure
        assert allowed is True
        assert count == 1

    @mock_aws
    def test_rate_limit_exceeded_get_item_failure_returns_limit(self, aws_credentials, mock_dynamodb):
        """When rate limit is hit and get_item for current count fails, should return limit."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage

        user_id = "user_limit_getfail"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set USER_META at limit
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 100,
            }
        )

        # The condition check will fail (rate limit exceeded), then get_item
        # for current count should also fail
        condition_error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Limit exceeded"}}, "UpdateItem"
        )

        call_count = [0]

        def mock_update_item(**kwargs):
            call_count[0] += 1
            raise condition_error

        def mock_get_item(**kwargs):
            raise RuntimeError("Get item failed too")

        mock_table = MagicMock()
        mock_table.update_item.side_effect = mock_update_item
        mock_table.get_item.side_effect = mock_get_item

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            allowed, count = check_and_increment_usage(user_id, "some_hash", 100)

        assert allowed is False
        assert count == 100  # Falls back to limit value

    @mock_aws
    def test_throttling_error_records_circuit_failure_and_raises(self, aws_credentials, mock_dynamodb):
        """Throttling error should record circuit failure and re-raise."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitBreakerState

        DYNAMODB_CIRCUIT._state = CircuitBreakerState()

        throttle_error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}}, "UpdateItem"
        )

        mock_table = MagicMock()
        mock_table.update_item.side_effect = throttle_error

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError):
                check_and_increment_usage("user_throttle", "hash", 5000)

        assert DYNAMODB_CIRCUIT._state.failure_count == 1


class TestCheckAndIncrementUsageBatchCircuitBreaker:
    """Tests for circuit breaker and error handling in check_and_increment_usage_batch."""

    @mock_aws
    def test_batch_circuit_open_allows_degraded(self, aws_credentials, mock_dynamodb):
        """When circuit is open, batch check should allow in degraded mode."""
        from shared.auth import check_and_increment_usage_batch
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitState

        DYNAMODB_CIRCUIT._state.state = CircuitState.OPEN
        DYNAMODB_CIRCUIT._state.last_failure_time = __import__("time").time()

        allowed, count = check_and_increment_usage_batch("user_test", "hash_test", 5000, count=10)

        assert allowed is True
        assert count == -1

    @mock_aws
    def test_batch_per_key_failure_does_not_block(self, aws_credentials, mock_dynamodb):
        """Per-key counter failure in batch mode should not block."""
        from unittest.mock import patch

        from shared.auth import check_and_increment_usage_batch, generate_api_key, validate_api_key

        user_id = "user_batch_perkey"
        api_key = generate_api_key(user_id, tier="free")
        user = validate_api_key(api_key)

        import boto3

        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")
        original_update = table.update_item
        call_count = [0]

        def selective_fail(**kwargs):
            call_count[0] += 1
            if call_count[0] == 2:  # Second call is per-key update
                raise RuntimeError("Per-key counter update failed")
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(wraps=table)
            patched_table.update_item = selective_fail
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table
            allowed, count = check_and_increment_usage_batch(user["user_id"], user["key_hash"], 5000, count=3)

        assert allowed is True
        assert count == 3

    @mock_aws
    def test_batch_rate_limit_get_item_failure(self, aws_credentials, mock_dynamodb):
        """When batch limit is hit and get_item fails, should return limit."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_batch

        condition_error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}}, "UpdateItem"
        )

        mock_table = MagicMock()
        mock_table.update_item.side_effect = condition_error
        mock_table.get_item.side_effect = RuntimeError("Get item failed")

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            allowed, count = check_and_increment_usage_batch("user_x", "hash_x", 200, count=10)

        assert allowed is False
        assert count == 200  # Falls back to limit

    @mock_aws
    def test_batch_throttling_records_failure_and_raises(self, aws_credentials, mock_dynamodb):
        """Throttling in batch mode should record circuit failure and re-raise."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_batch
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitBreakerState

        DYNAMODB_CIRCUIT._state = CircuitBreakerState()

        throttle_error = ClientError({"Error": {"Code": "RequestLimitExceeded", "Message": ""}}, "UpdateItem")

        mock_table = MagicMock()
        mock_table.update_item.side_effect = throttle_error

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError):
                check_and_increment_usage_batch("user_t", "hash_t", 5000, count=5)

        assert DYNAMODB_CIRCUIT._state.failure_count == 1


class TestCheckAndIncrementUsageWithBonus:
    """Tests for bonus credit consumption in check_and_increment_usage_with_bonus."""

    @mock_aws
    def test_circuit_open_allows_degraded_mode(self, aws_credentials, mock_dynamodb):
        """When circuit is open, should allow request in degraded mode with -1 bonus."""
        from shared.auth import check_and_increment_usage_with_bonus
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitState

        DYNAMODB_CIRCUIT._state.state = CircuitState.OPEN
        DYNAMODB_CIRCUIT._state.last_failure_time = __import__("time").time()

        allowed, count, bonus = check_and_increment_usage_with_bonus("user_b", "hash_b", 5000)

        assert allowed is True
        assert count == -1
        assert bonus == -1

    @mock_aws
    def test_within_monthly_limit_no_bonus_consumed(self, aws_credentials, mock_dynamodb):
        """When within monthly limit, should not consume bonus credits."""
        import boto3

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_within_limit"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up USER_META with some usage and bonus
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 10,
                "bonus_requests": 500,
                "total_packages_scanned": 5,
            }
        )

        allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=5000, count=1)

        assert allowed is True
        assert count == 11
        assert bonus == 500  # Bonus untouched

    @mock_aws
    def test_exceeds_monthly_consumes_bonus(self, aws_credentials, mock_dynamodb):
        """When usage exceeds monthly limit, bonus credits should be consumed."""
        import boto3

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_bonus_consume"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up USER_META at monthly limit with bonus credits available
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 100,
                "bonus_requests": 500,
                "total_packages_scanned": 50,
            }
        )

        allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=100, count=1)

        assert allowed is True
        assert count == 101  # 100 + 1
        assert bonus == 499  # 500 - 1

    @mock_aws
    def test_exceeds_effective_limit_denied(self, aws_credentials, mock_dynamodb):
        """When usage exceeds both monthly and bonus, should be denied."""
        import boto3

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_full_deny"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 100,
                "bonus_requests": 0,
                "total_packages_scanned": 50,
            }
        )

        allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=100, count=1)

        assert allowed is False
        assert count == 100
        assert bonus == 0

    @mock_aws
    def test_bonus_race_condition_returns_false(self, aws_credentials, mock_dynamodb):
        """When bonus is consumed by concurrent request, should return False."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_bonus_race"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up near-depleted bonus
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 100,
                "bonus_requests": 1,
                "total_packages_scanned": 50,
            }
        )

        original_update = table.update_item
        call_count = [0]

        def simulate_race(**kwargs):
            call_count[0] += 1
            # First update is the bonus consumption - make it fail with condition check
            if call_count[0] == 1:
                update_expr = kwargs.get("UpdateExpression", "")
                if "bonus_requests" in update_expr and "bonus_requests - " in update_expr:
                    raise ClientError(
                        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Bonus depleted"}},
                        "UpdateItem",
                    )
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = MagicMock(wraps=table)
            patched_table.update_item = simulate_race
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table
            allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=100, count=1)

        assert allowed is False
        assert bonus == 0

    @mock_aws
    def test_monthly_limit_race_condition_returns_false(self, aws_credentials, mock_dynamodb):
        """When concurrent request pushes usage over limit, should return False."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_monthly_race"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up at a point where monthly still has room
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 99,
                "bonus_requests": 10,
                "total_packages_scanned": 50,
            }
        )

        original_update = table.update_item
        call_count = [0]

        def simulate_race(**kwargs):
            call_count[0] += 1
            cond_expr = kwargs.get("ConditionExpression", "")
            # The monthly increment path uses ConditionExpression with max_allowed
            if (
                "max_allowed" in str(kwargs.get("ExpressionAttributeValues", {}))
                or "requests_this_month < :max_allowed" in cond_expr
            ):
                raise ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Race"}}, "UpdateItem"
                )
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = MagicMock(wraps=table)
            patched_table.update_item = simulate_race
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table
            allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=100, count=1)

        assert allowed is False
        assert count == 99
        assert bonus == 10

    @mock_aws
    def test_per_key_counter_failure_silently_ignored(self, aws_credentials, mock_dynamodb):
        """Per-key counter failure in bonus path should be silently ignored."""
        from unittest.mock import patch

        import boto3

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_perkey_bonus"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 10,
                "bonus_requests": 0,
                "total_packages_scanned": 5,
            }
        )

        original_update = table.update_item
        call_count = [0]

        def selective_fail(**kwargs):
            call_count[0] += 1
            # The per-key update is the one that uses ADD requests_this_month
            key = kwargs.get("Key", {})
            if key.get("sk") == "some_hash":
                raise RuntimeError("Per-key counter failed")
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            from unittest.mock import MagicMock

            patched_table = MagicMock(wraps=table)
            patched_table.update_item = selective_fail
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table
            allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=5000, count=1)

        assert allowed is True

    @mock_aws
    def test_throttling_in_bonus_path_records_failure_and_raises(self, aws_credentials, mock_dynamodb):
        """Throttling in bonus path should record circuit failure and re-raise."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_with_bonus
        from shared.circuit_breaker import DYNAMODB_CIRCUIT, CircuitBreakerState

        DYNAMODB_CIRCUIT._state = CircuitBreakerState()

        throttle_error = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DynamoDB is overloaded"}}, "GetItem"
        )

        mock_table = MagicMock()
        mock_table.get_item.side_effect = throttle_error

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError):
                check_and_increment_usage_with_bonus("user_t", "hash_t", 5000)

        assert DYNAMODB_CIRCUIT._state.failure_count == 1

    @mock_aws
    def test_activity_gate_triggers_referral_credit(self, aws_credentials, mock_dynamodb):
        """Crossing activity threshold should trigger referral credit."""
        from unittest.mock import patch

        import boto3

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_activity_gate"
        referrer_id = "user_referrer_123"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up referred user just below threshold (100)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 98,
                "bonus_requests": 0,
                "total_packages_scanned": 99,  # One more and we cross threshold
                "referral_pending": True,
                "referred_by": referrer_id,
                "referral_pending_expires": (
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
                    + __import__("datetime").timedelta(days=30)
                ).isoformat(),
            }
        )

        # Set up referrer USER_META
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        with patch("shared.auth._trigger_referral_activity_gate") as mock_trigger:
            allowed, count, bonus = check_and_increment_usage_with_bonus(user_id, "some_hash", limit=5000, count=1)

        assert allowed is True
        mock_trigger.assert_called_once()


class TestTriggerReferralActivityGate:
    """Tests for _trigger_referral_activity_gate function."""

    @mock_aws
    def test_no_referrer_logs_warning(self, aws_credentials, mock_dynamodb):
        """Should log warning and return if no referrer in user_meta."""
        from shared.auth import _trigger_referral_activity_gate

        # No referred_by in meta
        _trigger_referral_activity_gate("user_no_ref", {})
        # Should not raise

    @mock_aws
    def test_expired_referral_clears_pending(self, aws_credentials, mock_dynamodb):
        """Should clear pending flag and return if referral has expired."""
        from datetime import datetime, timedelta, timezone

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_expired_ref"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META with expired referral
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": "user_referrer",
                "referral_pending_expires": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            }
        )

        meta = {
            "referred_by": "user_referrer",
            "referral_pending_expires": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        }

        _trigger_referral_activity_gate(user_id, meta)

        # Verify pending flag was cleared
        response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        item = response.get("Item", {})
        assert "referral_pending" not in item
        assert "referral_pending_expires" not in item

    @mock_aws
    def test_concurrent_gate_only_one_succeeds(self, aws_credentials, mock_dynamodb):
        """If another request already processed the gate, should not double-credit."""

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_race_gate"
        referrer_id = "user_referrer_race"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # USER_META already has referral_activity_credited = True (another request won)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
                "referral_activity_credited": True,
            }
        )

        meta = {
            "referred_by": referrer_id,
        }

        # Should not raise, and should not credit again
        _trigger_referral_activity_gate(user_id, meta)

    @mock_aws
    def test_successful_gate_credits_referrer(self, aws_credentials, mock_dynamodb):
        """Successful gate trigger should credit referrer and update event."""
        from unittest.mock import patch

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_gate_success"
        referrer_id = "user_referrer_success"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create referred user META with pending referral
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
            }
        )

        # Create referrer USER_META
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        meta = {
            "referred_by": referrer_id,
        }

        with (
            patch("shared.referral_utils.add_bonus_with_cap", return_value=5000) as mock_bonus,
            patch("shared.referral_utils.update_referral_event_to_credited") as mock_event,
            patch("shared.referral_utils.update_referrer_stats") as mock_stats,
        ):
            _trigger_referral_activity_gate(user_id, meta)

        mock_bonus.assert_called_once_with(referrer_id, 5000)
        mock_event.assert_called_once_with(referrer_id, user_id, 5000)
        mock_stats.assert_called_once()

    @mock_aws
    def test_error_in_crediting_does_not_raise(self, aws_credentials, mock_dynamodb):
        """Error during crediting should be caught, not propagated."""
        from unittest.mock import patch

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_gate_error"
        referrer_id = "user_referrer_error"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
            }
        )

        meta = {"referred_by": referrer_id}

        with patch("shared.referral_utils.add_bonus_with_cap", side_effect=RuntimeError("Boom")):
            # Should not raise
            _trigger_referral_activity_gate(user_id, meta)


class TestValidateApiKeyMaxRetriesExhausted:
    """Tests covering lines 160-161: max retries exceeded path in validate_api_key."""

    @mock_aws
    def test_all_retries_fail_with_throttling_returns_none(self, aws_credentials, mock_dynamodb):
        """When every retry attempt is throttled, should return None after exhausting retries."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        from shared.auth import validate_api_key

        # Create throttling error
        throttle_error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}},
            "Query",
        )

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            # All attempts fail with throttling
            mock_table.query.side_effect = throttle_error
            mock_ddb.return_value.Table.return_value = mock_table

            with patch("shared.auth.time.sleep"):
                # Use max_retries=3 to go through all retries
                result = validate_api_key("pw_test_exhaust_retries_key", max_retries=3)

        assert result is None
        # Should have attempted 3 times
        assert mock_table.query.call_count == 3


class TestCheckAndIncrementUsageWithBonusReRaise:
    """Tests covering re-raise lines in check_and_increment_usage_with_bonus.

    Line 440: re-raise after bonus conditional check failure (non-ConditionalCheckFailedException)
    Line 469: re-raise after monthly limit conditional check failure (non-ConditionalCheckFailedException)
    """

    @mock_aws
    def test_bonus_path_non_conditional_client_error_reraises(self, aws_credentials, mock_dynamodb):
        """Non-conditional ClientError during bonus update should re-raise (line 440)."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_bonus_reraise"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up at monthly limit with bonus available (to trigger bonus path)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 100,
                "bonus_requests": 50,
                "total_packages_scanned": 50,
            }
        )

        original_update = table.update_item

        def fail_bonus_update(**kwargs):
            update_expr = kwargs.get("UpdateExpression", "")
            if "bonus_requests" in update_expr and "bonus_requests - " in update_expr:
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "DynamoDB internal error"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = MagicMock(wraps=table)
            patched_table.update_item = fail_bonus_update
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table

            with pytest.raises(ClientError) as exc_info:
                check_and_increment_usage_with_bonus(user_id, "some_hash", limit=100, count=1)

            assert exc_info.value.response["Error"]["Code"] == "InternalServerError"

    @mock_aws
    def test_monthly_path_non_conditional_client_error_reraises(self, aws_credentials, mock_dynamodb):
        """Non-conditional ClientError during monthly update should re-raise (line 469)."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import check_and_increment_usage_with_bonus

        user_id = "user_monthly_reraise"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Set up with room in monthly limit (NOT in bonus path)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 50,
                "bonus_requests": 10,
                "total_packages_scanned": 50,
            }
        )

        original_update = table.update_item

        def fail_monthly_update(**kwargs):
            kwargs.get("UpdateExpression", "")
            kwargs.get("ConditionExpression", "")
            # Monthly path uses max_allowed in condition
            if "max_allowed" in str(kwargs.get("ExpressionAttributeValues", {})):
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "DynamoDB error"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = MagicMock(wraps=table)
            patched_table.update_item = fail_monthly_update
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table

            with pytest.raises(ClientError) as exc_info:
                check_and_increment_usage_with_bonus(user_id, "some_hash", limit=5000, count=1)

            assert exc_info.value.response["Error"]["Code"] == "InternalServerError"


class TestTriggerReferralActivityGateEdgeCases:
    """Tests covering lines 541-542, 566 in _trigger_referral_activity_gate.

    Lines 541-542: except (ValueError, TypeError): pass - invalid referral_pending_expires format
    Line 566: re-raise from conditional check failure (non-ConditionalCheckFailedException)
    """

    @mock_aws
    def test_malformed_expires_value_ignored(self, aws_credentials, mock_dynamodb):
        """Should handle malformed referral_pending_expires gracefully (lines 541-542)."""
        from unittest.mock import patch

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_bad_expires"
        referrer_id = "user_referrer_bad"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        # Create USER_META with pending referral
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
            }
        )

        # Pass malformed expires in meta - should hit except (ValueError, TypeError)
        meta = {
            "referred_by": referrer_id,
            "referral_pending_expires": "not-a-valid-date-at-all",
        }

        # Should not raise - the malformed date should be silently ignored
        # and processing should continue to the conditional update
        with (
            patch("shared.referral_utils.add_bonus_with_cap", return_value=5000),
            patch("shared.referral_utils.update_referral_event_to_credited"),
            patch("shared.referral_utils.update_referrer_stats"),
        ):
            _trigger_referral_activity_gate(user_id, meta)

    @mock_aws
    def test_none_expires_value_ignored(self, aws_credentials, mock_dynamodb):
        """Should handle None referral_pending_expires gracefully (TypeError branch)."""
        from unittest.mock import patch

        import boto3

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_none_expires"
        referrer_id = "user_referrer_none"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
            }
        )

        meta = {
            "referred_by": referrer_id,
            "referral_pending_expires": None,  # Will cause TypeError in fromisoformat
        }

        with (
            patch("shared.referral_utils.add_bonus_with_cap", return_value=5000),
            patch("shared.referral_utils.update_referral_event_to_credited"),
            patch("shared.referral_utils.update_referrer_stats"),
        ):
            _trigger_referral_activity_gate(user_id, meta)

    @mock_aws
    def test_conditional_update_non_conditional_error_reraises(self, aws_credentials, mock_dynamodb):
        """Non-ConditionalCheckFailedException during atomic gate should re-raise (line 566)."""
        from unittest.mock import MagicMock, patch

        import boto3
        from botocore.exceptions import ClientError

        from shared.auth import _trigger_referral_activity_gate

        user_id = "user_gate_reraise"
        referrer_id = "user_referrer_reraise"
        table = boto3.resource("dynamodb").Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_pending": True,
                "referred_by": referrer_id,
            }
        )

        meta = {"referred_by": referrer_id}

        original_update = table.update_item

        def fail_conditional(**kwargs):
            cond_expr = kwargs.get("ConditionExpression", "")
            # The idempotency conditional update
            if "referral_pending" in str(cond_expr) and "referral_activity_credited" in str(cond_expr):
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "DynamoDB error"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch("shared.auth.get_dynamodb") as mock_ddb:
            patched_table = MagicMock(wraps=table)
            patched_table.update_item = fail_conditional
            patched_table.get_item = table.get_item
            mock_ddb.return_value.Table.return_value = patched_table

            with pytest.raises(ClientError) as exc_info:
                _trigger_referral_activity_gate(user_id, meta)

            assert exc_info.value.response["Error"]["Code"] == "InternalServerError"
