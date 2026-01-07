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

        result = validate_api_key("dh_invalid_key_that_doesnt_exist")

        assert result is None

    @mock_aws
    def test_missing_key_returns_none(self, aws_credentials, mock_dynamodb):
        """Missing/empty API key should return None."""
        from shared.auth import validate_api_key

        assert validate_api_key(None) is None
        assert validate_api_key("") is None

    @mock_aws
    def test_wrong_prefix_returns_none(self, aws_credentials, mock_dynamodb):
        """Key without 'dh_' prefix should return None."""
        from shared.auth import validate_api_key

        assert validate_api_key("wrong_prefix_key") is None
        assert validate_api_key("sk_live_123") is None

    @mock_aws
    def test_very_long_key_handled(self, aws_credentials, mock_dynamodb):
        """Very long key should not crash."""
        from shared.auth import validate_api_key

        long_key = "dh_" + "x" * 10000
        result = validate_api_key(long_key)

        assert result is None  # Should not crash, just return None


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    @mock_aws
    def test_generates_valid_key_format(self, aws_credentials, mock_dynamodb):
        """Generated key should have correct format."""
        from shared.auth import generate_api_key

        api_key = generate_api_key("user_123", tier="free")

        assert api_key.startswith("dh_")
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
        from shared.auth import TIER_LIMITS, generate_api_key, validate_api_key

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
