"""
Tests for auth.py bonus credit functions.

Tests cover:
- check_and_increment_usage_with_bonus
- Activity gate triggering
- Bonus consumption from monthly overflow
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest

# Set environment variables before importing modules
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"


class TestCheckAndIncrementUsageWithBonus:
    """Tests for check_and_increment_usage_with_bonus function."""

    @pytest.fixture
    def user_with_bonus(self, mock_dynamodb):
        """Create a user with bonus credits."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_bonus_usage"
        key_hash = hashlib.sha256(b"test_key").hexdigest()

        # Create API key record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )

        # Create USER_META with bonus
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 0,
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 10000,
                "total_packages_scanned": 0,
            }
        )

        return table, user_id, key_hash

    @pytest.fixture
    def user_at_monthly_limit(self, mock_dynamodb):
        """Create a user at their monthly limit with bonus available."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_at_limit"
        key_hash = hashlib.sha256(b"test_key_limit").hexdigest()

        # Create API key record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )

        # Create USER_META at monthly limit
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 5000,  # At free tier limit
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 10000,
                "total_packages_scanned": 50,
            }
        )

        return table, user_id, key_hash

    @pytest.fixture
    def user_with_pending_referral(self, mock_dynamodb):
        """Create a user with pending referral near activity threshold."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        user_id = "user_pending_referral"
        referrer_id = "user_referrer_pending"
        key_hash = hashlib.sha256(b"test_key_pending").hexdigest()

        # Create referrer
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
                "referral_total": 1,
                "referral_pending_count": 1,
            }
        )

        # Create API key record for referred user
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )

        # Create USER_META with pending referral at 99 packages
        expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 99,
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 10000,
                "total_packages_scanned": 99,
                "referral_pending": True,
                "referral_pending_expires": expires,
                "referred_by": referrer_id,
            }
        )

        # Create pending referral event
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{user_id}#pending",
                "referrer_id": referrer_id,
                "referred_id": user_id,
                "event_type": "pending",
            }
        )

        return table, events_table, user_id, key_hash, referrer_id

    def test_allows_request_within_monthly_limit(self, user_with_bonus):
        """Should allow request within monthly limit."""
        # Reset auth module cache
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table, user_id, key_hash = user_with_bonus

        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=1)

        assert allowed is True
        assert usage == 1
        assert bonus == 10000  # Unchanged

    def test_allows_request_using_bonus_at_limit(self, user_at_monthly_limit):
        """Should allow request using bonus when at monthly limit."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table, user_id, key_hash = user_at_monthly_limit

        # Request 1 more should use bonus
        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=1)

        assert allowed is True
        assert usage == 5001  # Over monthly limit
        assert bonus == 9999  # Bonus consumed

    def test_rejects_request_when_no_credits(self, mock_dynamodb):
        """Should reject request when no monthly or bonus credits available."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_no_credits"
        key_hash = hashlib.sha256(b"test_key_no").hexdigest()

        # Create user at limit with no bonus
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 5000,
                "bonus_requests": 0,
                "total_packages_scanned": 100,
            }
        )

        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=1)

        assert allowed is False
        assert usage == 5000
        assert bonus == 0

    def test_triggers_activity_gate_at_threshold(self, user_with_pending_referral):
        """Should trigger activity gate when crossing 100 packages threshold."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        import shared.referral_utils as referral_module

        referral_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table, events_table, user_id, key_hash, referrer_id = user_with_pending_referral

        # This request should push total to 100 and trigger activity gate
        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=1)

        assert allowed is True

        # Verify referrer was credited
        response = table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        referrer_meta = response["Item"]
        assert referrer_meta.get("bonus_requests", 0) == 5000  # Signup reward
        assert referrer_meta.get("referral_pending_count", 0) == 0  # Decremented

        # Verify referred user's pending flag was cleared
        response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        referred_meta = response["Item"]
        assert referred_meta.get("referral_pending") is not True
        assert referred_meta.get("referral_activity_credited") is True

    def test_batch_request_uses_bonus_correctly(self, user_at_monthly_limit):
        """Should handle batch requests crossing into bonus correctly."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table, user_id, key_hash = user_at_monthly_limit

        # Request 100 packages (all from bonus since at limit)
        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=100)

        assert allowed is True
        assert usage == 5100
        assert bonus == 9900  # 100 consumed from bonus

    def test_rejects_batch_exceeding_available(self, mock_dynamodb):
        """Should reject batch request exceeding available credits."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_small_bonus"
        key_hash = hashlib.sha256(b"test_key_small").hexdigest()

        # Create user at limit with small bonus
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "requests_this_month": 5000,
                "bonus_requests": 50,  # Only 50 bonus
                "total_packages_scanned": 100,
            }
        )

        # Request 100 should be rejected (only 50 available)
        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=100)

        assert allowed is False

    def test_handles_missing_user_meta(self, mock_dynamodb):
        """Should handle case where USER_META doesn't exist."""
        import shared.auth as auth_module

        auth_module._dynamodb = None

        from shared.auth import check_and_increment_usage_with_bonus

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_no_meta"
        key_hash = hashlib.sha256(b"test_key_no_meta").hexdigest()

        # Only create API key record, not USER_META
        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
            }
        )

        # Should still work with defaults (0 usage, 0 bonus)
        allowed, usage, bonus = check_and_increment_usage_with_bonus(user_id, key_hash, limit=5000, count=1)

        assert allowed is True
        assert usage == 1
        assert bonus == 0  # No bonus
