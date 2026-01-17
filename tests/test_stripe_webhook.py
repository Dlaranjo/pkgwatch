"""
Tests for Stripe webhook handler.
"""

import hashlib
import json
import os
from datetime import datetime, timezone, timedelta

import pytest
from moto import mock_aws


class TestStripeWebhookHandler:
    """Tests for the Stripe webhook Lambda handler."""

    @mock_aws
    def test_returns_500_without_stripe_secrets(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe secrets are not configured."""
        pytest.importorskip("stripe")  # Skip if stripe not installed

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = ""
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = ""

        import api.stripe_webhook as webhook_module
        # Clear the secrets cache to ensure test isolation
        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        from api.stripe_webhook import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = "{}"

        result = handler(api_gateway_event, {})

        # Should fail due to missing secrets
        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"] == "Stripe not configured"

    @mock_aws
    def test_price_to_tier_mapping_handles_empty_env_vars(self, mock_dynamodb):
        """Should use fallback price IDs when env vars are empty strings."""
        # Set empty string env vars (simulating CDK fallback)
        os.environ["STRIPE_PRICE_STARTER"] = ""
        os.environ["STRIPE_PRICE_PRO"] = ""
        os.environ["STRIPE_PRICE_BUSINESS"] = ""

        # Re-import to get fresh PRICE_TO_TIER
        import importlib
        import api.stripe_webhook as webhook_module
        importlib.reload(webhook_module)

        # Should have fallback prices, not empty strings
        assert "price_starter" in webhook_module.PRICE_TO_TIER
        assert "price_pro" in webhook_module.PRICE_TO_TIER
        assert "price_business" in webhook_module.PRICE_TO_TIER
        assert "" not in webhook_module.PRICE_TO_TIER

        # Clean up
        del os.environ["STRIPE_PRICE_STARTER"]
        del os.environ["STRIPE_PRICE_PRO"]
        del os.environ["STRIPE_PRICE_BUSINESS"]


class TestUpdateUserTier:
    """Tests for the _update_user_tier function."""

    @mock_aws
    def test_skips_pending_records(self, mock_dynamodb):
        """Should skip PENDING records when updating user tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create PENDING record
        table.put_item(
            Item={
                "pk": "user_pending123",
                "sk": "PENDING",
                "email": "pending@example.com",
                "tier": "free",
            }
        )

        # Create verified API key record
        key_hash = hashlib.sha256(b"pw_test123").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pending123",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pending@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_tier

        _update_user_tier("pending@example.com", "pro", "cus_123", "sub_123")

        # Check PENDING record was NOT updated
        pending_response = table.get_item(Key={"pk": "user_pending123", "sk": "PENDING"})
        pending_item = pending_response.get("Item")
        assert pending_item["tier"] == "free"  # Still free
        assert "stripe_customer_id" not in pending_item

        # Check API key record WAS updated
        key_response = table.get_item(Key={"pk": "user_pending123", "sk": key_hash})
        key_item = key_response.get("Item")
        assert key_item["tier"] == "pro"
        assert key_item["stripe_customer_id"] == "cus_123"

    @mock_aws
    def test_updates_all_verified_keys_for_user(self, mock_dynamodb):
        """Should update all verified API keys for the user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create two API keys for same user
        key_hash1 = hashlib.sha256(b"pw_key1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_key2").hexdigest()

        for key_hash in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_multi123",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "multi@example.com",
                    "tier": "free",
                    "email_verified": True,
                }
            )

        from api.stripe_webhook import _update_user_tier

        _update_user_tier("multi@example.com", "business", "cus_456", "sub_456")

        # Both keys should be updated
        for key_hash in [key_hash1, key_hash2]:
            response = table.get_item(Key={"pk": "user_multi123", "sk": key_hash})
            item = response.get("Item")
            assert item["tier"] == "business"
            assert item["stripe_customer_id"] == "cus_456"

    @mock_aws
    def test_logs_warning_when_no_verified_keys(self, mock_dynamodb):
        """Should log warning when only PENDING records exist."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create only PENDING record
        table.put_item(
            Item={
                "pk": "user_onlypending",
                "sk": "PENDING",
                "email": "onlypending@example.com",
                "tier": "free",
            }
        )

        from api.stripe_webhook import _update_user_tier

        # Should not raise, just log warning
        _update_user_tier("onlypending@example.com", "pro", "cus_789", "sub_789")


class TestHandleCheckoutCompleted:
    """Tests for _handle_checkout_completed function."""

    @mock_aws
    def test_handles_one_time_payment(self, mock_dynamodb):
        """Should handle one-time payments (no subscription_id)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_onetime").hexdigest()
        table.put_item(
            Item={
                "pk": "user_onetime",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "onetime@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_checkout_completed

        session = {
            "customer_email": "onetime@example.com",
            "customer": "cus_onetime",
            "subscription": None,  # No subscription for one-time payment
        }

        _handle_checkout_completed(session)

        # Should be updated to starter tier
        response = table.get_item(Key={"pk": "user_onetime", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"
        assert item["stripe_customer_id"] == "cus_onetime"


class TestHandlePaymentFailed:
    """Tests for _handle_payment_failed function."""

    @mock_aws
    def test_downgrades_after_grace_period_and_three_failures(self, mock_dynamodb):
        """Should downgrade to free after 3 failed payments AND grace period expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_failing").hexdigest()
        # Set first_payment_failure_at to 10 days ago (past the 7-day grace period)
        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        table.put_item(
            Item={
                "pk": "user_failing",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "failing@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_failing",
                "email_verified": True,
                "first_payment_failure_at": ten_days_ago,  # Grace period already started
                "payment_failures": 2,  # Previous failures
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_failing",
            "customer_email": "failing@example.com",
            "attempt_count": 3,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_failing", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        assert item["payment_failures"] == 3
        # Grace period state should be cleared on downgrade
        assert "first_payment_failure_at" not in item

    @mock_aws
    def test_no_downgrade_within_grace_period(self, mock_dynamodb):
        """Should NOT downgrade if still within 7-day grace period, even with 3 failures."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_grace").hexdigest()
        # Set first_payment_failure_at to 3 days ago (within grace period)
        three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        table.put_item(
            Item={
                "pk": "user_grace",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "grace@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_grace",
                "email_verified": True,
                "first_payment_failure_at": three_days_ago,
                "payment_failures": 2,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_grace",
            "customer_email": "grace@example.com",
            "attempt_count": 3,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_grace", "sk": key_hash})
        item = response.get("Item")
        # Should still be pro tier - within grace period
        assert item["tier"] == "pro"
        assert item["payment_failures"] == 3
        # Grace period state should be preserved
        assert item["first_payment_failure_at"] == three_days_ago

    @mock_aws
    def test_first_failure_starts_grace_period(self, mock_dynamodb):
        """First payment failure should start the grace period."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_first").hexdigest()
        table.put_item(
            Item={
                "pk": "user_first",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "first@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_first",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_first",
            "customer_email": "first@example.com",
            "attempt_count": 1,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_first", "sk": key_hash})
        item = response.get("Item")
        # Should still be pro tier - first failure
        assert item["tier"] == "pro"
        assert item["payment_failures"] == 1
        # Grace period should be started
        assert "first_payment_failure_at" in item

    @mock_aws
    def test_tracks_failure_count_under_three(self, mock_dynamodb):
        """Should track failure count but not downgrade under 3 attempts."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_tracking").hexdigest()
        table.put_item(
            Item={
                "pk": "user_tracking",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "tracking@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_tracking",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_tracking",
            "customer_email": "tracking@example.com",
            "attempt_count": 2,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_tracking", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"  # Not downgraded
        assert item["payment_failures"] == 2


class TestHandleSubscriptionDeleted:
    """Tests for _handle_subscription_deleted function."""

    @mock_aws
    def test_downgrades_to_free(self, mock_dynamodb):
        """Should downgrade user to free tier when subscription is deleted."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancelled").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancelled",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancelled@example.com",
                "tier": "business",
                "stripe_customer_id": "cus_cancelled",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_deleted

        subscription = {
            "customer": "cus_cancelled",
        }

        _handle_subscription_deleted(subscription)

        response = table.get_item(Key={"pk": "user_cancelled", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"

    @mock_aws
    def test_clears_cancellation_state_on_delete(self, mock_dynamodb):
        """Should clear cancellation_pending and cancellation_date when subscription is deleted."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancelled_pending").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancelled_pending",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancelled_pending@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cancelled_pending",
                "email_verified": True,
                "cancellation_pending": True,
                "cancellation_date": 1707955200,
            }
        )

        from api.stripe_webhook import _handle_subscription_deleted

        subscription = {
            "customer": "cus_cancelled_pending",
        }

        _handle_subscription_deleted(subscription)

        response = table.get_item(Key={"pk": "user_cancelled_pending", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        assert item["cancellation_pending"] == False
        assert item.get("cancellation_date") is None


class TestHandleSubscriptionUpdatedCancellation:
    """Tests for cancellation pending state tracking in _handle_subscription_updated."""

    @mock_aws
    def test_sets_cancellation_pending_when_cancel_at_period_end(self, mock_dynamodb):
        """Should set cancellation_pending=True when cancel_at_period_end is True."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_PRICE_PRO"] = "price_pro_123"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancelling").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancelling",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancelling@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cancelling",
                "email_verified": True,
            }
        )

        # Re-import to pick up STRIPE_PRICE_PRO env var
        import importlib
        import api.stripe_webhook as webhook_module
        importlib.reload(webhook_module)

        subscription = {
            "customer": "cus_cancelling",
            "status": "active",
            "cancel_at_period_end": True,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro_123"},
                        "current_period_end": 1707955200,  # Unix timestamp - on item, not subscription
                    }
                ]
            }
        }

        webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_cancelling", "sk": key_hash})
        item = response.get("Item")
        assert item["cancellation_pending"] == True
        assert item["cancellation_date"] == 1707955200

        # Clean up
        del os.environ["STRIPE_PRICE_PRO"]

    @mock_aws
    def test_clears_cancellation_pending_when_resubscribed(self, mock_dynamodb):
        """Should clear cancellation_pending when user resubscribes."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_PRICE_PRO"] = "price_pro_123"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_resubscribing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_resubscribing",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "resubscribing@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_resubscribing",
                "email_verified": True,
                "cancellation_pending": True,
                "cancellation_date": 1707955200,
            }
        )

        import importlib
        import api.stripe_webhook as webhook_module
        importlib.reload(webhook_module)

        subscription = {
            "customer": "cus_resubscribing",
            "status": "active",
            "cancel_at_period_end": False,  # User resubscribed
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro_123"},
                        "current_period_end": 1709164800,  # Unix timestamp - on item
                    }
                ]
            }
        }

        webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_resubscribing", "sk": key_hash})
        item = response.get("Item")
        assert item["cancellation_pending"] == False
        assert item.get("cancellation_date") is None

        # Clean up
        del os.environ["STRIPE_PRICE_PRO"]

    @mock_aws
    def test_ignores_non_active_status(self, mock_dynamodb):
        """Should ignore subscription updates that are not active status."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_inactive").hexdigest()
        table.put_item(
            Item={
                "pk": "user_inactive",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "inactive@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_inactive",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_updated

        subscription = {
            "customer": "cus_inactive",
            "status": "past_due",  # Not active
            "cancel_at_period_end": True,
            "current_period_end": 1707955200,
        }

        _handle_subscription_updated(subscription)

        # Should not have been updated
        response = table.get_item(Key={"pk": "user_inactive", "sk": key_hash})
        item = response.get("Item")
        assert "cancellation_pending" not in item


class TestUpdateUserSubscriptionState:
    """Tests for _update_user_subscription_state function."""

    @mock_aws
    def test_updates_tier_and_cancellation_state(self, mock_dynamodb):
        """Should update both tier and cancellation state together."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_combined").hexdigest()
        table.put_item(
            Item={
                "pk": "user_combined",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "combined@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_combined",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_combined",
            tier="pro",
            cancellation_pending=True,
            cancellation_date=1707955200,
        )

        response = table.get_item(Key={"pk": "user_combined", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["cancellation_pending"] == True
        assert item["cancellation_date"] == 1707955200

    @mock_aws
    def test_updates_only_cancellation_state(self, mock_dynamodb):
        """Should update cancellation state without changing tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancelonly").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancelonly",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancelonly@example.com",
                "tier": "business",
                "stripe_customer_id": "cus_cancelonly",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_cancelonly",
            tier=None,  # Don't change tier
            cancellation_pending=True,
            cancellation_date=1707955200,
        )

        response = table.get_item(Key={"pk": "user_cancelonly", "sk": key_hash})
        item = response.get("Item")
        # Tier should be unchanged
        assert item["tier"] == "business"
        # Cancellation state should be updated
        assert item["cancellation_pending"] == True
        assert item["cancellation_date"] == 1707955200


class TestSubscriptionCreated:
    """Tests for customer.subscription.created webhook handler."""

    @mock_aws
    def test_subscription_created_sets_tier(self, mock_dynamodb):
        """customer.subscription.created should set user tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_PRICE_STARTER"] = "price_starter"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_subcreated").hexdigest()
        table.put_item(
            Item={
                "pk": "user_subcreated",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "subcreated@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_subcreated",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_created

        subscription = {
            "customer": "cus_subcreated",
            "status": "active",
            "items": {"data": [{"price": {"id": "price_starter"}}]},
            "current_period_start": 1704067200,
            "current_period_end": 1706745600,
        }
        _handle_subscription_created(subscription)

        response = table.get_item(Key={"pk": "user_subcreated", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"

    @mock_aws
    def test_subscription_created_ignores_incomplete(self, mock_dynamodb):
        """Should skip subscriptions with incomplete status."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_subscription_created

        subscription = {
            "customer": "cus_incomplete",
            "status": "incomplete",
            "items": {"data": []},
        }
        # Should not raise and should not update anything
        _handle_subscription_created(subscription)

    @mock_aws
    def test_subscription_created_ignores_past_due(self, mock_dynamodb):
        """Should skip subscriptions with past_due status."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_subscription_created

        subscription = {
            "customer": "cus_pastdue",
            "status": "past_due",
            "items": {"data": [{"price": {"id": "price_starter"}}]},
        }
        # Should not raise and should not update anything
        _handle_subscription_created(subscription)

    @mock_aws
    def test_subscription_created_handles_missing_customer(self, mock_dynamodb):
        """Should handle missing customer ID gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_subscription_created

        subscription = {
            "status": "active",
            "items": {"data": [{"price": {"id": "price_starter"}}]},
        }
        # Should not raise
        _handle_subscription_created(subscription)

    @mock_aws
    def test_subscription_created_handles_empty_items(self, mock_dynamodb):
        """Should handle empty subscription items gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_subscription_created

        subscription = {
            "customer": "cus_noitems",
            "status": "active",
            "items": {"data": []},
        }
        # Should not raise
        _handle_subscription_created(subscription)

    @mock_aws
    def test_subscription_created_handles_trialing(self, mock_dynamodb):
        """Should handle trialing subscriptions."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_trial").hexdigest()
        table.put_item(
            Item={
                "pk": "user_trial",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "trial@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_trial",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_created, PRICE_TO_TIER
        from unittest.mock import patch

        # Patch PRICE_TO_TIER since it reads env vars at module load time
        with patch.dict(PRICE_TO_TIER, {"price_pro_trial": "pro"}):
            subscription = {
                "customer": "cus_trial",
                "status": "trialing",
                "items": {"data": [{"price": {"id": "price_pro_trial"}}]},
                "current_period_start": 1704067200,
                "current_period_end": 1706745600,
            }
            _handle_subscription_created(subscription)

        response = table.get_item(Key={"pk": "user_trial", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"


class TestUpdateUserTierByCustomerId:
    """Tests for _update_user_tier_by_customer_id function."""

    @mock_aws
    def test_updates_tier_by_customer_id(self, mock_dynamodb):
        """Should update tier for user found by Stripe customer ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_customer_tier").hexdigest()
        table.put_item(
            Item={
                "pk": "user_custid",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "custid@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_test123",
                "email_verified": True,
                "requests_this_month": 100,
            }
        )

        from api.stripe_webhook import _update_user_tier_by_customer_id

        _update_user_tier_by_customer_id(
            customer_id="cus_test123",
            tier="pro",
            current_period_start=1704067200,
            current_period_end=1706745600,
        )

        response = table.get_item(Key={"pk": "user_custid", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["current_period_start"] == 1704067200
        assert item["current_period_end"] == 1706745600
        assert item["payment_failures"] == 0

    @mock_aws
    def test_returns_early_with_no_customer_id(self, mock_dynamodb):
        """Should return early when customer_id is empty/None."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_tier_by_customer_id

        # Should not raise - just returns early
        _update_user_tier_by_customer_id(customer_id=None, tier="pro")
        _update_user_tier_by_customer_id(customer_id="", tier="pro")

    @mock_aws
    def test_handles_no_user_found(self, mock_dynamodb):
        """Should handle case when no user found for customer ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_tier_by_customer_id

        # Should not raise - logs warning and returns
        _update_user_tier_by_customer_id(
            customer_id="cus_nonexistent",
            tier="pro",
        )

    @mock_aws
    def test_resets_usage_on_upgrade(self, mock_dynamodb):
        """Should reset usage counter when upgrading tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_upgrade_reset").hexdigest()
        table.put_item(
            Item={
                "pk": "user_upgrade",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "upgrade@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_upgrade",
                "email_verified": True,
                "requests_this_month": 5000,  # At limit for starter
            }
        )

        from api.stripe_webhook import _update_user_tier_by_customer_id

        _update_user_tier_by_customer_id(
            customer_id="cus_upgrade",
            tier="pro",  # Upgrade from starter to pro
        )

        response = table.get_item(Key={"pk": "user_upgrade", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["requests_this_month"] == 0  # Reset on upgrade

    @mock_aws
    def test_warns_on_downgrade_over_limit(self, mock_dynamodb):
        """Should log warning when downgrading user over new limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_downgrade_over").hexdigest()
        table.put_item(
            Item={
                "pk": "user_downgrade",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "downgrade@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_downgrade",
                "email_verified": True,
                "requests_this_month": 15000,  # Over starter limit of 5000
            }
        )

        from api.stripe_webhook import _update_user_tier_by_customer_id

        _update_user_tier_by_customer_id(
            customer_id="cus_downgrade",
            tier="starter",  # Downgrade from pro to starter
        )

        response = table.get_item(Key={"pk": "user_downgrade", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"
        # Usage NOT reset on downgrade
        assert item["requests_this_month"] == 15000


class TestUpdateUserSubscriptionState:
    """Tests for _update_user_subscription_state function."""

    @mock_aws
    def test_updates_cancellation_pending(self, mock_dynamodb):
        """Should set cancellation_pending flag and date."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancel_pending").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancel",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancel@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cancel",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        cancellation_time = 1706745600  # End of billing period

        _update_user_subscription_state(
            customer_id="cus_cancel",
            cancellation_pending=True,
            cancellation_date=cancellation_time,
        )

        response = table.get_item(Key={"pk": "user_cancel", "sk": key_hash})
        item = response.get("Item")
        assert item["cancellation_pending"] is True
        assert item["cancellation_date"] == cancellation_time

    @mock_aws
    def test_clears_cancellation_on_reactivation(self, mock_dynamodb):
        """Should clear cancellation_date when cancellation_pending is False."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_reactivate").hexdigest()
        table.put_item(
            Item={
                "pk": "user_reactivate",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "reactivate@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_reactivate",
                "email_verified": True,
                "cancellation_pending": True,
                "cancellation_date": 1706745600,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_reactivate",
            cancellation_pending=False,  # User reactivated
        )

        response = table.get_item(Key={"pk": "user_reactivate", "sk": key_hash})
        item = response.get("Item")
        assert item["cancellation_pending"] is False
        assert item.get("cancellation_date") is None

    @mock_aws
    def test_returns_early_with_no_customer_id(self, mock_dynamodb):
        """Should return early when customer_id is empty/None."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_subscription_state

        # Should not raise
        _update_user_subscription_state(customer_id=None, cancellation_pending=True)
        _update_user_subscription_state(customer_id="", cancellation_pending=True)

    @mock_aws
    def test_handles_no_user_found(self, mock_dynamodb):
        """Should handle case when no user found for customer ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_subscription_state

        # Should not raise
        _update_user_subscription_state(
            customer_id="cus_nonexistent",
            cancellation_pending=True,
        )

    @mock_aws
    def test_updates_tier_and_cancellation_together(self, mock_dynamodb):
        """Should update both tier and cancellation state in one call."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_both").hexdigest()
        table.put_item(
            Item={
                "pk": "user_both",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "both@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_both",
                "email_verified": True,
                "requests_this_month": 100,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_both",
            tier="pro",
            cancellation_pending=False,
            current_period_start=1704067200,
            current_period_end=1706745600,
        )

        response = table.get_item(Key={"pk": "user_both", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["cancellation_pending"] is False
        assert item["current_period_start"] == 1704067200
        assert item["current_period_end"] == 1706745600
        assert item["requests_this_month"] == 0  # Reset on upgrade

    @mock_aws
    def test_upgrade_resets_usage_via_subscription_state(self, mock_dynamodb):
        """Should reset usage when upgrading via _update_user_subscription_state."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_upgrade_state").hexdigest()
        table.put_item(
            Item={
                "pk": "user_upgrade_state",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "upgradestate@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_upgrade_state",
                "email_verified": True,
                "requests_this_month": 4500,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_upgrade_state",
            tier="business",  # Upgrade from starter to business
            cancellation_pending=False,
        )

        response = table.get_item(Key={"pk": "user_upgrade_state", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "business"
        assert item["requests_this_month"] == 0  # Reset on upgrade
