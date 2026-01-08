"""
Tests for Stripe webhook handler.
"""

import hashlib
import json
import os

import pytest
from moto import mock_aws


class TestStripeWebhookHandler:
    """Tests for the Stripe webhook Lambda handler."""

    @mock_aws
    def test_returns_500_without_stripe_secrets(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe secrets are not configured."""
        pytest.importorskip("stripe")  # Skip if stripe not installed

        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = ""
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = ""

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
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

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
        key_hash = hashlib.sha256(b"dh_test123").hexdigest()
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
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        # Create two API keys for same user
        key_hash1 = hashlib.sha256(b"dh_key1").hexdigest()
        key_hash2 = hashlib.sha256(b"dh_key2").hexdigest()

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
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

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
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        key_hash = hashlib.sha256(b"dh_onetime").hexdigest()
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
    def test_downgrades_after_three_failures(self, mock_dynamodb):
        """Should downgrade to free after 3 failed payments."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        key_hash = hashlib.sha256(b"dh_failing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_failing",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "failing@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_failing",
                "email_verified": True,
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

    @mock_aws
    def test_tracks_failure_count_under_three(self, mock_dynamodb):
        """Should track failure count but not downgrade under 3 attempts."""
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        key_hash = hashlib.sha256(b"dh_tracking").hexdigest()
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
        os.environ["API_KEYS_TABLE"] = "dephealth-api-keys"

        table = mock_dynamodb.Table("dephealth-api-keys")

        key_hash = hashlib.sha256(b"dh_cancelled").hexdigest()
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
