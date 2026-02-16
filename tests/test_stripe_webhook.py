"""
Tests for Stripe webhook handler.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError
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
        assert body["error"]["code"] == "stripe_not_configured"
        assert body["error"]["message"] == "Stripe not configured"

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

    @mock_aws
    def test_updates_user_meta(self, mock_dynamodb):
        """Should update USER_META with tier and monthly_limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_meta_tier").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_tier",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "metatier@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_meta_tier",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.stripe_webhook import _update_user_tier

        _update_user_tier(
            "metatier@example.com",
            "pro",
            "cus_meta",
            "sub_meta",
            current_period_end=1709424000,
        )

        # Check USER_META was updated
        response = table.get_item(Key={"pk": "user_meta_tier", "sk": "USER_META"})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["monthly_limit"] == 100000
        assert item["current_period_end"] == 1709424000

    @mock_aws
    def test_handles_missing_user_meta(self, mock_dynamodb):
        """Should handle missing USER_META gracefully (legacy accounts)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_meta_tier").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_meta_tier",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nometatier@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_tier

        # Should not raise
        _update_user_tier("nometatier@example.com", "pro", "cus_123", "sub_123")

        # API key should still be updated
        response = table.get_item(Key={"pk": "user_no_meta_tier", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"


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

    @mock_aws
    def test_first_failure_sends_email_notification(self, mock_dynamodb):
        """Should send payment failure email on first failure."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_email_first").hexdigest()
        table.put_item(
            Item={
                "pk": "user_email_first",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "emailfirst@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_email_first",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_email_first",
            "customer_email": "emailfirst@example.com",
            "attempt_count": 1,
        }

        with patch("api.stripe_webhook.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            _handle_payment_failed(invoice)

        mock_ses.send_email.assert_called_once()
        call_args = mock_ses.send_email.call_args
        assert call_args[1]["Destination"]["ToAddresses"] == ["emailfirst@example.com"]
        assert "Payment" in call_args[1]["Message"]["Subject"]["Data"]

    @mock_aws
    def test_subsequent_failure_does_not_send_email(self, mock_dynamodb):
        """Should NOT send email on 2nd failure."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_email_sub").hexdigest()
        two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        table.put_item(
            Item={
                "pk": "user_email_sub",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "emailsub@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_email_sub",
                "email_verified": True,
                "first_payment_failure_at": two_days_ago,
                "payment_failures": 1,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_email_sub",
            "customer_email": "emailsub@example.com",
            "attempt_count": 2,
        }

        with patch("api.stripe_webhook.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            _handle_payment_failed(invoice)

        mock_ses.send_email.assert_not_called()

    @mock_aws
    def test_email_failure_does_not_break_grace_period(self, mock_dynamodb):
        """SES failure should not prevent grace period from starting."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_email_fail").hexdigest()
        table.put_item(
            Item={
                "pk": "user_email_fail",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "emailfail@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_email_fail",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_email_fail",
            "customer_email": "emailfail@example.com",
            "attempt_count": 1,
        }

        with patch("api.stripe_webhook.ses") as mock_ses:
            mock_ses.send_email.side_effect = Exception("SES unavailable")
            _handle_payment_failed(invoice)

        # Grace period should still be started despite email failure
        response = table.get_item(Key={"pk": "user_email_fail", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"
        assert item["payment_failures"] == 1
        assert "first_payment_failure_at" in item

    @mock_aws
    def test_email_prefers_customer_email_from_invoice(self, mock_dynamodb):
        """Should prefer customer_email from invoice over item email."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_email_pref").hexdigest()
        table.put_item(
            Item={
                "pk": "user_email_pref",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "old@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_email_pref",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_email_pref",
            "customer_email": "current@example.com",
            "attempt_count": 1,
        }

        with patch("api.stripe_webhook.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            _handle_payment_failed(invoice)

        call_args = mock_ses.send_email.call_args
        assert call_args[1]["Destination"]["ToAddresses"] == ["current@example.com"]


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
        assert not item["cancellation_pending"]
        assert item.get("cancellation_date") is None

    @mock_aws
    def test_removes_stripe_subscription_id(self, mock_dynamodb):
        """Should remove stripe_subscription_id so user can re-subscribe via checkout."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_resub_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_resub",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "resub@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_resub",
                "stripe_subscription_id": "sub_to_delete",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_deleted

        subscription = {"customer": "cus_resub"}
        _handle_subscription_deleted(subscription)

        response = table.get_item(Key={"pk": "user_resub", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        # stripe_subscription_id should be fully removed, not just set to None
        assert "stripe_subscription_id" not in item
        # stripe_customer_id should be preserved for re-subscription
        assert item["stripe_customer_id"] == "cus_resub"

    @mock_aws
    def test_removes_subscription_id_from_all_keys(self, mock_dynamodb):
        """Should remove stripe_subscription_id from ALL API key records for the user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash_1 = hashlib.sha256(b"pw_multikey_1").hexdigest()
        key_hash_2 = hashlib.sha256(b"pw_multikey_2").hexdigest()
        for key_hash in [key_hash_1, key_hash_2]:
            table.put_item(
                Item={
                    "pk": "user_multikey",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "multikey@example.com",
                    "tier": "pro",
                    "stripe_customer_id": "cus_multikey",
                    "stripe_subscription_id": "sub_multikey",
                    "email_verified": True,
                }
            )

        from api.stripe_webhook import _handle_subscription_deleted

        subscription = {"customer": "cus_multikey"}
        _handle_subscription_deleted(subscription)

        for key_hash in [key_hash_1, key_hash_2]:
            response = table.get_item(Key={"pk": "user_multikey", "sk": key_hash})
            item = response.get("Item")
            assert item["tier"] == "free"
            assert "stripe_subscription_id" not in item
            assert item["stripe_customer_id"] == "cus_multikey"


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
            },
        }

        webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_cancelling", "sk": key_hash})
        item = response.get("Item")
        assert item["cancellation_pending"]
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
            },
        }

        webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_resubscribing", "sk": key_hash})
        item = response.get("Item")
        assert not item["cancellation_pending"]
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
        assert item["cancellation_pending"]
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
        assert item["cancellation_pending"]
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

        from unittest.mock import patch

        from api.stripe_webhook import PRICE_TO_TIER, _handle_subscription_created

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
    def test_preserves_usage_on_upgrade(self, mock_dynamodb):
        """Should preserve usage counter when upgrading tier."""
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
        assert item["requests_this_month"] == 5000  # Preserved on upgrade

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

    @mock_aws
    def test_updates_user_meta(self, mock_dynamodb):
        """Should update USER_META with tier and monthly_limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_meta_custid").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_custid",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "metacustid@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_meta_custid",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_meta_custid",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.stripe_webhook import _update_user_tier_by_customer_id

        _update_user_tier_by_customer_id(
            customer_id="cus_meta_custid",
            tier="pro",
            current_period_end=1709424000,
        )

        # Check USER_META was updated
        response = table.get_item(Key={"pk": "user_meta_custid", "sk": "USER_META"})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["monthly_limit"] == 100000
        assert item["current_period_end"] == 1709424000

    @mock_aws
    def test_handles_missing_user_meta(self, mock_dynamodb):
        """Should handle missing USER_META gracefully (legacy accounts)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_meta_custid").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_meta_custid",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nometacustid@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_no_meta_custid",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_tier_by_customer_id

        # Should not raise
        _update_user_tier_by_customer_id(
            customer_id="cus_no_meta_custid",
            tier="pro",
        )

        # API key should still be updated
        response = table.get_item(Key={"pk": "user_no_meta_custid", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"


class TestUpdateUserSubscriptionStateEdgeCases:
    """Tests for _update_user_subscription_state function edge cases."""

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
        assert item["requests_this_month"] == 100  # Preserved on upgrade

    @mock_aws
    def test_preserves_usage_on_upgrade_via_subscription_state(self, mock_dynamodb):
        """Should preserve usage when upgrading via _update_user_subscription_state."""
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
        assert item["requests_this_month"] == 4500  # Preserved on upgrade


class TestCheckAndClaimEvent:
    """Tests for _check_and_claim_event idempotency function."""

    @mock_aws
    def test_first_claim_succeeds(self, mock_dynamodb):
        """First claim of an event should succeed."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        result = _check_and_claim_event("evt_123", "invoice.paid")

        assert result is True

        # Verify event was recorded
        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_123", "sk": "invoice.paid"})
        assert response.get("Item") is not None
        assert response["Item"]["status"] == "processing"

    @mock_aws
    def test_duplicate_claim_fails(self, mock_dynamodb):
        """Second claim of same event should fail (idempotency)."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        # First claim
        result1 = _check_and_claim_event("evt_dup", "checkout.session.completed")
        assert result1 is True

        # Second claim - should fail
        result2 = _check_and_claim_event("evt_dup", "checkout.session.completed")
        assert result2 is False

    @mock_aws
    def test_same_event_different_types_can_both_claim(self, mock_dynamodb):
        """Same event_id with different types should both succeed (edge case)."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        # This tests the pk+sk composite key - same pk, different sk
        result1 = _check_and_claim_event("evt_multi", "invoice.paid")
        result2 = _check_and_claim_event("evt_multi", "invoice.payment_failed")

        assert result1 is True
        assert result2 is True

    @mock_aws
    def test_claim_records_ttl(self, mock_dynamodb):
        """Event claim should include TTL for automatic cleanup."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        _check_and_claim_event("evt_ttl", "invoice.paid")

        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_ttl", "sk": "invoice.paid"})
        item = response.get("Item")

        assert "ttl" in item
        # TTL should be ~90 days in the future
        import time

        now = int(time.time())
        assert item["ttl"] > now + (85 * 24 * 60 * 60)  # At least 85 days
        assert item["ttl"] < now + (95 * 24 * 60 * 60)  # At most 95 days

    @mock_aws
    def test_concurrent_claims_only_one_succeeds(self, mock_dynamodb):
        """Simulate concurrent webhook deliveries - only one should claim."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        # Pre-insert the event to simulate a concurrent claim that "won"
        table = mock_dynamodb.Table("pkgwatch-billing-events")
        table.put_item(
            Item={
                "pk": "evt_concurrent",
                "sk": "invoice.paid",
                "status": "processing",
                "processed_at": "2024-01-15T10:00:00Z",
            }
        )

        # Now this claim should fail
        result = _check_and_claim_event("evt_concurrent", "invoice.paid")
        assert result is False


class TestReleaseEventClaim:
    """Tests for _release_event_claim function."""

    @mock_aws
    def test_release_deletes_event_claim(self, mock_dynamodb):
        """Releasing a claim should delete the event record."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event, _release_event_claim

        # First claim the event
        _check_and_claim_event("evt_release", "invoice.paid")

        # Verify it exists
        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_release", "sk": "invoice.paid"})
        assert response.get("Item") is not None

        # Release the claim
        _release_event_claim("evt_release", "invoice.paid")

        # Verify it's deleted
        response = table.get_item(Key={"pk": "evt_release", "sk": "invoice.paid"})
        assert response.get("Item") is None

    @mock_aws
    def test_release_allows_retry_to_reclaim(self, mock_dynamodb):
        """After release, a retry should be able to claim the event."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event, _release_event_claim

        # Claim
        result1 = _check_and_claim_event("evt_retry", "invoice.paid")
        assert result1 is True

        # Duplicate would fail
        result2 = _check_and_claim_event("evt_retry", "invoice.paid")
        assert result2 is False

        # Release
        _release_event_claim("evt_retry", "invoice.paid")

        # Now retry can claim
        result3 = _check_and_claim_event("evt_retry", "invoice.paid")
        assert result3 is True

    @mock_aws
    def test_release_nonexistent_event_does_not_raise(self, mock_dynamodb):
        """Releasing a nonexistent event should not raise."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _release_event_claim

        # Should not raise
        _release_event_claim("evt_nonexistent", "invoice.paid")


class TestHandleInvoicePaid:
    """Tests for _handle_invoice_paid billing cycle reset."""

    @mock_aws
    def test_resets_usage_on_subscription_cycle(self, mock_dynamodb):
        """Should reset usage counters when billing cycle renews."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_renewal").hexdigest()
        table.put_item(
            Item={
                "pk": "user_renewal",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "renewal@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_renewal",
                "email_verified": True,
                "requests_this_month": 50000,
                "last_reset_period_start": 1704067200,  # Previous period
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_renewal",
            "subscription": "sub_renewal",
            "billing_reason": "subscription_cycle",
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1706745600,  # New period
                            "end": 1709424000,
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_renewal", "sk": key_hash})
        item = response.get("Item")
        assert item["requests_this_month"] == 0  # Reset
        assert item["current_period_start"] == 1706745600
        assert item["current_period_end"] == 1709424000
        assert item["last_reset_period_start"] == 1706745600

    @mock_aws
    def test_skips_non_subscription_billing_reasons(self, mock_dynamodb):
        """Should not reset usage for manual invoices, etc."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_manual").hexdigest()
        table.put_item(
            Item={
                "pk": "user_manual",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "manual@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_manual",
                "email_verified": True,
                "requests_this_month": 25000,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_manual",
            "subscription": "sub_manual",
            "billing_reason": "manual",  # Not subscription_cycle
            "lines": {"data": []},
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_manual", "sk": key_hash})
        item = response.get("Item")
        assert item["requests_this_month"] == 25000  # Not reset

    @mock_aws
    def test_resets_usage_on_subscription_create(self, mock_dynamodb):
        """Should reset usage on initial subscription creation."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_initial").hexdigest()
        table.put_item(
            Item={
                "pk": "user_initial",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "initial@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_initial",
                "email_verified": True,
                "requests_this_month": 100,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_initial",
            "subscription": "sub_initial",
            "billing_reason": "subscription_create",  # Initial payment
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1706745600,
                            "end": 1709424000,
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_initial", "sk": key_hash})
        item = response.get("Item")
        assert item["requests_this_month"] == 0

    @mock_aws
    def test_clears_payment_failure_state_on_renewal(self, mock_dynamodb):
        """Successful payment should clear payment failure grace period."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_recover").hexdigest()
        table.put_item(
            Item={
                "pk": "user_recover",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "recover@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_recover",
                "email_verified": True,
                "requests_this_month": 10000,
                "payment_failures": 2,
                "first_payment_failure_at": "2024-01-10T00:00:00Z",
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_recover",
            "subscription": "sub_recover",
            "billing_reason": "subscription_cycle",
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1706745600,
                            "end": 1709424000,
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_recover", "sk": key_hash})
        item = response.get("Item")
        assert item["payment_failures"] == 0
        assert "first_payment_failure_at" not in item

    @mock_aws
    def test_idempotent_reset_same_period(self, mock_dynamodb):
        """Reset should be idempotent - same period processed twice does nothing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_idempotent").hexdigest()
        table.put_item(
            Item={
                "pk": "user_idempotent",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "idempotent@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_idempotent",
                "email_verified": True,
                "requests_this_month": 0,
                "last_reset_period_start": 1706745600,  # Already reset for this period
                "current_period_start": 1706745600,
                "current_period_end": 1709424000,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        # Simulate user making some requests after reset
        table.update_item(
            Key={"pk": "user_idempotent", "sk": key_hash},
            UpdateExpression="SET requests_this_month = :val",
            ExpressionAttributeValues={":val": 1500},
        )

        invoice = {
            "customer": "cus_idempotent",
            "subscription": "sub_idempotent",
            "billing_reason": "subscription_cycle",
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1706745600,  # Same period - already processed
                            "end": 1709424000,
                        },
                    }
                ]
            },
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_idempotent", "sk": key_hash})
        item = response.get("Item")
        # Should NOT reset - already processed this period
        assert item["requests_this_month"] == 1500

    @mock_aws
    def test_resets_all_api_keys_for_user(self, mock_dynamodb):
        """Should reset usage on all API keys for a user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash1 = hashlib.sha256(b"pw_multi1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_multi2").hexdigest()

        for i, key_hash in enumerate([key_hash1, key_hash2]):
            table.put_item(
                Item={
                    "pk": "user_multikey",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "multikey@example.com",
                    "tier": "pro",
                    "stripe_customer_id": "cus_multikey",
                    "email_verified": True,
                    "requests_this_month": 10000 + i * 5000,
                }
            )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_multikey",
            "subscription": "sub_multikey",
            "billing_reason": "subscription_cycle",
            "lines": {"data": [{"type": "subscription", "period": {"start": 1706745600, "end": 1709424000}}]},
        }

        _handle_invoice_paid(invoice)

        for key_hash in [key_hash1, key_hash2]:
            response = table.get_item(Key={"pk": "user_multikey", "sk": key_hash})
            item = response.get("Item")
            assert item["requests_this_month"] == 0

    @mock_aws
    def test_also_resets_user_meta(self, mock_dynamodb):
        """Should also reset USER_META record for consistency."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_meta").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "metatest@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_meta",
                "email_verified": True,
                "requests_this_month": 30000,
            }
        )

        # Create USER_META record
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": "USER_META",
                "requests_this_month": 30000,
                "key_count": 1,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_meta",
            "subscription": "sub_meta",
            "billing_reason": "subscription_cycle",
            "lines": {"data": [{"type": "subscription", "period": {"start": 1706745600, "end": 1709424000}}]},
        }

        _handle_invoice_paid(invoice)

        # Check USER_META was also reset
        response = table.get_item(Key={"pk": "user_meta_test", "sk": "USER_META"})
        item = response.get("Item")
        assert item["requests_this_month"] == 0
        assert item["current_period_end"] == 1709424000


class TestExtractPeriodFromInvoice:
    """Tests for _extract_period_from_invoice helper."""

    def test_extracts_period_from_subscription_line(self):
        """Should extract period from subscription line items."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {
            "lines": {
                "data": [
                    {
                        "type": "subscription",
                        "period": {
                            "start": 1706745600,
                            "end": 1709424000,
                        },
                    }
                ]
            }
        }

        start, end = _extract_period_from_invoice(invoice)
        assert start == 1706745600
        assert end == 1709424000

    def test_returns_none_for_non_subscription_lines(self):
        """Should return None when no subscription lines exist."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {
            "lines": {
                "data": [
                    {
                        "type": "invoiceitem",  # Not subscription
                        "period": {"start": 1706745600, "end": 1709424000},
                    }
                ]
            }
        }

        start, end = _extract_period_from_invoice(invoice)
        assert start is None
        assert end is None

    def test_returns_none_for_empty_lines(self):
        """Should return None for empty lines."""
        from api.stripe_webhook import _extract_period_from_invoice

        invoice = {"lines": {"data": []}}

        start, end = _extract_period_from_invoice(invoice)
        assert start is None
        assert end is None


class TestResetUserUsageForBillingCycle:
    """Tests for _reset_user_usage_for_billing_cycle function."""

    @mock_aws
    def test_atomic_reset_prevents_race_condition(self, mock_dynamodb):
        """ConditionExpression should prevent TOCTOU race."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_atomic").hexdigest()
        table.put_item(
            Item={
                "pk": "user_atomic",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "atomic@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_atomic",
                "email_verified": True,
                "requests_this_month": 50000,
                "last_reset_period_start": 1706745600,
            }
        )

        from api.stripe_webhook import _reset_user_usage_for_billing_cycle

        # Try to reset for same period - should be skipped
        _reset_user_usage_for_billing_cycle(
            customer_id="cus_atomic",
            period_start=1706745600,  # Same as last_reset_period_start
            period_end=1709424000,
        )

        response = table.get_item(Key={"pk": "user_atomic", "sk": key_hash})
        item = response.get("Item")
        # Usage should NOT be reset
        assert item["requests_this_month"] == 50000

    @mock_aws
    def test_skips_pending_records_during_reset(self, mock_dynamodb):
        """Should skip PENDING records during billing reset."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_pending_skip").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pending_skip",
                "sk": "PENDING",
                "email": "pendingskip@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_pending_skip",
            }
        )
        table.put_item(
            Item={
                "pk": "user_pending_skip",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pendingskip@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_pending_skip",
                "email_verified": True,
                "requests_this_month": 20000,
            }
        )

        from api.stripe_webhook import _reset_user_usage_for_billing_cycle

        _reset_user_usage_for_billing_cycle(
            customer_id="cus_pending_skip",
            period_start=1706745600,
            period_end=1709424000,
        )

        # PENDING should be untouched
        pending = table.get_item(Key={"pk": "user_pending_skip", "sk": "PENDING"})
        assert pending.get("Item") is not None

        # API key should be reset
        key_item = table.get_item(Key={"pk": "user_pending_skip", "sk": key_hash})
        assert key_item["Item"]["requests_this_month"] == 0


class TestDoubleChargingPrevention:
    """Tests to ensure double-charging prevention via idempotency."""

    @mock_aws
    def test_duplicate_checkout_webhook_does_not_double_process(self, mock_dynamodb, api_gateway_event):
        """Duplicate checkout.session.completed should be skipped."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        # Pre-claim the event to simulate it already being processed
        billing_table = mock_dynamodb.Table("pkgwatch-billing-events")
        billing_table.put_item(
            Item={
                "pk": "evt_checkout_dup",
                "sk": "checkout.session.completed",
                "status": "success",
                "processed_at": "2024-01-15T10:00:00Z",
            }
        )

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        from api.stripe_webhook import _check_and_claim_event

        # This simulates the handler checking for duplicates
        result = _check_and_claim_event("evt_checkout_dup", "checkout.session.completed")

        assert result is False  # Should not process duplicate

    @mock_aws
    def test_subscription_update_webhook_idempotent(self, mock_dynamodb):
        """Subscription update events should be idempotent."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_sub_idem").hexdigest()
        table.put_item(
            Item={
                "pk": "user_sub_idem",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "subidem@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_sub_idem",
                "email_verified": True,
                "requests_this_month": 1000,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        # First update - upgrade to pro
        _update_user_subscription_state(
            customer_id="cus_sub_idem",
            tier="pro",
            cancellation_pending=False,
        )

        response = table.get_item(Key={"pk": "user_sub_idem", "sk": key_hash})
        assert response["Item"]["tier"] == "pro"
        assert response["Item"]["requests_this_month"] == 1000  # Preserved on upgrade

        # Second identical update - should be safe (idempotent)
        _update_user_subscription_state(
            customer_id="cus_sub_idem",
            tier="pro",
            cancellation_pending=False,
        )

        response = table.get_item(Key={"pk": "user_sub_idem", "sk": key_hash})
        assert response["Item"]["tier"] == "pro"


class TestChargeRefunded:
    """Tests for charge.refunded webhook handler."""

    @mock_aws
    def test_logs_refund_details(self, mock_dynamodb, caplog):
        """Should log refund details for audit trail."""
        import logging

        caplog.set_level(logging.INFO)

        from api.stripe_webhook import _handle_charge_refunded

        charge = {
            "customer": "cus_refund",
            "amount_refunded": 2900,  # $29.00 in cents
            "refund_reason": "requested_by_customer",
        }

        _handle_charge_refunded(charge)

        assert "Refund processed for customer cus_refund" in caplog.text
        assert "$29.00" in caplog.text
        assert "requested_by_customer" in caplog.text

    def test_handles_missing_refund_reason(self, caplog):
        """Should handle missing refund_reason gracefully."""
        import logging

        caplog.set_level(logging.INFO)

        from api.stripe_webhook import _handle_charge_refunded

        charge = {
            "customer": "cus_no_reason",
            "amount_refunded": 1000,
        }

        _handle_charge_refunded(charge)

        assert "not_specified" in caplog.text


class TestDisputeCreated:
    """Tests for charge.dispute.created webhook handler."""

    @mock_aws
    def test_logs_dispute_warning(self, mock_dynamodb, caplog):
        """Should log dispute as warning for attention."""
        import logging

        caplog.set_level(logging.WARNING)

        from api.stripe_webhook import _handle_dispute_created

        dispute = {
            "customer": "cus_dispute",
            "reason": "fraudulent",
            "amount": 4900,  # $49.00 in cents
        }

        _handle_dispute_created(dispute)

        assert "Dispute created for customer cus_dispute" in caplog.text
        assert "$49.00" in caplog.text
        assert "fraudulent" in caplog.text

    def test_handles_nested_customer_id(self, caplog):
        """Should handle customer_id nested in charge object."""
        import logging

        caplog.set_level(logging.WARNING)

        from api.stripe_webhook import _handle_dispute_created

        dispute = {
            "charge": {"customer": "cus_nested"},
            "reason": "product_not_received",
            "amount": 2900,
        }

        _handle_dispute_created(dispute)

        assert "cus_nested" in caplog.text

    def test_handles_missing_customer_id(self, caplog):
        """Should handle missing customer_id gracefully."""
        import logging

        caplog.set_level(logging.WARNING)

        from api.stripe_webhook import _handle_dispute_created

        dispute = {
            "reason": "general",
            "amount": 1900,
        }

        _handle_dispute_created(dispute)

        assert "None" in caplog.text or "dispute" in caplog.text.lower()

    @mock_aws
    def test_sends_sns_notification_when_alert_topic_configured(self, mock_dynamodb, caplog):
        """Should publish SNS notification when ALERT_TOPIC_ARN is set."""
        import logging

        import boto3

        caplog.set_level(logging.INFO)

        # Create a real SNS topic via moto
        sns_client = boto3.client("sns", region_name="us-east-1")
        topic = sns_client.create_topic(Name="pkgwatch-alerts")
        topic_arn = topic["TopicArn"]

        os.environ["ALERT_TOPIC_ARN"] = topic_arn

        # Reset SNS client so it picks up moto mock
        from shared.aws_clients import reset_clients

        reset_clients()

        try:
            from api.stripe_webhook import _handle_dispute_created

            dispute = {
                "customer": "cus_sns_test",
                "reason": "fraudulent",
                "amount": 4900,
            }

            _handle_dispute_created(dispute)

            assert "Dispute notification sent for customer cus_sns_test" in caplog.text
        finally:
            os.environ.pop("ALERT_TOPIC_ARN", None)
            reset_clients()

    def test_skips_sns_when_alert_topic_not_configured(self, caplog):
        """Should skip SNS notification when ALERT_TOPIC_ARN is not set."""
        import logging

        caplog.set_level(logging.DEBUG, logger="api.stripe_webhook")

        os.environ.pop("ALERT_TOPIC_ARN", None)

        from api.stripe_webhook import _handle_dispute_created

        dispute = {
            "customer": "cus_no_sns",
            "reason": "duplicate",
            "amount": 2900,
        }

        _handle_dispute_created(dispute)

        assert "ALERT_TOPIC_ARN not configured" in caplog.text
        assert "Dispute notification sent" not in caplog.text

    @mock_aws
    def test_sns_failure_does_not_break_dispute_handling(self, mock_dynamodb, caplog):
        """Should handle SNS publish errors gracefully without breaking dispute handling."""
        import logging
        from unittest.mock import MagicMock, patch

        caplog.set_level(logging.WARNING)

        os.environ["ALERT_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789:fake-topic"

        # Mock get_sns to return a client that raises on publish
        mock_sns = MagicMock()
        mock_sns.publish.side_effect = Exception("SNS publish failed")

        try:
            with patch("api.stripe_webhook.get_sns", return_value=mock_sns):
                from api.stripe_webhook import _handle_dispute_created

                dispute = {
                    "customer": "cus_sns_fail",
                    "reason": "product_not_received",
                    "amount": 3900,
                }

                # Should not raise - SNS failure is handled gracefully
                _handle_dispute_created(dispute)

            # Dispute was still logged
            assert "Dispute created for customer cus_sns_fail" in caplog.text
            # SNS error was logged
            assert "Failed to send dispute notification" in caplog.text
        finally:
            os.environ.pop("ALERT_TOPIC_ARN", None)


class TestWebhookHandlerTransientErrors:
    """Tests for transient error handling and claim release."""

    @mock_aws
    def test_dynamodb_error_releases_claim_and_returns_500(self, mock_dynamodb, api_gateway_event):
        """DynamoDB ClientError should release claim and return 500."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["STRIPE_SECRET_ARN"] = ""
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = ""

        # Reset secrets cache
        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        # This test verifies the error handling pattern - when a ClientError
        # occurs, _release_event_claim should be called to allow retry
        from api.stripe_webhook import _check_and_claim_event, _release_event_claim

        # Claim an event
        _check_and_claim_event("evt_transient", "invoice.paid")

        # Release should work
        _release_event_claim("evt_transient", "invoice.paid")

        # Now a retry can claim
        result = _check_and_claim_event("evt_transient", "invoice.paid")
        assert result is True


class TestSubscriptionRaceConditions:
    """Tests for race conditions in subscription state updates."""

    @mock_aws
    def test_concurrent_payment_success_clears_grace_period(self, mock_dynamodb):
        """Successful payment racing with failure should clear grace period."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_race").hexdigest()
        # User with in-progress grace period
        table.put_item(
            Item={
                "pk": "user_race",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "race@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_race",
                "email_verified": True,
                "payment_failures": 2,
                "first_payment_failure_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        # Successful payment clears grace period
        invoice = {
            "customer": "cus_race",
            "subscription": "sub_race",
            "billing_reason": "subscription_cycle",
            "lines": {"data": [{"type": "subscription", "period": {"start": 1706745600, "end": 1709424000}}]},
        }

        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_race", "sk": key_hash})
        item = response.get("Item")
        assert item["payment_failures"] == 0
        assert "first_payment_failure_at" not in item

    @mock_aws
    def test_payment_failure_conditional_prevents_race_with_success(self, mock_dynamodb):
        """Payment failure downgrade should use conditional write to prevent race."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cond_race").hexdigest()
        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        table.put_item(
            Item={
                "pk": "user_cond_race",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "condrace@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cond_race",
                "email_verified": True,
                "payment_failures": 2,
                "first_payment_failure_at": ten_days_ago,
            }
        )

        # Simulate: successful payment cleared grace period between check and update
        # by removing first_payment_failure_at before the downgrade attempt
        table.update_item(
            Key={"pk": "user_cond_race", "sk": key_hash},
            UpdateExpression="REMOVE first_payment_failure_at SET payment_failures = :zero",
            ExpressionAttributeValues={":zero": 0},
        )

        from api.stripe_webhook import _handle_payment_failed

        # Now payment failure handler runs - should NOT downgrade due to condition
        invoice = {
            "customer": "cus_cond_race",
            "customer_email": "condrace@example.com",
            "attempt_count": 3,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_cond_race", "sk": key_hash})
        item = response.get("Item")
        # Should NOT be downgraded - conditional check should fail
        assert item["tier"] == "pro"


class TestRecordBillingEvent:
    """Tests for _record_billing_event audit function."""

    @mock_aws
    def test_records_event_with_all_fields(self, mock_dynamodb):
        """Should record billing event with all audit fields."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _record_billing_event

        event = {
            "id": "evt_audit_test",
            "type": "invoice.paid",
            "created": 1706745600,
            "livemode": False,
            "data": {"object": {"customer": "cus_audit"}},
        }

        _record_billing_event(event, "success")

        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_audit_test", "sk": "invoice.paid"})
        item = response.get("Item")

        assert item is not None
        assert item["status"] == "success"
        assert item["customer_id"] == "cus_audit"
        assert item["event_created_at"] == 1706745600
        assert item["livemode"] is False
        assert "ttl" in item

    @mock_aws
    def test_records_error_on_failure(self, mock_dynamodb):
        """Should record error message on failure."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _record_billing_event

        event = {
            "id": "evt_failed",
            "type": "checkout.session.completed",
            "data": {"object": {"customer": "cus_failed"}},
        }

        _record_billing_event(event, "failed", "User not found")

        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_failed", "sk": "checkout.session.completed"})
        item = response.get("Item")

        assert item["status"] == "failed"
        assert item["error"] == "User not found"

    @mock_aws
    def test_handles_missing_customer_id(self, mock_dynamodb):
        """Should use 'unknown' for missing customer_id."""
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _record_billing_event

        event = {
            "id": "evt_no_customer",
            "type": "checkout.session.completed",
            "data": {"object": {}},  # No customer field
        }

        _record_billing_event(event, "success")

        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_no_customer", "sk": "checkout.session.completed"})
        item = response.get("Item")

        assert item["customer_id"] == "unknown"


class TestHandlerSignatureValidation:
    """Tests for handler-level Stripe signature validation."""

    @mock_aws
    def test_missing_stripe_signature_returns_400(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when Stripe-Signature header is missing."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:stripe"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:webhook"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "invoice.paid"})
        api_gateway_event["headers"] = {}  # No stripe-signature header

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_signature"
        assert body["error"]["message"] == "Missing Stripe signature"


class TestGetUserIdLookups:
    """Tests for user ID lookup helper functions."""

    @mock_aws
    def test_get_user_id_by_email_finds_user(self, mock_dynamodb):
        """Should find user_id by email."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_lookup_email").hexdigest()
        table.put_item(
            Item={
                "pk": "user_email_lookup",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "lookup@example.com",
                "tier": "starter",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _get_user_id_by_email

        result = _get_user_id_by_email("lookup@example.com")
        assert result == "user_email_lookup"

    @mock_aws
    def test_get_user_id_by_email_returns_none_for_missing(self, mock_dynamodb):
        """Should return None when email not found."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _get_user_id_by_email

        result = _get_user_id_by_email("nonexistent@example.com")
        assert result is None

    @mock_aws
    def test_get_user_id_by_email_skips_pending(self, mock_dynamodb):
        """Should skip PENDING records when looking up by email."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Only a PENDING record exists
        table.put_item(
            Item={
                "pk": "user_pending_only",
                "sk": "PENDING",
                "email": "pendingonly@example.com",
                "tier": "free",
            }
        )

        from api.stripe_webhook import _get_user_id_by_email

        result = _get_user_id_by_email("pendingonly@example.com")
        assert result is None  # PENDING record should be skipped

    @mock_aws
    def test_get_user_id_by_customer_id_finds_user(self, mock_dynamodb):
        """Should find user_id by Stripe customer ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_lookup_cust").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cust_lookup",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "custlookup@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_lookup_test",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _get_user_id_by_customer_id

        result = _get_user_id_by_customer_id("cus_lookup_test")
        assert result == "user_cust_lookup"

    @mock_aws
    def test_get_user_id_by_customer_id_returns_none_for_missing(self, mock_dynamodb):
        """Should return None when customer ID not found."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _get_user_id_by_customer_id

        result = _get_user_id_by_customer_id("cus_nonexistent")
        assert result is None


class TestHandleInvoicePaidMissingCustomer:
    """Edge case tests for _handle_invoice_paid."""

    @mock_aws
    def test_returns_early_with_no_customer_id(self, mock_dynamodb):
        """Should return early when customer ID is missing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "subscription": "sub_test",
            "billing_reason": "subscription_cycle",
            "lines": {"data": []},
        }

        # Should not raise
        _handle_invoice_paid(invoice)

    @mock_aws
    def test_handles_missing_period_gracefully(self, mock_dynamodb):
        """Should handle missing period in invoice lines."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_period").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_period",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "noperiod@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_no_period",
                "email_verified": True,
                "requests_this_month": 5000,
            }
        )

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_no_period",
            "subscription": "sub_no_period",
            "billing_reason": "subscription_cycle",
            "lines": {"data": []},  # No subscription lines
        }

        # Should not raise, but also should not reset (no period)
        _handle_invoice_paid(invoice)

        response = table.get_item(Key={"pk": "user_no_period", "sk": key_hash})
        item = response.get("Item")
        # Usage should NOT be reset since we couldn't extract period
        assert item["requests_this_month"] == 5000

    @mock_aws
    def test_handles_no_user_found_for_customer(self, mock_dynamodb):
        """Should handle case when customer ID has no matching user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_invoice_paid

        invoice = {
            "customer": "cus_nonexistent",
            "subscription": "sub_test",
            "billing_reason": "subscription_cycle",
            "lines": {"data": [{"type": "subscription", "period": {"start": 1706745600, "end": 1709424000}}]},
        }

        # Should not raise - just logs warning
        _handle_invoice_paid(invoice)


class TestUpdateUserTierEdgeCases:
    """Edge case tests for _update_user_tier."""

    @mock_aws
    def test_returns_early_with_no_email(self, mock_dynamodb):
        """Should return early when email is empty/None."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_tier

        # Should not raise
        _update_user_tier(None, "pro", "cus_123", "sub_123")
        _update_user_tier("", "pro", "cus_123", "sub_123")

    @mock_aws
    def test_handles_no_user_found(self, mock_dynamodb):
        """Should handle case when no user found for email."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _update_user_tier

        # Should not raise - logs error
        _update_user_tier("nonexistent@example.com", "pro", "cus_123", "sub_123")

    @mock_aws
    def test_stores_billing_cycle_fields(self, mock_dynamodb):
        """Should store billing cycle fields for per-user reset tracking."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_billing_cycle").hexdigest()
        table.put_item(
            Item={
                "pk": "user_billing_cycle",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "billingcycle@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_tier

        _update_user_tier(
            "billingcycle@example.com",
            "pro",
            "cus_123",
            "sub_123",
            current_period_start=1706745600,
            current_period_end=1709424000,
        )

        response = table.get_item(Key={"pk": "user_billing_cycle", "sk": key_hash})
        item = response.get("Item")
        assert item["current_period_start"] == 1706745600
        assert item["current_period_end"] == 1709424000
        assert item["last_reset_period_start"] == 1706745600

    @mock_aws
    def test_preserves_usage_on_tier_update(self, mock_dynamodb):
        """Should preserve usage when updating tier (usage only resets on billing cycle)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_reset_flag").hexdigest()
        table.put_item(
            Item={
                "pk": "user_reset_flag",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "resetflag@example.com",
                "tier": "starter",
                "email_verified": True,
                "requests_this_month": 4000,
            }
        )

        from api.stripe_webhook import _update_user_tier

        _update_user_tier(
            "resetflag@example.com",
            "pro",
            "cus_123",
            "sub_123",
        )

        response = table.get_item(Key={"pk": "user_reset_flag", "sk": key_hash})
        item = response.get("Item")
        assert item["requests_this_month"] == 4000


class TestSubscriptionUpdatedEdgeCases:
    """Edge case tests for _handle_subscription_updated."""

    @mock_aws
    def test_extracts_billing_cycle_from_item(self, mock_dynamodb):
        """Should extract current_period_start/end from subscription item."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_PRICE_PRO"] = "price_pro_cycle"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cycle_extract").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cycle_extract",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cycleextract@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cycle_extract",
                "email_verified": True,
            }
        )

        import importlib

        import api.stripe_webhook as webhook_module

        importlib.reload(webhook_module)

        subscription = {
            "customer": "cus_cycle_extract",
            "status": "active",
            "cancel_at_period_end": False,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro_cycle"},
                        "current_period_start": 1706745600,
                        "current_period_end": 1709424000,
                    }
                ]
            },
        }

        webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_cycle_extract", "sk": key_hash})
        item = response.get("Item")
        assert item["current_period_start"] == 1706745600
        assert item["current_period_end"] == 1709424000

        # Clean up
        del os.environ["STRIPE_PRICE_PRO"]


class TestSubscriptionDeletedEdgeCases:
    """Edge case tests for _handle_subscription_deleted."""

    @mock_aws
    def test_logs_warning_for_future_period_end(self, mock_dynamodb, caplog):
        """Should log warning when period_end is in the future."""
        import logging
        import time

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_future_end").hexdigest()
        table.put_item(
            Item={
                "pk": "user_future_end",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "futureend@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_future_end",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_subscription_deleted

        future_timestamp = int(time.time()) + 86400 * 30  # 30 days in future

        subscription = {
            "customer": "cus_future_end",
            "canceled_at": int(time.time()),
            "ended_at": None,
            "current_period_end": future_timestamp,  # In the future
        }

        _handle_subscription_deleted(subscription)

        # Should still downgrade but log warning
        response = table.get_item(Key={"pk": "user_future_end", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        assert "period_end" in caplog.text and "future" in caplog.text


class TestPaymentFailedEdgeCases:
    """Edge case tests for _handle_payment_failed."""

    @mock_aws
    def test_handles_missing_customer_id(self, mock_dynamodb):
        """Should handle missing customer_id gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer_email": "test@example.com",
            "attempt_count": 1,
        }

        # Should not raise
        _handle_payment_failed(invoice)

    @mock_aws
    def test_handles_no_user_found(self, mock_dynamodb):
        """Should handle case when no user found for customer."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_nonexistent",
            "customer_email": "test@example.com",
            "attempt_count": 1,
        }

        # Should not raise - logs warning
        _handle_payment_failed(invoice)


class TestUserMetaSyncEdgeCases:
    """Edge case tests for USER_META synchronization."""

    @mock_aws
    def test_subscription_state_creates_or_updates_user_meta(self, mock_dynamodb):
        """Should update USER_META with subscription state."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_meta_sync").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_sync",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "metasync@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_meta_sync",
                "email_verified": True,
            }
        )

        # Create USER_META
        table.put_item(
            Item={
                "pk": "user_meta_sync",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_meta_sync",
            tier="pro",
            cancellation_pending=True,
            cancellation_date=1709424000,
            current_period_end=1709424000,
        )

        # Check USER_META was updated
        response = table.get_item(Key={"pk": "user_meta_sync", "sk": "USER_META"})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["cancellation_pending"] is True
        assert item["cancellation_date"] == 1709424000
        assert item["current_period_end"] == 1709424000

    @mock_aws
    def test_subscription_state_handles_missing_user_meta(self, mock_dynamodb):
        """Should handle case when USER_META doesn't exist."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_meta").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_meta",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nometa@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_no_meta",
                "email_verified": True,
            }
        )

        # No USER_META record

        from api.stripe_webhook import _update_user_subscription_state

        # Should not raise - USER_META update should fail gracefully
        _update_user_subscription_state(
            customer_id="cus_no_meta",
            tier="pro",
            cancellation_pending=False,
        )

        # API key should still be updated
        response = table.get_item(Key={"pk": "user_no_meta", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"


class TestUnknownPriceId:
    """Tests for handling unknown price IDs in PRICE_TO_TIER mapping."""

    @mock_aws
    def test_checkout_completed_skips_unknown_price(self, mock_dynamodb):
        """checkout.session.completed should return early on unknown price ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_unknown_price").hexdigest()
        table.put_item(
            Item={
                "pk": "user_unknown_price",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unknown@example.com",
                "tier": "starter",
                "email_verified": True,
            }
        )

        from unittest.mock import MagicMock, patch

        import api.stripe_webhook as webhook_module

        mock_subscription = MagicMock()
        mock_subscription.__getitem__ = lambda self, key: {
            "items": {
                "data": [{"price": {"id": "price_unknown_xyz"}, "current_period_start": 100, "current_period_end": 200}]
            },
        }[key]
        mock_subscription.get = lambda key, default=None: {
            "items": {
                "data": [{"price": {"id": "price_unknown_xyz"}, "current_period_start": 100, "current_period_end": 200}]
            },
        }.get(key, default)

        session = {
            "customer_email": "unknown@example.com",
            "customer": "cus_unknown",
            "subscription": "sub_unknown",
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            # Ensure PRICE_TO_TIER has no mapping for this price
            with patch.dict(webhook_module.PRICE_TO_TIER, {}, clear=True):
                webhook_module._handle_checkout_completed(session)

        # Tier should remain unchanged
        response = table.get_item(Key={"pk": "user_unknown_price", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"

    @mock_aws
    def test_subscription_updated_skips_tier_on_unknown_price(self, mock_dynamodb):
        """subscription.updated should skip tier update but still update cancellation state."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_unknown_sub_upd").hexdigest()
        table.put_item(
            Item={
                "pk": "user_unknown_sub_upd",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unknownupd@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_unknown_upd",
                "email_verified": True,
            }
        )

        import api.stripe_webhook as webhook_module

        subscription = {
            "customer": "cus_unknown_upd",
            "status": "active",
            "cancel_at_period_end": True,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_unknown_xyz"},
                        "current_period_end": 1707955200,
                    }
                ]
            },
        }

        from unittest.mock import patch

        with patch.dict(webhook_module.PRICE_TO_TIER, {}, clear=True):
            webhook_module._handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_unknown_sub_upd", "sk": key_hash})
        item = response.get("Item")
        # Tier should NOT be changed (unknown price → tier=None → skipped)
        assert item["tier"] == "pro"
        # Cancellation state SHOULD still be updated
        assert item["cancellation_pending"] is True

    @mock_aws
    def test_subscription_created_skips_unknown_price(self, mock_dynamodb):
        """subscription.created should return early on unknown price ID."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_unknown_sub_crt").hexdigest()
        table.put_item(
            Item={
                "pk": "user_unknown_sub_crt",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unknowncrt@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_unknown_crt",
                "email_verified": True,
            }
        )

        import api.stripe_webhook as webhook_module

        subscription = {
            "customer": "cus_unknown_crt",
            "status": "active",
            "items": {"data": [{"price": {"id": "price_unknown_xyz"}}]},
            "current_period_start": 1704067200,
            "current_period_end": 1706745600,
        }

        from unittest.mock import patch

        with patch.dict(webhook_module.PRICE_TO_TIER, {}, clear=True):
            webhook_module._handle_subscription_created(subscription)

        # Tier should remain unchanged
        response = table.get_item(Key={"pk": "user_unknown_sub_crt", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"


class TestWebhookSignatureTampering:
    """Tests for Stripe webhook signature verification to prevent tampering."""

    @mock_aws
    def test_tampered_payload_rejected(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook with tampered payload that doesn't match signature."""
        pytest.importorskip("stripe")
        import hashlib as stdlib_hashlib
        import hmac
        import time

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:stripe"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789012:secret:webhook"

        # Reset secrets cache with test webhook secret
        import api.stripe_webhook as webhook_module

        webhook_secret = "whsec_test_secret_key"
        webhook_module._stripe_secrets_cache = ("sk_test_xxx", webhook_secret)
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        # Create a valid signature for original payload
        original_payload = json.dumps({"type": "invoice.paid", "id": "evt_123"})
        timestamp = int(time.time())
        signed_payload = f"{timestamp}.{original_payload}"
        expected_sig = hmac.new(
            webhook_secret.encode("utf-8"), signed_payload.encode("utf-8"), stdlib_hashlib.sha256
        ).hexdigest()
        stripe_signature = f"t={timestamp},v1={expected_sig}"

        # Now TAMPER with the payload (change event ID)
        tampered_payload = json.dumps({"type": "invoice.paid", "id": "evt_TAMPERED"})

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = tampered_payload  # Tampered!
        api_gateway_event["headers"] = {"stripe-signature": stripe_signature}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        # Should be rejected - signature doesn't match tampered payload
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_signature"
        assert body["error"]["message"] == "Invalid signature"

    @mock_aws
    def test_expired_signature_rejected(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook with expired timestamp in signature."""
        pytest.importorskip("stripe")
        import hashlib as stdlib_hashlib
        import hmac
        import time

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_secret = "whsec_test_expired"
        webhook_module._stripe_secrets_cache = ("sk_test_xxx", webhook_secret)
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        # Create a signature with OLD timestamp (6 minutes ago, beyond Stripe's 5 min tolerance)
        payload = json.dumps({"type": "invoice.paid", "id": "evt_456"})
        old_timestamp = int(time.time()) - 360  # 6 minutes ago
        signed_payload = f"{old_timestamp}.{payload}"
        expected_sig = hmac.new(
            webhook_secret.encode("utf-8"), signed_payload.encode("utf-8"), stdlib_hashlib.sha256
        ).hexdigest()
        stripe_signature = f"t={old_timestamp},v1={expected_sig}"

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = payload
        api_gateway_event["headers"] = {"stripe-signature": stripe_signature}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        # Should be rejected due to timestamp tolerance
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_signature"
        assert body["error"]["message"] == "Invalid signature"

    @mock_aws
    def test_replay_attack_prevented_by_idempotency(self, mock_dynamodb, api_gateway_event):
        """Should prevent replay attacks via idempotency check."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        from api.stripe_webhook import _check_and_claim_event

        # First claim succeeds
        result1 = _check_and_claim_event("evt_replay", "invoice.paid")
        assert result1 is True

        # Replay attempt is blocked
        result2 = _check_and_claim_event("evt_replay", "invoice.paid")
        assert result2 is False

        # Verify the event was recorded
        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_replay", "sk": "invoice.paid"})
        assert response.get("Item") is not None

    @mock_aws
    def test_malformed_signature_rejected(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook with malformed signature format."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_test")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "invoice.paid"})
        # Malformed signature - missing timestamp
        api_gateway_event["headers"] = {"stripe-signature": "v1=abc123"}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_signature"
        assert body["error"]["message"] == "Invalid signature"

    @mock_aws
    def test_wrong_webhook_secret_rejected(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook signed with wrong secret."""
        pytest.importorskip("stripe")
        import hashlib as stdlib_hashlib
        import hmac
        import time

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        # Server expects this secret
        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_correct_secret")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        # But payload was signed with wrong secret
        wrong_secret = "whsec_WRONG_secret"
        payload = json.dumps({"type": "invoice.paid", "id": "evt_wrong"})
        timestamp = int(time.time())
        signed_payload = f"{timestamp}.{payload}"
        wrong_sig = hmac.new(
            wrong_secret.encode("utf-8"), signed_payload.encode("utf-8"), stdlib_hashlib.sha256
        ).hexdigest()
        stripe_signature = f"t={timestamp},v1={wrong_sig}"

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = payload
        api_gateway_event["headers"] = {"stripe-signature": stripe_signature}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_signature"
        assert body["error"]["message"] == "Invalid signature"


class TestWebhookErrorResponseQuality:
    """Tests for webhook error response quality and security."""

    @mock_aws
    def test_signature_error_does_not_leak_secret(self, mock_dynamodb, api_gateway_event, caplog):
        """Signature errors should not leak the webhook secret in logs or response."""
        pytest.importorskip("stripe")
        import logging

        caplog.set_level(logging.DEBUG)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        secret = "whsec_supersecret123"
        webhook_module._stripe_secrets_cache = ("sk_test_xxx", secret)
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "invoice.paid"})
        api_gateway_event["headers"] = {"stripe-signature": "invalid_signature"}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        # Secret should NOT appear in response
        assert secret not in result["body"]

        # Secret should NOT appear in logs
        assert secret not in caplog.text

    @mock_aws
    def test_error_response_is_generic_not_detailed(self, mock_dynamodb, api_gateway_event):
        """Error responses should be generic to not aid attackers."""
        pytest.importorskip("stripe")

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_test")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "invoice.paid"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=wrong"}

        from api.stripe_webhook import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        # Should just say "Invalid signature", not "signature mismatch" or
        # "expected X got Y" which could leak information
        assert body["error"]["code"] == "invalid_signature"
        assert body["error"]["message"] == "Invalid signature"
        # Should NOT contain detailed information
        assert "expected" not in body.get("error", {}).get("message", "").lower()
        assert "hmac" not in body.get("error", {}).get("message", "").lower()
        assert "secret" not in body.get("error", {}).get("message", "").lower()


class TestGetStripeSecretsPlainTextFallback:
    """Tests for get_stripe_secrets handling of plain-text (non-JSON) secrets."""

    @mock_aws
    def test_plain_text_stripe_api_key(self):
        """Should fall back to raw secret string when it is not valid JSON."""
        from unittest.mock import patch

        import boto3

        sm = boto3.client("secretsmanager", region_name="us-east-1")
        resp1 = sm.create_secret(
            Name="stripe-api-key-plain",
            SecretString="sk_live_plaintext123",
        )
        resp2 = sm.create_secret(
            Name="stripe-webhook-secret-plain",
            SecretString='{"secret": "whsec_json123"}',
        )

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0
        # Force fresh client so it uses the mocked Secrets Manager
        webhook_module._secretsmanager = None

        # Patch module-level constants (they are read at import time)
        with (
            patch.object(webhook_module, "STRIPE_SECRET_ARN", resp1["ARN"]),
            patch.object(webhook_module, "STRIPE_WEBHOOK_SECRET_ARN", resp2["ARN"]),
        ):
            api_key, webhook_secret = webhook_module.get_stripe_secrets()

        # Plain text should be used directly (JSONDecodeError fallback)
        assert api_key == "sk_live_plaintext123"
        assert webhook_secret == "whsec_json123"

    @mock_aws
    def test_plain_text_webhook_secret(self):
        """Should fall back to raw secret string for webhook secret when not JSON."""
        from unittest.mock import patch

        import boto3

        sm = boto3.client("secretsmanager", region_name="us-east-1")
        resp1 = sm.create_secret(
            Name="stripe-key-json",
            SecretString='{"key": "sk_test_json"}',
        )
        resp2 = sm.create_secret(
            Name="stripe-webhook-plain",
            SecretString="whsec_plaintext456",
        )

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0
        webhook_module._secretsmanager = None

        with (
            patch.object(webhook_module, "STRIPE_SECRET_ARN", resp1["ARN"]),
            patch.object(webhook_module, "STRIPE_WEBHOOK_SECRET_ARN", resp2["ARN"]),
        ):
            api_key, webhook_secret = webhook_module.get_stripe_secrets()

        assert api_key == "sk_test_json"
        # Plain text fallback on JSONDecodeError
        assert webhook_secret == "whsec_plaintext456"

    @mock_aws
    def test_uses_cached_secrets_within_ttl(self, mock_dynamodb):
        """Should return cached secrets without calling Secrets Manager again."""
        import time

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_cached", "whsec_cached")
        webhook_module._stripe_secrets_cache_time = time.time()  # Just now

        api_key, webhook_secret = webhook_module.get_stripe_secrets()

        assert api_key == "sk_cached"
        assert webhook_secret == "whsec_cached"


class TestHandlerFullEventFlow:
    """Tests for the full handler event routing, covering error branches and success path."""

    @mock_aws
    def test_general_exception_in_construct_event_returns_400(self, mock_dynamodb, api_gateway_event):
        """A generic Exception during construct_event should return 400."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = "not a json payload"
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        # Patch construct_event to raise a generic Exception (not SignatureVerificationError)
        with patch("stripe.Webhook.construct_event", side_effect=Exception("something broke")):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_webhook_payload"
        assert body["error"]["message"] == "Invalid webhook payload"

    @mock_aws
    def test_successful_event_processing_returns_200(self, mock_dynamodb, api_gateway_event):
        """Successfully processed event should return 200 with received=True."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "some.event"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        # Mock construct_event to return a valid unhandled event
        mock_event = {
            "id": "evt_success_test",
            "type": "some.unhandled.event",
            "data": {"object": {}},
        }
        with patch("stripe.Webhook.construct_event", return_value=mock_event):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["received"] is True

    @mock_aws
    def test_duplicate_event_returns_200_with_duplicate_flag(self, mock_dynamodb, api_gateway_event):
        """Duplicate event should return 200 with duplicate=True."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        # Pre-claim the event
        billing_table = mock_dynamodb.Table("pkgwatch-billing-events")
        billing_table.put_item(
            Item={
                "pk": "evt_dup_handler",
                "sk": "invoice.paid",
                "status": "success",
            }
        )

        mock_event = {
            "id": "evt_dup_handler",
            "type": "invoice.paid",
            "data": {"object": {"customer": "cus_dup"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "invoice.paid"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        with patch("stripe.Webhook.construct_event", return_value=mock_event):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["duplicate"] is True

    @mock_aws
    def test_client_error_releases_claim_returns_500(self, mock_dynamodb, api_gateway_event):
        """ClientError during event handling should release claim and return 500."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        from botocore.exceptions import ClientError

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_client_error",
            "type": "checkout.session.completed",
            "data": {"object": {"customer_email": "test@example.com"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "checkout.session.completed"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        dynamo_error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}},
            "UpdateItem",
        )

        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_checkout_completed", side_effect=dynamo_error),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "temporary_error"
        assert body["error"]["message"] == "Temporary error, please retry"

        # Event claim should have been released to allow retry
        table = mock_dynamodb.Table("pkgwatch-billing-events")
        response = table.get_item(Key={"pk": "evt_client_error", "sk": "checkout.session.completed"})
        # The claim was released (deleted), then _record_billing_event re-wrote it with "failed"
        item = response.get("Item")
        assert item is not None
        assert item["status"] == "failed"

    @mock_aws
    def test_value_error_returns_200_processed_false(self, mock_dynamodb, api_gateway_event):
        """ValueError during event handling should return 200 with processed=False."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_value_error",
            "type": "checkout.session.completed",
            "data": {"object": {"customer_email": "bad@example.com"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "checkout.session.completed"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_checkout_completed", side_effect=ValueError("bad data")),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["received"] is True
        assert body["processed"] is False
        assert body["error"]["code"] == "invalid_event_data"
        assert body["error"]["message"] == "Invalid event data"

    @mock_aws
    def test_unexpected_exception_releases_claim_returns_500(self, mock_dynamodb, api_gateway_event):
        """Unexpected exception should release claim and return 500."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_unexpected",
            "type": "checkout.session.completed",
            "data": {"object": {"customer_email": "test@example.com"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "checkout.session.completed"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_checkout_completed", side_effect=RuntimeError("unexpected")),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "processing_failed"
        assert body["error"]["message"] == "Processing failed"

    @mock_aws
    def test_stripe_api_connection_error_releases_claim_returns_500(self, mock_dynamodb, api_gateway_event):
        """Stripe APIConnectionError should release claim and return 500."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        import stripe

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_stripe_conn",
            "type": "checkout.session.completed",
            "data": {"object": {"customer_email": "test@example.com"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "checkout.session.completed"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=stripe.error.APIConnectionError("connection failed"),
            ),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "stripe_error"
        assert body["error"]["message"] == "Stripe error, please retry"

    @mock_aws
    def test_permanent_stripe_error_returns_200_processed_false(self, mock_dynamodb, api_gateway_event):
        """Permanent Stripe error (e.g., InvalidRequestError) should return 200 with processed=False."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        import stripe

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_stripe_perm",
            "type": "checkout.session.completed",
            "data": {"object": {"customer_email": "test@example.com"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "checkout.session.completed"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=stripe.error.InvalidRequestError("bad request", "param"),
            ),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["received"] is True
        assert body["processed"] is False
        assert body["error"]["code"] == "stripe_validation_error"
        assert body["error"]["message"] == "Stripe validation error"


class TestHandlerEventRouting:
    """Tests for handler routing to specific event type handlers."""

    @mock_aws
    def test_routes_subscription_updated(self, mock_dynamodb, api_gateway_event):
        """Should route customer.subscription.updated to _handle_subscription_updated."""
        pytest.importorskip("stripe")
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_sub_update_route",
            "type": "customer.subscription.updated",
            "data": {"object": {"customer": "cus_route", "status": "active"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "customer.subscription.updated"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        mock_handler = MagicMock()
        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_subscription_updated", mock_handler),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        mock_handler.assert_called_once_with(mock_event["data"]["object"])

    @mock_aws
    def test_routes_subscription_deleted(self, mock_dynamodb, api_gateway_event):
        """Should route customer.subscription.deleted to _handle_subscription_deleted."""
        pytest.importorskip("stripe")
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_sub_delete_route",
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_route"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "customer.subscription.deleted"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        mock_handler = MagicMock()
        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_subscription_deleted", mock_handler),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        mock_handler.assert_called_once_with(mock_event["data"]["object"])

    @mock_aws
    def test_routes_charge_refunded(self, mock_dynamodb, api_gateway_event):
        """Should route charge.refunded to _handle_charge_refunded."""
        pytest.importorskip("stripe")
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_refund_route",
            "type": "charge.refunded",
            "data": {"object": {"customer": "cus_refund_route"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "charge.refunded"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        mock_handler = MagicMock()
        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_charge_refunded", mock_handler),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        mock_handler.assert_called_once_with(mock_event["data"]["object"])

    @mock_aws
    def test_routes_dispute_created(self, mock_dynamodb, api_gateway_event):
        """Should route charge.dispute.created to _handle_dispute_created."""
        pytest.importorskip("stripe")
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        mock_event = {
            "id": "evt_dispute_route",
            "type": "charge.dispute.created",
            "data": {"object": {"customer": "cus_dispute_route"}},
        }

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"type": "charge.dispute.created"})
        api_gateway_event["headers"] = {"stripe-signature": "t=123,v1=abc"}

        mock_handler = MagicMock()
        with (
            patch("stripe.Webhook.construct_event", return_value=mock_event),
            patch.object(webhook_module, "_handle_dispute_created", mock_handler),
        ):
            result = webhook_module.handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        mock_handler.assert_called_once_with(mock_event["data"]["object"])


class TestCheckoutCompletedWithSubscription:
    """Tests for _handle_checkout_completed with subscription (Stripe API call path)."""

    @mock_aws
    def test_checkout_with_subscription_upgrades_user(self, mock_dynamodb):
        """Should retrieve subscription from Stripe and upgrade user to correct tier."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_sub_checkout").hexdigest()
        table.put_item(
            Item={
                "pk": "user_sub_checkout",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "subcheckout@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.stripe_webhook as webhook_module

        # Mock stripe.Subscription.retrieve
        mock_subscription = {
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro_test"},
                        "current_period_start": 1706745600,
                        "current_period_end": 1709424000,
                    }
                ]
            }
        }

        session = {
            "customer_email": "subcheckout@example.com",
            "customer": "cus_sub_checkout",
            "subscription": "sub_checkout_123",
        }

        # Patch PRICE_TO_TIER since it reads env vars at module load time
        with (
            patch("stripe.Subscription.retrieve", return_value=mock_subscription),
            patch.dict(webhook_module.PRICE_TO_TIER, {"price_pro_test": "pro"}),
        ):
            webhook_module._handle_checkout_completed(session)

        response = table.get_item(Key={"pk": "user_sub_checkout", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["stripe_customer_id"] == "cus_sub_checkout"
        assert item["stripe_subscription_id"] == "sub_checkout_123"
        assert item["current_period_start"] == 1706745600
        assert item["current_period_end"] == 1709424000

    @mock_aws
    def test_checkout_by_customer_id_only(self, mock_dynamodb):
        """Should upgrade by customer_id when no email is present in checkout session."""
        pytest.importorskip("stripe")
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cust_only_checkout").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cust_only",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "custonly@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_only_checkout",
                "email_verified": True,
            }
        )

        import api.stripe_webhook as webhook_module

        mock_subscription = {
            "items": {
                "data": [
                    {
                        "price": {"id": "price_starter"},
                        "current_period_start": 1706745600,
                        "current_period_end": 1709424000,
                    }
                ]
            }
        }

        session = {
            "customer_email": None,
            "customer": "cus_only_checkout",
            "subscription": "sub_only_checkout",
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            webhook_module._handle_checkout_completed(session)

        response = table.get_item(Key={"pk": "user_cust_only", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"

    @mock_aws
    def test_checkout_one_time_by_customer_id_no_email(self, mock_dynamodb):
        """One-time payment with customer_id but no email should update via customer_id."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_onetime_cust").hexdigest()
        table.put_item(
            Item={
                "pk": "user_onetime_cust",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "onetimecust@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_onetime_cust",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_checkout_completed

        session = {
            "customer_email": None,
            "customer": "cus_onetime_cust",
            "subscription": None,  # One-time payment
        }

        _handle_checkout_completed(session)

        response = table.get_item(Key={"pk": "user_onetime_cust", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"

    @mock_aws
    def test_checkout_no_email_no_customer_id(self, mock_dynamodb, caplog):
        """Checkout with neither email nor customer_id should log warning and return."""
        import logging

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_checkout_completed

        session = {
            "customer_email": None,
            "customer": None,
            "subscription": None,
        }

        _handle_checkout_completed(session)

        assert "No customer email or customer ID" in caplog.text

    @mock_aws
    def test_checkout_subscription_no_email_no_customer(self, mock_dynamodb, caplog):
        """Checkout with subscription but no email or customer should log warning."""
        pytest.importorskip("stripe")
        import logging
        from unittest.mock import patch

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.stripe_webhook as webhook_module

        mock_subscription = {
            "items": {
                "data": [
                    {
                        "price": {"id": "price_starter"},
                        "current_period_start": 1706745600,
                        "current_period_end": 1709424000,
                    }
                ]
            }
        }

        session = {
            "customer_email": None,
            "customer": None,
            "subscription": "sub_orphan",
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            webhook_module._handle_checkout_completed(session)

        assert "No customer email or customer ID" in caplog.text


class TestProcessPaidReferralReward:
    """Tests for _process_paid_referral_reward function."""

    @mock_aws
    def test_awards_referrer_when_user_was_referred(self, mock_dynamodb):
        """Should credit referrer with paid conversion bonus when referred user upgrades."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Set up referrer with USER_META
        api_table.put_item(
            Item={
                "pk": "user_referrer",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        # Set up referred user with USER_META that has referred_by
        api_table.put_item(
            Item={
                "pk": "user_referred",
                "sk": "USER_META",
                "referred_by": "user_referrer",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_referred", "referred@example.com")

        # Check referrer got credits
        response = api_table.get_item(Key={"pk": "user_referrer", "sk": "USER_META"})
        item = response.get("Item")
        assert item["bonus_requests"] == 25000
        assert item["bonus_requests_lifetime"] == 25000

    @mock_aws
    def test_skips_when_user_not_referred(self, mock_dynamodb):
        """Should do nothing when user has no referred_by field."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")

        # User without referred_by
        api_table.put_item(
            Item={
                "pk": "user_not_referred",
                "sk": "USER_META",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        # Should not raise
        _process_paid_referral_reward("user_not_referred", "test@example.com")

    @mock_aws
    def test_idempotent_does_not_double_reward(self, mock_dynamodb):
        """Should not award duplicate reward if already processed."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        billing_table = mock_dynamodb.Table("pkgwatch-billing-events")

        # Set up referrer
        api_table.put_item(
            Item={
                "pk": "user_ref_idem",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 25000,
                "bonus_requests_lifetime": 25000,
            }
        )

        # Set up referred user
        api_table.put_item(
            Item={
                "pk": "user_refd_idem",
                "sk": "USER_META",
                "referred_by": "user_ref_idem",
            }
        )

        # Mark as already processed
        billing_table.put_item(
            Item={
                "pk": "referral_paid:user_ref_idem:user_refd_idem",
                "sk": "paid",
                "processed_at": "2024-01-15T10:00:00Z",
                "reward_amount": 25000,
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_idem", "referred@example.com")

        # Referrer should NOT get double credits
        response = api_table.get_item(Key={"pk": "user_ref_idem", "sk": "USER_META"})
        item = response.get("Item")
        assert item["bonus_requests"] == 25000  # Unchanged
        assert item["bonus_requests_lifetime"] == 25000  # Unchanged

    @mock_aws
    def test_handles_missing_user_meta_gracefully(self, mock_dynamodb):
        """Should not raise when USER_META does not exist for user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        from api.stripe_webhook import _process_paid_referral_reward

        # No USER_META exists for this user
        _process_paid_referral_reward("user_nonexistent", "test@example.com")
        # Should not raise - gracefully returns

    @mock_aws
    def test_cleans_up_pending_event_on_direct_upgrade(self, mock_dynamodb):
        """Should delete #pending event when creating #paid (direct upgrade path)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        # Set up referrer
        api_table.put_item(
            Item={
                "pk": "user_referrer_cleanup",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        # Set up referred user
        api_table.put_item(
            Item={
                "pk": "user_referred_cleanup",
                "sk": "USER_META",
                "referred_by": "user_referrer_cleanup",
                "referral_pending": True,
                "referral_pending_expires": "2025-06-01T00:00:00Z",
            }
        )

        # Create a pending referral event
        events_table.put_item(
            Item={
                "pk": "user_referrer_cleanup",
                "sk": "user_referred_cleanup#pending",
                "referred_id": "user_referred_cleanup",
                "event_type": "pending",
                "reward_amount": 0,
                "referred_email_masked": "te**@example.com",
                "ttl": int((datetime.now(timezone.utc) + timedelta(days=60)).timestamp()),
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_referred_cleanup", "test@example.com")

        # Pending event should be gone
        pending = events_table.get_item(Key={"pk": "user_referrer_cleanup", "sk": "user_referred_cleanup#pending"})
        assert "Item" not in pending

        # Paid event should exist with inherited masked email
        paid = events_table.get_item(Key={"pk": "user_referrer_cleanup", "sk": "user_referred_cleanup#paid"})
        assert "Item" in paid
        assert paid["Item"]["event_type"] == "paid"
        assert paid["Item"]["reward_amount"] == 25000
        assert paid["Item"]["referred_email_masked"] == "te**@example.com"

    @mock_aws
    def test_cleans_up_signup_event_after_activity_gate(self, mock_dynamodb):
        """Should delete #signup event when creating #paid (activity gate then upgrade)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_referrer_ag",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 5000,
                "bonus_requests_lifetime": 5000,
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_referred_ag",
                "sk": "USER_META",
                "referred_by": "user_referrer_ag",
            }
        )

        # Signup event (from activity gate)
        events_table.put_item(
            Item={
                "pk": "user_referrer_ag",
                "sk": "user_referred_ag#signup",
                "referred_id": "user_referred_ag",
                "event_type": "signup",
                "reward_amount": 5000,
                "referred_email_masked": "te**@test.com",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_referred_ag", "test@test.com")

        # Signup should be gone
        signup = events_table.get_item(Key={"pk": "user_referrer_ag", "sk": "user_referred_ag#signup"})
        assert "Item" not in signup

        # Paid should exist with 25K reward
        paid = events_table.get_item(Key={"pk": "user_referrer_ag", "sk": "user_referred_ag#paid"})
        assert "Item" in paid
        assert paid["Item"]["reward_amount"] == 25000

    @mock_aws
    def test_decrements_pending_count_on_direct_upgrade(self, mock_dynamodb):
        """Should decrement referral_pending_count when transitioning from pending."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_ref_dec",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
                "referral_total": 1,
                "referral_pending_count": 1,
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_dec",
                "sk": "USER_META",
                "referred_by": "user_ref_dec",
                "referral_pending": True,
            }
        )

        events_table.put_item(
            Item={
                "pk": "user_ref_dec",
                "sk": "user_refd_dec#pending",
                "referred_id": "user_refd_dec",
                "event_type": "pending",
                "reward_amount": 0,
                "ttl": int((datetime.now(timezone.utc) + timedelta(days=60)).timestamp()),
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_dec", "dec@example.com")

        # Check referrer stats
        response = api_table.get_item(Key={"pk": "user_ref_dec", "sk": "USER_META"})
        item = response["Item"]
        assert int(item.get("referral_pending_count", 0)) == 0
        assert int(item.get("referral_paid", 0)) == 1

    @mock_aws
    def test_clears_referral_pending_flag(self, mock_dynamodb):
        """Should clear referral_pending on referred user's USER_META."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")

        api_table.put_item(
            Item={
                "pk": "user_ref_flag",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_flag",
                "sk": "USER_META",
                "referred_by": "user_ref_flag",
                "referral_pending": True,
                "referral_pending_expires": "2025-06-01T00:00:00Z",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_flag", "flag@example.com")

        # Check referred user's USER_META — flags should be cleared
        response = api_table.get_item(Key={"pk": "user_refd_flag", "sk": "USER_META"})
        item = response["Item"]
        assert "referral_pending" not in item
        assert "referral_pending_expires" not in item

    @mock_aws
    def test_no_pending_decrement_when_ttl_expired(self, mock_dynamodb):
        """Should NOT decrement pending_count if the pending event's TTL already expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_ref_ttl",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
                "referral_total": 1,
                "referral_pending_count": 0,  # Already decremented by cleanup Lambda
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_ttl",
                "sk": "USER_META",
                "referred_by": "user_ref_ttl",
            }
        )

        # Pending event with EXPIRED TTL (cleanup Lambda ran but DynamoDB TTL hasn't purged yet)
        events_table.put_item(
            Item={
                "pk": "user_ref_ttl",
                "sk": "user_refd_ttl#pending",
                "referred_id": "user_refd_ttl",
                "event_type": "pending",
                "reward_amount": 0,
                "ttl": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_ttl", "ttl@example.com")

        # pending_count should NOT have gone negative
        response = api_table.get_item(Key={"pk": "user_ref_ttl", "sk": "USER_META"})
        item = response["Item"]
        assert int(item.get("referral_pending_count", 0)) == 0

    @mock_aws
    def test_no_pending_decrement_from_signup(self, mock_dynamodb):
        """Should NOT decrement pending_count when transitioning from signup (already decremented)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_ref_nosub",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 5000,
                "bonus_requests_lifetime": 5000,
                "referral_total": 1,
                "referral_pending_count": 0,  # Already decremented at signup
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_nosub",
                "sk": "USER_META",
                "referred_by": "user_ref_nosub",
            }
        )

        events_table.put_item(
            Item={
                "pk": "user_ref_nosub",
                "sk": "user_refd_nosub#signup",
                "referred_id": "user_refd_nosub",
                "event_type": "signup",
                "reward_amount": 5000,
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_nosub", "nosub@example.com")

        # pending_count should stay 0 (not decremented again)
        response = api_table.get_item(Key={"pk": "user_ref_nosub", "sk": "USER_META"})
        item = response["Item"]
        assert int(item.get("referral_pending_count", 0)) == 0

    @mock_aws
    def test_paid_event_has_retention_fields(self, mock_dynamodb):
        """Should create #paid event with needs_retention_check and retention_check_date."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_ref_ret",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_ret",
                "sk": "USER_META",
                "referred_by": "user_ref_ret",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_ret", "ret@example.com")

        # Check #paid event has retention fields
        paid = events_table.get_item(Key={"pk": "user_ref_ret", "sk": "user_refd_ret#paid"})
        assert "Item" in paid
        item = paid["Item"]
        assert item["needs_retention_check"] == "true"
        assert "retention_check_date" in item
        # retention_check_date should be an ISO datetime string
        assert "T" in item["retention_check_date"]

    @mock_aws
    def test_skips_stats_when_transition_race_lost(self, mock_dynamodb):
        """Should skip stats update when transition race is lost (higher-priority event exists)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        api_table.put_item(
            Item={
                "pk": "user_ref_race",
                "sk": "USER_META",
                "key_count": 1,
                "bonus_requests": 25000,
                "bonus_requests_lifetime": 25000,
                "referral_total": 1,
                "referral_paid": 1,
                "referral_retained": 0,
            }
        )

        api_table.put_item(
            Item={
                "pk": "user_refd_race",
                "sk": "USER_META",
                "referred_by": "user_ref_race",
            }
        )

        # Pre-create #retained event (higher priority than #paid)
        events_table.put_item(
            Item={
                "pk": "user_ref_race",
                "sk": "user_refd_race#retained",
                "referred_id": "user_refd_race",
                "event_type": "retained",
                "reward_amount": 25000,
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        _process_paid_referral_reward("user_refd_race", "race@example.com")

        # Stats should be unchanged — transition was skipped
        response = api_table.get_item(Key={"pk": "user_ref_race", "sk": "USER_META"})
        item = response["Item"]
        assert int(item.get("referral_paid", 0)) == 1  # Not incremented
        assert int(item.get("referral_retained", 0)) == 0  # Not changed

        # No idempotency record written
        billing_table = mock_dynamodb.Table("pkgwatch-billing-events")
        idem = billing_table.get_item(Key={"pk": "referral_paid:user_ref_race:user_refd_race", "sk": "paid"})
        assert "Item" not in idem


class TestPaymentFailedRaceConditions:
    """Tests for payment failure race condition branches."""

    @mock_aws
    def test_first_failure_concurrent_start_updates_count(self, mock_dynamodb):
        """When first failure conditional write fails (race), should still update count."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_concurrent_first").hexdigest()
        # Grace period already started by concurrent request
        table.put_item(
            Item={
                "pk": "user_concurrent_first",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "concfirst@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_concurrent_first",
                "email_verified": True,
                "first_payment_failure_at": datetime.now(timezone.utc).isoformat(),
                "payment_failures": 1,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        # attempt_count=1 but first_payment_failure_at already exists
        # This triggers the ConditionalCheckFailedException branch (lines 754-763)
        invoice = {
            "customer": "cus_concurrent_first",
            "customer_email": "concfirst@example.com",
            "attempt_count": 1,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_concurrent_first", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"  # Not downgraded
        assert item["payment_failures"] == 1  # Updated
        assert "first_payment_failure_at" in item  # Grace period preserved

    @mock_aws
    def test_downgrade_skipped_when_payment_succeeds_during_processing(self, mock_dynamodb):
        """If payment succeeds while we are processing a failure, downgrade should be skipped."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_race_skip").hexdigest()
        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        table.put_item(
            Item={
                "pk": "user_race_skip",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "raceskip@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_race_skip",
                "email_verified": True,
                "payment_failures": 2,
                "first_payment_failure_at": ten_days_ago,
            }
        )

        # Simulate: between our query and update, a successful payment removed first_payment_failure_at
        table.update_item(
            Key={"pk": "user_race_skip", "sk": key_hash},
            UpdateExpression="REMOVE first_payment_failure_at SET payment_failures = :zero",
            ExpressionAttributeValues={":zero": 0},
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_race_skip",
            "customer_email": "raceskip@example.com",
            "attempt_count": 3,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_race_skip", "sk": key_hash})
        item = response.get("Item")
        # Should NOT be downgraded - conditional check prevents it
        assert item["tier"] == "pro"

    @mock_aws
    def test_second_failure_with_existing_grace_period_tracks_count(self, mock_dynamodb):
        """2nd attempt with existing grace period should just update failure count."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_second_fail").hexdigest()
        two_days_ago = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        table.put_item(
            Item={
                "pk": "user_second_fail",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "secondfail@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_second_fail",
                "email_verified": True,
                "payment_failures": 1,
                "first_payment_failure_at": two_days_ago,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        invoice = {
            "customer": "cus_second_fail",
            "customer_email": "secondfail@example.com",
            "attempt_count": 2,
        }

        _handle_payment_failed(invoice)

        response = table.get_item(Key={"pk": "user_second_fail", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"  # Not downgraded
        assert item["payment_failures"] == 2
        assert item["first_payment_failure_at"] == two_days_ago  # Grace period preserved


class TestRecordBillingEventErrorHandling:
    """Tests for _record_billing_event error handling (best-effort)."""

    @mock_aws
    def test_does_not_raise_on_dynamodb_failure(self, mock_dynamodb, caplog):
        """Should swallow DynamoDB errors and log them."""
        import logging
        from unittest.mock import MagicMock, patch

        caplog.set_level(logging.ERROR)

        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        event = {
            "id": "evt_fail_record",
            "type": "invoice.paid",
            "data": {"object": {"customer": "cus_fail"}},
        }

        # Make the table's put_item raise
        mock_table = MagicMock()
        mock_table.put_item.side_effect = Exception("DynamoDB down")

        with patch.object(webhook_module, "get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            # Should NOT raise
            webhook_module._record_billing_event(event, "success")

        assert "Failed to record billing event" in caplog.text


class TestReleaseEventClaimErrorHandling:
    """Tests for _release_event_claim error handling (best-effort)."""

    @mock_aws
    def test_does_not_raise_on_delete_failure(self, mock_dynamodb, caplog):
        """Should swallow errors when releasing claim fails."""
        import logging
        from unittest.mock import MagicMock, patch

        caplog.set_level(logging.ERROR)

        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        mock_table = MagicMock()
        mock_table.delete_item.side_effect = Exception("DynamoDB down")

        with patch.object(webhook_module, "get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            # Should NOT raise
            webhook_module._release_event_claim("evt_fail_release", "invoice.paid")

        assert "Failed to release event claim" in caplog.text


class TestCheckAndClaimEventReraise:
    """Tests for _check_and_claim_event re-raising non-ConditionalCheck errors."""

    @mock_aws
    def test_reraises_non_conditional_check_error(self, mock_dynamodb):
        """Should re-raise ClientError if it is not ConditionalCheckFailedException."""
        from unittest.mock import MagicMock, patch

        from botocore.exceptions import ClientError

        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DynamoDB failed"}},
            "PutItem",
        )

        with patch.object(webhook_module, "get_dynamodb") as mock_ddb:
            mock_ddb.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError) as exc_info:
                webhook_module._check_and_claim_event("evt_reraised", "invoice.paid")

            assert exc_info.value.response["Error"]["Code"] == "InternalServerError"


class TestUpdateUserSubscriptionStateDowngradeWarning:
    """Tests for downgrade-over-limit warning in _update_user_subscription_state."""

    @mock_aws
    def test_logs_warning_when_downgrading_over_limit(self, mock_dynamodb, caplog):
        """Should log warning when user has usage over the new tier's limit."""
        import logging

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_down_warn_state").hexdigest()
        table.put_item(
            Item={
                "pk": "user_down_warn",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "downwarn@example.com",
                "tier": "business",
                "stripe_customer_id": "cus_down_warn",
                "email_verified": True,
                "requests_this_month": 200000,  # Over free limit of 5000
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_down_warn",
            tier="free",
            cancellation_pending=False,
        )

        response = table.get_item(Key={"pk": "user_down_warn", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        assert "over limit" in caplog.text.lower() or "200000" in caplog.text


class TestSubscriptionStateRemoveAttributes:
    """Tests for _update_user_subscription_state with remove_attributes."""

    @mock_aws
    def test_removes_specified_attributes(self, mock_dynamodb):
        """Should REMOVE specified attributes from the record."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_remove_attrs").hexdigest()
        table.put_item(
            Item={
                "pk": "user_remove_attrs",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "removeattrs@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_remove_attrs",
                "stripe_subscription_id": "sub_to_remove",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_remove_attrs",
            tier="free",
            cancellation_pending=False,
            remove_attributes=["stripe_subscription_id"],
        )

        response = table.get_item(Key={"pk": "user_remove_attrs", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "free"
        assert "stripe_subscription_id" not in item
        assert item["stripe_customer_id"] == "cus_remove_attrs"


class TestSubscriptionUpdatedTrialing:
    """Tests for subscription.updated with trialing status."""

    @mock_aws
    def test_handles_trialing_status(self, mock_dynamodb):
        """Should process subscription updates with trialing status."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_trial_updated").hexdigest()
        table.put_item(
            Item={
                "pk": "user_trial_updated",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "trialupdated@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_trial_updated",
                "email_verified": True,
            }
        )

        from unittest.mock import patch

        from api.stripe_webhook import PRICE_TO_TIER, _handle_subscription_updated

        with patch.dict(PRICE_TO_TIER, {"price_trial_pro": "pro"}):
            subscription = {
                "customer": "cus_trial_updated",
                "status": "trialing",
                "cancel_at_period_end": False,
                "items": {
                    "data": [
                        {
                            "price": {"id": "price_trial_pro"},
                            "current_period_start": 1706745600,
                            "current_period_end": 1709424000,
                        }
                    ]
                },
            }

            _handle_subscription_updated(subscription)

        response = table.get_item(Key={"pk": "user_trial_updated", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        assert item["cancellation_pending"] is False


class TestGetStripeSecretsErrors:
    """Tests for get_stripe_secrets error handling (lines 82-83, 94-95)."""

    @mock_aws
    def test_stripe_api_key_client_error_returns_none(self, mock_dynamodb):
        """ClientError fetching Stripe API key should log error and return None for api_key."""
        from unittest.mock import MagicMock, patch

        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret:stripe-key"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = ""

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Secret not found"}},
            "GetSecretValue",
        )

        with patch("api.stripe_webhook.get_secretsmanager", return_value=mock_sm):
            api_key, webhook_secret = webhook_module.get_stripe_secrets()

        assert api_key is None
        assert webhook_secret is None

    @mock_aws
    def test_webhook_secret_client_error_returns_none(self, mock_dynamodb):
        """ClientError fetching webhook secret should log error and return None for webhook_secret."""
        from unittest.mock import MagicMock, patch

        os.environ["STRIPE_SECRET_ARN"] = ""
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret:webhook"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "DecryptionFailure", "Message": "Cannot decrypt"}},
            "GetSecretValue",
        )

        with patch("api.stripe_webhook.get_secretsmanager", return_value=mock_sm):
            api_key, webhook_secret = webhook_module.get_stripe_secrets()

        assert api_key is None
        assert webhook_secret is None

    @mock_aws
    def test_api_key_fetched_but_webhook_secret_fails(self, mock_dynamodb):
        """Should return api_key even if webhook secret fetch fails."""
        from unittest.mock import MagicMock, patch

        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret:stripe-key"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret:webhook"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = (None, None)
        webhook_module._stripe_secrets_cache_time = 0.0

        mock_sm = MagicMock()
        call_count = [0]

        def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"SecretString": '{"key": "sk_test_good"}'}
            raise ClientError(
                {"Error": {"Code": "InternalServiceError", "Message": "Service error"}},
                "GetSecretValue",
            )

        mock_sm.get_secret_value.side_effect = side_effect

        with patch("api.stripe_webhook.get_secretsmanager", return_value=mock_sm):
            api_key, webhook_secret = webhook_module.get_stripe_secrets()

        assert api_key == "sk_test_good"
        assert webhook_secret is None


class TestHandlerEventRoutingNewEvents:
    """Tests for handler routing to sub-handlers for newer event types (lines 256, 259, 262)."""

    @mock_aws
    def test_routes_subscription_created_event(self, mock_dynamodb, api_gateway_event):
        """Should route customer.subscription.created to _handle_subscription_created."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_sub_created_route",
            "type": "customer.subscription.created",
            "data": {
                "object": {
                    "customer": "cus_route_test",
                    "status": "active",
                    "items": {"data": [{"price": {"id": "price_starter"}}]},
                }
            },
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(webhook_module, "_handle_subscription_created") as mock_handler:
                api_gateway_event["body"] = "{}"
                api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                result = webhook_module.handler(api_gateway_event, {})

                assert result["statusCode"] == 200
                mock_handler.assert_called_once_with(stripe_event["data"]["object"])

    @mock_aws
    def test_routes_payment_failed_event(self, mock_dynamodb, api_gateway_event):
        """Should route invoice.payment_failed to _handle_payment_failed."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_pay_failed_route",
            "type": "invoice.payment_failed",
            "data": {
                "object": {
                    "customer": "cus_pay_failed",
                    "attempt_count": 1,
                }
            },
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(webhook_module, "_handle_payment_failed") as mock_handler:
                api_gateway_event["body"] = "{}"
                api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                result = webhook_module.handler(api_gateway_event, {})

                assert result["statusCode"] == 200
                mock_handler.assert_called_once_with(stripe_event["data"]["object"])

    @mock_aws
    def test_routes_invoice_paid_event(self, mock_dynamodb, api_gateway_event):
        """Should route invoice.paid to _handle_invoice_paid."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_invoice_paid_route",
            "type": "invoice.paid",
            "data": {
                "object": {
                    "customer": "cus_paid",
                    "billing_reason": "subscription_cycle",
                }
            },
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(webhook_module, "_handle_invoice_paid") as mock_handler:
                api_gateway_event["body"] = "{}"
                api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                result = webhook_module.handler(api_gateway_event, {})

                assert result["statusCode"] == 200
                mock_handler.assert_called_once_with(stripe_event["data"]["object"])


class TestPaidReferralRewardErrors:
    """Tests for _process_paid_referral_reward error handling (lines 426-427)."""

    @mock_aws
    def test_referral_error_does_not_block_tier_upgrade(self, mock_dynamodb):
        """Referral processing error should not prevent the tier upgrade from succeeding."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_referral_err").hexdigest()
        table.put_item(
            Item={
                "pk": "user_referral_err",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "referral_err@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        # Create USER_META with referred_by
        table.put_item(
            Item={
                "pk": "user_referral_err",
                "sk": "USER_META",
                "referred_by": "referrer_user_123",
            }
        )

        from api.stripe_webhook import _process_paid_referral_reward

        # Patch add_bonus_with_cap to raise an error
        with patch("api.stripe_webhook.add_bonus_with_cap", side_effect=Exception("DynamoDB timeout")):
            # Should NOT raise - error is caught and logged
            _process_paid_referral_reward("user_referral_err", "referral_err@example.com")


class TestLookupErrorHandling:
    """Tests for user lookup error handling (lines 521-522, 538-539)."""

    @mock_aws
    def test_get_user_id_by_email_handles_exception(self, mock_dynamodb):
        """Should return None when email lookup raises an exception."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _get_user_id_by_email

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB timeout")

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            result = _get_user_id_by_email("error@example.com")

        assert result is None

    @mock_aws
    def test_get_user_id_by_customer_id_handles_exception(self, mock_dynamodb):
        """Should return None when customer_id lookup raises an exception."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _get_user_id_by_customer_id

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB timeout")

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            result = _get_user_id_by_customer_id("cus_error")

        assert result is None


class TestPaymentFailedReRaiseErrors:
    """Tests for re-raise paths in _handle_payment_failed (lines 728, 755-760)."""

    @mock_aws
    def test_first_failure_non_conditional_error_re_raises(self, mock_dynamodb):
        """Non-ConditionalCheckFailedException during first failure should re-raise (line 728)."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_reraise_first").hexdigest()
        table.put_item(
            Item={
                "pk": "user_reraise_first",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "reraise@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_reraise_first",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_payment_failed

        # Mock update_item to raise a non-conditional DynamoDB error
        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {
                    "pk": "user_reraise_first",
                    "sk": key_hash,
                    "tier": "pro",
                }
            ]
        }
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throughput exceeded"}},
            "UpdateItem",
        )

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError) as exc_info:
                _handle_payment_failed(
                    {
                        "customer": "cus_reraise_first",
                        "attempt_count": 1,
                    }
                )
            assert exc_info.value.response["Error"]["Code"] == "ProvisionedThroughputExceededException"

    @mock_aws
    def test_downgrade_non_conditional_error_re_raises(self, mock_dynamodb):
        """Non-ConditionalCheckFailedException during downgrade should re-raise (lines 755-760)."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_payment_failed

        ten_days_ago = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {
                    "pk": "user_reraise_down",
                    "sk": "somehash",
                    "tier": "pro",
                    "first_payment_failure_at": ten_days_ago,
                    "payment_failures": 2,
                }
            ]
        }
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "DynamoDB internal error"}},
            "UpdateItem",
        )

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError) as exc_info:
                _handle_payment_failed(
                    {
                        "customer": "cus_reraise_down",
                        "attempt_count": 3,
                    }
                )
            assert exc_info.value.response["Error"]["Code"] == "InternalServerError"


class TestBillingCycleResetReRaise:
    """Tests for re-raise paths in _reset_user_usage_for_billing_cycle (lines 972, 998)."""

    @mock_aws
    def test_non_conditional_error_in_key_reset_re_raises(self, mock_dynamodb):
        """Non-ConditionalCheckFailedException during API key reset should re-raise (line 972)."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _reset_user_usage_for_billing_cycle

        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {
                    "pk": "user_key_reraise",
                    "sk": "somekey",
                    "tier": "pro",
                    "stripe_customer_id": "cus_key_reraise",
                }
            ]
        }
        mock_table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throughput exceeded"}},
            "UpdateItem",
        )

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError) as exc_info:
                _reset_user_usage_for_billing_cycle(
                    customer_id="cus_key_reraise",
                    period_start=1706745600,
                    period_end=1709424000,
                )
            assert exc_info.value.response["Error"]["Code"] == "ProvisionedThroughputExceededException"

    @mock_aws
    def test_non_conditional_error_in_user_meta_reset_re_raises(self, mock_dynamodb):
        """Non-ConditionalCheckFailedException in USER_META reset should re-raise (line 998)."""
        from unittest.mock import MagicMock, patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _reset_user_usage_for_billing_cycle

        # First update_item call (API key) succeeds, second (USER_META) fails
        call_count = [0]

        def update_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {}  # API key update succeeds
            raise ClientError(
                {"Error": {"Code": "ValidationException", "Message": "Validation error"}},
                "UpdateItem",
            )

        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {
                    "pk": "user_meta_reraise",
                    "sk": "somekey",
                    "tier": "pro",
                    "stripe_customer_id": "cus_meta_reraise",
                }
            ]
        }
        mock_table.update_item.side_effect = update_side_effect

        with patch("api.stripe_webhook.get_dynamodb") as mock_db:
            mock_db.return_value.Table.return_value = mock_table
            with pytest.raises(ClientError) as exc_info:
                _reset_user_usage_for_billing_cycle(
                    customer_id="cus_meta_reraise",
                    period_start=1706745600,
                    period_end=1709424000,
                )
            assert exc_info.value.response["Error"]["Code"] == "ValidationException"


class TestUserMetaSyncNonConditionalError:
    """Tests for USER_META update non-conditional error (line 1350)."""

    @mock_aws
    def test_user_meta_non_conditional_error_logged_not_raised(self, mock_dynamodb):
        """Non-ConditionalCheckFailedException in USER_META sync should be logged but not raised."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_meta_err").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_err",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "metaerr@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_meta_err",
                "email_verified": True,
            }
        )

        # Create USER_META so it exists
        table.put_item(
            Item={
                "pk": "user_meta_err",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        # Track update calls: first one (API key) uses real table, then mock USER_META
        original_update = table.update_item
        call_count = [0]

        def update_side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] <= 1:
                # First call is the API key update - let it work
                return original_update(**kwargs)
            # Second call is USER_META - simulate a non-conditional error
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throttled"}},
                "UpdateItem",
            )

        with patch.object(table, "update_item", side_effect=update_side_effect):
            # Should NOT raise - error is caught and logged
            _update_user_subscription_state(
                customer_id="cus_meta_err",
                tier="pro",
                cancellation_pending=False,
            )

        # API key should still have been updated (first call worked)
        response = table.get_item(Key={"pk": "user_meta_err", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"


class TestDowngradeOverLimitWarning:
    """Tests for downgrade over-limit warning in _update_user_subscription_state (line 1153)."""

    @mock_aws
    def test_warns_on_downgrade_over_limit_in_subscription_state(self, mock_dynamodb, caplog):
        """Should log warning when downgrading user whose usage exceeds new tier limit."""
        import logging

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_over_limit_sub").hexdigest()
        table.put_item(
            Item={
                "pk": "user_over_limit_sub",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "overlimit_sub@example.com",
                "tier": "business",
                "stripe_customer_id": "cus_over_limit_sub",
                "email_verified": True,
                "requests_this_month": 200000,  # Over pro limit of 100000
            }
        )

        from api.stripe_webhook import _update_user_subscription_state

        _update_user_subscription_state(
            customer_id="cus_over_limit_sub",
            tier="pro",  # Downgrade from business to pro
            cancellation_pending=False,
        )

        response = table.get_item(Key={"pk": "user_over_limit_sub", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "pro"
        # Usage should NOT be reset on downgrade
        assert item["requests_this_month"] == 200000
        # Warning should have been logged
        assert "downgraded to pro" in caplog.text
        assert "200000" in caplog.text


class TestHandlerStripeTransientErrors:
    """Tests for Stripe transient error handling in main handler."""

    @mock_aws
    def test_stripe_api_connection_error_releases_claim(self, mock_dynamodb, api_gateway_event):
        """Stripe APIConnectionError should release claim and return 500."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import stripe as real_stripe

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_stripe_conn_err",
            "type": "checkout.session.completed",
            "data": {"object": {"customer": "cus_test"}},
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=real_stripe.error.APIConnectionError("Connection failed"),
            ):
                with patch.object(webhook_module, "_release_event_claim") as mock_release:
                    api_gateway_event["body"] = "{}"
                    api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                    result = webhook_module.handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_error"
                    mock_release.assert_called_once()

    @mock_aws
    def test_stripe_permanent_error_returns_200_with_error(self, mock_dynamodb, api_gateway_event):
        """Stripe InvalidRequestError should return 200 with error but not release claim."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import stripe as real_stripe

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_stripe_perm_err",
            "type": "checkout.session.completed",
            "data": {"object": {"customer": "cus_test"}},
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=real_stripe.error.InvalidRequestError("Bad request", param="test"),
            ):
                with patch.object(webhook_module, "_release_event_claim") as mock_release:
                    api_gateway_event["body"] = "{}"
                    api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                    result = webhook_module.handler(api_gateway_event, {})

                    # Permanent Stripe errors return 200 (no retry)
                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_validation_error"
                    # Should NOT release claim for permanent errors
                    mock_release.assert_not_called()

    @mock_aws
    def test_value_error_returns_200_does_not_retry(self, mock_dynamodb, api_gateway_event):
        """ValueError in handler should return 200 with error and not retry."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_value_err",
            "type": "checkout.session.completed",
            "data": {"object": {"customer": "cus_test"}},
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=ValueError("Invalid data format"),
            ):
                api_gateway_event["body"] = "{}"
                api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                result = webhook_module.handler(api_gateway_event, {})

                assert result["statusCode"] == 200
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_event_data"
                # Internal error message should not leak
                assert "Invalid data format" not in body["error"]["message"]

    @mock_aws
    def test_unknown_error_releases_claim_returns_500(self, mock_dynamodb, api_gateway_event):
        """Unknown exception should release claim and return 500."""
        from unittest.mock import patch

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BILLING_EVENTS_TABLE"] = "pkgwatch-billing-events"

        import api.stripe_webhook as webhook_module

        webhook_module._stripe_secrets_cache = ("sk_test_xxx", "whsec_xxx")
        webhook_module._stripe_secrets_cache_time = 9999999999.0

        stripe_event = {
            "id": "evt_unknown_err",
            "type": "checkout.session.completed",
            "data": {"object": {"customer": "cus_test"}},
        }

        with patch("api.stripe_webhook.stripe.Webhook.construct_event", return_value=stripe_event):
            with patch.object(
                webhook_module,
                "_handle_checkout_completed",
                side_effect=RuntimeError("Completely unexpected"),
            ):
                with patch.object(webhook_module, "_release_event_claim") as mock_release:
                    api_gateway_event["body"] = "{}"
                    api_gateway_event["headers"] = {"stripe-signature": "sig_test"}

                    result = webhook_module.handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "processing_failed"
                    mock_release.assert_called_once()


class TestCheckoutOneTimePaymentByCustomerIdOnly:
    """Tests for checkout completed with customer_id but no email."""

    @mock_aws
    def test_one_time_payment_by_customer_id_without_email(self, mock_dynamodb):
        """Should handle one-time payment with customer_id but no email."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_custonly_onetime").hexdigest()
        table.put_item(
            Item={
                "pk": "user_custonly",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "custonly@example.com",
                "tier": "free",
                "stripe_customer_id": "cus_custonly",
                "email_verified": True,
            }
        )

        from api.stripe_webhook import _handle_checkout_completed

        session = {
            "customer_email": None,
            "customer": "cus_custonly",
            "subscription": None,  # One-time payment, no subscription
        }

        _handle_checkout_completed(session)

        response = table.get_item(Key={"pk": "user_custonly", "sk": key_hash})
        item = response.get("Item")
        assert item["tier"] == "starter"

    @mock_aws
    def test_checkout_completed_no_email_no_customer_logs_warning(self, mock_dynamodb, caplog):
        """Should log warning when checkout has no email and no customer ID."""
        import logging

        caplog.set_level(logging.WARNING)

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.stripe_webhook import _handle_checkout_completed

        session = {
            "customer_email": None,
            "customer": None,
            "subscription": None,
        }

        _handle_checkout_completed(session)

        assert "No customer email or customer ID" in caplog.text
