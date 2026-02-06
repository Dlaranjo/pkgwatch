"""
Tests for upgrade preview handler.
"""

import hashlib
import json
import os
import time
from unittest.mock import patch

import boto3
import stripe as stripe_module
from moto import mock_aws

import shared.billing_utils as billing_utils


class TestUpgradePreviewHandler:
    """Tests for the upgrade preview Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        # Clear cache
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            from api.upgrade_preview import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["body"] = json.dumps({"tier": "pro"})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401
            body = json.loads(result["body"])
            assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired or invalid."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=invalid_token"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 401
                body = json.loads(result["body"])
                assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_400_for_invalid_tier(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = json.dumps({"tier": "invalid"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_tier"

    @mock_aws
    def test_returns_400_for_starter_tier(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when trying to preview upgrade to starter (not allowed)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = json.dumps({"tier": "starter"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_tier"

    @mock_aws
    def test_returns_400_for_no_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user has no active subscription (free tier)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_free",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "free@example.com",
                "tier": "free",
                "email_verified": True,
                # No stripe_subscription_id
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_free", "email": "free@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_active_subscription"

    @mock_aws
    def test_returns_400_for_same_tier(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when trying to upgrade to same tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pro",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pro@example.com",
                "tier": "pro",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pro", "email": "pro@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "same_tier"

    @mock_aws
    def test_returns_400_for_downgrade(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when trying to downgrade."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_business",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "business@example.com",
                "tier": "business",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_business", "email": "business@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "downgrade_not_allowed"

    @mock_aws
    def test_returns_402_for_past_due_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 402 when subscription is past_due."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    # Mock subscription with past_due status
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "past_due",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 402
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "payment_required"

    @mock_aws
    def test_returns_400_for_canceled_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when subscription is canceled."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "canceled",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 400
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "subscription_invalid"

    @mock_aws
    def test_returns_preview_for_active_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return preview with proration details for active subscription."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    # Mock subscription
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                        "cancel_at_period_end": False,
                        "current_period_end": int(time.time()) + 86400 * 15,  # 15 days from now
                    }

                    # Mock invoice preview
                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 4400,  # $44.00
                        "currency": "usd",
                        "lines": {
                            "data": [
                                {"proration": True, "amount": -500},  # Credit
                                {"proration": False, "amount": 4900},  # New plan
                            ]
                        },
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert "preview" in body
                    preview = body["preview"]
                    assert preview["current_tier"] == "starter"
                    assert preview["new_tier"] == "pro"
                    assert preview["credit_amount_cents"] == 500
                    assert preview["new_plan_prorated_cents"] == 4900
                    assert preview["amount_due_cents"] == 4400
                    assert preview["amount_due_formatted"] == "$44.00"
                    assert preview["currency"] == "usd"
                    assert "proration_date" in preview
                    assert preview["cancellation_will_clear"] is False

    @mock_aws
    def test_returns_preview_for_trialing_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return preview for subscription in trial period."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    # Mock subscription in trialing status
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "trialing",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                        "cancel_at_period_end": False,
                        "current_period_end": int(time.time()) + 86400 * 7,
                    }

                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 4900,
                        "currency": "usd",
                        "lines": {"data": [{"proration": False, "amount": 4900}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["preview"]["new_tier"] == "pro"

    @mock_aws
    def test_indicates_cancellation_will_clear(self, mock_dynamodb, api_gateway_event):
        """Should indicate when upgrade will clear pending cancellation."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    # Mock subscription with cancel_at_period_end = True
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                        "cancel_at_period_end": True,
                        "current_period_end": int(time.time()) + 86400 * 15,
                    }

                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 4400,
                        "currency": "usd",
                        "lines": {"data": [{"proration": True, "amount": -500}, {"proration": False, "amount": 4900}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["preview"]["cancellation_will_clear"] is True

    @mock_aws
    def test_returns_500_on_stripe_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 on Stripe errors."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import stripe as stripe_module

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.StripeError = stripe_module.StripeError
                    mock_stripe.Subscription.retrieve.side_effect = stripe_module.StripeError("API error")

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_error"

    @mock_aws
    def test_returns_500_when_stripe_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API key is not configured (lines 112-113)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value=None):
            from api.upgrade_preview import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"]["cookie"] = "session=valid"
            api_gateway_event["body"] = json.dumps({"tier": "pro"})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "stripe_not_configured"

    @mock_aws
    def test_returns_400_for_invalid_json_body(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when request body is not valid JSON (lines 148-149)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = "{not valid json"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_returns_500_when_price_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when the price ID for the target tier is not set (lines 166-167).

        Prevents previewing an upgrade to a tier with no Stripe price configured.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        # Ensure price is NOT configured
        original_price = preview_module.TIER_TO_PRICE.get("pro")
        preview_module.TIER_TO_PRICE["pro"] = None

        try:
            with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
                with patch("api.auth_callback.verify_session_token") as mock_verify:
                    mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "price_not_configured"
        finally:
            preview_module.TIER_TO_PRICE["pro"] = original_price

    @mock_aws
    def test_skips_pending_records_in_user_lookup(self, mock_dynamodb, api_gateway_event):
        """Should skip PENDING records when looking up user subscription (line 186).

        PENDING records are pre-verification user records that should not be
        considered for billing operations.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()

        # PENDING record with a stripe subscription (should be skipped)
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": "PENDING",
                "email": "starter@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_pending",
                "stripe_subscription_id": "sub_pending",
            }
        )

        # Verified API key record with subscription
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {
                            "data": [
                                {
                                    "id": "si_123",
                                    "price": {"id": "price_starter_123"},
                                    "current_period_end": int(time.time()) + 86400 * 15,
                                }
                            ]
                        },
                        "cancel_at_period_end": False,
                    }

                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 4400,
                        "currency": "usd",
                        "lines": {"data": [{"amount": -500}, {"amount": 4900}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    # Should have used the verified record's subscription, not the PENDING one
                    mock_stripe.Subscription.retrieve.assert_called_once_with("sub_123")

    @mock_aws
    def test_formats_non_usd_currency(self, mock_dynamodb, api_gateway_event):
        """Should format non-USD currency correctly (line 294).

        Non-USD currencies should show the amount followed by the currency code.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {
                            "data": [
                                {
                                    "id": "si_123",
                                    "price": {"id": "price_starter_123"},
                                    "current_period_end": int(time.time()) + 86400 * 15,
                                }
                            ]
                        },
                        "cancel_at_period_end": False,
                    }

                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 3900,
                        "currency": "eur",
                        "lines": {"data": [{"amount": 3900}]},
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    preview = body["preview"]
                    assert preview["currency"] == "eur"
                    assert preview["amount_due_formatted"] == "39.00 EUR"

    @mock_aws
    def test_returns_500_on_unexpected_exception(self, mock_dynamodb, api_gateway_event):
        """Should return 500 for unexpected non-Stripe exceptions (lines 329-331).

        Catches any exception not handled by the Stripe error handler.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.StripeError = stripe_module.StripeError

                    # Simulate unexpected exception during Stripe call
                    mock_stripe.Subscription.retrieve.side_effect = RuntimeError("Unexpected crash")

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_no_subscription_when_only_pending_records(self, mock_dynamodb, api_gateway_event):
        """Should return no_active_subscription when user only has PENDING records.

        If a user has only PENDING records and no verified email records, they
        should not be able to preview an upgrade.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        # Only a PENDING record, no verified records
        table.put_item(
            Item={
                "pk": "user_pending_only",
                "sk": "PENDING",
                "email": "pending@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_pending",
                "stripe_subscription_id": "sub_pending",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pending_only", "email": "pending@example.com"}

                from api.upgrade_preview import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_active_subscription"

    @mock_aws
    def test_preview_with_zero_credit_full_charge(self, mock_dynamodb, api_gateway_event):
        """Should handle preview with no credit (e.g., start of billing period)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
            }
        )

        import api.upgrade_preview as preview_module

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["business"] = "price_business_123"

        with patch("api.upgrade_preview.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(preview_module, "stripe") as mock_stripe:
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {
                            "data": [
                                {
                                    "id": "si_123",
                                    "price": {"id": "price_starter_123"},
                                    "current_period_end": int(time.time()) + 86400 * 30,
                                }
                            ]
                        },
                        "cancel_at_period_end": False,
                    }

                    # Full charge, no credit (upgrading at start of period)
                    mock_stripe.Invoice.create_preview.return_value = {
                        "amount_due": 19900,
                        "currency": "usd",
                        "lines": {
                            "data": [
                                {"amount": -900},  # Tiny credit for old plan
                                {"amount": 20800},  # New plan charge
                            ]
                        },
                    }

                    from api.upgrade_preview import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "business"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    preview = body["preview"]
                    assert preview["current_tier"] == "starter"
                    assert preview["new_tier"] == "business"
                    assert preview["credit_amount_cents"] == 900
                    assert preview["new_plan_prorated_cents"] == 20800
                    assert preview["amount_due_cents"] == 19900
                    assert preview["amount_due_formatted"] == "$199.00"


class TestPreviewGetStripeApiKey:
    """Tests for the get_stripe_api_key function in shared.billing_utils."""

    @mock_aws
    def test_returns_cached_key_within_ttl(self):
        """Should return cached key when cache is still valid."""
        billing_utils._stripe_api_key_cache = "sk_cached_key"
        billing_utils._stripe_api_key_cache_time = time.time()

        result = billing_utils.get_stripe_api_key()

        assert result == "sk_cached_key"

    @mock_aws
    def test_returns_none_when_no_secret_arn(self):
        """Should return None when STRIPE_SECRET_ARN is not set."""
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = None

        try:
            result = billing_utils.get_stripe_api_key()
            assert result is None
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn

    @mock_aws
    def test_retrieves_key_from_json_secret(self):
        """Should parse JSON secret and extract key."""
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe-preview"
        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = secret_arn

        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe-preview",
            SecretString=json.dumps({"key": "sk_live_preview_json"}),
        )

        try:
            result = billing_utils.get_stripe_api_key()
            assert result == "sk_live_preview_json"
            assert billing_utils._stripe_api_key_cache == "sk_live_preview_json"
            assert billing_utils._stripe_api_key_cache_time > 0
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn
            billing_utils._stripe_api_key_cache = None
            billing_utils._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_retrieves_plain_string_secret(self):
        """Should handle plain string secret (not JSON)."""
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe-preview-plain"
        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = secret_arn

        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe-preview-plain",
            SecretString="sk_live_plain_preview",
        )

        try:
            result = billing_utils.get_stripe_api_key()
            assert result == "sk_live_plain_preview"
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn
            billing_utils._stripe_api_key_cache = None
            billing_utils._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_returns_none_on_client_error(self):
        """Should return None when Secrets Manager call fails."""
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789:secret:nonexistent"

        try:
            result = billing_utils.get_stripe_api_key()
            assert result is None
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn
            billing_utils._stripe_api_key_cache = None
            billing_utils._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_cache_expires_after_ttl(self):
        """Should re-fetch key when cache has expired."""
        billing_utils._stripe_api_key_cache = "sk_old_cached"
        billing_utils._stripe_api_key_cache_time = time.time() - billing_utils.STRIPE_CACHE_TTL - 10

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe-preview-ttl"
        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = secret_arn

        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe-preview-ttl",
            SecretString=json.dumps({"key": "sk_refreshed_key"}),
        )

        try:
            result = billing_utils.get_stripe_api_key()
            assert result == "sk_refreshed_key"
            assert billing_utils._stripe_api_key_cache == "sk_refreshed_key"
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn
            billing_utils._stripe_api_key_cache = None
            billing_utils._stripe_api_key_cache_time = 0.0
