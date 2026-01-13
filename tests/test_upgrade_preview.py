"""
Tests for upgrade preview handler.
"""

import hashlib
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestUpgradePreviewHandler:
    """Tests for the upgrade preview Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        # Clear cache
        import api.upgrade_preview as preview_module
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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

        import api.upgrade_preview as preview_module
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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

        import api.upgrade_preview as preview_module
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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

        import api.upgrade_preview as preview_module
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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

        import api.upgrade_preview as preview_module
        import stripe as stripe_module
        preview_module._stripe_api_key_cache = None
        preview_module._stripe_api_key_cache_time = 0.0
        preview_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(preview_module, "_get_stripe_api_key", return_value="sk_test_123"):
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
