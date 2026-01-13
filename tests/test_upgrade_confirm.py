"""
Tests for upgrade confirm handler.
"""

import hashlib
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestUpgradeConfirmHandler:
    """Tests for the upgrade confirm Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        # Clear cache
        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            from api.upgrade_confirm import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401
            body = json.loads(result["body"])
            assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired or invalid."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=invalid_token"
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 401
                body = json.loads(result["body"])
                assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_400_for_invalid_tier(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = json.dumps({"tier": "invalid", "proration_date": int(time.time())})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_tier"

    @mock_aws
    def test_returns_400_for_missing_proration_date(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when proration_date is missing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = json.dumps({"tier": "pro"})  # No proration_date

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_proration_date"

    @mock_aws
    def test_returns_400_for_expired_proration_date(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when proration_date is more than 5 minutes old."""
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                # proration_date is 10 minutes old
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time()) - 600})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "proration_date_expired"

    @mock_aws
    def test_returns_400_for_no_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user has no active subscription."""
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
            }
        )

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_free", "email": "free@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_active_subscription"

    @mock_aws
    def test_returns_402_for_payment_failure(self, mock_dynamodb, api_gateway_event):
        """Should return 402 when card is declined."""
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

        import api.upgrade_confirm as confirm_module
        import stripe as stripe_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    # Setup exception types
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    # Mock subscription retrieval
                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    # Mock card decline
                    mock_stripe.Subscription.modify.side_effect = stripe_module.CardError(
                        message="Your card was declined.",
                        param="",
                        code="card_declined",
                    )

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 402
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "payment_failed"

    @mock_aws
    def test_returns_503_for_stripe_api_error(self, mock_dynamodb, api_gateway_event):
        """Should return 503 when Stripe API is unavailable."""
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

        import api.upgrade_confirm as confirm_module
        import stripe as stripe_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    # Setup exception types
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.InvalidRequestError = stripe_module.InvalidRequestError
                    mock_stripe.APIError = stripe_module.APIError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    # Mock API error
                    mock_stripe.Subscription.modify.side_effect = stripe_module.APIError("Stripe is down")

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 503
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_unavailable"

    @mock_aws
    def test_successful_upgrade(self, mock_dynamodb, api_gateway_event):
        """Should successfully upgrade subscription and update DynamoDB."""
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
                "monthly_limit": 25000,
                "requests_this_month": 5000,
            }
        )

        import api.upgrade_confirm as confirm_module
        import stripe as stripe_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "status": "active",
                        "latest_invoice": "in_abc123",
                    }

                    mock_stripe.Invoice.retrieve.return_value = {
                        "id": "in_abc123",
                        "amount_paid": 4400,
                    }

                    from api.upgrade_confirm import handler

                    proration_date = int(time.time())
                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": proration_date})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["success"] is True
                    assert body["new_tier"] == "pro"
                    assert body["amount_charged_cents"] == 4400
                    assert body["invoice_id"] == "in_abc123"

                    # Verify Stripe was called with idempotency key
                    mock_stripe.Subscription.modify.assert_called_once()
                    call_kwargs = mock_stripe.Subscription.modify.call_args[1]
                    assert call_kwargs["idempotency_key"] == f"upgrade-user_starter-pro-{proration_date}"
                    assert call_kwargs["proration_behavior"] == "always_invoice"
                    assert call_kwargs["payment_behavior"] == "error_if_incomplete"

                    # Verify DynamoDB was updated
                    response = table.get_item(Key={"pk": "user_starter", "sk": key_hash})
                    item = response["Item"]
                    assert item["tier"] == "pro"
                    assert item["monthly_limit"] == 100000  # Pro limit
                    assert item["requests_this_month"] == 0  # Reset on upgrade

    @mock_aws
    def test_updates_all_user_api_keys(self, mock_dynamodb, api_gateway_event):
        """Should update all API keys for the user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create multiple API keys for the same user
        key_hash1 = hashlib.sha256(b"pw_key1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_key2").hexdigest()

        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash1,
                "key_hash": key_hash1,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
                "monthly_limit": 25000,
                "requests_this_month": 1000,
            }
        )
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash2,
                "key_hash": key_hash2,
                "email": "starter@example.com",
                "tier": "starter",
                "email_verified": True,
                "stripe_customer_id": "cus_123",
                "stripe_subscription_id": "sub_123",
                "monthly_limit": 25000,
                "requests_this_month": 2000,
            }
        )

        import api.upgrade_confirm as confirm_module
        import stripe as stripe_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": "in_abc123",
                    }

                    mock_stripe.Invoice.retrieve.return_value = {"amount_paid": 4400}

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200

                    # Verify both API keys were updated
                    response1 = table.get_item(Key={"pk": "user_starter", "sk": key_hash1})
                    response2 = table.get_item(Key={"pk": "user_starter", "sk": key_hash2})

                    assert response1["Item"]["tier"] == "pro"
                    assert response1["Item"]["monthly_limit"] == 100000
                    assert response1["Item"]["requests_this_month"] == 0

                    assert response2["Item"]["tier"] == "pro"
                    assert response2["Item"]["monthly_limit"] == 100000
                    assert response2["Item"]["requests_this_month"] == 0

    @mock_aws
    def test_skips_pending_records(self, mock_dynamodb, api_gateway_event):
        """Should skip PENDING records when updating."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()

        # Active API key
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
                "monthly_limit": 25000,
            }
        )

        # PENDING record (should be skipped)
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": "PENDING",
                "email": "starter@example.com",
                "tier": "free",
            }
        )

        import api.upgrade_confirm as confirm_module
        import stripe as stripe_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123", "price": {"id": "price_starter_123"}}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": "in_abc123",
                    }

                    mock_stripe.Invoice.retrieve.return_value = {"amount_paid": 4400}

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200

                    # PENDING record should still be at free tier
                    response = table.get_item(Key={"pk": "user_starter", "sk": "PENDING"})
                    assert response["Item"]["tier"] == "free"
