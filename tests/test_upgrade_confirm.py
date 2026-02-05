"""
Tests for upgrade confirm handler.
"""

import hashlib
import json
import os
import time
from unittest.mock import MagicMock, patch

import boto3
import pytest
import stripe as stripe_module
from botocore.exceptions import ClientError
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

    @mock_aws
    def test_returns_500_when_stripe_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API key is not configured (lines 108-109)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value=None):
            from api.upgrade_confirm import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"]["cookie"] = "session=valid"
            api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "stripe_not_configured"

    @mock_aws
    def test_returns_400_for_invalid_json_body(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when request body is not valid JSON (lines 144-145)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = "not valid json{{"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_returns_400_for_future_proration_date(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when proration_date is in the future (line 173).

        This prevents users from manipulating the proration date to get a
        cheaper upgrade by claiming to upgrade in the future.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                # proration_date is 1 hour in the future
                future_date = int(time.time()) + 3600
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": future_date})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_proration_date"

    @mock_aws
    def test_returns_500_when_price_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when the price ID for the target tier is not set (lines 191-192).

        Prevents an upgrade to a tier that has no corresponding Stripe price.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        # Ensure the pro price is NOT configured
        original_price = confirm_module.TIER_TO_PRICE.get("pro")
        confirm_module.TIER_TO_PRICE["pro"] = None

        try:
            with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
                with patch("api.auth_callback.verify_session_token") as mock_verify:
                    mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "price_not_configured"
        finally:
            # Restore original price to avoid polluting other tests
            confirm_module.TIER_TO_PRICE["pro"] = original_price

    @mock_aws
    def test_returns_400_for_same_tier_upgrade(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user tries to 'upgrade' to their current tier (lines 230-236).

        This prevents a billing event for a no-op upgrade.
        """
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pro", "email": "pro@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "same_tier"
                assert "already on" in body["error"]["message"]

    @mock_aws
    def test_returns_400_for_downgrade_attempt(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user tries to downgrade via upgrade endpoint (lines 237-238).

        Downgrades must go through the billing portal; this endpoint only handles upgrades.
        """
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_business", "email": "business@example.com"}

                from api.upgrade_confirm import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "downgrade_not_allowed"
                assert "billing portal" in body["error"]["message"]

    @mock_aws
    def test_returns_402_for_past_due_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 402 when subscription is past_due (line 252).

        Users with unpaid invoices must resolve payment before upgrading.
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

        import api.upgrade_confirm as confirm_module
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
                        "status": "past_due",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 402
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "payment_required"
                    # Stripe.Subscription.modify should NOT have been called
                    mock_stripe.Subscription.modify.assert_not_called()

    @mock_aws
    def test_returns_400_for_canceled_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when subscription has an invalid status like canceled (line 260).

        Canceled subscriptions cannot be upgraded; user needs to start fresh.
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

        import api.upgrade_confirm as confirm_module
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
                        "status": "canceled",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 400
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "subscription_invalid"
                    # Stripe.Subscription.modify should NOT have been called
                    mock_stripe.Subscription.modify.assert_not_called()

    @mock_aws
    def test_returns_400_for_unpaid_subscription(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for 'unpaid' subscription status (another invalid status)."""
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

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "unpaid",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 400
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "subscription_invalid"

    @mock_aws
    def test_handles_invoice_retrieval_failure_gracefully(self, mock_dynamodb, api_gateway_event):
        """Should succeed even when invoice retrieval fails (lines 294-296).

        Invoice retrieval is non-critical; the upgrade itself succeeded via Stripe.
        Amount charged defaults to 0 instead of causing an error.
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
                "monthly_limit": 25000,
                "requests_this_month": 100,
            }
        )

        import api.upgrade_confirm as confirm_module
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
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": "in_abc123",
                    }

                    # Invoice retrieval fails
                    mock_stripe.Invoice.retrieve.side_effect = stripe_module.StripeError(
                        "Invoice not found"
                    )

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    # Should still succeed
                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["success"] is True
                    assert body["new_tier"] == "pro"
                    assert body["amount_charged_cents"] == 0  # Defaults to 0 on failure
                    assert body["invoice_id"] == "in_abc123"

                    # DynamoDB should still be updated
                    response = table.get_item(Key={"pk": "user_starter", "sk": key_hash})
                    assert response["Item"]["tier"] == "pro"

    @mock_aws
    def test_handles_concurrent_upgrade_race_condition(self, mock_dynamodb, api_gateway_event):
        """Should handle ConditionalCheckFailedException during DynamoDB update (lines 327-331).

        If a concurrent upgrade changed the tier between Stripe modification and
        DynamoDB update, the conditional update fails safely. The upgrade still succeeds
        because Stripe was already updated (the authoritative source).
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
                "monthly_limit": 25000,
                "requests_this_month": 100,
            }
        )

        import api.upgrade_confirm as confirm_module
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
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": "in_abc123",
                    }

                    mock_stripe.Invoice.retrieve.return_value = {"amount_paid": 4400}

                    from api.upgrade_confirm import handler

                    # Directly simulate ConditionalCheckFailedException from DynamoDB
                    # We must create a mock table that the handler will use internally
                    conditional_error = ClientError(
                        {
                            "Error": {
                                "Code": "ConditionalCheckFailedException",
                                "Message": "The conditional request failed",
                            }
                        },
                        "UpdateItem",
                    )

                    mock_table = MagicMock()
                    mock_table.query.return_value = {
                        "Items": [{
                            "pk": "user_starter",
                            "sk": key_hash,
                            "email": "starter@example.com",
                            "tier": "starter",
                            "email_verified": True,
                            "stripe_customer_id": "cus_123",
                            "stripe_subscription_id": "sub_123",
                        }]
                    }
                    mock_table.update_item.side_effect = conditional_error

                    mock_dynamodb_resource = MagicMock()
                    mock_dynamodb_resource.Table.return_value = mock_table

                    with patch.object(confirm_module, "dynamodb", mock_dynamodb_resource):
                        api_gateway_event["httpMethod"] = "POST"
                        api_gateway_event["headers"]["cookie"] = "session=valid"
                        api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                        result = handler(api_gateway_event, {})

                        # Should still succeed - Stripe was already updated
                        assert result["statusCode"] == 200
                        body = json.loads(result["body"])
                        assert body["success"] is True
                        assert body["new_tier"] == "pro"

                        # update_item was called but raised ConditionalCheckFailedException
                        mock_table.update_item.assert_called_once()

    @mock_aws
    def test_reraises_non_conditional_dynamodb_error(self, mock_dynamodb, api_gateway_event):
        """Should re-raise ClientError that is not ConditionalCheckFailedException (line 331).

        Non-conditional DynamoDB errors (throttling, service unavailable) should
        propagate up and be caught by the generic Exception handler.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        key_hash = hashlib.sha256(b"pw_test").hexdigest()

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.InvalidRequestError = stripe_module.InvalidRequestError
                    mock_stripe.APIError = stripe_module.APIError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": "in_abc123",
                    }

                    mock_stripe.Invoice.retrieve.return_value = {"amount_paid": 4400}

                    from api.upgrade_confirm import handler

                    # Simulate a throttling error (not ConditionalCheckFailedException)
                    throttle_error = ClientError(
                        {
                            "Error": {
                                "Code": "ProvisionedThroughputExceededException",
                                "Message": "Rate exceeded",
                            }
                        },
                        "UpdateItem",
                    )

                    mock_table = MagicMock()
                    mock_table.query.return_value = {
                        "Items": [{
                            "pk": "user_starter",
                            "sk": key_hash,
                            "email": "starter@example.com",
                            "tier": "starter",
                            "email_verified": True,
                            "stripe_customer_id": "cus_123",
                            "stripe_subscription_id": "sub_123",
                        }]
                    }
                    mock_table.update_item.side_effect = throttle_error

                    mock_dynamodb_resource = MagicMock()
                    mock_dynamodb_resource.Table.return_value = mock_table

                    with patch.object(confirm_module, "dynamodb", mock_dynamodb_resource):
                        api_gateway_event["httpMethod"] = "POST"
                        api_gateway_event["headers"]["cookie"] = "session=valid"
                        api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                        result = handler(api_gateway_event, {})

                        # The ClientError should re-raise and be caught by generic handler
                        assert result["statusCode"] == 500
                        body = json.loads(result["body"])
                        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_returns_400_for_invalid_stripe_request(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for InvalidRequestError from Stripe (lines 348-349).

        E.g., subscription ID doesn't exist or invalid parameters.
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.InvalidRequestError = stripe_module.InvalidRequestError
                    mock_stripe.APIError = stripe_module.APIError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    mock_stripe.Subscription.modify.side_effect = stripe_module.InvalidRequestError(
                        message="No such subscription",
                        param="subscription",
                    )

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 400
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "invalid_request"

    @mock_aws
    def test_returns_500_for_generic_stripe_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 for generic StripeError (lines 357-361).

        Catches any Stripe error not handled by more specific handlers.
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.InvalidRequestError = stripe_module.InvalidRequestError
                    mock_stripe.APIError = stripe_module.APIError
                    mock_stripe.StripeError = stripe_module.StripeError

                    # Use plain StripeError (not CardError, APIError, or InvalidRequestError)
                    mock_stripe.Subscription.retrieve.side_effect = stripe_module.StripeError(
                        "Unknown Stripe error"
                    )

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_error"

    @mock_aws
    def test_returns_500_for_unexpected_exception(self, mock_dynamodb, api_gateway_event):
        """Should return 500 for unexpected exceptions (lines 362-364).

        Catches any non-Stripe exception to prevent unhandled errors.
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

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.InvalidRequestError = stripe_module.InvalidRequestError
                    mock_stripe.APIError = stripe_module.APIError
                    mock_stripe.StripeError = stripe_module.StripeError

                    # Simulate unexpected exception
                    mock_stripe.Subscription.retrieve.side_effect = RuntimeError("Database connection lost")

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_successful_upgrade_with_invoice_object(self, mock_dynamodb, api_gateway_event):
        """Should handle latest_invoice as an object (not just string ID).

        Stripe may return the invoice as a nested object instead of just a string ID.
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
                "monthly_limit": 25000,
                "requests_this_month": 0,
            }
        )

        import api.upgrade_confirm as confirm_module
        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0
        confirm_module.TIER_TO_PRICE["business"] = "price_business_123"

        with patch.object(confirm_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(confirm_module, "stripe") as mock_stripe:
                    mock_stripe.CardError = stripe_module.CardError
                    mock_stripe.StripeError = stripe_module.StripeError

                    mock_stripe.Subscription.retrieve.return_value = {
                        "status": "active",
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    # latest_invoice is an object, not a string
                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": {"id": "in_obj_123", "amount_paid": 9900},
                    }

                    mock_stripe.Invoice.retrieve.return_value = {
                        "id": "in_obj_123",
                        "amount_paid": 9900,
                    }

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "business", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["success"] is True
                    assert body["new_tier"] == "business"
                    assert body["invoice_id"] == "in_obj_123"

                    # Verify DynamoDB updated to business tier limits
                    response = table.get_item(Key={"pk": "user_starter", "sk": key_hash})
                    item = response["Item"]
                    assert item["tier"] == "business"
                    assert item["monthly_limit"] == 500000

    @mock_aws
    def test_successful_upgrade_with_no_latest_invoice(self, mock_dynamodb, api_gateway_event):
        """Should handle when latest_invoice is None (edge case)."""
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
                "requests_this_month": 0,
            }
        )

        import api.upgrade_confirm as confirm_module
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
                        "items": {"data": [{"id": "si_123"}]},
                    }

                    mock_stripe.Subscription.modify.return_value = {
                        "id": "sub_123",
                        "latest_invoice": None,
                    }

                    from api.upgrade_confirm import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro", "proration_date": int(time.time())})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["success"] is True
                    assert body["amount_charged_cents"] == 0
                    assert body["invoice_id"] is None


class TestGetStripeApiKey:
    """Tests for the _get_stripe_api_key function (lines 55-75)."""

    @mock_aws
    def test_returns_cached_key_within_ttl(self):
        """Should return cached key when cache is still valid (line 55-56)."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = "sk_cached_key"
        confirm_module._stripe_api_key_cache_time = time.time()  # Just cached

        result = confirm_module._get_stripe_api_key()

        assert result == "sk_cached_key"

    @mock_aws
    def test_returns_none_when_no_secret_arn(self):
        """Should return None when STRIPE_SECRET_ARN is not set (line 58-59)."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        original_arn = confirm_module.STRIPE_SECRET_ARN
        confirm_module.STRIPE_SECRET_ARN = None

        try:
            result = confirm_module._get_stripe_api_key()
            assert result is None
        finally:
            confirm_module.STRIPE_SECRET_ARN = original_arn

    @mock_aws
    def test_retrieves_key_from_json_secret(self):
        """Should parse JSON secret and extract key (lines 62-72)."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe"
        confirm_module.STRIPE_SECRET_ARN = secret_arn

        # Create the secret in mocked Secrets Manager
        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe",
            SecretString=json.dumps({"key": "sk_live_from_json"}),
        )

        try:
            result = confirm_module._get_stripe_api_key()
            assert result == "sk_live_from_json"
            assert confirm_module._stripe_api_key_cache == "sk_live_from_json"
            assert confirm_module._stripe_api_key_cache_time > 0
        finally:
            confirm_module.STRIPE_SECRET_ARN = None
            confirm_module._stripe_api_key_cache = None
            confirm_module._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_retrieves_plain_string_secret(self):
        """Should handle plain string secret (not JSON) (lines 67-68)."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe-plain"
        confirm_module.STRIPE_SECRET_ARN = secret_arn

        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe-plain",
            SecretString="sk_live_plain_string",
        )

        try:
            result = confirm_module._get_stripe_api_key()
            assert result == "sk_live_plain_string"
        finally:
            confirm_module.STRIPE_SECRET_ARN = None
            confirm_module._stripe_api_key_cache = None
            confirm_module._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_returns_none_on_client_error(self):
        """Should return None when Secrets Manager call fails (lines 73-75)."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = None
        confirm_module._stripe_api_key_cache_time = 0.0

        # Set ARN to a secret that does not exist
        confirm_module.STRIPE_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789:secret:nonexistent"

        try:
            result = confirm_module._get_stripe_api_key()
            assert result is None
        finally:
            confirm_module.STRIPE_SECRET_ARN = None
            confirm_module._stripe_api_key_cache = None
            confirm_module._stripe_api_key_cache_time = 0.0

    @mock_aws
    def test_cache_expires_after_ttl(self):
        """Should re-fetch key when cache has expired."""
        import api.upgrade_confirm as confirm_module

        confirm_module._stripe_api_key_cache = "sk_old_cached"
        # Set cache time to well beyond the TTL
        confirm_module._stripe_api_key_cache_time = time.time() - confirm_module.STRIPE_CACHE_TTL - 10

        secret_arn = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe-ttl"
        confirm_module.STRIPE_SECRET_ARN = secret_arn

        sm_client = boto3.client("secretsmanager", region_name="us-east-1")
        sm_client.create_secret(
            Name="test-stripe-ttl",
            SecretString=json.dumps({"key": "sk_new_from_sm"}),
        )

        try:
            result = confirm_module._get_stripe_api_key()
            assert result == "sk_new_from_sm"
            assert confirm_module._stripe_api_key_cache == "sk_new_from_sm"
        finally:
            confirm_module.STRIPE_SECRET_ARN = None
            confirm_module._stripe_api_key_cache = None
            confirm_module._stripe_api_key_cache_time = 0.0
