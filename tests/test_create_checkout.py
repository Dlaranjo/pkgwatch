"""
Tests for create checkout session handler.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestCreateCheckoutHandler:
    """Tests for the create checkout Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        # Clear the API key cache
        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            from api.create_checkout import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["body"] = json.dumps({"tier": "starter"})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401
            body = json.loads(result["body"])
            assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired or invalid."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=invalid_token"
                api_gateway_event["body"] = json.dumps({"tier": "starter"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 401
                body = json.loads(result["body"])
                assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_400_for_invalid_tier(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = json.dumps({"tier": "invalid"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_tier"

    @mock_aws
    def test_returns_400_for_invalid_json(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid JSON body."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_123", "email": "test@example.com"}

                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid_token"
                api_gateway_event["body"] = "not valid json"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_prevents_downgrade(self, mock_dynamodb, api_gateway_event):
        """Should prevent downgrade via checkout."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pro",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pro@example.com",
                "tier": "pro",  # Already on Pro
                "email_verified": True,
            }
        )

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0
        # Set price IDs directly since module reads env at import time
        checkout_module.TIER_TO_PRICE["starter"] = "price_starter_123"

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pro", "email": "pro@example.com"}

                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "starter"})  # Downgrade attempt

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_upgrade"

    @mock_aws
    def test_prevents_same_tier_checkout(self, mock_dynamodb, api_gateway_event):
        """Should prevent checkout for same tier."""
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
            }
        )

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0
        checkout_module.TIER_TO_PRICE["starter"] = "price_starter_123"

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "starter"})  # Same tier

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "invalid_upgrade"

    @mock_aws
    def test_creates_checkout_session(self, mock_dynamodb, api_gateway_event):
        """Should create Stripe checkout session for valid upgrade."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

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

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0
        checkout_module.TIER_TO_PRICE["pro"] = "price_pro_123"

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_free", "email": "free@example.com"}

                with patch.object(checkout_module, "stripe") as mock_stripe:
                    mock_session = MagicMock()
                    mock_session.url = "https://checkout.stripe.com/test_session"
                    mock_stripe.checkout.Session.create.return_value = mock_session

                    from api.create_checkout import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "pro"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["checkout_url"] == "https://checkout.stripe.com/test_session"

                    # Verify Stripe was called with correct parameters
                    mock_stripe.checkout.Session.create.assert_called_once()
                    call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
                    assert call_kwargs["mode"] == "subscription"
                    assert call_kwargs["line_items"] == [{"price": "price_pro_123", "quantity": 1}]
                    assert call_kwargs["customer_email"] == "free@example.com"
                    assert call_kwargs["client_reference_id"] == "user_free"

    @mock_aws
    def test_reuses_existing_stripe_customer(self, mock_dynamodb, api_gateway_event):
        """Should reuse existing Stripe customer ID for upgrades."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_starter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "starter@example.com",
                "tier": "starter",
                "stripe_customer_id": "cus_existing123",
                "email_verified": True,
            }
        )

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0
        checkout_module.TIER_TO_PRICE["business"] = "price_business_123"

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_starter", "email": "starter@example.com"}

                with patch.object(checkout_module, "stripe") as mock_stripe:
                    mock_session = MagicMock()
                    mock_session.url = "https://checkout.stripe.com/upgrade"
                    mock_stripe.checkout.Session.create.return_value = mock_session

                    from api.create_checkout import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["body"] = json.dumps({"tier": "business"})

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 200

                    # Verify existing customer ID is used
                    call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
                    assert call_kwargs["customer"] == "cus_existing123"
                    assert "customer_email" not in call_kwargs  # Should not set email when customer exists

    @mock_aws
    def test_returns_500_when_stripe_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API key is not configured."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = ""

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0

        with patch.object(checkout_module, "_get_stripe_api_key", return_value=None):
            from api.create_checkout import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["body"] = json.dumps({"tier": "starter"})

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "stripe_not_configured"

    @mock_aws
    def test_returns_500_when_price_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when price ID is not configured for tier."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_PRICE_STARTER"] = ""  # Not configured

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

        import api.create_checkout as checkout_module
        checkout_module._stripe_api_key_cache = None
        checkout_module._stripe_api_key_cache_time = 0.0
        # Force TIER_TO_PRICE to have None for starter
        checkout_module.TIER_TO_PRICE["starter"] = None

        with patch.object(checkout_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_free", "email": "free@example.com"}

                from api.create_checkout import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"
                api_gateway_event["body"] = json.dumps({"tier": "starter"})

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 500
                body = json.loads(result["body"])
                assert body["error"]["code"] == "price_not_configured"
