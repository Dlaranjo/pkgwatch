"""
Tests for create billing portal session handler.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws


class TestCreateBillingPortalHandler:
    """Tests for the create billing portal Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            from api.create_billing_portal import handler

            api_gateway_event["httpMethod"] = "POST"

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401
            body = json.loads(result["body"])
            assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired or invalid."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=invalid_token"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 401
                body = json.loads(result["body"])
                assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_400_for_free_tier_user(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user has no stripe_customer_id (free tier)."""
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
                # No stripe_customer_id
            }
        )

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_free", "email": "free@example.com"}

                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_subscription"

    @mock_aws
    def test_creates_billing_portal_session(self, mock_dynamodb, api_gateway_event):
        """Should create Stripe billing portal session for paid user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.laranjo.dev"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pro",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pro@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_existing123",
                "email_verified": True,
            }
        )

        # Reload module to pick up BASE_URL env var
        import importlib
        import api.create_billing_portal as portal_module
        importlib.reload(portal_module)
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pro", "email": "pro@example.com"}

                with patch.object(portal_module, "stripe") as mock_stripe:
                    mock_session = MagicMock()
                    mock_session.url = "https://billing.stripe.com/session/test"
                    mock_stripe.billing_portal.Session.create.return_value = mock_session

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"

                    result = portal_module.handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    body = json.loads(result["body"])
                    assert body["portal_url"] == "https://billing.stripe.com/session/test"

                    # Verify Stripe was called correctly
                    # Return URL includes portal_return=1 so dashboard refreshes subscription data
                    mock_stripe.billing_portal.Session.create.assert_called_once_with(
                        customer="cus_existing123",
                        return_url="https://pkgwatch.laranjo.dev/dashboard?portal_return=1",
                    )

    @mock_aws
    def test_returns_500_when_stripe_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API key is not configured."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value=None):
            from api.create_billing_portal import handler

            api_gateway_event["httpMethod"] = "POST"

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "stripe_not_configured"

    @mock_aws
    def test_handles_stripe_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API fails."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.laranjo.dev"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pro",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pro@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_existing123",
                "email_verified": True,
            }
        )

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_pro", "email": "pro@example.com"}

                with patch.object(portal_module, "stripe") as mock_stripe:
                    import stripe as real_stripe
                    mock_stripe.StripeError = real_stripe.StripeError
                    mock_stripe.billing_portal.Session.create.side_effect = real_stripe.StripeError("API Error")

                    from api.create_billing_portal import handler

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"

                    result = handler(api_gateway_event, {})

                    assert result["statusCode"] == 500
                    body = json.loads(result["body"])
                    assert body["error"]["code"] == "stripe_error"

    @mock_aws
    def test_skips_pending_records(self, mock_dynamodb, api_gateway_event):
        """Should skip PENDING records when looking for stripe_customer_id."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add PENDING record (should be skipped)
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "PENDING",
                "email": "test@example.com",
                "stripe_customer_id": "cus_wrong",  # Should not use this
            }
        )

        # Add verified record without stripe_customer_id
        key_hash = hashlib.sha256(b"pw_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "test@example.com",
                "tier": "free",
                "email_verified": True,
                # No stripe_customer_id
            }
        )

        import api.create_billing_portal as portal_module
        portal_module._stripe_api_key_cache = None
        portal_module._stripe_api_key_cache_time = 0.0

        with patch.object(portal_module, "_get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_test", "email": "test@example.com"}

                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"

                result = handler(api_gateway_event, {})

                # Should return no_subscription since PENDING was skipped
                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_subscription"
