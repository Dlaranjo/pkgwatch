"""
Tests for create billing portal session handler.
"""

import hashlib
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws

import shared.billing_utils as billing_utils


class TestCreateBillingPortalHandler:
    """Tests for the create billing portal Lambda handler."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

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
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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
                        return_url="https://pkgwatch.dev/dashboard?portal_return=1",
                    )

    @mock_aws
    def test_returns_500_when_stripe_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when Stripe API key is not configured."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value=None):
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
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

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
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
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


class TestBillingPortalCorsHandling:
    """Tests for CORS handling on billing portal endpoint."""

    @mock_aws
    def test_includes_cors_headers_on_success(self, mock_dynamodb, api_gateway_event):
        """Should include CORS headers on successful response."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_cors").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cors",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cors@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_cors123",
                "email_verified": True,
            }
        )

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_cors", "email": "cors@example.com"}

                with patch.object(portal_module, "stripe") as mock_stripe:
                    mock_session = MagicMock()
                    mock_session.url = "https://billing.stripe.com/session/test"
                    mock_stripe.billing_portal.Session.create.return_value = mock_session

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"
                    api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

                    result = portal_module.handler(api_gateway_event, {})

                    assert result["statusCode"] == 200
                    assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"

    @mock_aws
    def test_includes_cors_headers_on_error(self, mock_dynamodb, api_gateway_event):
        """Should include CORS headers on error response."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            from api.create_billing_portal import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"
            # No session cookie

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401
            assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"


class TestBillingPortalCookieHandling:
    """Tests for session cookie handling variations."""

    @mock_aws
    def test_accepts_lowercase_cookie_header(self, mock_dynamodb, api_gateway_event):
        """Should accept lowercase 'cookie' header."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=test_token"

                result = handler(api_gateway_event, {})

                # Should reach session verification (401 because token is invalid)
                assert result["statusCode"] == 401

    @mock_aws
    def test_accepts_uppercase_cookie_header(self, mock_dynamodb, api_gateway_event):
        """Should accept uppercase 'Cookie' header."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token", return_value=None):
                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["Cookie"] = "session=test_token"

                result = handler(api_gateway_event, {})

                assert result["statusCode"] == 401

    @mock_aws
    def test_extracts_session_from_multiple_cookies(self, mock_dynamodb, api_gateway_event):
        """Should extract session cookie when multiple cookies present."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = None  # Invalid token

                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "other=value; session=expected_token; tracking=xyz"

                result = handler(api_gateway_event, {})

                # verify_session_token should have been called with the session value
                mock_verify.assert_called_once_with("expected_token")


class TestBillingPortalEdgeCases:
    """Tests for edge cases and unusual inputs."""

    @mock_aws
    def test_handles_null_headers(self, mock_dynamodb, api_gateway_event):
        """Should handle None headers gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            from api.create_billing_portal import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"] = None

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401

    @mock_aws
    def test_handles_empty_cookie_header(self, mock_dynamodb, api_gateway_event):
        """Should handle empty cookie header."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            from api.create_billing_portal import handler

            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"]["cookie"] = ""

            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 401

    @mock_aws
    def test_requires_email_verified_for_stripe_customer(self, mock_dynamodb, api_gateway_event):
        """Should only use stripe_customer_id from email_verified records."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add unverified record with stripe_customer_id
        key_hash = hashlib.sha256(b"pw_unverified").hexdigest()
        table.put_item(
            Item={
                "pk": "user_unverified",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unverified@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_should_not_use",
                "email_verified": False,  # Not verified!
            }
        )

        import api.create_billing_portal as portal_module
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_unverified", "email": "unverified@example.com"}

                from api.create_billing_portal import handler

                api_gateway_event["httpMethod"] = "POST"
                api_gateway_event["headers"]["cookie"] = "session=valid"

                result = handler(api_gateway_event, {})

                # Should return no_subscription since email_verified is False
                assert result["statusCode"] == 400
                body = json.loads(result["body"])
                assert body["error"]["code"] == "no_subscription"


class TestBillingPortalStripeApiKeyCache:
    """Tests for Stripe API key caching behavior."""

    @mock_aws
    def test_caches_stripe_api_key(self, mock_dynamodb, api_gateway_event):
        """Should cache Stripe API key to avoid repeated Secrets Manager calls."""
        import time
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123:secret:test"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        # First call should fetch from secrets manager
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": '{"key": "sk_test_cached"}'}

        with patch("shared.billing_utils._get_secretsmanager", return_value=mock_sm):
            original_arn = billing_utils.STRIPE_SECRET_ARN
            billing_utils.STRIPE_SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123:secret:test"
            try:
                result1 = billing_utils.get_stripe_api_key()
                assert result1 == "sk_test_cached"
                assert mock_sm.get_secret_value.call_count == 1

                # Second call should use cache
                result2 = billing_utils.get_stripe_api_key()
                assert result2 == "sk_test_cached"
                assert mock_sm.get_secret_value.call_count == 1  # Still 1 - cache hit
            finally:
                billing_utils.STRIPE_SECRET_ARN = original_arn

    @mock_aws
    def test_returns_none_when_stripe_arn_not_configured(self, mock_dynamodb, api_gateway_event):
        """Should return None when STRIPE_SECRET_ARN is not set."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        # Remove or set empty ARN
        original = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = ""

        try:
            result = billing_utils.get_stripe_api_key()
            assert result is None
        finally:
            billing_utils.STRIPE_SECRET_ARN = original


class TestBillingPortalReturnUrl:
    """Tests for billing portal return URL handling."""

    @mock_aws
    def test_return_url_includes_portal_return_param(self, mock_dynamodb, api_gateway_event):
        """Return URL should include portal_return=1 for dashboard refresh."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://pkgwatch.dev"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_return").hexdigest()
        table.put_item(
            Item={
                "pk": "user_return",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "return@example.com",
                "tier": "pro",
                "stripe_customer_id": "cus_return123",
                "email_verified": True,
            }
        )

        import importlib
        import api.create_billing_portal as portal_module
        importlib.reload(portal_module)
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        with patch("api.create_billing_portal.get_stripe_api_key", return_value="sk_test_123"):
            with patch("api.auth_callback.verify_session_token") as mock_verify:
                mock_verify.return_value = {"user_id": "user_return", "email": "return@example.com"}

                with patch.object(portal_module, "stripe") as mock_stripe:
                    mock_session = MagicMock()
                    mock_session.url = "https://billing.stripe.com/session/test"
                    mock_stripe.billing_portal.Session.create.return_value = mock_session

                    api_gateway_event["httpMethod"] = "POST"
                    api_gateway_event["headers"]["cookie"] = "session=valid"

                    portal_module.handler(api_gateway_event, {})

                    # Verify return_url includes portal_return param
                    call_args = mock_stripe.billing_portal.Session.create.call_args
                    assert "portal_return=1" in call_args[1]["return_url"]
