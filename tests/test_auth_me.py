"""
Tests for auth_me.py - GET /auth/me endpoint.

Coverage targets:
- Session validation (missing, invalid, expired)
- User data retrieval from DynamoDB
- Stripe subscription refresh logic
- Rate limiting checks
- Referral code handling
- Error handling
"""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

import shared.billing_utils as billing_utils


@pytest.fixture
def setup_session_secret():
    """Set up secrets manager with a session secret."""
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(
        Name="pkgwatch/session-secret", SecretString=json.dumps({"secret": "test-session-secret-12345"})
    )
    os.environ["SESSION_SECRET_ARN"] = "pkgwatch/session-secret"
    return "test-session-secret-12345"


@pytest.fixture
def setup_stripe_secret():
    """Set up secrets manager with Stripe API key."""
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(Name="pkgwatch/stripe-secret", SecretString=json.dumps({"key": "sk_test_12345"}))
    os.environ["STRIPE_SECRET_ARN"] = "pkgwatch/stripe-secret"
    return "sk_test_12345"


def create_session_token(data: dict, secret: str) -> str:
    """Create a signed session token for testing."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def create_test_user(table, user_id: str, email: str, tier: str = "free", **extra):
    """Create a test user in the API keys table."""
    key_hash = hashlib.sha256(f"pw_test_{user_id}".encode()).hexdigest()

    item = {
        "pk": user_id,
        "sk": key_hash,
        "key_hash": key_hash,
        "email": email,
        "tier": tier,
        "requests_this_month": 0,
        "created_at": "2024-01-01T00:00:00Z",
        "email_verified": True,
        **extra,
    }

    table.put_item(Item=item)
    return item


def create_user_meta(table, user_id: str, **extra):
    """Create USER_META record for a user."""
    item = {
        "pk": user_id,
        "sk": "USER_META",
        "requests_this_month": 0,
        "key_count": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    table.put_item(Item=item)
    return item


class TestAuthMeSessionValidation:
    """Tests for session cookie validation."""

    @mock_aws
    def test_no_cookie_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when no session cookie is provided."""
        # Clear cache to pick up new secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": {},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_empty_cookie_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when cookie header is empty."""
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": {"cookie": ""},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_invalid_session_token_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when session token is invalid."""
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": {"cookie": "session=invalid.token"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_expired_session_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when session token is expired."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        # Create expired session (1 day ago)
        expired_time = datetime.now(timezone.utc) - timedelta(days=1)
        session_data = {
            "user_id": "user_test123",
            "email": "test@example.com",
            "tier": "free",
            "exp": int(expired_time.timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_tampered_session_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when session signature is invalid."""
        setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        # Create token with wrong secret
        session_data = {
            "user_id": "user_test123",
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, "wrong-secret")

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401


class TestAuthMeUserRetrieval:
    """Tests for user data retrieval."""

    @mock_aws
    def test_valid_session_returns_user_info(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return user info for valid session."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        # Create test user
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_test123", "test@example.com", tier="pro")

        # Create valid session
        session_data = {
            "user_id": "user_test123",
            "email": "test@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["user_id"] == "user_test123"
        assert body["email"] == "test@example.com"
        assert body["tier"] == "pro"
        assert body["data_source"] == "cache"

    @mock_aws
    def test_user_not_found_returns_404(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 404 when user not found in DynamoDB."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        # Create session for non-existent user
        session_data = {
            "user_id": "user_nonexistent",
            "email": "ghost@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "user_not_found"

    @mock_aws
    def test_skips_pending_records(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should skip PENDING records when looking for API keys."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create PENDING record (from incomplete signup)
        table.put_item(
            Item={
                "pk": "user_pending_test",
                "sk": "PENDING",
                "email": "pending@example.com",
            }
        )

        # Create valid API key record
        create_test_user(table, "user_pending_test", "pending@example.com", tier="free")

        session_data = {
            "user_id": "user_pending_test",
            "email": "pending@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["user_id"] == "user_pending_test"

    @mock_aws
    def test_returns_usage_from_user_meta(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return usage count from USER_META record."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_meta_test", "meta@example.com", tier="free")
        create_user_meta(table, "user_meta_test", requests_this_month=1500)

        session_data = {
            "user_id": "user_meta_test",
            "email": "meta@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["requests_this_month"] == 1500

    @mock_aws
    def test_fallback_to_per_key_counters(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should sum per-key counters when USER_META doesn't have requests_this_month."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create multiple API keys with usage
        create_test_user(table, "user_multikey", "multi@example.com", tier="free", requests_this_month=100)
        key_hash2 = hashlib.sha256(b"pw_test_key2").hexdigest()
        table.put_item(
            Item={
                "pk": "user_multikey",
                "sk": key_hash2,
                "key_hash": key_hash2,
                "email": "multi@example.com",
                "tier": "free",
                "requests_this_month": 200,
            }
        )

        # Create USER_META without requests_this_month (old schema)
        table.put_item(
            Item={
                "pk": "user_multikey",
                "sk": "USER_META",
                "key_count": 2,
            }
        )

        session_data = {
            "user_id": "user_multikey",
            "email": "multi@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should sum both keys: 100 + 200 = 300
        assert body["requests_this_month"] == 300


class TestAuthMeStripeRefresh:
    """Tests for Stripe subscription refresh logic."""

    @mock_aws
    def test_refresh_stripe_updates_user_data(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should refresh data from Stripe when requested."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        # Clear price env vars so module uses defaults (price_pro -> pro mapping)
        for key in ["STRIPE_PRICE_STARTER", "STRIPE_PRICE_PRO", "STRIPE_PRICE_BUSINESS"]:
            os.environ.pop(key, None)
        importlib.reload(module)

        # Clear Stripe key cache and reset lazy client for moto
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_stripe",
            "stripe@example.com",
            tier="starter",
            stripe_subscription_id="sub_test123",
            stripe_customer_id="cus_test123",
        )
        create_user_meta(table, "user_stripe")

        session_data = {
            "user_id": "user_stripe",
            "email": "stripe@example.com",
            "tier": "starter",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        # Mock Stripe subscription response
        mock_subscription = {
            "status": "active",
            "cancel_at_period_end": False,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro"},
                        "current_period_end": 1735689600,  # Future timestamp
                    }
                ]
            },
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "pro"  # Updated from Stripe
        assert body["data_source"] == "live"

    @mock_aws
    def test_no_refresh_without_subscription(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should not attempt refresh for users without subscription."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_free", "free@example.com", tier="free")

        session_data = {
            "user_id": "user_free",
            "email": "free@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        with patch("stripe.Subscription.retrieve") as mock_stripe:
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        # Should not call Stripe (no subscription_id)
        mock_stripe.assert_not_called()

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["data_source"] == "cache"

    @mock_aws
    def test_stripe_error_returns_cached_data(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should return cached data when Stripe API fails."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_stripe_fail",
            "stripefail@example.com",
            tier="pro",
            stripe_subscription_id="sub_test456",
        )
        create_user_meta(table, "user_stripe_fail")

        session_data = {
            "user_id": "user_stripe_fail",
            "email": "stripefail@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        import stripe

        with patch("stripe.Subscription.retrieve", side_effect=stripe.StripeError("API error")):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "pro"  # Cached value
        assert body["data_source"] == "cache"  # Fallback to cache

    @mock_aws
    def test_refresh_handles_cancelled_subscription(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should handle subscription that's set to cancel."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_cancel",
            "cancel@example.com",
            tier="pro",
            stripe_subscription_id="sub_cancel123",
        )
        create_user_meta(table, "user_cancel")

        session_data = {
            "user_id": "user_cancel",
            "email": "cancel@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        mock_subscription = {
            "status": "active",
            "cancel_at_period_end": True,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro"},
                        "current_period_end": 1735689600,
                    }
                ]
            },
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["cancellation_pending"] is True
        assert body["cancellation_date"] == 1735689600

    @mock_aws
    def test_refresh_downgrades_inactive_subscription(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should downgrade to free tier when subscription is not active."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_inactive",
            "inactive@example.com",
            tier="pro",
            stripe_subscription_id="sub_inactive123",
        )
        create_user_meta(table, "user_inactive")

        session_data = {
            "user_id": "user_inactive",
            "email": "inactive@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        mock_subscription = {
            "status": "canceled",  # Not active
            "cancel_at_period_end": False,
            "items": {"data": []},
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "free"  # Downgraded
        assert body["data_source"] == "live"


class TestAuthMeReferralAndBonus:
    """Tests for referral code and bonus credit handling."""

    @mock_aws
    def test_returns_referral_code(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return user's referral code."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_referral", "referral@example.com", tier="free")
        create_user_meta(table, "user_referral", referral_code="ABCD1234")

        session_data = {
            "user_id": "user_referral",
            "email": "referral@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["referral_code"] == "ABCD1234"

    @mock_aws
    def test_returns_bonus_credits(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return bonus credit balance."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_bonus", "bonus@example.com", tier="free")
        create_user_meta(
            table,
            "user_bonus",
            bonus_requests=15000,
            bonus_requests_lifetime=50000,
        )

        session_data = {
            "user_id": "user_bonus",
            "email": "bonus@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["bonus_requests"] == 15000
        assert body["bonus_lifetime"] == 50000
        assert body["bonus_cap"] == 500000

    @mock_aws
    def test_can_add_late_referral_within_window(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should show can_add_referral=True within 14-day window."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_new", "new@example.com", tier="free")

        # Created 5 days ago (within 14-day window)
        created_at = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        create_user_meta(table, "user_new", created_at=created_at)

        session_data = {
            "user_id": "user_new",
            "email": "new@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is True
        assert body["referral_code_deadline"] is not None

    @mock_aws
    def test_cannot_add_late_referral_if_already_referred(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should show can_add_referral=False if user already has referrer."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_referred", "referred@example.com", tier="free")

        created_at = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        create_user_meta(table, "user_referred", created_at=created_at, referred_by="user_other")

        session_data = {
            "user_id": "user_referred",
            "email": "referred@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is False

    @mock_aws
    def test_effective_limit_includes_bonus(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should calculate effective_limit as monthly + bonus."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_limit", "limit@example.com", tier="free")
        create_user_meta(table, "user_limit", bonus_requests=10000)

        session_data = {
            "user_id": "user_limit",
            "email": "limit@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["monthly_limit"] == 5000  # Free tier
        assert body["bonus_requests"] == 10000
        assert body["effective_limit"] == 15000  # 5000 + 10000


class TestAuthMeCORS:
    """Tests for CORS header handling."""

    @mock_aws
    def test_cors_headers_for_allowed_origin(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should include CORS headers for allowed origin."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_cors", "cors@example.com", tier="free")

        session_data = {
            "user_id": "user_cors",
            "email": "cors@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {
                "cookie": f"session={token}",
                "origin": "https://pkgwatch.dev",
            },
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"
        assert result["headers"].get("Access-Control-Allow-Credentials") == "true"

    @mock_aws
    def test_error_includes_cors_for_allowed_origin(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Error responses should include CORS headers."""
        setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": {
                "origin": "https://pkgwatch.dev",
            },
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"


class TestAuthMeErrorHandling:
    """Tests for error handling."""

    @mock_aws
    def test_handles_internal_error(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 500 for unexpected errors."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        session_data = {
            "user_id": "user_error",
            "email": "error@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        # Mock DynamoDB to raise an error
        mock_ddb = MagicMock()
        mock_ddb.Table.side_effect = Exception("DynamoDB error")
        with patch.object(module, "get_dynamodb", return_value=mock_ddb):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": None,
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_none_headers(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should handle None headers gracefully."""
        setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": None,
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 401


class TestStripeKeyCache:
    """Tests for Stripe API key caching."""

    @mock_aws
    def test_stripe_key_cached(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
        """Should cache Stripe API key and reuse it."""
        setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        # Clear cache
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None  # Reset lazy client so moto is used
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        # First call should fetch from Secrets Manager
        key1 = billing_utils.get_stripe_api_key()
        assert key1 == "sk_test_12345"

        # Second call should use cache
        key2 = billing_utils.get_stripe_api_key()
        assert key2 == "sk_test_12345"

    @mock_aws
    def test_stripe_key_returns_none_without_arn(self, aws_credentials, mock_dynamodb):
        """Should return None when STRIPE_SECRET_ARN is not set."""
        os.environ.pop("STRIPE_SECRET_ARN", None)

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = None

        try:
            key = billing_utils.get_stripe_api_key()
            assert key is None
        finally:
            billing_utils.STRIPE_SECRET_ARN = original_arn

    @mock_aws
    def test_stripe_key_handles_plain_text_secret(self, aws_credentials, mock_dynamodb):
        """Should handle plain text secret (not JSON)."""
        client = boto3.client("secretsmanager", region_name="us-east-1")
        client.create_secret(
            Name="pkgwatch/stripe-plain",
            SecretString="sk_plain_text_key",  # Not JSON
        )
        os.environ["STRIPE_SECRET_ARN"] = "pkgwatch/stripe-plain"

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None  # Reset lazy client so moto is used
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        key = billing_utils.get_stripe_api_key()
        assert key == "sk_plain_text_key"


class TestAuthMeStripeRefreshUserMetaErrors:
    """Tests covering lines 292-294 and 308-310 in auth_me.py.

    Lines 292-294: ClientError during USER_META update in _refresh_from_stripe
                   that is NOT a ConditionalCheckFailedException (logged as error).
    Lines 308-310: Generic (non-Stripe) Exception during _refresh_from_stripe.
    """

    @mock_aws
    def test_user_meta_update_non_conditional_client_error(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should still succeed when USER_META update fails with non-conditional ClientError."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        for key in ["STRIPE_PRICE_STARTER", "STRIPE_PRICE_PRO", "STRIPE_PRICE_BUSINESS"]:
            os.environ.pop(key, None)
        importlib.reload(module)

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_meta_err",
            "metaerr@example.com",
            tier="starter",
            stripe_subscription_id="sub_meta_err",
        )
        create_user_meta(table, "user_meta_err")

        session_data = {
            "user_id": "user_meta_err",
            "email": "metaerr@example.com",
            "tier": "starter",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        mock_subscription = {
            "status": "active",
            "cancel_at_period_end": False,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro"},
                        "current_period_end": 1735689600,
                    }
                ]
            },
        }

        # We need the real table update to succeed for API key records
        # but fail for USER_META. Patch _refresh_from_stripe's inner update.
        from botocore.exceptions import ClientError as BotoClientError

        original_update = table.update_item
        call_count = [0]

        def selective_fail(**kwargs):
            call_count[0] += 1
            key = kwargs.get("Key", {})
            cond_expr = kwargs.get("ConditionExpression", "")
            # The USER_META update uses ConditionExpression="attribute_exists(pk)"
            if key.get("sk") == "USER_META" and "attribute_exists(pk)" in str(cond_expr):
                raise BotoClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "DynamoDB internal error"}},
                    "UpdateItem",
                )
            return original_update(**kwargs)

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            with patch.object(module, "get_dynamodb") as mock_ddb:
                patched_table = MagicMock(wraps=table)
                patched_table.update_item = selective_fail
                patched_table.query = table.query
                patched_table.get_item = table.get_item
                mock_ddb.return_value.Table.return_value = patched_table

                event = {
                    "headers": {"cookie": f"session={token}"},
                    "queryStringParameters": {"refresh": "stripe"},
                }

                result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should still show refreshed data (USER_META error is non-fatal)
        assert body["tier"] == "pro"
        assert body["data_source"] == "live"

    @mock_aws
    def test_generic_exception_during_stripe_refresh(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """Should return cached data when a generic (non-Stripe) Exception occurs during refresh."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_gen_err",
            "generr@example.com",
            tier="pro",
            stripe_subscription_id="sub_gen_err",
        )
        create_user_meta(table, "user_gen_err")

        session_data = {
            "user_id": "user_gen_err",
            "email": "generr@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        # Raise a generic Exception (not stripe.StripeError) - covers lines 308-310
        with patch("stripe.Subscription.retrieve", side_effect=RuntimeError("Unexpected connection reset")):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "pro"  # Cached value
        assert body["data_source"] == "cache"  # Fallback to cache

    @mock_aws
    def test_user_meta_conditional_check_failure_silently_ignored(
        self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret
    ):
        """ConditionalCheckFailedException on USER_META update should be silently ignored (line 293 condition)."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        for key in ["STRIPE_PRICE_STARTER", "STRIPE_PRICE_PRO", "STRIPE_PRICE_BUSINESS"]:
            os.environ.pop(key, None)
        importlib.reload(module)

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None
        billing_utils.STRIPE_SECRET_ARN = os.environ.get("STRIPE_SECRET_ARN")

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_cond_fail",
            "condfail@example.com",
            tier="starter",
            stripe_subscription_id="sub_cond_fail",
        )
        # Do NOT create USER_META, so ConditionExpression="attribute_exists(pk)" will fail

        session_data = {
            "user_id": "user_cond_fail",
            "email": "condfail@example.com",
            "tier": "starter",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        mock_subscription = {
            "status": "active",
            "cancel_at_period_end": False,
            "items": {
                "data": [
                    {
                        "price": {"id": "price_pro"},
                        "current_period_end": 1735689600,
                    }
                ]
            },
        }

        with patch("stripe.Subscription.retrieve", return_value=mock_subscription):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Refresh should still succeed even though USER_META update failed
        assert body["tier"] == "pro"
        assert body["data_source"] == "live"


class TestAuthMeCreatedAtParsingError:
    """Tests covering lines 165-166 in auth_me.py.

    Lines 165-166: except (ValueError, TypeError): pass when parsing created_at
    for the late referral code deadline.
    """

    @mock_aws
    def test_malformed_created_at_in_user_meta(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should handle malformed created_at gracefully (ValueError branch)."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_bad_created", "bad@example.com", tier="free")
        # USER_META with malformed created_at
        create_user_meta(table, "user_bad_created", created_at="not-a-valid-iso-date")

        session_data = {
            "user_id": "user_bad_created",
            "email": "bad@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should default to can_add_referral=False when parsing fails
        assert body["can_add_referral"] is False

    @mock_aws
    def test_none_created_at_in_user_meta(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should handle None created_at gracefully (TypeError branch)."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_none_created", "none@example.com", tier="free")
        # USER_META without created_at field at all
        table.put_item(
            Item={
                "pk": "user_none_created",
                "sk": "USER_META",
                "requests_this_month": 0,
                "key_count": 1,
            }
        )

        session_data = {
            "user_id": "user_none_created",
            "email": "none@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is False


class TestAuthMeStripeKeyNotAvailable:
    """Tests covering lines 221-222 in auth_me.py.

    Lines 221-222: get_stripe_api_key() returns None, so refresh returns None.
    """

    @mock_aws
    def test_refresh_with_no_stripe_key_returns_cached(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return cached data when Stripe API key is not available."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table,
            "user_no_stripe_key",
            "nokey@example.com",
            tier="pro",
            stripe_subscription_id="sub_nokey",
        )
        create_user_meta(table, "user_no_stripe_key")

        session_data = {
            "user_id": "user_no_stripe_key",
            "email": "nokey@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        # Patch get_stripe_api_key to return None
        with patch.object(module, "get_stripe_api_key", return_value=None):
            event = {
                "headers": {"cookie": f"session={token}"},
                "queryStringParameters": {"refresh": "stripe"},
            }

            result = module.handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tier"] == "pro"  # Cached value unchanged
        assert body["data_source"] == "cache"  # Did not refresh


class TestAuthMeSessionBypass:
    """Security tests for session authentication bypass attempts."""

    @mock_aws
    def test_cookie_with_extra_fields_ignored(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Extra cookies alongside session should not affect behavior."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_extra_cookie", "extra@example.com", tier="free")

        session_data = {
            "user_id": "user_extra_cookie",
            "email": "extra@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"tracking=abc123; session={token}; other=xyz"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["user_id"] == "user_extra_cookie"

    @mock_aws
    def test_case_insensitive_cookie_header(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should handle 'Cookie' header (capital C) as well as 'cookie'."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_cookie_case", "case@example.com", tier="free")

        session_data = {
            "user_id": "user_cookie_case",
            "email": "case@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        # Use "Cookie" (capital C) header
        event = {
            "headers": {"Cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)
        assert result["statusCode"] == 200

    @mock_aws
    def test_wrong_cookie_name_returns_401(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should return 401 when cookie has wrong name (e.g., 'token' instead of 'session')."""
        setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        event = {
            "headers": {"cookie": "token=some_value; auth=something_else"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)
        assert result["statusCode"] == 401

    @mock_aws
    def test_no_cache_headers_in_response(self, aws_credentials, mock_dynamodb, setup_session_secret):
        """Should include no-cache headers to prevent stale data."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        import importlib

        import api.auth_me as module

        importlib.reload(module)

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(table, "user_nocache", "nocache@example.com", tier="free")

        session_data = {
            "user_id": "user_nocache",
            "email": "nocache@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        token = create_session_token(session_data, secret)

        event = {
            "headers": {"cookie": f"session={token}"},
            "queryStringParameters": None,
        }

        result = module.handler(event, None)
        assert result["statusCode"] == 200
        assert "no-store" in result["headers"].get("Cache-Control", "")
        assert "no-cache" in result["headers"].get("Cache-Control", "")
