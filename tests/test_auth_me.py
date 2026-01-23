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
from decimal import Decimal
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture
def setup_session_secret():
    """Set up secrets manager with a session secret."""
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(
        Name="pkgwatch/session-secret",
        SecretString=json.dumps({"secret": "test-session-secret-12345"})
    )
    os.environ["SESSION_SECRET_ARN"] = "pkgwatch/session-secret"
    return "test-session-secret-12345"


@pytest.fixture
def setup_stripe_secret():
    """Set up secrets manager with Stripe API key."""
    import boto3

    client = boto3.client("secretsmanager", region_name="us-east-1")
    client.create_secret(
        Name="pkgwatch/stripe-secret",
        SecretString=json.dumps({"key": "sk_test_12345"})
    )
    os.environ["STRIPE_SECRET_ARN"] = "pkgwatch/stripe-secret"
    return "sk_test_12345"


def create_session_token(data: dict, secret: str) -> str:
    """Create a signed session token for testing."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
    signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
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
        table.put_item(Item={
            "pk": "user_pending_test",
            "sk": "PENDING",
            "email": "pending@example.com",
        })

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
        table.put_item(Item={
            "pk": "user_multikey",
            "sk": key_hash2,
            "key_hash": key_hash2,
            "email": "multi@example.com",
            "tier": "free",
            "requests_this_month": 200,
        })

        # Create USER_META without requests_this_month (old schema)
        table.put_item(Item={
            "pk": "user_multikey",
            "sk": "USER_META",
            "key_count": 2,
        })

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
    def test_refresh_stripe_updates_user_data(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
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

        # Clear Stripe key cache
        module._stripe_api_key_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table, "user_stripe", "stripe@example.com",
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
            }
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
    def test_no_refresh_without_subscription(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
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
    def test_stripe_error_returns_cached_data(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
        """Should return cached data when Stripe API fails."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback
        auth_callback._session_secret_cache = None

        import importlib
        import api.auth_me as module
        importlib.reload(module)
        module._stripe_api_key_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table, "user_stripe_fail", "stripefail@example.com",
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
    def test_refresh_handles_cancelled_subscription(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
        """Should handle subscription that's set to cancel."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback
        auth_callback._session_secret_cache = None

        import importlib
        import api.auth_me as module
        importlib.reload(module)
        module._stripe_api_key_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table, "user_cancel", "cancel@example.com",
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
            }
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
    def test_refresh_downgrades_inactive_subscription(self, aws_credentials, mock_dynamodb, setup_session_secret, setup_stripe_secret):
        """Should downgrade to free tier when subscription is not active."""
        secret = setup_session_secret
        import api.auth_callback as auth_callback
        auth_callback._session_secret_cache = None

        import importlib
        import api.auth_me as module
        importlib.reload(module)
        module._stripe_api_key_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        create_test_user(
            table, "user_inactive", "inactive@example.com",
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
            table, "user_bonus",
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
        with patch.object(module.dynamodb, "Table", side_effect=Exception("DynamoDB error")):
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
        module._stripe_api_key_cache = None
        module._stripe_api_key_cache_time = 0.0

        # First call should fetch from Secrets Manager
        key1 = module._get_stripe_api_key()
        assert key1 == "sk_test_12345"

        # Second call should use cache
        key2 = module._get_stripe_api_key()
        assert key2 == "sk_test_12345"

    @mock_aws
    def test_stripe_key_returns_none_without_arn(self, aws_credentials, mock_dynamodb):
        """Should return None when STRIPE_SECRET_ARN is not set."""
        os.environ.pop("STRIPE_SECRET_ARN", None)

        import importlib
        import api.auth_me as module
        importlib.reload(module)

        module._stripe_api_key_cache = None
        module._stripe_api_key_cache_time = 0.0

        key = module._get_stripe_api_key()
        assert key is None

    @mock_aws
    def test_stripe_key_handles_plain_text_secret(self, aws_credentials, mock_dynamodb):
        """Should handle plain text secret (not JSON)."""
        client = boto3.client("secretsmanager", region_name="us-east-1")
        client.create_secret(
            Name="pkgwatch/stripe-plain",
            SecretString="sk_plain_text_key"  # Not JSON
        )
        os.environ["STRIPE_SECRET_ARN"] = "pkgwatch/stripe-plain"

        import importlib
        import api.auth_me as module
        importlib.reload(module)

        module._stripe_api_key_cache = None
        module._stripe_api_key_cache_time = 0.0

        key = module._get_stripe_api_key()
        assert key == "sk_plain_text_key"
