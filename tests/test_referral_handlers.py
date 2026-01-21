"""
Tests for referral program Lambda handlers.

Tests cover:
- Referral redirect handler (/r/{code})
- Referral status handler (GET /referral/status)
- Add referral code handler (POST /referral/add-code)
- Referral cleanup scheduled handler
- Referral retention check scheduled handler
"""

import base64
import hashlib
import hmac
import json
import os
import pytest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def referral_env_vars():
    """Set environment variables for referral tests."""
    original_env = os.environ.copy()

    os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
    os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"
    os.environ["BASE_URL"] = "https://pkgwatch.dev"
    os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

    # Reset module-level BASE_URL in referral modules
    try:
        import api.referral_redirect as redirect_module
        redirect_module.BASE_URL = "https://pkgwatch.dev"
    except ImportError:
        pass

    try:
        import api.referral_status as status_module
        status_module.BASE_URL = "https://pkgwatch.dev"
    except ImportError:
        pass

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


def create_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create a valid session token for testing."""
    session_secret = "test-secret-key-for-signing-sessions-1234567890"
    session_expires = datetime.now(timezone.utc) + timedelta(days=7)
    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int(session_expires.timestamp()),
    }
    payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
    signature = hmac.new(
        session_secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


class TestReferralRedirectHandler:
    """Tests for GET /r/{code} redirect handler."""

    def test_valid_code_redirects_with_ref_param(self):
        """Valid referral code should redirect to start page with ref param."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": {"code": "abc12345"},
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start?ref=abc12345"
        assert result["headers"]["Cache-Control"] == "no-store"

    def test_missing_code_redirects_to_start(self):
        """Missing code should redirect to start page without ref."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": {},
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start"

    def test_invalid_code_too_short_redirects_to_start(self):
        """Code that's too short should redirect to start without ref."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": {"code": "abc"},  # Too short
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start"

    def test_invalid_code_too_long_redirects_to_start(self):
        """Code that's too long should redirect to start without ref."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": {"code": "a" * 20},  # Too long
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start"

    def test_invalid_code_special_chars_redirects_to_start(self):
        """Code with special chars should redirect to start without ref."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": {"code": "abc!@#123"},  # Special chars
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start"

    def test_null_path_parameters_handled(self):
        """Null pathParameters should be handled gracefully."""
        from api.referral_redirect import handler

        event = {
            "httpMethod": "GET",
            "pathParameters": None,
            "headers": {},
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 302
        assert result["headers"]["Location"] == "https://pkgwatch.dev/start"


class TestReferralStatusHandler:
    """Tests for GET /referral/status handler."""

    @pytest.fixture
    def user_with_referrals(self, mock_dynamodb):
        """Create a user with referral code and stats."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_status_test"

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_code": "testcode",
                "email": "status@example.com",
                "bonus_requests": 15000,
                "bonus_requests_lifetime": 30000,
                "referral_total": 3,
                "referral_pending_count": 1,
                "referral_paid": 1,
                "referral_retained": 1,
                "referral_rewards_earned": 30000,
            }
        )

        return table, user_id

    def test_returns_401_without_session(self, mock_dynamodb):
        """Should return 401 without session cookie."""
        from api.referral_status import handler

        event = {
            "httpMethod": "GET",
            "headers": {},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401

    @patch("api.auth_callback._get_session_secret")
    def test_returns_referral_status(self, mock_secret, user_with_referrals):
        """Should return complete referral status for authenticated user."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table, user_id = user_with_referrals

        from api.referral_status import handler

        session_token = create_session_token(user_id, "status@example.com")

        event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        assert body["referral_code"] == "testcode"
        assert body["referral_url"] == "https://pkgwatch.dev/r/testcode"
        assert body["bonus_requests"] == 15000
        assert body["bonus_cap"] == 500000
        assert body["bonus_lifetime"] == 30000
        assert body["at_cap"] is False
        assert body["stats"]["total_referrals"] == 3
        assert body["stats"]["pending_referrals"] == 1

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_invalid_user_id_format(self, mock_secret, mock_dynamodb):
        """Should return 401 for session with invalid user_id format."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.referral_status import handler

        # Create session with invalid user_id format
        session_data = {
            "user_id": "invalid_format",  # Should start with "user_"
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
        signature = hmac.new(
            b"test-secret-key-for-signing-sessions-1234567890",
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        bad_session = f"{payload}.{signature}"

        event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={bad_session}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_session"


class TestAddReferralCodeHandler:
    """Tests for POST /referral/add-code handler."""

    @pytest.fixture
    def recent_user_and_referrer(self, mock_dynamodb):
        """Create a recent user and a referrer with code."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create referrer
        referrer_id = "user_referrer"
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "email": "referrer@example.com",
                "referral_code": "refcode1",
            }
        )

        # Create recent user (within 14 days)
        user_id = "user_recent"
        created = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "email": "recent@example.com",
                "created_at": created,
            }
        )

        return table, user_id, referrer_id

    def test_returns_401_without_session(self, mock_dynamodb):
        """Should return 401 without session cookie."""
        from api.add_referral_code import handler

        event = {
            "httpMethod": "POST",
            "headers": {},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_invalid_json(self, mock_secret, mock_dynamodb):
        """Should return 400 for invalid JSON body."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": "not valid json",
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_invalid_code_format(self, mock_secret, mock_dynamodb):
        """Should return 400 for invalid referral code format."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test_format",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test_format", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "ab"}),  # Too short
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_payload_too_large(self, mock_secret, mock_dynamodb):
        """Should return 400 for payload exceeding size limit."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_test_large", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": "x" * 2000,  # Exceeds 1000 byte limit
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "payload_too_large"


class TestReferralCleanupHandler:
    """Tests for scheduled referral cleanup handler."""

    @pytest.fixture
    def expired_pending_referrals(self, mock_dynamodb):
        """Create users with expired pending referrals."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create referrer
        referrer_id = "user_referrer_cleanup"
        table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "referral_total": 2,
                "referral_pending_count": 2,
            }
        )

        # Create expired pending referral (91 days ago)
        expired_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        table.put_item(
            Item={
                "pk": "user_expired1",
                "sk": "USER_META",
                "referral_pending": True,
                "referral_pending_expires": expired_date,
                "referred_by": referrer_id,
            }
        )

        # Create non-expired pending referral (future expiry)
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        table.put_item(
            Item={
                "pk": "user_active",
                "sk": "USER_META",
                "referral_pending": True,
                "referral_pending_expires": future_date,
                "referred_by": referrer_id,
            }
        )

        return table, referrer_id

    def test_cleans_expired_pending_referrals(self, expired_pending_referrals):
        """Should clean up expired pending referrals."""
        # Reset the module's dynamodb cache
        import api.referral_cleanup as cleanup_module
        cleanup_module._dynamodb = None

        from api.referral_cleanup import handler

        table, referrer_id = expired_pending_referrals

        result = handler({}, {})

        assert result["cleaned"] >= 1
        assert result["errors"] == 0

        # Verify expired user's pending flag was cleared
        response = table.get_item(Key={"pk": "user_expired1", "sk": "USER_META"})
        item = response.get("Item", {})
        assert item.get("referral_pending") is not True

        # Verify active user's pending flag is still set
        response = table.get_item(Key={"pk": "user_active", "sk": "USER_META"})
        item = response["Item"]
        assert item.get("referral_pending") is True

    def test_handles_empty_scan(self, mock_dynamodb):
        """Should handle case with no expired referrals."""
        import api.referral_cleanup as cleanup_module
        cleanup_module._dynamodb = None

        from api.referral_cleanup import handler

        result = handler({}, {})

        assert result["processed"] == 0
        assert result["cleaned"] == 0
        assert result["errors"] == 0


class TestReferralRetentionCheckHandler:
    """Tests for scheduled retention check handler."""

    @pytest.fixture
    def retention_due_referrals(self, mock_dynamodb):
        """Create referrals due for retention check."""
        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        # Create referrer
        referrer_id = "user_referrer_retention"
        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
                "referral_paid": 1,
                "referral_retained": 0,
            }
        )

        # Create referred user with Stripe subscription
        referred_id = "user_referred_retention"
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "USER_META",
                "stripe_subscription_id": "sub_test123",
                "tier": "pro",
            }
        )

        # Create retention event that's due (past date)
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": past_date,
            }
        )

        return api_table, events_table, referrer_id, referred_id

    @patch("api.referral_retention_check._get_stripe_api_key")
    def test_handles_empty_retention_queue(self, mock_stripe_key, mock_dynamodb):
        """Should handle case with no referrals due for retention."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Reset module caches
        import api.referral_retention_check as retention_module
        retention_module._dynamodb = None

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 0
        assert result["credited"] == 0
        assert result["errors"] == 0
