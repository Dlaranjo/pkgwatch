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
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest


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
    signature = hmac.new(session_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
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

    def test_handles_conditional_check_failed_in_cleanup(self, mock_dynamodb):
        """Should handle ConditionalCheckFailedException when pending flag already cleared (lines 101-104)."""

        import api.referral_cleanup as cleanup_module

        cleanup_module._dynamodb = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create expired pending referral
        expired_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        table.put_item(
            Item={
                "pk": "user_race_condition",
                "sk": "USER_META",
                "referral_pending": True,
                "referral_pending_expires": expired_date,
                "referred_by": "user_referrer_race",
            }
        )

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_referrer_race",
                "sk": "USER_META",
                "referral_pending_count": 1,
            }
        )

        from api.referral_cleanup import handler

        # Now clear the pending flag manually to simulate a race condition
        table.update_item(
            Key={"pk": "user_race_condition", "sk": "USER_META"},
            UpdateExpression="REMOVE referral_pending, referral_pending_expires",
        )

        result = handler({}, {})

        # Should not count as an error - the ConditionalCheckFailedException is expected
        assert result["errors"] == 0

    def test_handles_generic_exception_in_cleanup_loop(self, mock_dynamodb):
        """Should count errors when unexpected exceptions occur during cleanup (lines 109-111)."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create expired pending referral
        expired_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        table.put_item(
            Item={
                "pk": "user_cleanup_err",
                "sk": "USER_META",
                "referral_pending": True,
                "referral_pending_expires": expired_date,
                "referred_by": "user_referrer_err",
            }
        )

        # Create a mock table that wraps the real one but fails on update_item
        mock_table = MagicMock()
        mock_table.scan.side_effect = table.scan
        mock_table.update_item.side_effect = Exception("Unexpected error")

        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table

        from api.referral_cleanup import handler

        with patch("api.referral_cleanup.get_dynamodb", return_value=mock_db):
            result = handler({}, {})

        assert result["errors"] >= 1

    def test_handles_scan_level_exception(self, mock_dynamodb):
        """Should return error result when the scan itself fails (lines 119-121)."""
        # Use a mock that raises on scan
        mock_table = MagicMock()
        mock_table.scan.side_effect = Exception("DynamoDB scan failure")

        mock_db = MagicMock()
        mock_db.Table.return_value = mock_table

        from api.referral_cleanup import handler

        with patch("api.referral_cleanup.get_dynamodb", return_value=mock_db):
            result = handler({}, {})

        assert result["processed"] == 0
        assert result["cleaned"] == 0
        assert "error" in result
        assert "DynamoDB scan failure" in result["error"]

    def test_pagination_processes_multiple_pages(self, mock_dynamodb):
        """Should paginate through multiple scan pages (lines 114-117)."""
        import api.referral_cleanup as cleanup_module

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_referrer_page",
                "sk": "USER_META",
                "referral_pending_count": 3,
            }
        )

        # Create multiple expired pending referrals
        expired_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        for i in range(3):
            table.put_item(
                Item={
                    "pk": f"user_page_{i}",
                    "sk": "USER_META",
                    "referral_pending": True,
                    "referral_pending_expires": expired_date,
                    "referred_by": "user_referrer_page",
                }
            )

        # Use a mock that simulates pagination
        original_scan = table.scan

        call_count = [0]

        def paginated_scan(**kwargs):
            call_count[0] += 1
            result = original_scan(**kwargs)
            # On first call, simulate there being another page
            if call_count[0] == 1 and result.get("Items"):
                # Keep only first item and pretend there's more
                first_item = result["Items"][0]
                result["Items"] = [first_item]
                result["LastEvaluatedKey"] = {"pk": {"S": first_item["pk"]}, "sk": {"S": "USER_META"}}
            return result

        cleanup_module._dynamodb = None

        from api.referral_cleanup import handler

        with patch.object(table, "scan", side_effect=paginated_scan):
            result = handler({}, {})

        # Should have cleaned at least 1 item across pages
        assert result["cleaned"] >= 1
        assert result["errors"] == 0


class TestReferralStatusErrorPaths:
    """Tests for referral_status.py error handling and edge cases."""

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_expired_session(self, mock_secret, mock_dynamodb):
        """Should return 401 when session token is expired (line 65)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.referral_status import handler

        # Create an expired session token
        session_data = {
            "user_id": "user_expired",
            "email": "expired@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
        }
        payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
        signature = hmac.new(
            b"test-secret-key-for-signing-sessions-1234567890",
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        expired_token = f"{payload}.{signature}"

        event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={expired_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @patch("api.auth_callback._get_session_secret")
    def test_generates_referral_code_for_legacy_user(self, mock_secret, mock_dynamodb):
        """Should generate a referral code for legacy users without one (lines 93-101)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = "user_legacy_nocode"

        # Create user WITHOUT a referral code
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "email": "legacy@example.com",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        from api.referral_status import handler

        session_token = create_session_token(user_id, "legacy@example.com")

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

        # Should have generated a referral code
        assert body["referral_code"] is not None
        assert len(body["referral_code"]) >= 6
        assert body["referral_url"].startswith("https://pkgwatch.dev/r/")

        # Verify it was persisted to DB
        response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert response["Item"].get("referral_code") is not None

    @patch("api.auth_callback._get_session_secret")
    def test_returns_referral_events_with_pending_and_expiry(self, mock_secret, mock_dynamodb):
        """Should return referral events including pending with expiry dates (lines 121-144)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")
        user_id = "user_events_test"

        # Create user with referral code
        api_table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_code": "evntcode",
                "email": "events@example.com",
                "bonus_requests": 5000,
                "bonus_requests_lifetime": 10000,
                "referral_total": 2,
                "referral_pending_count": 1,
                "referral_paid": 1,
                "referral_retained": 0,
                "referral_rewards_earned": 5000,
            }
        )

        # Create a credited referral event
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_ref1#signup",
                "event_type": "signup",
                "referred_id": "user_ref1",
                "referred_email_masked": "te**@example.com",
                "created_at": "2024-01-15T10:00:00Z",
                "reward_amount": 5000,
            }
        )

        # Create a pending referral event with TTL (expiry)
        future_ttl = int((datetime.now(timezone.utc) + timedelta(days=30)).timestamp())
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_ref2#pending",
                "event_type": "pending",
                "referred_id": "user_ref2",
                "referred_email_masked": "pe**@example.com",
                "created_at": "2024-01-20T10:00:00Z",
                "reward_amount": 0,
                "ttl": future_ttl,
            }
        )

        from api.referral_status import handler

        session_token = create_session_token(user_id, "events@example.com")

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

        # Check referrals list
        assert len(body["referrals"]) == 2

        # Find the pending referral
        pending_referrals = [r for r in body["referrals"] if r["status"] == "pending"]
        assert len(pending_referrals) == 1
        assert "expires" in pending_referrals[0]

        # Find the credited referral
        credited_referrals = [r for r in body["referrals"] if r["status"] == "credited"]
        assert len(credited_referrals) == 1
        assert credited_referrals[0]["reward"] == 5000

    @patch("api.auth_callback._get_session_secret")
    def test_returns_500_on_internal_error(self, mock_secret, mock_dynamodb):
        """Should return 500 when an unexpected error occurs (lines 167-169)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.referral_status import handler

        session_token = create_session_token("user_err_test", "err@example.com")

        event = {
            "httpMethod": "GET",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        # Patch dynamodb.Table to raise an exception
        import api.referral_status as status_module

        with patch.object(status_module.dynamodb, "Table", side_effect=Exception("DB connection failed")):
            result = handler(event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @patch("api.auth_callback._get_session_secret")
    def test_deduplicates_referral_events_by_referred_id(self, mock_secret, mock_dynamodb):
        """Should only show one entry per referred user even with multiple events."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")
        user_id = "user_dedup_test"

        api_table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_code": "dedupcd1",
                "email": "dedup@example.com",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
                "referral_total": 1,
                "referral_pending_count": 0,
                "referral_paid": 1,
                "referral_retained": 0,
                "referral_rewards_earned": 30000,
            }
        )

        # Same referred_id but different event types (pending -> signup -> paid)
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_same#pending",
                "event_type": "pending",
                "referred_id": "user_same",
                "referred_email_masked": "sa**@example.com",
                "created_at": "2024-01-10T10:00:00Z",
                "reward_amount": 0,
            }
        )
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_same#signup",
                "event_type": "signup",
                "referred_id": "user_same",
                "referred_email_masked": "sa**@example.com",
                "created_at": "2024-01-11T10:00:00Z",
                "reward_amount": 5000,
            }
        )
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_same#paid",
                "event_type": "paid",
                "referred_id": "user_same",
                "referred_email_masked": "sa**@example.com",
                "created_at": "2024-01-12T10:00:00Z",
                "reward_amount": 25000,
            }
        )

        from api.referral_status import handler

        session_token = create_session_token(user_id, "dedup@example.com")

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

        # Should only have 1 referral entry despite 3 events for same user
        assert len(body["referrals"]) == 1
        # Priority dedup should pick the highest-priority event (#paid, 25K reward)
        assert body["referrals"][0]["status"] == "credited"
        assert body["referrals"][0]["reward"] == 25000

    @patch("api.auth_callback._get_session_secret")
    def test_shows_paid_not_pending_when_both_exist(self, mock_secret, mock_dynamodb):
        """Priority dedup should show 'credited' even if stale #pending event exists."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")
        user_id = "user_priority_test"

        api_table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "referral_code": "priocd01",
                "email": "prio@example.com",
                "bonus_requests": 25000,
                "bonus_requests_lifetime": 25000,
                "referral_total": 1,
                "referral_pending_count": 0,
                "referral_paid": 1,
                "referral_retained": 0,
                "referral_rewards_earned": 25000,
            }
        )

        # Stale #pending event (should have been deleted but wasn't)
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_stale#pending",
                "event_type": "pending",
                "referred_id": "user_stale",
                "referred_email_masked": "st**@example.com",
                "created_at": "2024-01-10T10:00:00Z",
                "reward_amount": 0,
                "ttl": 1800000000,
            }
        )
        # Correct #paid event
        events_table.put_item(
            Item={
                "pk": user_id,
                "sk": "user_stale#paid",
                "event_type": "paid",
                "referred_id": "user_stale",
                "referred_email_masked": "st**@example.com",
                "created_at": "2024-01-15T10:00:00Z",
                "reward_amount": 25000,
            }
        )

        from api.referral_status import handler

        session_token = create_session_token(user_id, "prio@example.com")

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

        # Should show 1 referral with credited status and 25K reward
        assert len(body["referrals"]) == 1
        assert body["referrals"][0]["status"] == "credited"
        assert body["referrals"][0]["reward"] == 25000


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

    @patch("api.referral_retention_check.get_stripe_api_key")
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

    @patch("api.referral_retention_check.get_stripe_api_key")
    def test_returns_error_when_stripe_not_configured(self, mock_stripe_key, mock_dynamodb):
        """Should return error when Stripe API key is not available."""
        mock_stripe_key.return_value = None

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 0
        assert result["credited"] == 0
        assert result["error"] == "Stripe not configured"

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_credits_referrer_when_subscription_active(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Should credit referrer when referred user has active subscription."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock active Stripe subscription
        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None

        # Reset shared.referral_utils module cache
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        # Also need API key record (not just USER_META) for subscription lookup
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_123",
                "stripe_subscription_id": "sub_test123",
                "tier": "pro",
            }
        )

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 1
        assert result["errors"] == 0

        # Verify referrer received bonus credits
        response = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 25000
        assert item["bonus_requests_lifetime"] == 25000

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_credits_referrer_when_subscription_trialing(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Should credit referrer when referred user has trialing subscription."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock trialing Stripe subscription
        mock_subscription = MagicMock()
        mock_subscription.status = "trialing"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        # Add API key record with subscription
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_456",
                "stripe_subscription_id": "sub_test123",
                "tier": "pro",
            }
        )

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_skips_credit_when_subscription_canceled(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Should not credit referrer when referred user's subscription is canceled."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock canceled subscription
        mock_subscription = MagicMock()
        mock_subscription.status = "canceled"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_789",
                "stripe_subscription_id": "sub_test123",
            }
        )

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 0  # No credit awarded

        # Verify referrer did not receive bonus
        response = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 0

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_skips_credit_when_no_subscription_found(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Should not credit when referred user has no Stripe subscription."""
        mock_stripe_key.return_value = "sk_test_fake"

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        # Remove the USER_META with subscription and add one without
        api_table.delete_item(Key={"pk": referred_id, "sk": "USER_META"})
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "USER_META",
                "tier": "free",
                # No stripe_subscription_id
            }
        )

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 0

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_handles_stripe_api_error_gracefully(self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals):
        """Should handle Stripe API errors gracefully and continue processing."""
        import stripe

        mock_stripe_key.return_value = "sk_test_fake"

        # Mock Stripe error
        mock_stripe_retrieve.side_effect = stripe.StripeError("API Error")

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_stripe_err",
                "stripe_subscription_id": "sub_test123",
            }
        )

        result = handler({}, {})

        # Should process but not credit due to Stripe error
        assert result["processed"] == 1
        assert result["credited"] == 0
        assert result["errors"] == 0  # Stripe errors are warnings, not errors

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_clears_retention_flag_for_churned_user(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Should clear retention check flag when user churned (not retained)."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock canceled subscription (churned user)
        mock_subscription = MagicMock()
        mock_subscription.status = "canceled"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_clear",
                "stripe_subscription_id": "sub_test123",
            }
        )

        handler({}, {})

        # For churned users, #paid event should still exist but with flags cleared
        response = events_table.get_item(Key={"pk": referrer_id, "sk": f"{referred_id}#paid"})
        item = response.get("Item", {})
        assert item.get("needs_retention_check") is None
        assert item.get("retention_check_date") is None

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_processes_multiple_referrals_from_same_referrer(
        self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb
    ):
        """Should process multiple referrals from the same referrer."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_multi_referrer"

        # Create referrer
        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )

        # Create two referred users with active subscriptions
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        for i in range(2):
            referred_id = f"user_referred_multi_{i}"

            api_table.put_item(
                Item={
                    "pk": referred_id,
                    "sk": f"api_key_hash_{i}",
                    "stripe_subscription_id": f"sub_multi_{i}",
                    "tier": "pro",
                }
            )

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

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 2
        assert result["credited"] == 2

        # Verify referrer got credits for both
        response = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests"] == 50000  # 25000 * 2
        assert item["bonus_requests_lifetime"] == 50000

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_retention_check_date_boundary_future_date_not_processed(
        self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb
    ):
        """Referrals with future retention dates should not be processed."""
        mock_stripe_key.return_value = "sk_test_fake"

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_referrer_future"
        referred_id = "user_referred_future"

        api_table.put_item(Item={"pk": referrer_id, "sk": "USER_META"})
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_future",
            }
        )

        # Future date - should NOT be processed
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": future_date,
            }
        )

        from api.referral_retention_check import handler

        result = handler({}, {})

        # Should not process future-dated retention checks
        assert result["processed"] == 0
        assert result["credited"] == 0

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_retention_check_date_boundary_exactly_now(self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb):
        """Referrals with retention date at exactly now should be processed."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_referrer_now"
        referred_id = "user_referred_now"

        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_now",
            }
        )

        # Exactly now - should be processed (lte comparison)
        now_date = datetime.now(timezone.utc).isoformat()
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": now_date,
            }
        )

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_retention_check_60_days_after_paid(self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb):
        """Retention check should be scheduled for 60 days (2 months) after paid conversion."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_referrer_60d"
        referred_id = "user_referred_60d"

        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_60d",
            }
        )

        # Simulate paid event that occurred 61 days ago
        paid_date = datetime.now(timezone.utc) - timedelta(days=61)
        # Retention check was scheduled 60 days after that = 1 day ago
        retention_date = (paid_date + timedelta(days=60)).isoformat()

        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referrer_id": referrer_id,
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": retention_date,
                "created_at": paid_date.isoformat(),
            }
        )

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_records_retained_event(self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals):
        """Should record a 'retained' event when crediting referrer."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_record",
                "stripe_subscription_id": "sub_test123",
            }
        )

        handler({}, {})

        # Verify retained event was recorded
        response = events_table.get_item(Key={"pk": referrer_id, "sk": f"{referred_id}#retained"})
        assert "Item" in response
        item = response["Item"]
        assert item["event_type"] == "retained"
        assert item["reward_amount"] == 25000

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_updates_referrer_retained_stats(self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals):
        """Should update referrer's retained count when crediting."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_stats",
                "stripe_subscription_id": "sub_test123",
            }
        )

        handler({}, {})

        # Verify referrer stats updated
        response = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        item = response["Item"]
        assert item["referral_retained"] == 1  # Was 0, now 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("api.referral_retention_check.get_dynamodb")
    def test_handles_dynamodb_query_error(self, mock_get_dynamodb, mock_stripe_key, mock_dynamodb):
        """Should handle DynamoDB errors during index query."""
        mock_stripe_key.return_value = "sk_test_fake"

        from botocore.exceptions import ClientError

        # Create a mock table that raises an error on query
        mock_table = MagicMock()
        mock_table.query.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Query"
        )

        mock_dynamodb_resource = MagicMock()
        mock_dynamodb_resource.Table.return_value = mock_table
        mock_get_dynamodb.return_value = mock_dynamodb_resource

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 0
        assert result["credited"] == 0
        assert "error" in result

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_handles_processing_error_continues_with_others(self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb):
        """Should continue processing other referrals when one fails."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        # First referral - will have processing error (no referrer USER_META)
        events_table.put_item(
            Item={
                "pk": "user_missing_referrer",
                "sk": "user_referred_error#paid",
                "referrer_id": "user_missing_referrer",
                "referred_id": "user_referred_error",
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": past_date,
            }
        )
        api_table.put_item(
            Item={
                "pk": "user_referred_error",
                "sk": "api_key",
                "stripe_subscription_id": "sub_error",
            }
        )

        # Second referral - should succeed
        referrer_id = "user_good_referrer"
        referred_id = "user_good_referred"
        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 0,
                "bonus_requests_lifetime": 0,
            }
        )
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_good",
            }
        )
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

        from api.referral_retention_check import handler

        result = handler({}, {})

        # Should process both, credit at least one
        assert result["processed"] == 2
        assert result["credited"] >= 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_bonus_cap_applied_on_retention_credit(self, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb):
        """Should apply bonus cap when crediting retention reward."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_referrer_cap"
        referred_id = "user_referred_cap"

        # Referrer is at 490K of 500K cap
        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 490000,
            }
        )
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_cap",
            }
        )

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

        from api.referral_retention_check import handler

        result = handler({}, {})

        assert result["processed"] == 1
        assert result["credited"] == 1

        # Verify partial credit applied (only 10K to reach cap, not full 25K)
        response = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})
        item = response["Item"]
        assert item["bonus_requests_lifetime"] == 500000  # At cap

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_skips_pending_and_user_meta_records(self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals):
        """Should skip PENDING and USER_META records when looking for subscription."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        # Add PENDING record (should be skipped)
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "PENDING",
                "stripe_subscription_id": "should_be_skipped",
            }
        )

        # Add actual API key record with subscription
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_actual",
                "stripe_subscription_id": "sub_actual",
            }
        )

        result = handler({}, {})

        # Verify the actual subscription was found
        mock_stripe_retrieve.assert_called_once_with("sub_actual")
        assert result["credited"] == 1

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_retention_deletes_paid_creates_retained(
        self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals
    ):
        """Successful retention should delete #paid and create #retained event."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_ret",
                "stripe_subscription_id": "sub_test123",
            }
        )

        result = handler({}, {})
        assert result["credited"] == 1

        # #paid event should be GONE (deleted by transition)
        paid = events_table.get_item(Key={"pk": referrer_id, "sk": f"{referred_id}#paid"})
        assert "Item" not in paid

        # #retained event should exist
        retained = events_table.get_item(Key={"pk": referrer_id, "sk": f"{referred_id}#retained"})
        assert "Item" in retained
        assert retained["Item"]["event_type"] == "retained"
        assert retained["Item"]["reward_amount"] == 25000

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    def test_no_ghost_paid_after_retention(self, mock_stripe_retrieve, mock_stripe_key, retention_due_referrals):
        """After retention, mark_retention_checked should NOT create a ghost #paid item."""
        mock_stripe_key.return_value = "sk_test_fake"

        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        from api.referral_retention_check import handler

        api_table, events_table, referrer_id, referred_id = retention_due_referrals

        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_ghost",
                "stripe_subscription_id": "sub_test123",
            }
        )

        handler({}, {})

        # Verify no ghost #paid record exists
        paid = events_table.get_item(Key={"pk": referrer_id, "sk": f"{referred_id}#paid"})
        # Should not exist at all (no ghost from update_item on deleted key)
        assert "Item" not in paid


class TestGetStripeApiKey:
    """Tests for get_stripe_api_key function in shared.billing_utils."""

    @pytest.fixture(autouse=True)
    def setup_env(self):
        """Setup environment for Stripe tests."""
        import shared.billing_utils as billing_utils

        original_env = os.environ.copy()
        os.environ["STRIPE_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:123456789:secret:test-stripe"

        # Update billing_utils to pick up new environment variable
        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = os.environ["STRIPE_SECRET_ARN"]
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0
        billing_utils._secretsmanager = None

        yield

        os.environ.clear()
        os.environ.update(original_env)
        billing_utils.STRIPE_SECRET_ARN = original_arn
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

    @patch("shared.billing_utils.get_secretsmanager")
    def test_retrieves_key_from_json_secret(self, mock_get_sm):
        """Should retrieve Stripe key from JSON secret."""
        import shared.billing_utils as billing_utils

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": '{"key": "sk_test_json_key"}'}
        mock_get_sm.return_value = mock_sm

        result = billing_utils.get_stripe_api_key()

        assert result == "sk_test_json_key"

    @patch("shared.billing_utils.get_secretsmanager")
    def test_retrieves_key_from_plain_string_secret(self, mock_get_sm):
        """Should retrieve Stripe key from plain string secret."""
        import shared.billing_utils as billing_utils

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "sk_test_plain_key"}
        mock_get_sm.return_value = mock_sm

        result = billing_utils.get_stripe_api_key()

        assert result == "sk_test_plain_key"

    @patch("shared.billing_utils.get_secretsmanager")
    def test_handles_secrets_manager_error(self, mock_get_sm):
        """Should return None when Secrets Manager fails."""
        import shared.billing_utils as billing_utils

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        from botocore.exceptions import ClientError

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "Not found"}}, "GetSecretValue"
        )
        mock_get_sm.return_value = mock_sm

        result = billing_utils.get_stripe_api_key()

        assert result is None

    @patch("shared.billing_utils.get_secretsmanager")
    def test_uses_json_key_field_when_present(self, mock_get_sm):
        """Should prefer 'key' field from JSON over entire string."""
        import shared.billing_utils as billing_utils

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": '{"key": "sk_test_from_key_field", "other": "value"}'}
        mock_get_sm.return_value = mock_sm

        result = billing_utils.get_stripe_api_key()

        assert result == "sk_test_from_key_field"

    @patch("shared.billing_utils.get_secretsmanager")
    def test_falls_back_to_secret_string_when_key_empty(self, mock_get_sm):
        """Should fall back to full secret string when 'key' field is empty."""
        import shared.billing_utils as billing_utils

        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": '{"key": "", "fallback": "data"}'}
        mock_get_sm.return_value = mock_sm

        result = billing_utils.get_stripe_api_key()

        # Falls back to the entire JSON string when key is empty
        assert result == '{"key": "", "fallback": "data"}'


class TestRetentionCheckNoStripeArn:
    """Test behavior when STRIPE_SECRET_ARN is not set."""

    @pytest.fixture(autouse=True)
    def setup_env(self):
        """Setup environment without Stripe ARN."""
        import shared.billing_utils as billing_utils

        original_env = os.environ.copy()
        # Ensure STRIPE_SECRET_ARN is not set
        os.environ.pop("STRIPE_SECRET_ARN", None)

        original_arn = billing_utils.STRIPE_SECRET_ARN
        billing_utils.STRIPE_SECRET_ARN = None
        billing_utils._stripe_api_key_cache = None
        billing_utils._stripe_api_key_cache_time = 0.0

        yield

        os.environ.clear()
        os.environ.update(original_env)
        billing_utils.STRIPE_SECRET_ARN = original_arn

    def test_returns_not_configured_when_no_arn(self, mock_dynamodb):
        """Should return error when STRIPE_SECRET_ARN is not set."""
        import shared.billing_utils as billing_utils

        result = billing_utils.get_stripe_api_key()

        assert result is None


class TestRetentionCheckErrorRecovery:
    """Test error handling and recovery in retention check processing."""

    @pytest.fixture(autouse=True)
    def referral_env_vars(self):
        """Set environment variables for referral tests."""
        original_env = os.environ.copy()

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

        yield

        os.environ.clear()
        os.environ.update(original_env)

    @patch("api.referral_retention_check.get_stripe_api_key")
    @patch("stripe.Subscription.retrieve")
    @patch("api.referral_retention_check.add_bonus_with_cap")
    def test_increments_error_count_on_processing_exception(
        self, mock_add_bonus, mock_stripe_retrieve, mock_stripe_key, mock_dynamodb
    ):
        """Should increment error count when processing individual referral fails."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock active subscription
        mock_subscription = MagicMock()
        mock_subscription.status = "active"
        mock_stripe_retrieve.return_value = mock_subscription

        # Mock add_bonus_with_cap to raise an exception
        mock_add_bonus.side_effect = Exception("Simulated bonus error")

        import api.referral_retention_check as retention_module

        retention_module._dynamodb = None
        import shared.referral_utils as referral_utils_module

        referral_utils_module._dynamodb = None

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        referrer_id = "user_error_referrer"
        referred_id = "user_error_referred"

        # Create referral event with referred_id field
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

        # Add subscription for referred user
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key",
                "stripe_subscription_id": "sub_error_test",
            }
        )

        from api.referral_retention_check import handler

        result = handler({}, {})

        # Should have processed 1 and counted 1 error
        assert result["processed"] == 1
        assert result["credited"] == 0
        assert result["errors"] == 1


class TestRetentionIdempotency:
    """Tests for C9: retention check skips already-credited referrals."""

    @patch("api.referral_retention_check.stripe")
    @patch("api.referral_retention_check.get_stripe_api_key")
    def test_retention_check_skips_already_credited(self, mock_stripe_key, mock_stripe, mock_dynamodb):
        """Should skip crediting when a 'retained' event already exists."""
        mock_stripe_key.return_value = "sk_test_fake"

        # Mock active subscription (must be MagicMock for dot-access: subscription.status)
        mock_sub = MagicMock()
        mock_sub.status = "active"
        mock_stripe.Subscription.retrieve.return_value = mock_sub

        api_table = mock_dynamodb.Table("pkgwatch-api-keys")
        events_table = mock_dynamodb.Table("pkgwatch-referral-events")

        referrer_id = "user_referrer_idemp"
        referred_id = "user_referred_idemp"

        # Create referrer USER_META
        api_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": "USER_META",
                "bonus_requests": 100,
                "bonus_requests_lifetime": 100,
                "referral_paid": 1,
                "referral_retained": 0,
            }
        )

        # Create referred user metadata
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "USER_META",
                "tier": "pro",
            }
        )

        # Create referred user's API key record with subscription
        # (handler skips USER_META and PENDING when looking for stripe_subscription_id)
        api_table.put_item(
            Item={
                "pk": referred_id,
                "sk": "api_key_hash_idemp",
                "stripe_subscription_id": "sub_idemp123",
            }
        )

        # Create retention-due event (paid event with retention check due)
        past_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#paid",
                "referred_id": referred_id,
                "event_type": "paid",
                "needs_retention_check": "true",
                "retention_check_date": past_date,
            }
        )

        # PRE-INSERT a "retained" event — this is what makes it a duplicate
        events_table.put_item(
            Item={
                "pk": referrer_id,
                "sk": f"{referred_id}#retained",
                "referred_id": referred_id,
                "event_type": "retained",
                "reward_amount": 25000,
            }
        )

        # Record bonus before
        meta_before = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})["Item"]
        bonus_before = int(meta_before.get("bonus_requests", 0))

        from api.referral_retention_check import handler

        result = handler({}, {})

        # Should process the item but NOT credit (already retained)
        assert result["processed"] == 1
        assert result["credited"] == 0

        # Bonus should NOT have increased
        meta_after = api_table.get_item(Key={"pk": referrer_id, "sk": "USER_META"})["Item"]
        bonus_after = int(meta_after.get("bonus_requests", 0))
        assert bonus_after == bonus_before
