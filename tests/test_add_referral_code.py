"""
Comprehensive tests for POST /referral/add-code endpoint.

Tests cover:
- Authentication and authorization
- Input validation (code format, payload size)
- Business logic (window expiry, already referred, self-referral)
- Success cases (valid late referral)
- Edge cases (Gmail alias detection, date parsing)
- Error handling (internal errors)
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
def add_referral_code_env_vars():
    """Set environment variables for add_referral_code tests."""
    original_env = os.environ.copy()

    os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
    os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"
    os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


def create_session_token(
    user_id: str,
    email: str,
    tier: str = "free",
    expired: bool = False,
    secret: str = "test-secret-key-for-signing-sessions-1234567890"
) -> str:
    """Create a session token for testing.

    Args:
        user_id: User ID for the session
        email: User email
        tier: Subscription tier
        expired: If True, create an expired token
        secret: Secret key for signing

    Returns:
        Signed session token
    """
    if expired:
        session_expires = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        session_expires = datetime.now(timezone.utc) + timedelta(days=7)

    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int(session_expires.timestamp()),
    }
    payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
    signature = hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{signature}"


class TestAddReferralCodeAuthentication:
    """Tests for authentication and session validation."""

    def test_returns_401_without_cookie_header(self, mock_dynamodb):
        """Should return 401 when no cookie header is present."""
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
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    def test_returns_401_with_empty_session_cookie(self, mock_dynamodb):
        """Should return 401 when session cookie is empty."""
        from api.add_referral_code import handler

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": "session="},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_expired_session(self, mock_secret, mock_dynamodb):
        """Should return 401 when session token is expired."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        # Create expired session token
        expired_token = create_session_token("user_test", "test@example.com", expired=True)

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={expired_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_invalid_user_id_format_not_starting_with_user_(
        self, mock_secret, mock_dynamodb
    ):
        """Should return 401 when user_id doesn't start with 'user_'."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        # Create session with invalid user_id format
        session_data = {
            "user_id": "invalid_user_123",  # Doesn't start with "user_"
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
            "httpMethod": "POST",
            "headers": {"cookie": f"session={bad_session}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_session"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_empty_user_id(self, mock_secret, mock_dynamodb):
        """Should return 401 when user_id is empty string."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_data = {
            "user_id": "",
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
            "httpMethod": "POST",
            "headers": {"cookie": f"session={bad_session}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_session"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_401_for_non_string_user_id(self, mock_secret, mock_dynamodb):
        """Should return 401 when user_id is not a string."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_data = {
            "user_id": 12345,  # Not a string
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
            "httpMethod": "POST",
            "headers": {"cookie": f"session={bad_session}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_session"


class TestAddReferralCodeInputValidation:
    """Tests for input validation."""

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_payload_exceeding_1000_bytes(self, mock_secret, mock_dynamodb):
        """Should return 400 for payload larger than 1000 bytes."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": "x" * 1001,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "payload_too_large"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_invalid_json_body(self, mock_secret, mock_dynamodb):
        """Should return 400 for malformed JSON."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": "{not valid json",
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_empty_referral_code(self, mock_secret, mock_dynamodb):
        """Should return 400 when code is empty string."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": ""}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_code_too_short(self, mock_secret, mock_dynamodb):
        """Should return 400 when code is less than 6 characters."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12"}),  # 5 chars, needs 6
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_code_too_long(self, mock_secret, mock_dynamodb):
        """Should return 400 when code exceeds 12 characters."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "a" * 13}),  # 13 chars, max is 12
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_code_with_special_characters(self, mock_secret, mock_dynamodb):
        """Should return 400 for code with special characters (except _ and -)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc!@#12"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_accepts_code_with_underscore_and_hyphen(self, mock_secret, mock_dynamodb):
        """Should accept codes containing underscore and hyphen."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        # Reset shared.referral_utils module cache
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        # Create user
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc_-_12"}),  # Valid format with _ and -
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        # Code format is valid, but code won't be found (404-like error)
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "code_not_found"

    @patch("api.auth_callback._get_session_secret")
    def test_handles_null_body(self, mock_secret, mock_dynamodb):
        """Should handle null request body gracefully."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": None,
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        # Null body parses as empty object, code will be empty
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"


class TestAddReferralCodeBusinessLogic:
    """Tests for business logic validations."""

    @pytest.fixture
    def reset_referral_utils_cache(self, mock_dynamodb):
        """Reset referral_utils module cache before each test."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        yield mock_dynamodb

    @patch("api.auth_callback._get_session_secret")
    def test_returns_404_for_user_not_found(self, mock_secret, reset_referral_utils_cache):
        """Should return 404 when user doesn't exist."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_nonexistent", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "user_not_found"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_409_when_user_already_referred(self, mock_secret, reset_referral_utils_cache):
        """Should return 409 when user already has a referrer."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_already_referred",
                "sk": "USER_META",
                "email": "already@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "referred_by": "user_existing_referrer",  # Already has a referrer
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_already_referred", "already@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 409
        body = json.loads(result["body"])
        assert body["error"]["code"] == "already_referred"
        assert "already used a referral code" in body["error"]["message"]

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_when_created_at_missing(self, mock_secret, reset_referral_utils_cache):
        """Should return 400 when user has no created_at field."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_no_created",
                "sk": "USER_META",
                "email": "nocreated@example.com",
                # No created_at field
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_no_created", "nocreated@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_account"
        assert "verify account creation date" in body["error"]["message"]

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_when_created_at_invalid_format(self, mock_secret, reset_referral_utils_cache):
        """Should return 400 when created_at has invalid date format."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_bad_date",
                "sk": "USER_META",
                "email": "baddate@example.com",
                "created_at": "not-a-valid-date",  # Invalid format
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_bad_date", "baddate@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_account"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_when_14_day_window_expired(self, mock_secret, reset_referral_utils_cache):
        """Should return 400 when user tries to add code after 14-day window."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        # Account created 15 days ago (past the 14-day window)
        old_date = datetime.now(timezone.utc) - timedelta(days=15)
        table.put_item(
            Item={
                "pk": "user_old_account",
                "sk": "USER_META",
                "email": "old@example.com",
                "created_at": old_date.isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_old_account", "old@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "window_expired"
        assert "14 days" in body["error"]["message"]

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_referral_code_not_found(self, mock_secret, reset_referral_utils_cache):
        """Should return 400 when referral code doesn't exist."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": "USER_META",
                "email": "test@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "nonexist"}),  # Code doesn't exist
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "code_not_found"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_self_referral_same_email(self, mock_secret, reset_referral_utils_cache):
        """Should return 400 when user tries to use their own referral code."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer with a code
        table.put_item(
            Item={
                "pk": "user_referrer",
                "sk": "USER_META",
                "email": "self@example.com",
                "referral_code": "mycode12",
            }
        )

        # Create user trying to use the code (same email)
        table.put_item(
            Item={
                "pk": "user_self",
                "sk": "USER_META",
                "email": "self@example.com",  # Same email as referrer
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_self", "self@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "mycode12"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "self_referral"
        assert "your own referral code" in body["error"]["message"]

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_self_referral_gmail_alias(self, mock_secret, reset_referral_utils_cache):
        """Should detect Gmail alias as self-referral (john.doe vs johndoe)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Referrer with Gmail without dots
        table.put_item(
            Item={
                "pk": "user_referrer_gmail",
                "sk": "USER_META",
                "email": "johndoe@gmail.com",
                "referral_code": "gmail123",
            }
        )

        # User with dots in Gmail (same account due to Gmail aliasing)
        table.put_item(
            Item={
                "pk": "user_gmail_dots",
                "sk": "USER_META",
                "email": "john.doe@gmail.com",  # Same as johndoe@gmail.com
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_gmail_dots", "john.doe@gmail.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "gmail123"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "self_referral"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_self_referral_gmail_plus_alias(self, mock_secret, reset_referral_utils_cache):
        """Should detect Gmail plus alias as self-referral (john+ref vs john)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Referrer with base Gmail
        table.put_item(
            Item={
                "pk": "user_referrer_plus",
                "sk": "USER_META",
                "email": "john@gmail.com",
                "referral_code": "plusref1",
            }
        )

        # User with plus alias
        table.put_item(
            Item={
                "pk": "user_plus_alias",
                "sk": "USER_META",
                "email": "john+referral@gmail.com",  # Same as john@gmail.com
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_plus_alias", "john+referral@gmail.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "plusref1"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "self_referral"

    @patch("api.auth_callback._get_session_secret")
    def test_returns_400_for_self_referral_googlemail_vs_gmail(self, mock_secret, reset_referral_utils_cache):
        """Should detect googlemail.com as same as gmail.com."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Referrer with gmail.com
        table.put_item(
            Item={
                "pk": "user_gmail_domain",
                "sk": "USER_META",
                "email": "john@gmail.com",
                "referral_code": "domainc1",
            }
        )

        # User with googlemail.com (same as gmail.com)
        table.put_item(
            Item={
                "pk": "user_googlemail",
                "sk": "USER_META",
                "email": "john@googlemail.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_googlemail", "john@googlemail.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "domainc1"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "self_referral"


class TestAddReferralCodeSuccess:
    """Tests for successful referral code application."""

    @pytest.fixture
    def reset_referral_utils_cache(self, mock_dynamodb):
        """Reset referral_utils module cache before each test."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        yield mock_dynamodb

    @patch("api.auth_callback._get_session_secret")
    def test_successful_referral_code_application(self, mock_secret, reset_referral_utils_cache):
        """Should successfully apply referral code for valid user within window."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        api_table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        events_table = reset_referral_utils_cache.Table("pkgwatch-referral-events")

        # Create referrer with code
        table = api_table
        table.put_item(
            Item={
                "pk": "user_referrer",
                "sk": "USER_META",
                "email": "referrer@example.com",
                "referral_code": "validcde",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create referred user (within 14-day window)
        created_date = datetime.now(timezone.utc) - timedelta(days=5)
        table.put_item(
            Item={
                "pk": "user_referred",
                "sk": "USER_META",
                "email": "referred@example.com",
                "created_at": created_date.isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_referred", "referred@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "validcde"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "Referral code applied" in body["message"]
        assert body["bonus_added"] == 10000  # REFERRED_USER_BONUS

        # Verify user was updated
        response = table.get_item(Key={"pk": "user_referred", "sk": "USER_META"})
        item = response["Item"]
        assert item["referred_by"] == "user_referrer"
        assert item["referral_pending"] is True
        assert item["bonus_requests"] == 10000
        assert item["bonus_requests_lifetime"] == 10000
        assert "referred_at" in item
        assert "referral_pending_expires" in item

        # Verify referrer stats were updated
        response = table.get_item(Key={"pk": "user_referrer", "sk": "USER_META"})
        referrer = response["Item"]
        assert referrer["referral_total"] == 1
        assert referrer["referral_pending_count"] == 1

        # Verify pending referral event was recorded
        response = events_table.get_item(
            Key={"pk": "user_referrer", "sk": "user_referred#pending"}
        )
        assert "Item" in response
        event_item = response["Item"]
        assert event_item["event_type"] == "pending"
        assert event_item["referred_id"] == "user_referred"

    @patch("api.auth_callback._get_session_secret")
    def test_successful_referral_on_day_13(self, mock_secret, reset_referral_utils_cache):
        """Should accept referral code on day 13 (just before window closes)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_referrer_day13",
                "sk": "USER_META",
                "email": "referrer13@example.com",
                "referral_code": "day13cod",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user at day 13 (still within 14-day window)
        created_date = datetime.now(timezone.utc) - timedelta(days=13)
        table.put_item(
            Item={
                "pk": "user_day13",
                "sk": "USER_META",
                "email": "day13@example.com",
                "created_at": created_date.isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_day13", "day13@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "day13cod"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["bonus_added"] == 10000

    @patch("api.auth_callback._get_session_secret")
    def test_successful_referral_on_day_14_boundary(self, mock_secret, reset_referral_utils_cache):
        """Should accept referral code on exactly day 14."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_referrer_day14",
                "sk": "USER_META",
                "email": "referrer14@example.com",
                "referral_code": "day14cod",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user at exactly 14 days minus 1 minute (still valid)
        created_date = datetime.now(timezone.utc) - timedelta(days=14, minutes=-1)
        table.put_item(
            Item={
                "pk": "user_day14",
                "sk": "USER_META",
                "email": "day14@example.com",
                "created_at": created_date.isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_day14", "day14@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "day14cod"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200

    @patch("api.auth_callback._get_session_secret")
    def test_uses_email_from_meta_when_not_in_session(self, mock_secret, reset_referral_utils_cache):
        """Should use email from USER_META when session has no email."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_ref_meta",
                "sk": "USER_META",
                "email": "referrer_meta@example.com",
                "referral_code": "metacode",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user with email in meta
        table.put_item(
            Item={
                "pk": "user_no_sess_email",
                "sk": "USER_META",
                "email": "fromMeta@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        # Create session without email
        session_data = {
            "user_id": "user_no_sess_email",
            "email": "",  # Empty email in session
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
        signature = hmac.new(
            b"test-secret-key-for-signing-sessions-1234567890",
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        session_token = f"{payload}.{signature}"

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "metacode"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200

    @patch("api.auth_callback._get_session_secret")
    def test_handles_created_at_with_z_suffix(self, mock_secret, reset_referral_utils_cache):
        """Should handle ISO dates with Z suffix."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": "user_ref_zsuffix",
                "sk": "USER_META",
                "email": "referrer_z@example.com",
                "referral_code": "zcodexyz",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Use Z suffix for UTC
        created_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
        table.put_item(
            Item={
                "pk": "user_zsuffix",
                "sk": "USER_META",
                "email": "zsuffix@example.com",
                "created_at": created_date,
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_zsuffix", "zsuffix@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "zcodexyz"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200


class TestAddReferralCodeErrorHandling:
    """Tests for error handling scenarios."""

    @pytest.fixture
    def reset_referral_utils_cache(self, mock_dynamodb):
        """Reset referral_utils module cache before each test."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        yield mock_dynamodb

    @patch("api.auth_callback._get_session_secret")
    @patch("api.add_referral_code.dynamodb")
    def test_returns_500_on_dynamodb_error(self, mock_db, mock_secret, reset_referral_utils_cache):
        """Should return 500 when DynamoDB operation fails."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from botocore.exceptions import ClientError

        # Mock DynamoDB to raise an error
        mock_table = MagicMock()
        mock_table.get_item.side_effect = ClientError(
            {"Error": {"Code": "InternalServerError", "Message": "Test error"}},
            "GetItem"
        )
        mock_db.Table.return_value = mock_table

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


class TestAddReferralCodeCORSHeaders:
    """Tests for CORS header handling."""

    @patch("api.auth_callback._get_session_secret")
    def test_includes_origin_in_error_response(self, mock_secret, mock_dynamodb):
        """Should include origin header in error response."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        session_token = create_session_token("user_test", "test@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev"
            },
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "ab"}),  # Invalid code
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        assert "Access-Control-Allow-Origin" in result["headers"]

    @patch("api.auth_callback._get_session_secret")
    def test_handles_uppercase_origin_header(self, mock_secret, mock_dynamodb):
        """Should handle both Origin and origin header names."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        from api.add_referral_code import handler

        event = {
            "httpMethod": "POST",
            "headers": {
                "Cookie": "session=invalid",
                "Origin": "https://pkgwatch.dev"
            },
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        # Should work with uppercase header names
        assert result["statusCode"] == 401

    def test_handles_null_headers(self, mock_dynamodb):
        """Should handle null headers dict."""
        from api.add_referral_code import handler

        event = {
            "httpMethod": "POST",
            "headers": None,
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 401


class TestAddReferralCodeEdgeCases:
    """Tests for edge cases and boundary conditions."""

    @pytest.fixture
    def reset_referral_utils_cache(self, mock_dynamodb):
        """Reset referral_utils module cache before each test."""
        import shared.referral_utils as referral_utils_module
        referral_utils_module._dynamodb = None
        yield mock_dynamodb

    @patch("api.auth_callback._get_session_secret")
    def test_strips_whitespace_from_code(self, mock_secret, reset_referral_utils_cache):
        """Should strip whitespace from referral code."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer
        table.put_item(
            Item={
                "pk": "user_ref_strip",
                "sk": "USER_META",
                "email": "referrer_strip@example.com",
                "referral_code": "stripcd1",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user
        table.put_item(
            Item={
                "pk": "user_strip",
                "sk": "USER_META",
                "email": "strip@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_strip", "strip@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "  stripcd1  "}),  # Code with whitespace
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200

    @patch("api.auth_callback._get_session_secret")
    def test_rejects_day_15_after_window(self, mock_secret, reset_referral_utils_cache):
        """Should reject referral code on day 15 (after 14-day window)."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create user at day 15
        created_date = datetime.now(timezone.utc) - timedelta(days=15)
        table.put_item(
            Item={
                "pk": "user_day15",
                "sk": "USER_META",
                "email": "day15@example.com",
                "created_at": created_date.isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_day15", "day15@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "abc12345"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "window_expired"

    @patch("api.auth_callback._get_session_secret")
    def test_handles_missing_code_field(self, mock_secret, reset_referral_utils_cache):
        """Should handle JSON body without code field."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_nocode",
                "sk": "USER_META",
                "email": "nocode@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_nocode", "nocode@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"other_field": "value"}),  # No code field
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_code"

    @patch("api.auth_callback._get_session_secret")
    def test_allows_different_users_same_domain(self, mock_secret, reset_referral_utils_cache):
        """Should allow different users from the same domain to refer each other."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer from company.com
        table.put_item(
            Item={
                "pk": "user_alice",
                "sk": "USER_META",
                "email": "alice@company.com",
                "referral_code": "alicec01",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user from same domain (different person)
        table.put_item(
            Item={
                "pk": "user_bob",
                "sk": "USER_META",
                "email": "bob@company.com",  # Same domain, different person
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_bob", "bob@company.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "alicec01"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200

    @patch("api.auth_callback._get_session_secret")
    def test_referrer_without_email_in_meta(self, mock_secret, reset_referral_utils_cache):
        """Should handle referrer without email in USER_META."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        # Create referrer without email
        table.put_item(
            Item={
                "pk": "user_noemail_ref",
                "sk": "USER_META",
                # No email field
                "referral_code": "noemail1",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        # Create user
        table.put_item(
            Item={
                "pk": "user_with_email",
                "sk": "USER_META",
                "email": "user@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_with_email", "user@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"cookie": f"session={session_token}"},
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "noemail1"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        # Should succeed (comparing empty string to user@example.com is not self-referral)
        assert result["statusCode"] == 200

    @patch("api.auth_callback._get_session_secret")
    def test_handles_uppercase_cookie_header(self, mock_secret, reset_referral_utils_cache):
        """Should handle Cookie header with capital C."""
        mock_secret.return_value = "test-secret-key-for-signing-sessions-1234567890"

        table = reset_referral_utils_cache.Table("pkgwatch-api-keys")

        table.put_item(
            Item={
                "pk": "user_ref_caps",
                "sk": "USER_META",
                "email": "refcaps@example.com",
                "referral_code": "capsref1",
                "referral_total": 0,
                "referral_pending_count": 0,
            }
        )

        table.put_item(
            Item={
                "pk": "user_caps",
                "sk": "USER_META",
                "email": "caps@example.com",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        from api.add_referral_code import handler

        session_token = create_session_token("user_caps", "caps@example.com")

        event = {
            "httpMethod": "POST",
            "headers": {"Cookie": f"session={session_token}"},  # Capital C
            "pathParameters": {},
            "queryStringParameters": {},
            "body": json.dumps({"code": "capsref1"}),
            "requestContext": {"identity": {"sourceIp": "127.0.0.1"}},
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
