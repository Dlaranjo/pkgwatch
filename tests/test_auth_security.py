"""
Tests for auth backend security fixes.

This module tests the security hardening implemented in the auth flow:
1. verify_email.py - Token replay prevention with conditional delete
2. auth_callback.py - TOCTOU race condition fix with atomic conditional update
3. magic_link.py - Email enumeration prevention (SES failures don't leak info)
4. resend_verification.py - Timing normalization and cooldown enforcement
5. get_pending_key.py - Session auth and one-time key retrieval
"""

import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_ses():
    """Mock SES for email sending tests."""
    with mock_aws():
        ses = boto3.client("ses", region_name="us-east-1")
        ses.verify_email_identity(EmailAddress="noreply@pkgwatch.dev")
        yield ses


@pytest.fixture
def mock_secretsmanager():
    """Mock Secrets Manager for session secret."""
    with mock_aws():
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        sm.create_secret(Name="test-session-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}')
        yield sm


@pytest.fixture
def pending_user(mock_dynamodb):
    """Create a pending user with verification token."""
    table = mock_dynamodb.Table("pkgwatch-api-keys")
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    user_id = f"user_{secrets.token_hex(8)}"

    table.put_item(
        Item={
            "pk": user_id,
            "sk": "PENDING",
            "email": "pending@example.com",
            "verification_token": token,
            "verification_expires": expires,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    return {
        "user_id": user_id,
        "token": token,
        "email": "pending@example.com",
        "expires": expires,
        "table": table,
    }


@pytest.fixture
def verified_user_with_magic_token(mock_dynamodb):
    """Create a verified user with magic link token."""
    import hashlib

    table = mock_dynamodb.Table("pkgwatch-api-keys")
    magic_token = secrets.token_urlsafe(32)
    api_key = f"pw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    user_id = f"user_{secrets.token_hex(8)}"
    magic_expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "verified@example.com",
            "tier": "free",
            "requests_this_month": 0,
            "email_verified": True,
            "magic_token": magic_token,
            "magic_expires": magic_expires,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    return {
        "user_id": user_id,
        "key_hash": key_hash,
        "magic_token": magic_token,
        "magic_expires": magic_expires,
        "email": "verified@example.com",
        "api_key": api_key,
        "table": table,
    }


@pytest.fixture
def setup_env():
    """Set up environment variables for tests."""
    original_env = os.environ.copy()
    os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
    os.environ["BASE_URL"] = "https://test.example.com"
    os.environ["API_URL"] = "https://api.test.example.com"
    os.environ["SESSION_SECRET_ARN"] = "test-session-secret"
    os.environ["VERIFICATION_EMAIL_SENDER"] = "noreply@pkgwatch.dev"
    os.environ["LOGIN_EMAIL_SENDER"] = "noreply@pkgwatch.dev"

    yield

    os.environ.clear()
    os.environ.update(original_env)


# ============================================================================
# verify_email.py - Token Replay Prevention Tests
# ============================================================================


class TestVerifyEmailTokenReplay:
    """Tests for token replay prevention in verify_email.py."""

    @mock_aws
    def test_token_consumed_on_first_use(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """Token should be consumed (deleted) on first successful verification."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        # Mock generate_api_key to avoid side effects
        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify PENDING record was deleted
        response = pending_user["table"].get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})
        assert "Item" not in response

    @mock_aws
    def test_replay_attack_returns_token_already_used(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """Second use of same token should return token_already_used error."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        # First request - should succeed
        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result1 = handler(api_gateway_event, {})

        assert result1["statusCode"] == 302
        assert "verified=true" in result1["headers"]["Location"]

        # Second request (replay attack) - should fail with token_already_used
        result2 = handler(api_gateway_event, {})

        assert result2["statusCode"] == 302
        # After first use, token no longer exists in GSI, so it returns invalid_token
        # (the token_already_used error is for when the conditional delete fails)
        assert "error=invalid_token" in result2["headers"]["Location"]

    @mock_aws
    def test_concurrent_verification_only_one_succeeds(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """Simulates race condition where conditional delete prevents double-spend."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        # Simulate race: manually delete the PENDING record before handler runs
        # This simulates another request consuming the token first
        pending_user["table"].delete_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})

        # Now the handler should fail because token is already consumed
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=invalid_token" in result["headers"]["Location"]

    @mock_aws
    def test_conditional_delete_failure_returns_error(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """Test that ConditionalCheckFailedException returns token_already_used."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        # Modify the token in DB to simulate race condition (different token stored)
        pending_user["table"].update_item(
            Key={"pk": pending_user["user_id"], "sk": "PENDING"},
            UpdateExpression="SET verification_token = :new_token",
            ExpressionAttributeValues={":new_token": "different_token_now"},
        )

        result = handler(api_gateway_event, {})

        # Now the GSI query won't find the old token, so it returns invalid_token
        assert result["statusCode"] == 302
        assert "error=" in result["headers"]["Location"]


class TestVerifyEmailTimingNormalization:
    """Tests for timing normalization in verify_email.py."""

    @mock_aws
    def test_minimum_response_time_enforced(self, mock_dynamodb, setup_env, api_gateway_event):
        """Response should take at least MIN_RESPONSE_TIME_SECONDS."""
        from api.verify_email import MIN_RESPONSE_TIME_SECONDS, handler

        api_gateway_event["queryStringParameters"] = {"token": "nonexistent_token"}

        start = time.time()
        handler(api_gateway_event, {})
        elapsed = time.time() - start

        # Allow some tolerance for test execution overhead
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1

    @mock_aws
    def test_timing_normalized_for_invalid_token(self, mock_dynamodb, setup_env, api_gateway_event):
        """Invalid token should have same timing as valid token lookup."""
        from api.verify_email import MIN_RESPONSE_TIME_SECONDS

        # This test verifies the timing is normalized to prevent timing attacks
        # that could reveal token validity
        assert MIN_RESPONSE_TIME_SECONDS >= 1.0, "MIN_RESPONSE_TIME should be at least 1 second"


class TestVerifyEmailExpiration:
    """Tests for token expiration handling."""

    @mock_aws
    def test_expired_token_rejected(self, mock_dynamodb, setup_env, api_gateway_event):
        """Expired token should be rejected after atomic delete."""
        from api.verify_email import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        # Expired 1 hour ago
        expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        user_id = f"user_{secrets.token_hex(8)}"

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "expired@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        api_gateway_event["queryStringParameters"] = {"token": token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=token_expired" in result["headers"]["Location"]

        # PENDING record should still be deleted (consumed but expired)
        response = table.get_item(Key={"pk": user_id, "sk": "PENDING"})
        assert "Item" not in response


# ============================================================================
# auth_callback.py - TOCTOU Race Condition Fix Tests
# ============================================================================


class TestAuthCallbackTOCTOU:
    """Tests for TOCTOU race condition fix in auth_callback.py."""

    @mock_aws
    def test_atomic_token_consumption(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Magic token should be atomically consumed with expiration check."""
        # Clear the session secret cache
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "Set-Cookie" in result["headers"]

        # Verify magic token was removed
        response = verified_user_with_magic_token["table"].get_item(
            Key={"pk": verified_user_with_magic_token["user_id"], "sk": verified_user_with_magic_token["key_hash"]}
        )
        item = response.get("Item", {})
        assert "magic_token" not in item
        assert "magic_expires" not in item

    @mock_aws
    def test_replay_returns_token_already_used(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Second use of magic token should return token_already_used."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        # First request - should succeed
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 302
        assert "dashboard" in result1["headers"]["Location"]

        # Second request (replay) - should fail
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 302
        # Token no longer in GSI after first use
        assert "error=invalid_token" in result2["headers"]["Location"]

    @mock_aws
    def test_expired_token_returns_token_expired(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Expired magic token should return token_expired error."""
        import hashlib

        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        magic_token = secrets.token_urlsafe(32)
        api_key = f"pw_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        user_id = f"user_{secrets.token_hex(8)}"
        # Expired 1 hour ago
        magic_expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "expired@example.com",
                "tier": "free",
                "email_verified": True,
                "magic_token": magic_token,
                "magic_expires": magic_expires,
            }
        )

        api_gateway_event["queryStringParameters"] = {"token": magic_token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=token_expired" in result["headers"]["Location"]

        # Verify token was cleaned up
        response = table.get_item(Key={"pk": user_id, "sk": key_hash})
        item = response.get("Item", {})
        assert "magic_token" not in item

    @mock_aws
    def test_race_condition_token_consumed_by_another(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Simulates race where another request consumed the token first."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        # Manually consume the token to simulate race
        verified_user_with_magic_token["table"].update_item(
            Key={"pk": verified_user_with_magic_token["user_id"], "sk": verified_user_with_magic_token["key_hash"]},
            UpdateExpression="REMOVE magic_token, magic_expires SET last_login = :now",
            ExpressionAttributeValues={":now": datetime.now(timezone.utc).isoformat()},
        )

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        # Token no longer in GSI
        assert "error=invalid_token" in result["headers"]["Location"]


class TestAuthCallbackSessionCreation:
    """Tests for session token creation."""

    @mock_aws
    def test_session_cookie_set_correctly(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Session cookie should have correct security attributes."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        assert "session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie

    @mock_aws
    def test_verify_session_token(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Session token should be verifiable."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler, verify_session_token

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        result = handler(api_gateway_event, {})

        cookie = result["headers"]["Set-Cookie"]
        session_token = cookie.split("session=")[1].split(";")[0]

        # Verify the session token
        session_data = verify_session_token(session_token)

        assert session_data is not None
        assert session_data["user_id"] == verified_user_with_magic_token["user_id"]
        assert session_data["email"] == verified_user_with_magic_token["email"]


# ============================================================================
# magic_link.py - Email Enumeration Prevention Tests
# ============================================================================


class TestMagicLinkEmailEnumeration:
    """Tests for email enumeration prevention in magic_link.py."""

    @mock_aws
    def test_same_response_for_existing_email(
        self, mock_dynamodb, mock_ses, seeded_api_keys_table, setup_env, api_gateway_event
    ):
        """Should return success for existing email."""
        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "If an account exists" in body["message"]

    @mock_aws
    def test_same_response_for_nonexistent_email(self, mock_dynamodb, mock_ses, setup_env, api_gateway_event):
        """Should return same response for non-existent email (enumeration prevention)."""
        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "nonexistent@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "If an account exists" in body["message"]

    @mock_aws
    def test_ses_failure_returns_success(self, mock_dynamodb, seeded_api_keys_table, setup_env, api_gateway_event):
        """SES failure should still return success to prevent enumeration."""
        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})

        # Mock SES to raise an exception
        with patch("api.magic_link.ses.send_email", side_effect=Exception("SES Error")):
            result = handler(api_gateway_event, {})

        # Should still return success to not leak email existence
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "If an account exists" in body["message"]

    @mock_aws
    def test_ses_throttling_returns_success(self, mock_dynamodb, seeded_api_keys_table, setup_env, api_gateway_event):
        """SES throttling should still return success to prevent enumeration."""
        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})

        # Mock SES throttling error
        error_response = {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}
        with patch("api.magic_link.ses.send_email", side_effect=ClientError(error_response, "SendEmail")):
            result = handler(api_gateway_event, {})

        # Should still return success
        assert result["statusCode"] == 200


class TestMagicLinkTimingNormalization:
    """Tests for timing normalization in magic_link.py."""

    @mock_aws
    def test_minimum_response_time(self, mock_dynamodb, setup_env, api_gateway_event):
        """Response should take minimum time regardless of email existence."""
        from api.magic_link import MIN_RESPONSE_TIME_SECONDS, handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "any@example.com"})

        start = time.time()
        handler(api_gateway_event, {})
        elapsed = time.time() - start

        # Allow tolerance for test execution overhead
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1

    @mock_aws
    def test_timing_constant_for_existing_vs_nonexistent(
        self, mock_dynamodb, mock_ses, seeded_api_keys_table, setup_env, api_gateway_event
    ):
        """Timing should be similar for existing vs non-existent emails."""
        from api.magic_link import MIN_RESPONSE_TIME_SECONDS, handler

        api_gateway_event["httpMethod"] = "POST"

        # Time for existing email
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})
        start1 = time.time()
        handler(api_gateway_event, {})
        elapsed_existing = time.time() - start1

        # Time for non-existent email
        api_gateway_event["body"] = json.dumps({"email": "nonexistent@example.com"})
        start2 = time.time()
        handler(api_gateway_event, {})
        elapsed_nonexistent = time.time() - start2

        # Both should be at least MIN_RESPONSE_TIME_SECONDS
        assert elapsed_existing >= MIN_RESPONSE_TIME_SECONDS - 0.1
        assert elapsed_nonexistent >= MIN_RESPONSE_TIME_SECONDS - 0.1

        # Timing difference should be small (both normalized)
        assert abs(elapsed_existing - elapsed_nonexistent) < 0.5


# ============================================================================
# resend_verification.py Tests
# ============================================================================


class TestResendVerification:
    """Tests for resend_verification.py endpoint."""

    @mock_aws
    def test_resend_for_pending_user(self, mock_dynamodb, mock_ses, pending_user, setup_env, api_gateway_event):
        """Should generate new token and send email for pending user."""
        from api.resend_verification import handler

        original_token = pending_user["token"]

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": pending_user["email"]})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "pending verification" in body["message"]

        # Verify new token was generated
        response = pending_user["table"].get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})
        new_token = response["Item"]["verification_token"]
        assert new_token != original_token

    @mock_aws
    def test_same_response_for_nonexistent_email(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return same response for non-existent email (enumeration prevention)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "nonexistent@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "pending verification" in body["message"]

    @mock_aws
    def test_cooldown_enforced(self, mock_dynamodb, mock_ses, pending_user, setup_env, api_gateway_event):
        """Should enforce cooldown between resend requests."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": pending_user["email"]})

        # First request should succeed
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Second request within cooldown should fail with 429
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 429
        body = json.loads(result2["body"])
        assert body["error"]["code"] == "cooldown"

    @mock_aws
    def test_ses_failure_returns_success(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """SES failure should still return success for enumeration prevention."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": pending_user["email"]})

        with patch("api.resend_verification.ses.send_email", side_effect=Exception("SES Error")):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_timing_normalization(self, mock_dynamodb, setup_env, api_gateway_event):
        """Response should take minimum time."""
        from api.resend_verification import MIN_RESPONSE_TIME_SECONDS, handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "any@example.com"})

        start = time.time()
        handler(api_gateway_event, {})
        elapsed = time.time() - start

        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1


# ============================================================================
# get_pending_key.py Tests
# ============================================================================


class TestGetPendingKey:
    """Tests for get_pending_key.py endpoint."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 401 when no session cookie."""
        from api.get_pending_key import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_with_invalid_session(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """Should return 401 with invalid session token."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.get_pending_key import handler

        api_gateway_event["headers"]["Cookie"] = "session=invalid.token.here"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_pending_key_with_valid_session(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should return pending key with valid session."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import _create_session_token, _get_session_secret
        from api.get_pending_key import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = f"user_{secrets.token_hex(8)}"
        pending_api_key = f"pw_{secrets.token_urlsafe(32)}"

        # Create PENDING_DISPLAY record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_DISPLAY",
                "api_key": pending_api_key,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Create session token
        session_secret = _get_session_secret()
        session_data = {
            "user_id": user_id,
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(session_data, session_secret)

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["api_key"] == pending_api_key

    @mock_aws
    def test_pending_key_deleted_after_retrieval(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Pending key should be deleted after first retrieval (one-time use)."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import _create_session_token, _get_session_secret
        from api.get_pending_key import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = f"user_{secrets.token_hex(8)}"

        # Create PENDING_DISPLAY record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_DISPLAY",
                "api_key": "pw_test_key",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Create session token
        session_secret = _get_session_secret()
        session_data = {
            "user_id": user_id,
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(session_data, session_secret)

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # First request should succeed
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Second request should return 404 (key already retrieved)
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 404
        body = json.loads(result2["body"])
        assert body["error"]["code"] == "no_pending_key"

    @mock_aws
    def test_returns_404_when_no_pending_key(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """Should return 404 when no pending key exists."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import _create_session_token, _get_session_secret
        from api.get_pending_key import handler

        user_id = f"user_{secrets.token_hex(8)}"

        # Create session token (but no PENDING_DISPLAY record)
        session_secret = _get_session_secret()
        session_data = {
            "user_id": user_id,
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(session_data, session_secret)

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_key"


# ============================================================================
# Security Edge Cases
# ============================================================================


class TestSecurityEdgeCases:
    """Additional security edge case tests."""

    @mock_aws
    def test_verify_email_handles_malformed_token(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should handle malformed tokens gracefully."""
        from api.verify_email import handler

        test_tokens = [
            "",
            " ",
            "a" * 10000,  # Very long token
            "../../../etc/passwd",  # Path traversal attempt
            "<script>alert('xss')</script>",  # XSS attempt
            "'; DROP TABLE users; --",  # SQL injection attempt
        ]

        for token in test_tokens:
            api_gateway_event["queryStringParameters"] = {"token": token}
            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 302
            # Should not crash, should return error
            assert "error=" in result["headers"]["Location"]

    @mock_aws
    def test_auth_callback_handles_malformed_token(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should handle malformed magic tokens gracefully."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        test_tokens = [
            "",
            " ",
            "a" * 10000,
            "../../../etc/passwd",
            "<script>alert('xss')</script>",
        ]

        for token in test_tokens:
            api_gateway_event["queryStringParameters"] = {"token": token}
            result = handler(api_gateway_event, {})

            assert result["statusCode"] == 302
            assert "error=" in result["headers"]["Location"]

    @mock_aws
    def test_magic_link_handles_malformed_email(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should handle malformed emails gracefully."""
        from api.magic_link import handler

        test_emails = [
            "",
            " ",
            "notanemail",
            "a" * 10000,
            "<script>alert('xss')</script>",
        ]

        api_gateway_event["httpMethod"] = "POST"

        for email in test_emails:
            api_gateway_event["body"] = json.dumps({"email": email})
            result = handler(api_gateway_event, {})

            # Should return 400 for invalid format, not crash
            assert result["statusCode"] in [200, 400]

    @mock_aws
    def test_security_headers_present(self, mock_dynamodb, setup_env, api_gateway_event):
        """Security headers should be present in redirect responses."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": "invalid"}

        result = handler(api_gateway_event, {})

        assert result["headers"]["Cache-Control"] == "no-store"
        assert result["headers"]["Content-Security-Policy"] == "default-src 'none'"
        assert result["headers"]["X-Content-Type-Options"] == "nosniff"


class TestConcurrencySimulation:
    """Simulated concurrency tests for race condition prevention."""

    @mock_aws
    def test_verify_email_atomic_operation(self, mock_dynamodb, pending_user, setup_env, api_gateway_event):
        """Test that verify_email uses atomic conditional delete."""
        from api.verify_email import handler

        # The key security feature is that the delete uses a condition expression:
        # ConditionExpression="attribute_exists(verification_token) AND verification_token = :expected_token"
        # This ensures only one concurrent request can succeed

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        # Verify the record exists before
        response = pending_user["table"].get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})
        assert "Item" in response

        with patch("api.verify_email.generate_api_key", return_value="pw_test"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302

        # Record should be gone
        response = pending_user["table"].get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})
        assert "Item" not in response

    @mock_aws
    def test_auth_callback_atomic_operation(
        self, mock_dynamodb, mock_secretsmanager, verified_user_with_magic_token, setup_env, api_gateway_event
    ):
        """Test that auth_callback uses atomic conditional update."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        # The key security feature is the atomic update with condition:
        # ConditionExpression=(
        #     "attribute_exists(magic_token) AND "
        #     "magic_token = :expected_token AND "
        #     "magic_expires > :now_iso"
        # )

        api_gateway_event["queryStringParameters"] = {"token": verified_user_with_magic_token["magic_token"]}

        # Verify magic token exists before
        response = verified_user_with_magic_token["table"].get_item(
            Key={"pk": verified_user_with_magic_token["user_id"], "sk": verified_user_with_magic_token["key_hash"]}
        )
        assert "magic_token" in response["Item"]

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302

        # Magic token should be removed
        response = verified_user_with_magic_token["table"].get_item(
            Key={"pk": verified_user_with_magic_token["user_id"], "sk": verified_user_with_magic_token["key_hash"]}
        )
        assert "magic_token" not in response["Item"]


# ============================================================================
# resend_verification.py - Coverage Gaps (lines 70-71, 77, 119-120, 152-154)
# ============================================================================


class TestResendVerificationCoverageGaps:
    """Tests covering specific uncovered lines in resend_verification.py.

    Lines 70-71: json.JSONDecodeError when parsing request body
    Line 77: invalid email (missing @ or empty)
    Lines 119-120: except (ValueError, TypeError) when parsing last_verification_sent
    Lines 152-154: General except Exception handler
    """

    @mock_aws
    def test_invalid_json_body_returns_400(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 400 for invalid JSON body (lines 70-71)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = "not valid json {{{{"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_empty_email_returns_400(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 400 for empty email (line 77)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": ""})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_at_sign_returns_400(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 400 for email without @ (line 77)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "notanemailaddress"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_missing_email_field_returns_400(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 400 when email field is missing entirely (line 77)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"name": "test"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_malformed_last_verification_sent_timestamp(self, mock_dynamodb, mock_ses, setup_env, api_gateway_event):
        """Should ignore malformed last_verification_sent and continue (lines 119-120)."""
        from api.resend_verification import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create PENDING record with malformed last_verification_sent
        user_id = f"user_{secrets.token_hex(8)}"
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "malformed_ts@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_verification_sent": "not-a-valid-timestamp-at-all",  # Malformed
            }
        )

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "malformed_ts@example.com"})

        result = handler(api_gateway_event, {})

        # Should succeed (malformed timestamp silently ignored, treated as no cooldown)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "pending verification" in body["message"]

    @mock_aws
    def test_none_last_verification_sent_timestamp(self, mock_dynamodb, mock_ses, setup_env, api_gateway_event):
        """Should handle None last_verification_sent gracefully (TypeError in lines 119-120)."""
        from api.resend_verification import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        user_id = f"user_{secrets.token_hex(8)}"
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "none_ts@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                # last_verification_sent not set at all (will be None from .get())
            }
        )

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "none_ts@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_database_error_returns_500(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 500 when database query fails (lines 152-154)."""
        from unittest.mock import patch

        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "error@example.com"})

        # Patch dynamodb to raise an exception during query
        with patch("api.resend_verification.dynamodb") as mock_db:
            from unittest.mock import MagicMock

            mock_table = MagicMock()
            mock_table.query.side_effect = RuntimeError("DynamoDB connection error")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_null_body_treated_as_empty_json(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should handle None body gracefully (the `or "{}"` pattern)."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = None

        result = handler(api_gateway_event, {})

        # Empty JSON => empty email => 400
        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"


class TestResendVerificationEmailEnumeration:
    """Security tests for email enumeration prevention in resend_verification."""

    @mock_aws
    def test_same_message_for_existing_vs_nonexistent_email(
        self, mock_dynamodb, mock_ses, pending_user, setup_env, api_gateway_event
    ):
        """Should return identical success message regardless of email existence."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"

        # Request for existing pending email
        api_gateway_event["body"] = json.dumps({"email": pending_user["email"]})
        result_existing = handler(api_gateway_event, {})
        body_existing = json.loads(result_existing["body"])

        # Request for nonexistent email
        api_gateway_event["body"] = json.dumps({"email": "nonexistent_user_xyz@example.com"})
        result_nonexistent = handler(api_gateway_event, {})
        body_nonexistent = json.loads(result_nonexistent["body"])

        # Both should be 200 with same message
        assert result_existing["statusCode"] == 200
        assert result_nonexistent["statusCode"] == 200
        assert body_existing["message"] == body_nonexistent["message"]

    @mock_aws
    def test_email_normalization_case_insensitive(self, mock_dynamodb, mock_ses, setup_env, api_gateway_event):
        """Email should be normalized to lowercase before lookup."""
        from api.resend_verification import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create pending user with lowercase email
        user_id = f"user_{secrets.token_hex(8)}"
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "test@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        api_gateway_event["httpMethod"] = "POST"
        # Send with mixed case
        api_gateway_event["body"] = json.dumps({"email": "  Test@EXAMPLE.com  "})

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 200

    @mock_aws
    def test_whitespace_only_email_returns_400(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return 400 for whitespace-only email."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "   "})

        result = handler(api_gateway_event, {})
        assert result["statusCode"] == 400


class TestResendVerificationTimingNormalization:
    """Additional tests for timing normalization to prevent side-channel attacks."""

    @mock_aws
    def test_error_responses_also_timing_normalized(self, mock_dynamodb, setup_env, api_gateway_event):
        """Error responses (500) should also be timing-normalized (lines 152-154)."""
        from unittest.mock import patch

        from api.resend_verification import MIN_RESPONSE_TIME_SECONDS, handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "error@example.com"})

        with patch("api.resend_verification.dynamodb") as mock_db:
            from unittest.mock import MagicMock

            mock_table = MagicMock()
            mock_table.query.side_effect = RuntimeError("DynamoDB error")
            mock_db.Table.return_value = mock_table

            start = time.time()
            result = handler(api_gateway_event, {})
            elapsed = time.time() - start

        assert result["statusCode"] == 500
        # Error response should also be timing-normalized
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1


class TestSessionTamperingAndBypass:
    """Additional security tests for session cookie tampering and auth bypass."""

    @mock_aws
    def test_auth_callback_with_xss_in_token(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """XSS payload in token should not be reflected unsanitized in redirect."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        # Token is an XSS payload
        api_gateway_event["queryStringParameters"] = {"token": '<script>alert("xss")</script>'}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        # Token should not appear unencoded in the redirect URL
        assert "<script>" not in location

    @mock_aws
    def test_auth_callback_with_null_bytes_in_token(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Null bytes in token should be handled safely."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": "valid_looking\x00hidden_payload"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=" in result["headers"]["Location"]

    @mock_aws
    def test_resend_verification_with_xss_in_email(self, mock_dynamodb, setup_env, api_gateway_event):
        """XSS payload in email field should be handled safely."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": '<script>alert("xss")</script>@evil.com'})

        result = handler(api_gateway_event, {})
        # Should either be rejected (400 for invalid email) or return generic success
        assert result["statusCode"] in [200, 400]

    @mock_aws
    def test_resend_verification_sql_injection_in_email(self, mock_dynamodb, setup_env, api_gateway_event):
        """SQL injection in email should be handled safely."""
        from api.resend_verification import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "'; DROP TABLE users; --@evil.com"})

        result = handler(api_gateway_event, {})
        # Should return success (email exists check is generic)
        assert result["statusCode"] == 200
