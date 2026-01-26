"""
Comprehensive tests for auth callback endpoint (functions/api/auth_callback.py).

Security-critical code: Tests cover:
1. Valid token exchange for session cookie
2. Expired token handling
3. Invalid/tampered token handling
4. Token already used (replay attack prevention)
5. Race condition prevention via conditional update
6. Session token creation and signing
7. Session token verification
8. Missing token handling
9. Session secret configuration errors
10. Database error handling
11. TOCTOU race condition handling
12. Redirect URL construction
13. Security headers in responses
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws


# Set environment variables before importing modules
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["BASE_URL"] = "https://test.example.com"
# Use the secret name directly - moto accepts names as SecretId
os.environ["SESSION_SECRET_ARN"] = "pkgwatch-test-session-secret"


def reset_auth_callback_cache():
    """Reset the session secret cache in auth_callback module."""
    import api.auth_callback as auth_callback_module
    auth_callback_module._session_secret_cache = None
    auth_callback_module._session_secret_cache_time = 0.0


@contextmanager
def mock_session_secret(secret_value="test-secret-value-123"):
    """
    Context manager that mocks the session secret retrieval.

    Instead of trying to mock Secrets Manager (which has timing issues with
    module-level client creation), we directly patch _get_session_secret.
    """
    # Reset cache before patching
    reset_auth_callback_cache()

    with patch("api.auth_callback._get_session_secret", return_value=secret_value):
        yield secret_value


@pytest.fixture
def api_keys_table(mock_dynamodb):
    """Get the API keys table."""
    return mock_dynamodb.Table("pkgwatch-api-keys")


@pytest.fixture
def base_event():
    """Base API Gateway event for auth callback handler."""
    return {
        "httpMethod": "GET",
        "headers": {},
        "pathParameters": {},
        "queryStringParameters": {},
        "body": None,
        "requestContext": {
            "identity": {"sourceIp": "127.0.0.1"},
        },
    }


@pytest.fixture
def user_with_valid_magic_token(api_keys_table):
    """Create a user with a valid (non-expired) magic token."""
    key_hash = hashlib.sha256(b"pw_user_with_token_key").hexdigest()
    user_id = "user_with_token"
    magic_token = "valid_magic_token_for_testing_12345678901234"
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

    api_keys_table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "tokenuser@example.com",
            "tier": "pro",
            "email_verified": True,
            "created_at": "2024-01-01T00:00:00Z",
            "magic_token": magic_token,
            "magic_expires": expires,
        }
    )
    return {
        "user_id": user_id,
        "key_hash": key_hash,
        "email": "tokenuser@example.com",
        "magic_token": magic_token,
        "tier": "pro",
    }


@pytest.fixture
def user_with_expired_magic_token(api_keys_table):
    """Create a user with an expired magic token."""
    key_hash = hashlib.sha256(b"pw_expired_token_key").hexdigest()
    user_id = "user_expired_token"
    magic_token = "expired_magic_token_for_testing_1234567890"
    # Expired 1 hour ago
    expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    api_keys_table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "expireduser@example.com",
            "tier": "free",
            "email_verified": True,
            "created_at": "2024-01-01T00:00:00Z",
            "magic_token": magic_token,
            "magic_expires": expires,
        }
    )
    return {
        "user_id": user_id,
        "key_hash": key_hash,
        "email": "expireduser@example.com",
        "magic_token": magic_token,
    }


class TestValidTokenExchange:
    """Tests for valid token exchange."""

    @mock_aws
    def test_valid_token_creates_session_and_redirects(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should exchange valid token for session cookie and redirect to dashboard."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["statusCode"] == 302
            assert result["headers"]["Location"] == "https://test.example.com/dashboard"

            # Verify Set-Cookie header is present with session token
            assert "Set-Cookie" in result["headers"]
            cookie = result["headers"]["Set-Cookie"]
            assert "session=" in cookie
            assert "HttpOnly" in cookie
            assert "Secure" in cookie
            assert "SameSite=Strict" in cookie

    @mock_aws
    def test_valid_token_consumes_magic_token(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should remove magic token after successful exchange."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["statusCode"] == 302

            # Verify magic token was consumed (removed from database)
            from boto3.dynamodb.conditions import Key
            response = api_keys_table.query(
                KeyConditionExpression=Key("pk").eq(user_with_valid_magic_token["user_id"]),
            )
            api_key_item = [
                i for i in response["Items"]
                if i["sk"] == user_with_valid_magic_token["key_hash"]
            ][0]

            assert "magic_token" not in api_key_item
            assert "magic_expires" not in api_key_item
            assert "last_login" in api_key_item

    @mock_aws
    def test_valid_token_sets_last_login(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should set last_login timestamp on successful exchange."""
        with mock_session_secret():
            from api.auth_callback import handler

            now = datetime.now(timezone.utc)
            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            handler(base_event, {})

            # Verify last_login was set
            from boto3.dynamodb.conditions import Key
            response = api_keys_table.query(
                KeyConditionExpression=Key("pk").eq(user_with_valid_magic_token["user_id"]),
            )
            api_key_item = [
                i for i in response["Items"]
                if i["sk"] == user_with_valid_magic_token["key_hash"]
            ][0]

            last_login = datetime.fromisoformat(api_key_item["last_login"].replace("Z", "+00:00"))
            diff = abs((last_login - now).total_seconds())
            assert diff < 60  # Within 1 minute


class TestExpiredTokenHandling:
    """Tests for expired token handling."""

    @mock_aws
    def test_expired_token_redirects_with_error(
        self, mock_dynamodb, base_event, api_keys_table, user_with_expired_magic_token
    ):
        """Should redirect to login with error for expired token."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_expired_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["statusCode"] == 302
            location = result["headers"]["Location"]
            assert "https://test.example.com/start" in location
            assert "error=token_expired" in location
            assert "expired" in location.lower()

    @mock_aws
    def test_expired_token_cleans_up_record(
        self, mock_dynamodb, base_event, api_keys_table, user_with_expired_magic_token
    ):
        """Should clean up expired magic token from database."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_expired_magic_token["magic_token"]
            }

            handler(base_event, {})

            # Verify magic token was cleaned up
            from boto3.dynamodb.conditions import Key
            response = api_keys_table.query(
                KeyConditionExpression=Key("pk").eq(user_with_expired_magic_token["user_id"]),
            )
            api_key_item = [
                i for i in response["Items"]
                if i["sk"] == user_with_expired_magic_token["key_hash"]
            ][0]

            assert "magic_token" not in api_key_item
            assert "magic_expires" not in api_key_item


class TestInvalidTokenHandling:
    """Tests for invalid/tampered token handling."""

    @mock_aws
    def test_nonexistent_token_redirects_with_error(
        self, mock_dynamodb, base_event, api_keys_table
    ):
        """Should redirect to login with error for non-existent token."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": "nonexistent_token_that_does_not_exist_12345"
            }

            result = handler(base_event, {})

            assert result["statusCode"] == 302
            location = result["headers"]["Location"]
            assert "https://test.example.com/start" in location
            assert "error=invalid_token" in location

    @mock_aws
    def test_empty_token_redirects_with_error(self, mock_dynamodb, base_event):
        """Should redirect to login with error for empty token."""
        from api.auth_callback import handler

        base_event["queryStringParameters"] = {"token": ""}

        result = handler(base_event, {})

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "error=missing_token" in location


class TestMissingTokenHandling:
    """Tests for missing token handling."""

    @mock_aws
    def test_missing_token_parameter_redirects_with_error(
        self, mock_dynamodb, base_event
    ):
        """Should redirect to login with error when token parameter is missing."""
        from api.auth_callback import handler

        base_event["queryStringParameters"] = {}

        result = handler(base_event, {})

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "https://test.example.com/start" in location
        assert "error=missing_token" in location

    @mock_aws
    def test_null_query_params_redirects_with_error(self, mock_dynamodb, base_event):
        """Should handle null queryStringParameters gracefully."""
        from api.auth_callback import handler

        base_event["queryStringParameters"] = None

        result = handler(base_event, {})

        assert result["statusCode"] == 302
        location = result["headers"]["Location"]
        assert "error=missing_token" in location


class TestReplayAttackPrevention:
    """Tests for replay attack prevention (token already used)."""

    @mock_aws
    def test_token_reuse_returns_error(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should prevent token reuse (replay attack)."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            # First use - should succeed
            result1 = handler(base_event, {})
            assert result1["statusCode"] == 302
            assert "/dashboard" in result1["headers"]["Location"]

            # Second use - should fail (token consumed)
            result2 = handler(base_event, {})
            assert result2["statusCode"] == 302
            location = result2["headers"]["Location"]
            # Token no longer exists in GSI, so it's invalid
            assert "error=" in location


class TestConditionalUpdateRaceCondition:
    """Tests for race condition prevention via conditional update."""

    @mock_aws
    def test_conditional_check_prevents_concurrent_use(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should prevent TOCTOU race condition via conditional update."""
        with mock_session_secret():
            from api.auth_callback import handler

            # Simulate race condition by manually removing the token before handler completes
            with patch("api.auth_callback.dynamodb") as mock_db:
                mock_table = MagicMock()

                # GSI query returns the user (token exists)
                mock_table.query.return_value = {
                    "Items": [{
                        "pk": user_with_valid_magic_token["user_id"],
                        "sk": user_with_valid_magic_token["key_hash"],
                    }]
                }

                # get_item returns full user data with token
                mock_table.get_item.return_value = {
                    "Item": {
                        "pk": user_with_valid_magic_token["user_id"],
                        "sk": user_with_valid_magic_token["key_hash"],
                        "email": user_with_valid_magic_token["email"],
                        "tier": user_with_valid_magic_token["tier"],
                        "magic_token": user_with_valid_magic_token["magic_token"],
                        "magic_expires": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
                    }
                }

                # Conditional update fails (token already consumed by concurrent request)
                error_response = {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "Condition check failed",
                    }
                }
                mock_table.update_item.side_effect = ClientError(error_response, "UpdateItem")
                mock_db.Table.return_value = mock_table

                base_event["queryStringParameters"] = {
                    "token": user_with_valid_magic_token["magic_token"]
                }

                result = handler(base_event, {})

                # Should redirect with error (token already used)
                assert result["statusCode"] == 302
                location = result["headers"]["Location"]
                assert "error=" in location


class TestSessionTokenCreation:
    """Tests for session token creation and signing."""

    @mock_aws
    def test_session_token_contains_required_claims(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should create session token with required claims."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            # Extract session token from cookie
            cookie = result["headers"]["Set-Cookie"]
            session_part = cookie.split(";")[0]
            session_token = session_part.split("=", 1)[1]

            # Decode payload (before signature)
            payload_b64, signature = session_token.rsplit(".", 1)
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)

            # Verify required claims
            assert "user_id" in payload
            assert payload["user_id"] == user_with_valid_magic_token["user_id"]
            assert "email" in payload
            assert payload["email"] == user_with_valid_magic_token["email"]
            assert "tier" in payload
            assert payload["tier"] == user_with_valid_magic_token["tier"]
            assert "exp" in payload

    @mock_aws
    def test_session_token_expires_in_7_days(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should set session expiry to 7 days."""
        with mock_session_secret():
            from api.auth_callback import handler, SESSION_TTL_DAYS

            now = datetime.now(timezone.utc)
            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            # Extract and decode session token
            cookie = result["headers"]["Set-Cookie"]
            session_part = cookie.split(";")[0]
            session_token = session_part.split("=", 1)[1]
            payload_b64, _ = session_token.rsplit(".", 1)
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)

            # Verify expiry is approximately 7 days from now
            exp_timestamp = payload["exp"]
            expected_exp = (now + timedelta(days=SESSION_TTL_DAYS)).timestamp()
            diff = abs(exp_timestamp - expected_exp)
            assert diff < 60  # Within 1 minute


class TestSessionTokenVerification:
    """Tests for session token verification function."""

    @mock_aws
    def test_verify_valid_session_token(self, mock_dynamodb):
        """Should verify valid session token."""
        with mock_session_secret():
            from api.auth_callback import _create_session_token, verify_session_token, _get_session_secret

            session_secret = _get_session_secret()
            session_data = {
                "user_id": "user_test",
                "email": "test@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
            }

            token = _create_session_token(session_data, session_secret)
            verified = verify_session_token(token)

            assert verified is not None
            assert verified["user_id"] == "user_test"
            assert verified["email"] == "test@example.com"
            assert verified["tier"] == "free"

    @mock_aws
    def test_verify_expired_session_token_returns_none(self, mock_dynamodb):
        """Should return None for expired session token."""
        with mock_session_secret():
            from api.auth_callback import _create_session_token, verify_session_token, _get_session_secret

            session_secret = _get_session_secret()
            session_data = {
                "user_id": "user_test",
                "email": "test@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expired
            }

            token = _create_session_token(session_data, session_secret)
            verified = verify_session_token(token)

            assert verified is None

    @mock_aws
    def test_verify_tampered_session_token_returns_none(self, mock_dynamodb):
        """Should return None for tampered session token."""
        with mock_session_secret():
            from api.auth_callback import _create_session_token, verify_session_token, _get_session_secret

            session_secret = _get_session_secret()
            session_data = {
                "user_id": "user_test",
                "email": "test@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
            }

            token = _create_session_token(session_data, session_secret)

            # Tamper with the payload (change user_id)
            payload_b64, signature = token.rsplit(".", 1)
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
            payload = json.loads(payload_json)
            payload["user_id"] = "user_attacker"  # Tamper
            tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
            tampered_token = f"{tampered_payload}.{signature}"

            verified = verify_session_token(tampered_token)

            assert verified is None

    @mock_aws
    def test_verify_token_with_wrong_signature_returns_none(self, mock_dynamodb):
        """Should return None for token with wrong signature."""
        with mock_session_secret():
            from api.auth_callback import verify_session_token

            # Create token with wrong secret
            session_data = {
                "user_id": "user_test",
                "email": "test@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
            }
            payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
            wrong_signature = hmac.new(
                b"wrong-secret",
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            token = f"{payload}.{wrong_signature}"

            verified = verify_session_token(token)

            assert verified is None

    @mock_aws
    def test_verify_malformed_token_returns_none(self, mock_dynamodb):
        """Should return None for malformed token."""
        with mock_session_secret():
            from api.auth_callback import verify_session_token

            # No dot separator
            assert verify_session_token("malformedtoken") is None
            # Empty string
            assert verify_session_token("") is None
            # Invalid base64
            assert verify_session_token("invalid!!!.signature") is None


class TestSessionSecretConfiguration:
    """Tests for session secret configuration errors."""

    @mock_aws
    def test_missing_session_secret_arn_returns_error(self, mock_dynamodb, base_event):
        """Should redirect with error when SESSION_SECRET_ARN is not set."""
        reset_auth_callback_cache()

        # Temporarily remove the env var
        original = os.environ.get("SESSION_SECRET_ARN")
        os.environ["SESSION_SECRET_ARN"] = ""

        try:
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {"token": "some_token"}

            result = handler(base_event, {})

            assert result["statusCode"] == 302
            location = result["headers"]["Location"]
            assert "error=internal_error" in location
        finally:
            # Restore
            if original:
                os.environ["SESSION_SECRET_ARN"] = original

    @mock_aws
    def test_secrets_manager_error_returns_error(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should redirect with error when Secrets Manager fails."""
        reset_auth_callback_cache()

        from api.auth_callback import handler

        # Don't create the secret - Secrets Manager will fail
        # But we need to patch the secretsmanager client to use mocked one
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        with patch("api.auth_callback.secretsmanager", sm):
            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["statusCode"] == 302
            location = result["headers"]["Location"]
            assert "error=internal_error" in location


class TestDatabaseErrorHandling:
    """Tests for database error handling."""

    @mock_aws
    def test_gsi_query_error_redirects_with_error(self, mock_dynamodb, base_event):
        """Should redirect with error when GSI query fails."""
        with mock_session_secret():
            from api.auth_callback import handler

            with patch("api.auth_callback.dynamodb") as mock_db:
                mock_table = MagicMock()
                mock_table.query.side_effect = Exception("DynamoDB error")
                mock_db.Table.return_value = mock_table

                base_event["queryStringParameters"] = {"token": "some_token"}

                result = handler(base_event, {})

                assert result["statusCode"] == 302
                location = result["headers"]["Location"]
                assert "error=internal_error" in location

    @mock_aws
    def test_get_item_error_redirects_with_error(self, mock_dynamodb, base_event):
        """Should redirect with error when get_item fails."""
        with mock_session_secret():
            from api.auth_callback import handler

            with patch("api.auth_callback.dynamodb") as mock_db:
                mock_table = MagicMock()
                # Query succeeds
                mock_table.query.return_value = {
                    "Items": [{"pk": "user_test", "sk": "key_hash"}]
                }
                # get_item fails
                mock_table.get_item.side_effect = Exception("DynamoDB error")
                mock_db.Table.return_value = mock_table

                base_event["queryStringParameters"] = {"token": "some_token"}

                result = handler(base_event, {})

                assert result["statusCode"] == 302
                location = result["headers"]["Location"]
                assert "error=internal_error" in location


class TestSecurityHeaders:
    """Tests for security headers in responses."""

    @mock_aws
    def test_redirect_includes_cache_control(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should include Cache-Control: no-store header."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["headers"].get("Cache-Control") == "no-store"

    @mock_aws
    def test_redirect_includes_csp(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should include Content-Security-Policy header."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert "Content-Security-Policy" in result["headers"]

    @mock_aws
    def test_redirect_includes_x_content_type_options(
        self, mock_dynamodb, base_event, api_keys_table, user_with_valid_magic_token
    ):
        """Should include X-Content-Type-Options: nosniff header."""
        with mock_session_secret():
            from api.auth_callback import handler

            base_event["queryStringParameters"] = {
                "token": user_with_valid_magic_token["magic_token"]
            }

            result = handler(base_event, {})

            assert result["headers"].get("X-Content-Type-Options") == "nosniff"

    @mock_aws
    def test_error_redirect_includes_security_headers(self, mock_dynamodb, base_event):
        """Should include security headers in error redirects."""
        from api.auth_callback import handler

        base_event["queryStringParameters"] = {}

        result = handler(base_event, {})

        assert result["headers"].get("Cache-Control") == "no-store"
        assert "Content-Security-Policy" in result["headers"]
        assert result["headers"].get("X-Content-Type-Options") == "nosniff"


class TestSessionSecretCaching:
    """Tests for session secret caching behavior."""

    def test_session_secret_is_cached(self):
        """Should cache session secret to avoid repeated Secrets Manager calls."""
        import api.auth_callback as auth_callback_module

        # Reset cache
        reset_auth_callback_cache()

        # Simulate caching by setting the cache directly
        auth_callback_module._session_secret_cache = "cached-secret-value"
        auth_callback_module._session_secret_cache_time = time.time()

        # Function should return cached value without calling Secrets Manager
        with patch("api.auth_callback.secretsmanager") as mock_sm:
            from api.auth_callback import _get_session_secret
            secret = _get_session_secret()

            assert secret == "cached-secret-value"
            # Secrets Manager should NOT be called since cache is valid
            mock_sm.get_secret_value.assert_not_called()

    def test_session_secret_cache_ttl(self):
        """Should refresh cache after TTL expires."""
        import api.auth_callback as auth_callback_module

        # Set expired cache
        auth_callback_module._session_secret_cache = "old-cached-value"
        auth_callback_module._session_secret_cache_time = time.time() - 400  # Past 300s TTL

        # Mock Secrets Manager to return fresh value
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps({"secret": "fresh-secret-value"})
        }

        with patch("api.auth_callback.secretsmanager", mock_sm):
            from api.auth_callback import _get_session_secret
            secret = _get_session_secret()

            assert secret == "fresh-secret-value"
            # Secrets Manager should be called since cache expired
            mock_sm.get_secret_value.assert_called_once()


class TestUserNotFoundAfterGSIQuery:
    """Tests for edge case where GSI returns result but user is not found."""

    @mock_aws
    def test_user_not_found_after_gsi_query_redirects_with_error(
        self, mock_dynamodb, base_event
    ):
        """Should redirect with error when GSI returns result but get_item returns nothing."""
        with mock_session_secret():
            from api.auth_callback import handler

            with patch("api.auth_callback.dynamodb") as mock_db:
                mock_table = MagicMock()
                # GSI query returns a result
                mock_table.query.return_value = {
                    "Items": [{"pk": "user_test", "sk": "key_hash"}]
                }
                # But get_item returns nothing (user was deleted between queries)
                mock_table.get_item.return_value = {}
                mock_db.Table.return_value = mock_table

                base_event["queryStringParameters"] = {"token": "some_token"}

                result = handler(base_event, {})

                assert result["statusCode"] == 302
                location = result["headers"]["Location"]
                assert "error=invalid_token" in location


class TestSessionSecretPlainStringFormat:
    """Tests for session secret in plain string format (not JSON)."""

    def test_plain_string_secret_handled(self):
        """Should handle secret stored as plain string (not JSON)."""
        reset_auth_callback_cache()

        # Mock Secrets Manager to return plain string (not JSON)
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": "plain-string-secret-value"  # Not JSON
        }

        with patch("api.auth_callback.secretsmanager", mock_sm):
            from api.auth_callback import _get_session_secret
            secret = _get_session_secret()

            assert secret == "plain-string-secret-value"
