"""
Tests for auth_pending_recovery_codes.py endpoint.

This module tests the GET /auth/pending-recovery-codes endpoint which:
1. Retrieves newly generated recovery codes for one-time display
2. Atomically deletes the pending codes after retrieval (single-use)
3. Marks recovery_codes_shown=true in USER_META
4. Requires valid session authentication
"""

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def setup_env():
    """Set up environment variables for tests."""
    original_env = os.environ.copy()
    os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
    os.environ["BASE_URL"] = "https://test.example.com"
    os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

    yield

    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_secretsmanager():
    """Mock Secrets Manager for session secret."""
    with mock_aws():
        sm = boto3.client("secretsmanager", region_name="us-east-1")
        sm.create_secret(
            Name="test-session-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )
        yield sm


@pytest.fixture
def user_with_pending_codes(mock_dynamodb):
    """Create a user with pending recovery codes."""
    import hashlib

    table = mock_dynamodb.Table("pkgwatch-api-keys")
    user_id = f"user_{secrets.token_hex(8)}"
    api_key = f"pw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Recovery codes in the format the app uses
    recovery_codes = [
        "AAAA-BBBB-CCCC-DDDD",
        "EEEE-FFFF-GGGG-HHHH",
        "IIII-JJJJ-KKKK-LLLL",
        "MMMM-NNNN-OOOO-PPPP",
        "QQQQ-RRRR-SSSS-TTTT",
    ]

    # Create API key record
    table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "recovery@example.com",
            "tier": "free",
            "requests_this_month": 0,
            "email_verified": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Create PENDING_RECOVERY_CODES record
    table.put_item(
        Item={
            "pk": user_id,
            "sk": "PENDING_RECOVERY_CODES",
            "codes": recovery_codes,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Create USER_META record
    table.put_item(
        Item={
            "pk": user_id,
            "sk": "USER_META",
            "key_count": 1,
            "recovery_codes_shown": False,
        }
    )

    return {
        "user_id": user_id,
        "key_hash": key_hash,
        "email": "recovery@example.com",
        "recovery_codes": recovery_codes,
        "table": table,
    }


@pytest.fixture
def user_without_pending_codes(mock_dynamodb):
    """Create a user without pending recovery codes."""
    import hashlib

    table = mock_dynamodb.Table("pkgwatch-api-keys")
    user_id = f"user_{secrets.token_hex(8)}"
    api_key = f"pw_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    # Create API key record only (no pending codes)
    table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "nocodes@example.com",
            "tier": "free",
            "requests_this_month": 0,
            "email_verified": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    return {
        "user_id": user_id,
        "key_hash": key_hash,
        "email": "nocodes@example.com",
        "table": table,
    }


def create_valid_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create a valid session token for testing."""
    import api.auth_callback
    api.auth_callback._session_secret_cache = None
    api.auth_callback._session_secret_cache_time = 0.0

    from api.auth_callback import _create_session_token

    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
    }
    return _create_session_token(session_data, "test-secret-key-for-signing-sessions")


def create_expired_session_token(user_id: str, email: str) -> str:
    """Create an expired session token for testing."""
    from api.auth_callback import _create_session_token

    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": "free",
        "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),  # Expired
    }
    return _create_session_token(session_data, "test-secret-key-for-signing-sessions")


# ============================================================================
# Happy Path Tests
# ============================================================================


class TestPendingRecoveryCodesHappyPath:
    """Tests for successful recovery codes retrieval."""

    @mock_aws
    def test_returns_recovery_codes_with_valid_session(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return recovery codes for authenticated user with pending codes."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "codes" in body
        assert body["codes"] == user_with_pending_codes["recovery_codes"]
        assert "message" in body
        assert "only be shown once" in body["message"]

    @mock_aws
    def test_codes_deleted_after_retrieval(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Pending codes should be atomically deleted after successful retrieval."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # First request should succeed
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Verify PENDING_RECOVERY_CODES record was deleted
        response = user_with_pending_codes["table"].get_item(
            Key={"pk": user_with_pending_codes["user_id"], "sk": "PENDING_RECOVERY_CODES"}
        )
        assert "Item" not in response

    @mock_aws
    def test_recovery_codes_shown_flag_set(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should mark recovery_codes_shown=true in USER_META after retrieval."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        handler(api_gateway_event, {})

        # Verify USER_META was updated
        response = user_with_pending_codes["table"].get_item(
            Key={"pk": user_with_pending_codes["user_id"], "sk": "USER_META"}
        )
        assert response.get("Item", {}).get("recovery_codes_shown") is True

    @mock_aws
    def test_handles_lowercase_cookie_header(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should handle lowercase 'cookie' header."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_handles_capitalized_cookie_header(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should handle capitalized 'Cookie' header."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_response_includes_cors_headers(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Response should include CORS headers for allowed origins."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"


# ============================================================================
# Authentication Failure Tests
# ============================================================================


class TestPendingRecoveryCodesAuthFailures:
    """Tests for authentication failures."""

    @mock_aws
    def test_returns_401_without_session_cookie(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should return 401 when no session cookie is present."""
        from api.auth_pending_recovery_codes import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"
        assert "Not authenticated" in body["error"]["message"]

    @mock_aws
    def test_returns_401_with_empty_cookie_header(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should return 401 when cookie header is empty."""
        from api.auth_pending_recovery_codes import handler

        api_gateway_event["headers"]["Cookie"] = ""

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_with_cookie_but_no_session(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should return 401 when cookie header exists but no session cookie."""
        from api.auth_pending_recovery_codes import handler

        api_gateway_event["headers"]["Cookie"] = "other_cookie=value"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_with_invalid_session_token(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should return 401 for invalid session token."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        api_gateway_event["headers"]["Cookie"] = "session=invalid.token.here"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"
        assert "Session expired" in body["error"]["message"]

    @mock_aws
    def test_returns_401_with_expired_session_token(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 401 for expired session token."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        expired_token = create_expired_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={expired_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_401_with_malformed_session_token(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should return 401 for malformed session token (no dot separator)."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        api_gateway_event["headers"]["Cookie"] = "session=malformedtokenwithoutdot"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_401_with_tampered_session_token(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 401 for tampered session token (wrong signature)."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        valid_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )
        # Tamper with the signature
        payload, _ = valid_token.rsplit(".", 1)
        tampered_token = f"{payload}.tamperedsignature"

        api_gateway_event["headers"]["Cookie"] = f"session={tampered_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"


# ============================================================================
# Edge Cases Tests
# ============================================================================


class TestPendingRecoveryCodesEdgeCases:
    """Tests for edge cases and error handling."""

    @mock_aws
    def test_returns_404_when_no_pending_codes(
        self, mock_dynamodb, mock_secretsmanager, user_without_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 404 when user has no pending recovery codes."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_without_pending_codes["user_id"],
            user_without_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_codes"
        assert "already been retrieved" in body["error"]["message"]

    @mock_aws
    def test_returns_404_on_second_retrieval_attempt(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 404 on second retrieval attempt (one-time use)."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # First request succeeds
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Second request should return 404
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 404
        body = json.loads(result2["body"])
        assert body["error"]["code"] == "no_pending_codes"

    @mock_aws
    def test_handles_null_headers(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should handle null headers gracefully."""
        from api.auth_pending_recovery_codes import handler

        api_gateway_event["headers"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_handles_missing_headers_key(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should handle missing headers key gracefully."""
        from api.auth_pending_recovery_codes import handler

        del api_gateway_event["headers"]

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_continues_if_user_meta_update_fails(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should continue and return codes even if USER_META update fails."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Delete USER_META record to cause update to fail (no record to update creates new one)
        # Instead, we'll mock the update to fail
        original_handler = handler

        # Mock update_item to fail for USER_META
        with patch('api.auth_pending_recovery_codes.dynamodb') as mock_db:
            mock_table = MagicMock()
            mock_db.Table.return_value = mock_table

            # delete_item succeeds and returns the codes
            mock_table.delete_item.return_value = {
                "Attributes": {
                    "pk": user_with_pending_codes["user_id"],
                    "sk": "PENDING_RECOVERY_CODES",
                    "codes": user_with_pending_codes["recovery_codes"],
                }
            }

            # update_item fails
            mock_table.update_item.side_effect = Exception("DynamoDB error")

            result = original_handler(api_gateway_event, {})

        # Should still return 200 with codes despite USER_META update failure
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["codes"] == user_with_pending_codes["recovery_codes"]

    @mock_aws
    def test_handles_empty_codes_array(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should handle edge case of empty codes array."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = f"user_{secrets.token_hex(8)}"

        # Create PENDING_RECOVERY_CODES with empty codes array
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_RECOVERY_CODES",
                "codes": [],
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        session_token = create_valid_session_token(user_id, "empty@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["codes"] == []

    @mock_aws
    def test_handles_user_without_user_meta_record(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should work even if USER_META record doesn't exist."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = f"user_{secrets.token_hex(8)}"
        recovery_codes = ["CODE-1111-2222-3333"]

        # Create PENDING_RECOVERY_CODES without USER_META
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_RECOVERY_CODES",
                "codes": recovery_codes,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        session_token = create_valid_session_token(user_id, "nometa@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # Should succeed - USER_META update creates the record
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["codes"] == recovery_codes


# ============================================================================
# Database Error Tests
# ============================================================================


class TestPendingRecoveryCodesDatabaseErrors:
    """Tests for database error handling."""

    @mock_aws
    def test_returns_500_on_general_exception(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 500 on unexpected database errors."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch('api.auth_pending_recovery_codes.dynamodb') as mock_db:
            mock_table = MagicMock()
            mock_db.Table.return_value = mock_table
            mock_table.delete_item.side_effect = Exception("Unexpected database error")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_conditional_check_failed_exception(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 404 when conditional delete fails (codes attribute missing)."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Delete the pending codes record before the handler runs to simulate
        # race condition where codes were already retrieved
        user_with_pending_codes["table"].delete_item(
            Key={"pk": user_with_pending_codes["user_id"], "sk": "PENDING_RECOVERY_CODES"}
        )

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_codes"

    @mock_aws
    def test_reraises_non_conditional_check_client_error(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should re-raise ClientError that is not ConditionalCheckFailedException."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Mock a different ClientError (e.g., ProvisionedThroughputExceededException)
        error_response = {
            "Error": {
                "Code": "ProvisionedThroughputExceededException",
                "Message": "Throughput exceeded"
            }
        }
        with patch('api.auth_pending_recovery_codes.dynamodb') as mock_db:
            mock_table = MagicMock()
            mock_db.Table.return_value = mock_table
            mock_table.delete_item.side_effect = ClientError(error_response, "DeleteItem")

            result = handler(api_gateway_event, {})

        # Should return 500 because the ClientError is re-raised and caught by outer try/except
        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_delete_item_returning_empty_attributes(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should return 404 when delete_item returns None for Attributes (defensive)."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Mock delete_item to return empty response (Attributes is None)
        with patch('api.auth_pending_recovery_codes.dynamodb') as mock_db:
            mock_table = MagicMock()
            mock_db.Table.return_value = mock_table
            # Return response without Attributes key (simulates edge case)
            mock_table.delete_item.return_value = {}

            result = handler(api_gateway_event, {})

        # Should return 404 because pending_item is None
        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_codes"


# ============================================================================
# Response Format Validation Tests
# ============================================================================


class TestPendingRecoveryCodesResponseFormat:
    """Tests for response format validation."""

    @mock_aws
    def test_success_response_format(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Verify success response has correct format."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Content-Type"] == "application/json"

        body = json.loads(result["body"])
        assert isinstance(body["codes"], list)
        assert len(body["codes"]) == 5
        assert all(isinstance(code, str) for code in body["codes"])
        assert "message" in body

    @mock_aws
    def test_error_response_format(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Verify error response has correct format."""
        from api.auth_pending_recovery_codes import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        assert result["headers"]["Content-Type"] == "application/json"

        body = json.loads(result["body"])
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]

    @mock_aws
    def test_404_response_format(
        self, mock_dynamodb, mock_secretsmanager, user_without_pending_codes, setup_env, api_gateway_event
    ):
        """Verify 404 response has correct format."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_without_pending_codes["user_id"],
            user_without_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        assert result["headers"]["Content-Type"] == "application/json"

        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_codes"


# ============================================================================
# Security Tests
# ============================================================================


class TestPendingRecoveryCodesSecurity:
    """Tests for security-related behavior."""

    @mock_aws
    def test_codes_only_retrievable_by_owner(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Codes should only be retrievable by the user who owns them."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        # Create a session for a different user
        different_user_token = create_valid_session_token(
            "user_different",
            "different@example.com",
        )

        api_gateway_event["headers"]["Cookie"] = f"session={different_user_token}"

        result = handler(api_gateway_event, {})

        # Should return 404 because different user has no pending codes
        assert result["statusCode"] == 404

        # Original user's codes should still exist
        response = user_with_pending_codes["table"].get_item(
            Key={"pk": user_with_pending_codes["user_id"], "sk": "PENDING_RECOVERY_CODES"}
        )
        assert "Item" in response
        assert response["Item"]["codes"] == user_with_pending_codes["recovery_codes"]

    @mock_aws
    def test_atomic_delete_prevents_race_conditions(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """The conditional delete should prevent race condition exploits."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # First retrieval succeeds
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200
        codes1 = json.loads(result1["body"])["codes"]

        # Simulate another request trying to get the same codes
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 404

        # Codes should have been returned only once
        assert codes1 == user_with_pending_codes["recovery_codes"]

    @mock_aws
    def test_cors_headers_for_allowed_origin(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should include CORS headers for allowed origins."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["headers"]["Origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["headers"].get("Access-Control-Allow-Origin") == "https://pkgwatch.dev"
        assert "Access-Control-Allow-Credentials" in result["headers"]

    @mock_aws
    def test_cors_headers_for_disallowed_origin(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Should not include CORS headers for disallowed origins."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["headers"]["Origin"] = "https://evil.example.com"

        result = handler(api_gateway_event, {})

        assert result["headers"].get("Access-Control-Allow-Origin") is None


# ============================================================================
# Concurrency Simulation Tests
# ============================================================================


class TestPendingRecoveryCodesConcurrency:
    """Tests simulating concurrent access scenarios."""

    @mock_aws
    def test_concurrent_retrieval_only_one_succeeds(
        self, mock_dynamodb, mock_secretsmanager, user_with_pending_codes, setup_env, api_gateway_event
    ):
        """Simulates race condition where only one request should succeed."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        session_token = create_valid_session_token(
            user_with_pending_codes["user_id"],
            user_with_pending_codes["email"],
        )

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Simulate first request consuming the codes
        result1 = handler(api_gateway_event, {})

        # Simulate second concurrent request (record already deleted)
        result2 = handler(api_gateway_event, {})

        # First request should succeed
        assert result1["statusCode"] == 200

        # Second request should fail with 404
        assert result2["statusCode"] == 404

    @mock_aws
    def test_conditional_delete_with_attribute_exists(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Test that conditional delete requires 'codes' attribute to exist."""
        import api.auth_callback
        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_pending_recovery_codes import handler

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        user_id = f"user_{secrets.token_hex(8)}"

        # Create PENDING_RECOVERY_CODES without 'codes' attribute
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING_RECOVERY_CODES",
                # No 'codes' attribute
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        session_token = create_valid_session_token(user_id, "noattr@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # Should return 404 because condition "attribute_exists(codes)" fails
        assert result["statusCode"] == 404
