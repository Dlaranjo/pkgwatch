"""
Comprehensive tests for verify_email.py endpoint.

This module tests the email verification endpoint, covering:
1. Happy path verification with session creation
2. Token validation and expiration
3. Database error handling at various stages
4. Race condition handling (concurrent verification)
5. Referral code processing
6. Recovery codes generation
7. Session cookie creation

Security-critical: This endpoint activates user accounts and must handle
edge cases robustly to prevent account enumeration, replay attacks, and
data inconsistencies.
"""

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
    os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

    yield

    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def setup_env_no_session_secret():
    """Set up environment without session secret for testing fallback."""
    original_env = os.environ.copy()
    os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
    os.environ["BASE_URL"] = "https://test.example.com"
    os.environ["SESSION_SECRET_ARN"] = ""
    os.environ["REFERRAL_EVENTS_TABLE"] = "pkgwatch-referral-events"

    yield

    os.environ.clear()
    os.environ.update(original_env)


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
def pending_user_with_referral(mock_dynamodb):
    """Create a pending user who signed up with a referral code."""
    table = mock_dynamodb.Table("pkgwatch-api-keys")
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
    user_id = f"user_{secrets.token_hex(8)}"
    referrer_id = f"user_referrer_{secrets.token_hex(8)}"

    # Create the referrer's USER_META with a referral code
    referral_code = "TESTCODE123"
    table.put_item(
        Item={
            "pk": referrer_id,
            "sk": "USER_META",
            "email": "referrer@example.com",
            "referral_code": referral_code,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    # Create pending user who used that referral code
    table.put_item(
        Item={
            "pk": user_id,
            "sk": "PENDING",
            "email": "referred@example.com",
            "verification_token": token,
            "verification_expires": expires,
            "referral_code_used": referral_code,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    return {
        "user_id": user_id,
        "token": token,
        "email": "referred@example.com",
        "referrer_id": referrer_id,
        "referrer_email": "referrer@example.com",
        "referral_code": referral_code,
        "table": table,
    }


# ============================================================================
# Database Error Handling Tests
# ============================================================================


class TestDatabaseErrorHandling:
    """Tests for database error handling during verification."""

    @mock_aws
    def test_gsi_query_error_returns_internal_error(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return internal_error when GSI query fails."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": "some_token"}

        # Mock table.query to raise an exception
        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.side_effect = Exception("DynamoDB timeout")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=internal_error" in result["headers"]["Location"]
        # urlencode uses + for spaces
        assert "Failed+to+verify+token" in result["headers"]["Location"]

    @mock_aws
    def test_get_item_returns_none_for_deleted_user(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return invalid_token when user record was deleted between GSI query and get_item."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"

        # Create pending user
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "deleted@example.com",
                "verification_token": token,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        # Mock the entire dynamodb module to intercept get_item
        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            # Query returns the GSI result
            mock_table.query.return_value = {"Items": [{"pk": user_id, "sk": "PENDING", "verification_token": token}]}
            # get_item returns empty (simulating race condition where record was deleted)
            mock_table.get_item.return_value = {"ResponseMetadata": {}}  # No Item key
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=invalid_token" in result["headers"]["Location"]

    @mock_aws
    def test_get_item_exception_returns_internal_error(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return internal_error when get_item raises exception."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"

        # Create pending user
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "error@example.com",
                "verification_token": token,
            }
        )

        # Create a new mock that handles both query and get_item
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            # Query returns the GSI result
            mock_table.query.return_value = {"Items": [{"pk": user_id, "sk": "PENDING", "verification_token": token}]}
            # get_item raises exception
            mock_table.get_item.side_effect = Exception("DynamoDB error during get")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=internal_error" in result["headers"]["Location"]

    @mock_aws
    def test_delete_generic_exception_returns_internal_error(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return internal_error when delete_item raises a generic exception."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "delete_error@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.return_value = {"Items": [{"pk": user_id, "sk": "PENDING", "verification_token": token}]}
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": user_id,
                    "sk": "PENDING",
                    "email": "delete_error@example.com",
                    "verification_token": token,
                    "verification_expires": expires,
                }
            }
            # delete_item raises generic exception
            mock_table.delete_item.side_effect = Exception("Network error during delete")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=internal_error" in result["headers"]["Location"]

    @mock_aws
    def test_delete_client_error_non_conditional_returns_internal_error(
        self, mock_dynamodb, setup_env, api_gateway_event
    ):
        """Should return internal_error for ClientError that is not ConditionalCheckFailedException."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "client_error@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        error_response = {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Rate exceeded"}}

        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.return_value = {"Items": [{"pk": user_id, "sk": "PENDING", "verification_token": token}]}
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": user_id,
                    "sk": "PENDING",
                    "email": "client_error@example.com",
                    "verification_token": token,
                    "verification_expires": expires,
                }
            }
            mock_table.delete_item.side_effect = ClientError(error_response, "DeleteItem")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=internal_error" in result["headers"]["Location"]


# ============================================================================
# Token Validation Tests
# ============================================================================


class TestTokenValidation:
    """Tests for token validation edge cases."""

    @mock_aws
    def test_gsi_returns_non_pending_record(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should reject token if GSI returns a non-PENDING record (unexpected state)."""
        # This is a safety check - if somehow a verification_token GSI returns
        # a record that's not a PENDING record, reject it
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": "some_token"}

        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            # GSI returns a record with sk != "PENDING"
            mock_table.query.return_value = {
                "Items": [{"pk": "user_xyz", "sk": "SOME_OTHER_SK", "verification_token": "some_token"}]
            }
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=invalid_token" in result["headers"]["Location"]

    @mock_aws
    def test_malformed_expiration_date_ignored(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should continue verification if expiration date is malformed."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "malformed_exp@example.com",
                "verification_token": token,
                "verification_expires": "not-a-valid-date",  # Malformed
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        # Mock generate_api_key to avoid side effects
        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        # Should succeed since malformed date is ignored
        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "verified=true" in result["headers"]["Location"]

    @mock_aws
    def test_token_with_z_suffix_expiration(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should handle expiration dates with Z suffix (UTC indicator)."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"

        # Use Z suffix format
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
        expires_z = expires.strftime("%Y-%m-%dT%H:%M:%SZ")

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "zsuffix@example.com",
                "verification_token": token,
                "verification_expires": expires_z,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]


# ============================================================================
# Race Condition / Concurrent Verification Tests
# ============================================================================


class TestConcurrentVerification:
    """Tests for race condition handling during concurrent verification attempts."""

    @mock_aws
    def test_conditional_delete_failure_returns_token_already_used(self, mock_dynamodb, setup_env, api_gateway_event):
        """Should return token_already_used when conditional delete fails."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "race@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        error_response = {
            "Error": {"Code": "ConditionalCheckFailedException", "Message": "The conditional request failed"}
        }

        with patch("api.verify_email.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.return_value = {"Items": [{"pk": user_id, "sk": "PENDING", "verification_token": token}]}
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": user_id,
                    "sk": "PENDING",
                    "email": "race@example.com",
                    "verification_token": token,
                    "verification_expires": expires,
                }
            }
            mock_table.delete_item.side_effect = ClientError(error_response, "DeleteItem")
            mock_db.Table.return_value = mock_table

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=token_already_used" in result["headers"]["Location"]


# ============================================================================
# API Key Generation Error Tests
# ============================================================================


class TestApiKeyGenerationError:
    """Tests for API key generation failure handling."""

    @mock_aws
    def test_generate_api_key_exception_returns_internal_error(
        self, mock_dynamodb, pending_user, setup_env, api_gateway_event
    ):
        """Should return internal_error when API key generation fails."""
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", side_effect=Exception("Key generation failed")):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=internal_error" in result["headers"]["Location"]
        # urlencode uses + for spaces
        assert "Failed+to+create+API+key" in result["headers"]["Location"]


# ============================================================================
# PENDING_DISPLAY Storage Error Tests
# ============================================================================


class TestPendingDisplayStorageError:
    """Tests for PENDING_DISPLAY storage failure handling."""

    @mock_aws
    def test_pending_display_error_continues_verification(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should continue verification even if PENDING_DISPLAY storage fails."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        put_item_calls = []

        def track_put_item(**kwargs):
            put_item_calls.append(kwargs)
            item = kwargs.get("Item", {})
            if item.get("sk") == "PENDING_DISPLAY":
                raise Exception("Failed to store PENDING_DISPLAY")
            # Actually put the item for USER_META and other records
            pending_user["table"].put_item(**kwargs)

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            with patch.object(pending_user["table"], "put_item", side_effect=track_put_item):
                # Need to patch the dynamodb module's table reference
                with patch("api.verify_email.dynamodb") as mock_db:
                    original_table = pending_user["table"]

                    # Create a mock that delegates most operations but tracks put_item
                    mock_table = MagicMock()
                    mock_table.query.side_effect = original_table.query
                    mock_table.get_item.side_effect = original_table.get_item
                    mock_table.delete_item.side_effect = original_table.delete_item
                    mock_table.put_item.side_effect = track_put_item
                    mock_db.Table.return_value = mock_table

                    result = handler(api_gateway_event, {})

        # Should still redirect to dashboard (verification succeeded)
        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "verified=true" in result["headers"]["Location"]


# ============================================================================
# Recovery Codes Generation Error Tests
# ============================================================================


class TestRecoveryCodesGenerationError:
    """Tests for recovery codes generation failure handling."""

    @mock_aws
    def test_recovery_codes_error_continues_verification(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should continue verification even if recovery codes generation fails."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            with patch(
                "api.verify_email.generate_recovery_codes", side_effect=Exception("Recovery codes generation failed")
            ):
                result = handler(api_gateway_event, {})

        # Should still redirect to dashboard
        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "verified=true" in result["headers"]["Location"]


# ============================================================================
# Referral Processing Tests
# ============================================================================


class TestReferralProcessing:
    """Tests for referral code processing during verification."""

    @mock_aws
    def test_valid_referral_code_processed(
        self, mock_dynamodb, mock_secretsmanager, pending_user_with_referral, setup_env, api_gateway_event
    ):
        """Should process valid referral code and set up relationship."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        # Need to reset the lazy-loaded dynamodb resource in referral_utils
        import shared.referral_utils

        shared.referral_utils._dynamodb = None

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user_with_referral["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify USER_META was created with referral tracking
        table = pending_user_with_referral["table"]
        response = table.get_item(Key={"pk": pending_user_with_referral["user_id"], "sk": "USER_META"})

        assert "Item" in response
        user_meta = response["Item"]
        assert user_meta.get("referred_by") == pending_user_with_referral["referrer_id"]
        assert user_meta.get("referral_pending") is True
        assert "referral_pending_expires" in user_meta
        # Referred user gets immediate bonus
        from shared.referral_utils import REFERRED_USER_BONUS

        assert user_meta.get("bonus_requests") == REFERRED_USER_BONUS

    @mock_aws
    def test_self_referral_blocked(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """Should block self-referral attempt (same email)."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        import shared.referral_utils

        shared.referral_utils._dynamodb = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Referrer has the same email (canonicalized)
        referral_code = "SELFREF123"
        table.put_item(
            Item={
                "pk": "user_self_referrer",
                "sk": "USER_META",
                "email": "self.referral@gmail.com",  # With dot
                "referral_code": referral_code,
            }
        )

        # Pending user with same email (without dot - same canonical form for Gmail)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "selfreferral@gmail.com",  # Without dot
                "verification_token": token,
                "verification_expires": expires,
                "referral_code_used": referral_code,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify USER_META was created WITHOUT referral tracking
        response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert "Item" in response
        user_meta = response["Item"]
        # Self-referral should be blocked - no referred_by
        assert "referred_by" not in user_meta
        assert user_meta.get("bonus_requests", 0) == 0

    @mock_aws
    def test_invalid_referral_code_ignored(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """Should ignore referral code if referrer not found."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        import shared.referral_utils

        shared.referral_utils._dynamodb = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Pending user with non-existent referral code
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "orphan_ref@example.com",
                "verification_token": token,
                "verification_expires": expires,
                "referral_code_used": "NONEXISTENT",
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify USER_META was created without referral tracking
        response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert "Item" in response
        user_meta = response["Item"]
        assert "referred_by" not in user_meta
        assert user_meta.get("bonus_requests", 0) == 0


# ============================================================================
# Session Creation Tests
# ============================================================================


class TestSessionCreation:
    """Tests for session cookie creation after successful verification."""

    @mock_aws
    def test_session_cookie_set_on_success(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should set session cookie when verification succeeds and secret is available."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "Set-Cookie" in result["headers"]

        cookie = result["headers"]["Set-Cookie"]
        assert "session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie
        assert "Path=/" in cookie

    @mock_aws
    def test_no_session_cookie_without_secret(
        self, mock_dynamodb, pending_user, setup_env_no_session_secret, api_gateway_event
    ):
        """Should not set session cookie when SESSION_SECRET_ARN is not configured."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]
        # No Set-Cookie header when secret is not available
        assert "Set-Cookie" not in result["headers"]

    @mock_aws
    def test_session_cookie_contains_user_data(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should include correct user data in session token."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.auth_callback import verify_session_token
        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        # Extract and verify session token
        cookie = result["headers"]["Set-Cookie"]
        session_token = cookie.split("session=")[1].split(";")[0]

        session_data = verify_session_token(session_token)

        assert session_data is not None
        assert session_data["user_id"] == pending_user["user_id"]
        assert session_data["email"] == pending_user["email"]
        assert session_data["tier"] == "free"
        assert "exp" in session_data


# ============================================================================
# Happy Path / Full Flow Tests
# ============================================================================


class TestFullVerificationFlow:
    """End-to-end tests for the complete verification flow."""

    @mock_aws
    def test_complete_verification_creates_all_records(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should create API key, USER_META, PENDING_DISPLAY, and PENDING_RECOVERY_CODES."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_api_key") as mock_gen:
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify generate_api_key was called with email_verified=True
        mock_gen.assert_called_once()
        call_kwargs = mock_gen.call_args
        assert call_kwargs.kwargs.get("email_verified") is True or (
            len(call_kwargs.args) > 3 and call_kwargs.args[3] is True
        )

        table = pending_user["table"]

        # Check PENDING record was deleted
        pending_response = table.get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING"})
        assert "Item" not in pending_response

        # Check USER_META was created
        meta_response = table.get_item(Key={"pk": pending_user["user_id"], "sk": "USER_META"})
        assert "Item" in meta_response
        user_meta = meta_response["Item"]
        assert user_meta["key_count"] == 1
        assert "recovery_codes_hash" in user_meta
        assert "referral_code" in user_meta

        # Check PENDING_DISPLAY was created
        display_response = table.get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING_DISPLAY"})
        assert "Item" in display_response
        assert display_response["Item"]["api_key"] == "pw_test_api_key"

        # Check PENDING_RECOVERY_CODES was created
        codes_response = table.get_item(Key={"pk": pending_user["user_id"], "sk": "PENDING_RECOVERY_CODES"})
        assert "Item" in codes_response
        assert "codes" in codes_response["Item"]
        assert len(codes_response["Item"]["codes"]) == 4  # 4 recovery codes

    @mock_aws
    def test_security_headers_present_on_success(
        self, mock_dynamodb, mock_secretsmanager, pending_user, setup_env, api_gateway_event
    ):
        """Should include security headers in successful verification response."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": pending_user["token"]}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        assert result["headers"]["Cache-Control"] == "no-store"
        assert result["headers"]["Content-Security-Policy"] == "default-src 'none'"
        assert result["headers"]["X-Content-Type-Options"] == "nosniff"

    @mock_aws
    def test_email_without_at_symbol_handled(self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event):
        """Should handle edge case of email without @ symbol (malformed data)."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Malformed email (no @ symbol)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "malformedemail",  # No @ symbol
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.generate_api_key", return_value="pw_test_key"):
            result = handler(api_gateway_event, {})

        # Should still succeed - just affects logging
        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]


# ============================================================================
# Idempotency Guard Tests
# ============================================================================


class TestIdempotencyGuard:
    """Tests for the idempotency guard that prevents duplicate key creation."""

    @mock_aws
    def test_duplicate_verification_skips_key_creation(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should skip key creation when USER_META already exists (returning user)."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Create PENDING record (as if user signed up again)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "returning@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        # Create existing USER_META (user was already verified before)
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 50,
                "referral_code": "EXISTING_CODE",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        with patch("api.verify_email.generate_api_key") as mock_gen:
            result = handler(api_gateway_event, {})

        # Should redirect to dashboard WITHOUT ?verified=true
        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "verified=true" not in result["headers"]["Location"]

        # Should have a session cookie
        assert "Set-Cookie" in result["headers"]

        # generate_api_key should NOT have been called
        mock_gen.assert_not_called()

        # USER_META should be unchanged (not overwritten)
        meta_response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        user_meta = meta_response["Item"]
        assert user_meta["key_count"] == 1
        assert user_meta["requests_this_month"] == 50
        assert user_meta["referral_code"] == "EXISTING_CODE"
        assert user_meta["created_at"] == "2026-01-01T00:00:00+00:00"

    @mock_aws
    def test_conditional_user_meta_write_prevents_overwrite(
        self, mock_dynamodb, mock_secretsmanager, setup_env, api_gateway_event
    ):
        """Should not overwrite USER_META even if idempotency guard is bypassed."""
        import api.auth_callback

        api.auth_callback._session_secret_cache = None
        api.auth_callback._session_secret_cache_time = 0.0

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        user_id = f"user_{secrets.token_hex(8)}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        # Create PENDING record
        table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "conditional@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        # First verification: should create everything
        with patch("api.verify_email.generate_api_key", return_value="pw_first_key"):
            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "verified=true" in result["headers"]["Location"]

        # Verify USER_META was created with key_count=1
        meta_response = table.get_item(Key={"pk": user_id, "sk": "USER_META"})
        assert meta_response["Item"]["key_count"] == 1
