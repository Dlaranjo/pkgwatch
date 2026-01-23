"""
Tests for auth-related Lambda handlers.
"""

import json
import os

import pytest
from moto import mock_aws


class TestSignupHandler:
    """Tests for the signup endpoint."""

    @mock_aws
    def test_creates_pending_user(self, mock_dynamodb, api_gateway_event):
        """Should create a pending user record."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        # Mock SES to avoid actual email sending
        import boto3
        ses = boto3.client("ses", region_name="us-east-1")
        ses.verify_email_identity(EmailAddress="noreply@pkgwatch.dev")

        from api.signup import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "newuser@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "email" in body["message"].lower()

        # Verify user was created
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        from boto3.dynamodb.conditions import Key
        response = table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser@example.com"),
        )
        assert len(response["Items"]) == 1
        assert response["Items"][0]["sk"] == "PENDING"

    @mock_aws
    def test_returns_400_for_invalid_email(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid email format."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.signup import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "invalid-email"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_returns_200_for_existing_verified_user_to_prevent_enumeration(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """Should return 200 even for existing verified user (prevents email enumeration).

        Security: Returning different responses for existing vs non-existing emails
        would allow attackers to enumerate valid email addresses. The signup endpoint
        now returns the same 200 response regardless of email existence.
        """
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.signup import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})

        result = handler(api_gateway_event, {})

        # Should return 200 (same as new signup) to prevent email enumeration
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Generic message that doesn't reveal email existence
        assert "verification" in body["message"].lower() or "email" in body["message"].lower()


class TestAuthMeHandler:
    """Tests for the auth/me endpoint."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.auth_me import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_aggregates_requests_across_all_keys(self, mock_dynamodb, api_gateway_event):
        """Should aggregate requests_this_month across ALL API keys."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        # Set up secrets manager mock
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create multiple API keys with different request counts
        key_hash1 = hashlib.sha256(b"pw_key1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_key2").hexdigest()

        table.put_item(
            Item={
                "pk": "user_aggregate_test",
                "sk": key_hash1,
                "key_hash": key_hash1,
                "email": "aggregate@example.com",
                "tier": "free",
                "requests_this_month": 50,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_aggregate_test",
                "sk": key_hash2,
                "key_hash": key_hash2,
                "email": "aggregate@example.com",
                "tier": "free",
                "requests_this_month": 126,
                "created_at": "2024-01-02T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        # Create valid session token
        data = {
            "user_id": "user_aggregate_test",
            "email": "aggregate@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should be 50 + 126 = 176 (aggregated across both keys)
        assert body["requests_this_month"] == 176

    @mock_aws
    def test_excludes_user_meta_from_key_list(self, mock_dynamodb, api_gateway_event):
        """Should not count USER_META as an API key."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create API key
        key_hash = hashlib.sha256(b"pw_single_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "meta@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # Create USER_META record (should be ignored)
        table.put_item(
            Item={
                "pk": "user_meta_test",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_meta_test",
            "email": "meta@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should only count the actual API key's requests, not USER_META
        assert body["requests_this_month"] == 100

    @mock_aws
    def test_returns_404_when_no_api_keys(self, mock_dynamodb, api_gateway_event):
        """Should return 404 when user has no API keys (only PENDING or USER_META)."""
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create only PENDING record (no actual API keys)
        table.put_item(
            Item={
                "pk": "user_no_keys",
                "sk": "PENDING",
                "email": "nokeys@example.com",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_no_keys",
            "email": "nokeys@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "user_not_found"

    @mock_aws
    def test_excludes_pending_from_aggregation(self, mock_dynamodb, api_gateway_event):
        """Should exclude PENDING records from request aggregation."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create API key
        key_hash = hashlib.sha256(b"pw_real_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pending_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "pending@example.com",
                "tier": "free",
                "requests_this_month": 50,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # Create PENDING record (should be excluded)
        table.put_item(
            Item={
                "pk": "user_pending_test",
                "sk": "PENDING",
                "email": "pending@example.com",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_pending_test",
            "email": "pending@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should only count the actual API key, not PENDING
        assert body["requests_this_month"] == 50

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session token is expired."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_expired_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_expired_session",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "expired@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        # Create an EXPIRED session token (exp in the past)
        data = {
            "user_id": "user_expired_session",
            "email": "expired@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_401_for_malformed_session_token(self, mock_dynamodb, api_gateway_event):
        """Should return 401 for malformed session token."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.auth_me import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        # Test with malformed token (no dot separator)
        api_gateway_event["headers"]["Cookie"] = "session=malformed-token-no-dot"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_401_for_invalid_signature(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session token signature is invalid."""
        import boto3
        import base64

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.auth_me import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        # Create token with valid format but wrong signature
        payload = base64.urlsafe_b64encode(b'{"user_id":"user_test","email":"test@example.com","exp":9999999999}').decode()
        invalid_token = f"{payload}.invalid_signature_here"

        api_gateway_event["headers"]["Cookie"] = f"session={invalid_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_uses_user_meta_for_requests_count(self, mock_dynamodb, api_gateway_event):
        """Should use USER_META.requests_this_month when available."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create API key with per-key counter
        key_hash = hashlib.sha256(b"pw_meta_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_requests",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "meta@example.com",
                "tier": "free",
                "requests_this_month": 25,  # Per-key counter (should be ignored)
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # Create USER_META with authoritative count
        table.put_item(
            Item={
                "pk": "user_meta_requests",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 150,  # This should be used
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_meta_requests",
            "email": "meta@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should use USER_META count (150), not per-key count (25)
        assert body["requests_this_month"] == 150

    @mock_aws
    def test_returns_user_data_without_sensitive_fields(self, mock_dynamodb, api_gateway_event):
        """Should not expose sensitive fields like key_hash or full API keys."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_sensitive_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_sensitive",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "sensitive@example.com",
                "tier": "pro",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
                "stripe_customer_id": "cus_secret123",
                "stripe_subscription_id": "sub_secret456",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_sensitive",
            "email": "sensitive@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Should include safe fields
        assert "user_id" in body
        assert "email" in body
        assert "tier" in body
        assert "requests_this_month" in body
        assert "monthly_limit" in body

        # Should NOT include sensitive fields
        assert "key_hash" not in body
        assert "stripe_customer_id" not in body
        assert "stripe_subscription_id" not in body
        assert "sk" not in body
        assert "pk" not in body

    @mock_aws
    def test_returns_cancellation_state(self, mock_dynamodb, api_gateway_event):
        """Should return cancellation_pending and cancellation_date when present."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cancel_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cancelling",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cancelling@example.com",
                "tier": "pro",
                "requests_this_month": 50,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
                "cancellation_pending": True,
                "cancellation_date": 1735689600,  # Unix timestamp
                "current_period_end": 1735689600,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_cancelling",
            "email": "cancelling@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["cancellation_pending"] is True
        assert body["cancellation_date"] == 1735689600
        assert body["current_period_end"] == 1735689600

    @mock_aws
    def test_returns_bonus_and_referral_info(self, mock_dynamodb, api_gateway_event):
        """Should return bonus_requests, referral_code, and effective_limit."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_bonus_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_bonus",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "bonus@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # Create USER_META with bonus credits and referral code
        table.put_item(
            Item={
                "pk": "user_bonus",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 100,
                "bonus_requests": 10000,
                "bonus_requests_lifetime": 15000,
                "referral_code": "TESTCODE",
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_bonus",
            "email": "bonus@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["bonus_requests"] == 10000
        assert body["bonus_lifetime"] == 15000
        assert body["referral_code"] == "TESTCODE"
        # effective_limit = monthly_limit (5000 for free) + bonus_requests (10000)
        assert body["effective_limit"] == 15000
        assert body["monthly_limit"] == 5000

    @mock_aws
    def test_can_add_referral_within_deadline(self, mock_dynamodb, api_gateway_event):
        """Should return can_add_referral=True within 14-day window."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_new_user_key").hexdigest()
        # User created 5 days ago (within 14-day window)
        created_at = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()

        table.put_item(
            Item={
                "pk": "user_new_referral",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "newuser@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": created_at,
                "email_verified": True,
            }
        )
        # USER_META without referred_by (can add referral)
        table.put_item(
            Item={
                "pk": "user_new_referral",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 0,
                "created_at": created_at,
                # No referred_by field
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_new_referral",
            "email": "newuser@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is True
        assert body["referral_code_deadline"] is not None

    @mock_aws
    def test_cannot_add_referral_after_deadline(self, mock_dynamodb, api_gateway_event):
        """Should return can_add_referral=False after 14-day window."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_old_user_key").hexdigest()
        # User created 30 days ago (past 14-day window)
        created_at = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        table.put_item(
            Item={
                "pk": "user_old_referral",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "olduser@example.com",
                "tier": "free",
                "requests_this_month": 500,
                "created_at": created_at,
                "email_verified": True,
            }
        )
        # USER_META without referred_by but created too long ago
        table.put_item(
            Item={
                "pk": "user_old_referral",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 500,
                "created_at": created_at,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_old_referral",
            "email": "olduser@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is False
        assert body["referral_code_deadline"] is None

    @mock_aws
    def test_cannot_add_referral_if_already_referred(self, mock_dynamodb, api_gateway_event):
        """Should return can_add_referral=False if already has referred_by."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_referred_key").hexdigest()
        # User created recently but already has referred_by
        created_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()

        table.put_item(
            Item={
                "pk": "user_already_referred",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "referred@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": created_at,
                "email_verified": True,
            }
        )
        # USER_META with referred_by set
        table.put_item(
            Item={
                "pk": "user_already_referred",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 0,
                "created_at": created_at,
                "referred_by": "user_referrer123",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_already_referred",
            "email": "referred@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is False
        assert body["referral_code_deadline"] is None

    @mock_aws
    def test_returns_data_source_cache_by_default(self, mock_dynamodb, api_gateway_event):
        """Should return data_source='cache' when not refreshing."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_cache_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cache_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cache@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_cache_test",
            "email": "cache@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["data_source"] == "cache"

    @mock_aws
    def test_refresh_stripe_without_subscription_stays_cache(self, mock_dynamodb, api_gateway_event):
        """Should return data_source='cache' when refresh=stripe but no subscription."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_sub_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_subscription",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nosub@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
                # No stripe_subscription_id
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_no_subscription",
            "email": "nosub@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["queryStringParameters"] = {"refresh": "stripe"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # No subscription to refresh, so stays 'cache'
        assert body["data_source"] == "cache"

    @mock_aws
    def test_handles_lowercase_cookie_header(self, mock_dynamodb, api_gateway_event):
        """Should handle lowercase 'cookie' header."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_lower_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_lowercase",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "lower@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_lowercase",
            "email": "lower@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        # Use lowercase 'cookie' header
        api_gateway_event["headers"]["cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["user_id"] == "user_lowercase"

    @mock_aws
    def test_handles_null_headers(self, mock_dynamodb, api_gateway_event):
        """Should handle null headers gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.auth_me import handler

        api_gateway_event["headers"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_created_at_falls_back_to_user_meta(self, mock_dynamodb, api_gateway_event):
        """Should use USER_META.created_at if primary_key.created_at is missing."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_created_at").hexdigest()
        table.put_item(
            Item={
                "pk": "user_fallback_created",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "fallback@example.com",
                "tier": "free",
                "requests_this_month": 0,
                # No created_at on API key record
                "email_verified": True,
            }
        )
        # USER_META has created_at
        table.put_item(
            Item={
                "pk": "user_fallback_created",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 0,
                "created_at": "2024-06-15T12:00:00Z",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_fallback_created",
            "email": "fallback@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["created_at"] == "2024-06-15T12:00:00Z"

    @mock_aws
    def test_handles_invalid_created_at_format(self, mock_dynamodb, api_gateway_event):
        """Should handle invalid created_at date format gracefully."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_bad_date_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_bad_date",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "baddate@example.com",
                "tier": "free",
                "requests_this_month": 0,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )
        # USER_META with invalid created_at
        table.put_item(
            Item={
                "pk": "user_bad_date",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 0,
                "created_at": "not-a-valid-date",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        data = {
            "user_id": "user_bad_date",
            "email": "baddate@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # Should succeed despite invalid date (can_add_referral will be False)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["can_add_referral"] is False

    @mock_aws
    def test_refresh_stripe_with_subscription_no_secret(self, mock_dynamodb, api_gateway_event):
        """Should fall back to cache when Stripe secret is not configured."""
        import hashlib
        from datetime import datetime, timedelta, timezone
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"
        os.environ["STRIPE_SECRET_ARN"] = ""  # No Stripe secret

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_no_stripe_secret").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_stripe_secret",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nostripe@example.com",
                "tier": "pro",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
                "stripe_subscription_id": "sub_test123",
            }
        )

        from api.auth_me import handler
        from api.auth_callback import _create_session_token
        import api.auth_callback
        import api.auth_me
        api.auth_callback._session_secret_cache = None
        api.auth_me._stripe_api_key_cache = None  # Clear Stripe cache

        data = {
            "user_id": "user_no_stripe_secret",
            "email": "nostripe@example.com",
            "tier": "pro",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }
        session_token = _create_session_token(data, "test-secret-key-for-signing-sessions")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["queryStringParameters"] = {"refresh": "stripe"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Should stay 'cache' since Stripe secret is not available
        assert body["data_source"] == "cache"


class TestCheckAndIncrementUsage:
    """Tests for the atomic rate limit function."""

    @mock_aws
    def test_allows_request_under_limit(self, seeded_api_keys_table):
        """Should allow request when under limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import check_and_increment_usage

        table, test_key = seeded_api_keys_table

        allowed, count = check_and_increment_usage("user_test123", table.name, 5000)

        assert allowed is True
        assert count == 1

    @mock_aws
    def test_denies_request_at_limit(self, seeded_api_keys_table):
        """Should deny request when at limit."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Update USER_META to be at limit (rate limiting is now user-level)
        table, test_key = seeded_api_keys_table
        import hashlib
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Set USER_META.requests_this_month to limit
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 5000,
            }
        )

        from shared.auth import check_and_increment_usage

        allowed, count = check_and_increment_usage("user_test123", key_hash, 5000)

        assert allowed is False
        assert count == 5000

    @mock_aws
    def test_increments_count_atomically(self, seeded_api_keys_table):
        """Should atomically increment usage count."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import check_and_increment_usage

        table, test_key = seeded_api_keys_table
        import hashlib
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Make 3 requests
        check_and_increment_usage("user_test123", key_hash, 5000)
        check_and_increment_usage("user_test123", key_hash, 5000)
        allowed, count = check_and_increment_usage("user_test123", key_hash, 5000)

        assert allowed is True
        assert count == 3


class TestGenerateApiKey:
    """Tests for API key generation."""

    @mock_aws
    def test_generates_valid_key(self, mock_dynamodb):
        """Should generate a key with pw_ prefix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import generate_api_key

        key = generate_api_key("user_new", tier="free", email="new@example.com")

        assert key.startswith("pw_")
        assert len(key) > 20

    @mock_aws
    def test_stores_key_in_dynamodb(self, mock_dynamodb):
        """Should store hashed key in DynamoDB."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import generate_api_key

        key = generate_api_key("user_new", tier="free", email="new@example.com")

        # Verify it was stored
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        from boto3.dynamodb.conditions import Key
        response = table.query(
            KeyConditionExpression=Key("pk").eq("user_new"),
        )

        assert len(response["Items"]) == 1
        assert response["Items"][0]["email"] == "new@example.com"
        assert response["Items"][0]["tier"] == "free"


class TestValidateApiKey:
    """Tests for API key validation."""

    @mock_aws
    def test_validates_correct_key(self, seeded_api_keys_table):
        """Should validate a correct API key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import validate_api_key

        table, test_key = seeded_api_keys_table

        result = validate_api_key(test_key)

        assert result is not None
        assert result["user_id"] == "user_test123"
        assert result["tier"] == "free"
        assert result["email"] == "test@example.com"

    @mock_aws
    def test_returns_none_for_invalid_key(self, seeded_api_keys_table):
        """Should return None for invalid key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import validate_api_key

        result = validate_api_key("pw_invalid_key_12345")

        assert result is None

    @mock_aws
    def test_returns_none_for_wrong_prefix(self, seeded_api_keys_table):
        """Should return None for keys without pw_ prefix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import validate_api_key

        result = validate_api_key("wrong_prefix_key")

        assert result is None

    @mock_aws
    def test_returns_none_for_empty_key(self, mock_dynamodb):
        """Should return None for empty key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import validate_api_key

        assert validate_api_key(None) is None
        assert validate_api_key("") is None


class TestVerifyEmailHandler:
    """Tests for the /verify endpoint."""

    @mock_aws
    def test_verifies_valid_token(self, mock_dynamodb, api_gateway_event):
        """Should verify email with valid token and create API key."""
        import secrets
        from datetime import datetime, timedelta, timezone

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        # Create pending user
        table.put_item(
            Item={
                "pk": "user_pending123",
                "sk": "PENDING",
                "email": "pending@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "dashboard" in result["headers"]["Location"]
        assert "verified=true" in result["headers"]["Location"]

    @mock_aws
    def test_rejects_invalid_token(self, mock_dynamodb, api_gateway_event):
        """Should redirect with error for invalid token."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": "invalid_token"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "start" in result["headers"]["Location"]
        assert "error=invalid_token" in result["headers"]["Location"]

    @mock_aws
    def test_rejects_expired_token(self, mock_dynamodb, api_gateway_event):
        """Should redirect with error for expired token."""
        import secrets
        from datetime import datetime, timedelta, timezone

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        token = secrets.token_urlsafe(32)
        # Expired 1 hour ago
        expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        table.put_item(
            Item={
                "pk": "user_expired123",
                "sk": "PENDING",
                "email": "expired@example.com",
                "verification_token": token,
                "verification_expires": expires,
            }
        )

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {"token": token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "start" in result["headers"]["Location"]
        assert "error=token_expired" in result["headers"]["Location"]

    @mock_aws
    def test_rejects_missing_token(self, mock_dynamodb, api_gateway_event):
        """Should redirect with error when token is missing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        from api.verify_email import handler

        api_gateway_event["queryStringParameters"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=missing_token" in result["headers"]["Location"]


class TestMagicLinkHandler:
    """Tests for the /auth/magic-link endpoint."""

    @mock_aws
    def test_sends_magic_link_for_verified_user(self, seeded_api_keys_table, api_gateway_event):
        """Should send magic link for verified user."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        # Mock SES
        import boto3
        ses = boto3.client("ses", region_name="us-east-1")
        ses.verify_email_identity(EmailAddress="noreply@pkgwatch.dev")

        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "test@example.com"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "login link has been sent" in body["message"]

    @mock_aws
    def test_returns_same_response_for_unknown_email(self, mock_dynamodb, api_gateway_event):
        """Should return same response for unknown email (security)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "unknown@example.com"})

        result = handler(api_gateway_event, {})

        # Same 200 response to not reveal whether email exists
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "login link has been sent" in body["message"]

    @mock_aws
    def test_rejects_invalid_email_format(self, mock_dynamodb, api_gateway_event):
        """Should return 400 for invalid email format."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.magic_link import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "not-an-email"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"


class TestAuthCallbackHandler:
    """Tests for the /auth/callback endpoint."""

    @mock_aws
    def test_rejects_missing_token(self, mock_dynamodb, api_gateway_event):
        """Should redirect with error when token is missing."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "error=missing_token" in result["headers"]["Location"]

    @mock_aws
    def test_rejects_invalid_token(self, mock_dynamodb, api_gateway_event):
        """Should redirect with error for invalid token."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        # Need to mock secrets manager for this test
        import boto3
        from moto import mock_aws
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret",
            SecretString='{"secret": "test-secret-key-for-signing"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

        from api.auth_callback import handler, _session_secret_cache
        import api.auth_callback
        api.auth_callback._session_secret_cache = None  # Clear cache

        api_gateway_event["queryStringParameters"] = {"token": "invalid_token"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "start" in result["headers"]["Location"]
        assert "error=invalid_token" in result["headers"]["Location"]
