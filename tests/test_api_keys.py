"""
Tests for API key management endpoints (get, create, revoke).
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws


def _create_test_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create a test session token for testing authenticated endpoints."""
    from api.auth_callback import _create_session_token

    data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
    }
    # Use the test secret that will be set up in Secrets Manager mock
    return _create_session_token(data, "test-secret-key-for-signing-sessions")


class TestGetApiKeysHandler:
    """Tests for GET /api-keys endpoint."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.get_api_keys import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_keys_for_authenticated_user(self, mock_dynamodb, api_gateway_event):
        """Should return API keys for authenticated session."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        # Set up secrets manager mock
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create API key for user
        key_hash = hashlib.sha256(b"pw_testkey123").hexdigest()
        table.put_item(
            Item={
                "pk": "user_session123",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "session@example.com",
                "tier": "pro",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.get_api_keys import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        # Create valid session token
        session_token = _create_test_session_token("user_session123", "session@example.com", "pro")

        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "api_keys" in body
        assert len(body["api_keys"]) == 1
        assert body["api_keys"][0]["tier"] == "pro"
        # Should not expose actual key hash in response
        assert "key_hash" not in body["api_keys"][0]


class TestCreateApiKeyHandler:
    """Tests for POST /api-keys endpoint."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.create_api_key import handler

        api_gateway_event["httpMethod"] = "POST"
        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_creates_key_for_authenticated_user(self, mock_dynamodb, api_gateway_event):
        """Should create new API key for authenticated session."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing API key for user
        key_hash = hashlib.sha256(b"pw_existing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_create123",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "create@example.com",
                "tier": "pro",
                "email_verified": True,
            }
        )

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_create123", "create@example.com", "pro")

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert "api_key" in body
        assert body["api_key"].startswith("pw_")

    @mock_aws
    def test_creates_user_meta_on_first_key_creation(self, mock_dynamodb, api_gateway_event):
        """Should create USER_META record when creating first key for user without one."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing API key without USER_META
        key_hash = hashlib.sha256(b"pw_existing_no_meta").hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_meta",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "nometa@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_no_meta", "nometa@example.com")

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify USER_META was created with correct key_count
        meta_response = table.get_item(Key={"pk": "user_no_meta", "sk": "USER_META"})
        assert "Item" in meta_response
        assert meta_response["Item"]["key_count"] == 2  # 1 existing + 1 new

    @mock_aws
    def test_increments_user_meta_key_count(self, mock_dynamodb, api_gateway_event):
        """Should increment USER_META.key_count when creating additional keys."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing API key with USER_META
        key_hash = hashlib.sha256(b"pw_with_meta").hexdigest()
        table.put_item(
            Item={
                "pk": "user_with_meta",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "withmeta@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )
        table.put_item(
            Item={
                "pk": "user_with_meta",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_with_meta", "withmeta@example.com")

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify USER_META.key_count was incremented
        meta_response = table.get_item(Key={"pk": "user_with_meta", "sk": "USER_META"})
        assert meta_response["Item"]["key_count"] == 2

    @mock_aws
    def test_enforces_max_keys_limit(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when user has too many keys."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create 5 API keys (max allowed)
        for i in range(5):
            key_hash = hashlib.sha256(f"pw_key{i}".encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": "user_maxkeys",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "maxkeys@example.com",
                    "tier": "free",
                    "email_verified": True,
                }
            )

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_maxkeys", "maxkeys@example.com")

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "max_keys_reached"


class TestRevokeApiKeyHandler:
    """Tests for DELETE /api-keys/{key_id} endpoint."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.revoke_api_key import handler

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": "somekeyid"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_revokes_existing_key(self, mock_dynamodb, api_gateway_event):
        """Should revoke existing API key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create two API keys (need 2 so we can revoke 1)
        key_hash1 = hashlib.sha256(b"pw_torevoke").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_tokeep").hexdigest()

        for key_hash in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_revoke123",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "revoke@example.com",
                    "tier": "free",
                    "email_verified": True,
                }
            )

        from api.revoke_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_revoke123", "revoke@example.com")

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # 204 No Content is the correct status for successful DELETE
        assert result["statusCode"] == 204

        # Verify key was deleted
        response = table.get_item(Key={"pk": "user_revoke123", "sk": key_hash1})
        assert "Item" not in response

    @mock_aws
    def test_prevents_revoking_last_key(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when trying to revoke last key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create only one API key
        key_hash = hashlib.sha256(b"pw_onlykey").hexdigest()
        table.put_item(
            Item={
                "pk": "user_onlykey",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "onlykey@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.revoke_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_onlykey", "onlykey@example.com")

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "cannot_revoke_last_key"

    @mock_aws
    def test_returns_404_for_nonexistent_key(self, mock_dynamodb, api_gateway_event):
        """Should return 404 for non-existent key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create one key (so user exists)
        key_hash = hashlib.sha256(b"pw_existing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_notfound",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "notfound@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.revoke_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_notfound", "notfound@example.com")

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": "nonexistent_key_hash"}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
