"""
Tests for API key management endpoints (get, create, revoke).
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.get_api_keys import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.create_api_key import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.create_api_key import handler

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
    def test_key_creation_aggregates_existing_usage(self, mock_dynamodb, api_gateway_event):
        """Creating a key for user without USER_META should aggregate existing per-key usage."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing API key with usage but NO USER_META
        key_hash = hashlib.sha256(b"pw_has_usage").hexdigest()
        table.put_item(
            Item={
                "pk": "user_has_usage",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "hasusage@example.com",
                "tier": "free",
                "email_verified": True,
                "requests_this_month": 500,  # Existing usage
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_has_usage", "hasusage@example.com")

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify USER_META was created with AGGREGATED usage (not 0!)
        meta_response = table.get_item(Key={"pk": "user_has_usage", "sk": "USER_META"})
        assert "Item" in meta_response
        assert meta_response["Item"]["key_count"] == 2
        # Critical: usage should be preserved, not reset to 0
        assert meta_response["Item"]["requests_this_month"] == 500

    @mock_aws
    def test_increments_user_meta_key_count(self, mock_dynamodb, api_gateway_event):
        """Should increment USER_META.key_count when creating additional keys."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.create_api_key import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.create_api_key import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.revoke_api_key import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.revoke_api_key import handler

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
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        import api.auth_callback
        from api.revoke_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_notfound", "notfound@example.com")

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": "nonexistent_key_hash"}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404

    @mock_aws
    def test_listed_key_suffix_matches_created_key(self, mock_dynamodb, api_gateway_event):
        """The key suffix shown in the list should match the actual API key suffix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        import api.auth_callback
        from api.create_api_key import handler as create_handler
        from api.get_api_keys import handler as get_handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_suffix_test", "suffix@example.com", "pro")

        # Create a new API key
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        create_result = create_handler(api_gateway_event, {})
        assert create_result["statusCode"] == 201
        create_body = json.loads(create_result["body"])
        created_api_key = create_body["api_key"]

        # Get the last 8 chars of the actual API key
        actual_suffix = created_api_key[-8:]

        # List the keys
        api_gateway_event["httpMethod"] = "GET"
        get_result = get_handler(api_gateway_event, {})
        assert get_result["statusCode"] == 200
        get_body = json.loads(get_result["body"])

        # Find the key in the list and verify suffix matches
        assert len(get_body["api_keys"]) == 1
        listed_key_prefix = get_body["api_keys"][0]["key_prefix"]

        # The key_prefix should contain the actual key suffix, not the hash suffix
        assert listed_key_prefix.endswith(actual_suffix), (
            f"Listed key suffix '{listed_key_prefix}' should end with actual key suffix '{actual_suffix}'"
        )


class TestGetApiKeysFiltering:
    """Tests for filtering out non-API key records."""

    @mock_aws
    def test_filters_out_pending_records(self, mock_dynamodb, api_gateway_event):
        """Should not include PENDING records in API key list."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add PENDING record
        table.put_item(
            Item={
                "pk": "user_filter_test",
                "sk": "PENDING",
                "email": "filter@example.com",
            }
        )

        # Add real API key
        key_hash = hashlib.sha256(b"pw_real_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_filter_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "filter@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.get_api_keys import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_filter_test", "filter@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 1  # Only the real key, not PENDING

    @mock_aws
    def test_filters_out_user_meta_records(self, mock_dynamodb, api_gateway_event):
        """Should not include USER_META records in API key list."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add USER_META record
        table.put_item(
            Item={
                "pk": "user_meta_filter",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 100,
            }
        )

        # Add real API key
        key_hash = hashlib.sha256(b"pw_real_key_2").hexdigest()
        table.put_item(
            Item={
                "pk": "user_meta_filter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "meta_filter@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.get_api_keys import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_meta_filter", "meta_filter@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 1

    @mock_aws
    def test_filters_out_recovery_records(self, mock_dynamodb, api_gateway_event):
        """Should not include RECOVERY_* records in API key list."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add recovery session record
        table.put_item(
            Item={
                "pk": "user_recovery_filter",
                "sk": "RECOVERY_abc123",
                "recovery_code_hash": "somehash",
            }
        )

        # Add real API key
        key_hash = hashlib.sha256(b"pw_recovery_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_recovery_filter",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "recovery@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.get_api_keys import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_recovery_filter", "recovery@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 1


class TestCreateApiKeyWithName:
    """Tests for API key creation with custom names."""

    @mock_aws
    def test_creates_key_with_custom_name(self, mock_dynamodb, api_gateway_event):
        """Should create key with provided custom name."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing key to get past the count check
        key_hash = hashlib.sha256(b"pw_existing_named").hexdigest()
        table.put_item(
            Item={
                "pk": "user_named_key",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "named@example.com",
                "tier": "pro",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_named_key", "named@example.com", "pro")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "Production Server"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify the key was created with the custom name
        response = table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq("user_named_key"))
        # Find the new key (not the existing one)
        new_key = None
        for item in response["Items"]:
            if item.get("sk") != key_hash and item.get("sk") != "USER_META":
                new_key = item
                break

        assert new_key is not None
        assert new_key.get("key_name") == "Production Server"

    @mock_aws
    def test_creates_key_with_default_name(self, mock_dynamodb, api_gateway_event):
        """Should create key with default name when none provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create existing key
        key_hash = hashlib.sha256(b"pw_existing_default").hexdigest()
        table.put_item(
            Item={
                "pk": "user_default_name",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "default@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_default_name", "default@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        # No body provided

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201


class TestRevokeApiKeyEdgeCases:
    """Additional tests for API key revocation edge cases."""

    @mock_aws
    def test_returns_400_for_missing_key_id(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when key_id is not provided."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        import api.auth_callback
        from api.revoke_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_missing_id", "missing@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["pathParameters"] = {}  # No key_id

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_key_id"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        import api.auth_callback
        from api.revoke_api_key import handler

        api.auth_callback._session_secret_cache = None

        # Create expired session token
        from api.auth_callback import _create_session_token

        expired_data = {
            "user_id": "user_expired",
            "email": "expired@example.com",
            "tier": "free",
            "exp": 1000,  # Unix timestamp in the past
        }
        expired_token = _create_session_token(expired_data, "test-secret-key-for-signing-sessions")

        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["headers"]["Cookie"] = f"session={expired_token}"
        api_gateway_event["pathParameters"] = {"key_id": "somekeyid"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_decrements_user_meta_key_count(self, mock_dynamodb, api_gateway_event):
        """Should decrement USER_META.key_count when revoking a key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create two API keys
        key_hash1 = hashlib.sha256(b"pw_to_revoke_count").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_to_keep_count").hexdigest()

        for key_hash in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_count_test",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "count@example.com",
                    "tier": "free",
                    "email_verified": True,
                }
            )

        # Create USER_META with key_count=2
        table.put_item(
            Item={
                "pk": "user_count_test",
                "sk": "USER_META",
                "key_count": 2,
            }
        )

        import api.auth_callback
        from api.revoke_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_count_test", "count@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 204

        # Verify key_count was decremented
        meta_response = table.get_item(Key={"pk": "user_count_test", "sk": "USER_META"})
        assert meta_response["Item"]["key_count"] == 1


class TestApiKeysCorsHandling:
    """Tests for CORS handling on API key endpoints."""

    @mock_aws
    def test_get_keys_includes_cors_headers(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should include CORS headers for allowed origins."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_cors_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cors",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cors@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.get_api_keys import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_cors", "cors@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"

    @mock_aws
    def test_create_key_includes_cors_headers(self, mock_dynamodb, api_gateway_event):
        """POST /api-keys should include CORS headers for allowed origins."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_cors_create").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cors_create",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cors_create@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_cors_create", "cors_create@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["headers"]["origin"] = "https://pkgwatch.dev"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        assert result["headers"]["Access-Control-Allow-Origin"] == "https://pkgwatch.dev"


class TestApiKeysResponseFormat:
    """Tests for API response format and content."""

    @mock_aws
    def test_get_keys_includes_no_cache_headers(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should include no-cache headers."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_cache_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_cache",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cache@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.get_api_keys import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_cache", "cache@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert "Cache-Control" in result["headers"]
        assert "no-store" in result["headers"]["Cache-Control"]

    @mock_aws
    def test_create_key_returns_message(self, mock_dynamodb, api_gateway_event):
        """POST /api-keys should include warning message about key visibility."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_message_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_message",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "message@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_message", "message@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert "message" in body
        assert "won't be shown again" in body["message"]

    @mock_aws
    def test_create_key_returns_key_id(self, mock_dynamodb, api_gateway_event):
        """POST /api-keys should return key_id for identification."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret", SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_keyid_test").hexdigest()
        table.put_item(
            Item={
                "pk": "user_keyid",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "keyid@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        import api.auth_callback
        from api.create_api_key import handler

        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_keyid", "keyid@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert "key_id" in body
        assert len(body["key_id"]) == 16  # First 16 chars of hash


def _create_expired_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create an expired session token for testing session expiry paths."""
    from api.auth_callback import _create_session_token

    data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": 1000,  # Unix timestamp in the distant past
    }
    return _create_session_token(data, "test-secret-key-for-signing-sessions")


def _setup_secrets_manager():
    """Set up Secrets Manager mock with the test session secret."""
    os.environ["SESSION_SECRET_ARN"] = "test-secret"
    secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
    secretsmanager.create_secret(
        Name="test-secret",
        SecretString='{"secret": "test-secret-key-for-signing-sessions"}',
    )


def _reset_auth_cache():
    """Reset auth callback session secret cache."""
    import api.auth_callback

    api.auth_callback._session_secret_cache = None


# ---------------------------------------------------------------------------
# Coverage gap: create_api_key.py line 63 -- expired session
# ---------------------------------------------------------------------------
class TestCreateApiKeyExpiredSession:
    """Tests for session expiry on create_api_key."""

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 with session_expired when session token is expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        expired_token = _create_expired_session_token("user_exp", "exp@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={expired_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"


# ---------------------------------------------------------------------------
# Coverage gap: create_api_key.py lines 76-77 -- malformed JSON body
# ---------------------------------------------------------------------------
class TestCreateApiKeyMalformedBody:
    """Tests for malformed request bodies on create_api_key."""

    @mock_aws
    def test_handles_invalid_json_body(self, mock_dynamodb, api_gateway_event):
        """Should gracefully handle unparseable JSON body and create key with default name."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_badjson", "badjson@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = "not valid json {{{{"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert body["api_key"].startswith("pw_")

    @mock_aws
    def test_handles_non_dict_body(self, mock_dynamodb, api_gateway_event):
        """Should handle body that parses as non-dict (e.g. a list) via AttributeError."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_listbody", "listbody@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps(["not", "a", "dict"])

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201


# ---------------------------------------------------------------------------
# Coverage gap: create_api_key.py line 93 -- PENDING record skipped
# ---------------------------------------------------------------------------
class TestCreateApiKeySkipsPendingRecords:
    """Tests that PENDING records don't count toward the key limit."""

    @mock_aws
    def test_pending_records_not_counted_as_active_keys(self, mock_dynamodb, api_gateway_event):
        """PENDING records in the table should be ignored when counting active keys."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Insert a PENDING record
        table.put_item(
            Item={
                "pk": "user_pending_skip",
                "sk": "PENDING",
                "email": "pending@example.com",
            }
        )

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_pending_skip", "pending@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # Should succeed (PENDING record not counted, so 0 active keys)
        assert result["statusCode"] == 201

    @mock_aws
    def test_pending_record_with_max_minus_one_real_keys(self, mock_dynamodb, api_gateway_event):
        """With 4 real keys + 1 PENDING, should still allow creating a 5th key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create 4 real keys (max is 5)
        for i in range(4):
            kh = hashlib.sha256(f"pw_key_skip_{i}".encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": "user_pend_limit",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )

        # Add a PENDING record
        table.put_item(
            Item={
                "pk": "user_pend_limit",
                "sk": "PENDING",
                "email": "pendlimit@example.com",
            }
        )

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_pend_limit", "pendlimit@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # 4 real keys + PENDING => count=4 < 5 => allowed
        assert result["statusCode"] == 201


# ---------------------------------------------------------------------------
# Coverage gap: create_api_key.py lines 108-110 -- DynamoDB query exception
# ---------------------------------------------------------------------------
class TestCreateApiKeyQueryException:
    """Tests for DynamoDB query failure during key count check."""

    @mock_aws
    def test_returns_500_on_dynamodb_query_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when DynamoDB query raises an unexpected exception."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_queryerr", "queryerr@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Patch the table.query to raise an exception
        with patch("api.create_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = Exception("DynamoDB unavailable")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: create_api_key.py lines 192-199 -- transaction errors
# ---------------------------------------------------------------------------
class TestCreateApiKeyTransactionErrors:
    """Tests for transact_write_items failures during key creation."""

    @mock_aws
    def test_returns_409_on_transaction_cancelled(self, mock_dynamodb, api_gateway_event):
        """Should return 409 when transaction is cancelled (e.g. hash collision)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_txn_cancel", "txncancel@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Patch the low-level client to raise TransactionCanceledException
        with patch("api.create_api_key.dynamodb_client") as mock_client:
            mock_client.transact_write_items.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "TransactionCanceledException",
                        "Message": "Transaction cancelled",
                    }
                },
                "TransactWriteItems",
            )

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 409
        body = json.loads(result["body"])
        assert body["error"]["code"] == "key_creation_failed"

    @mock_aws
    def test_returns_500_on_generic_client_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 on non-TransactionCanceledException ClientError."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_txn_500", "txn500@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.create_api_key.dynamodb_client") as mock_client:
            mock_client.transact_write_items.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "InternalServerError",
                        "Message": "Service unavailable",
                    }
                },
                "TransactWriteItems",
            )

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: get_api_keys.py line 54 -- expired session
# ---------------------------------------------------------------------------
class TestGetApiKeysExpiredSession:
    """Tests for session expiry on get_api_keys."""

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 with session_expired when session is expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_api_keys import handler

        expired_token = _create_expired_session_token("user_get_exp", "getexp@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={expired_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"


# ---------------------------------------------------------------------------
# Coverage gap: get_api_keys.py lines 90-92 -- DynamoDB query exception
# ---------------------------------------------------------------------------
class TestGetApiKeysQueryException:
    """Tests for DynamoDB query failure on get_api_keys."""

    @mock_aws
    def test_returns_500_on_dynamodb_query_error(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when DynamoDB query raises an exception."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_get_err", "geterr@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.get_api_keys.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = Exception("DynamoDB unavailable")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: revoke_api_key.py line 76 -- skip PENDING and USER_META
# ---------------------------------------------------------------------------
class TestRevokeApiKeySkipsSpecialRecords:
    """Tests that revoke correctly skips PENDING and USER_META records."""

    @mock_aws
    def test_skips_pending_and_user_meta_when_searching_keys(self, mock_dynamodb, api_gateway_event):
        """Revoke should skip PENDING and USER_META when finding the target key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create two real keys
        key_hash1 = hashlib.sha256(b"pw_revoke_special_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_revoke_special_2").hexdigest()

        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_special_rev",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )

        # Add PENDING and USER_META
        table.put_item(Item={"pk": "user_special_rev", "sk": "PENDING", "email": "x@example.com"})
        table.put_item(Item={"pk": "user_special_rev", "sk": "USER_META", "key_count": 2})

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_special_rev", "special@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 204

        # Verify the key was deleted
        resp = table.get_item(Key={"pk": "user_special_rev", "sk": key_hash1})
        assert "Item" not in resp

        # Verify the other key still exists
        resp2 = table.get_item(Key={"pk": "user_special_rev", "sk": key_hash2})
        assert "Item" in resp2


# ---------------------------------------------------------------------------
# Coverage gap: revoke_api_key.py lines 111-117 -- USER_META init race/error
# ---------------------------------------------------------------------------
class TestRevokeApiKeyUserMetaInit:
    """Tests for USER_META initialization during revoke."""

    @mock_aws
    def test_initializes_user_meta_if_missing_during_revoke(self, mock_dynamodb, api_gateway_event):
        """Should create USER_META when it doesn't exist (legacy user)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Two keys, NO USER_META
        key_hash1 = hashlib.sha256(b"pw_meta_init_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_meta_init_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_meta_init",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                    "requests_this_month": 100,
                }
            )

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_meta_init", "metainit@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 204

        # Verify USER_META was created with aggregated usage
        meta = table.get_item(Key={"pk": "user_meta_init", "sk": "USER_META"})
        assert "Item" in meta
        # Initial count was 2 keys, transaction decremented to 1
        assert meta["Item"]["key_count"] == 1
        # Usage aggregated from 2 keys x 100 = 200
        assert meta["Item"]["requests_this_month"] == 200

    @mock_aws
    def test_handles_user_meta_init_exception(self, mock_dynamodb, api_gateway_event):
        """Should return 500 if USER_META initialization fails with unexpected error."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash1 = hashlib.sha256(b"pw_meta_fail_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_meta_fail_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_meta_fail",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_meta_fail", "metafail@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Patch table.get_item for USER_META to raise
        original_handler = handler

        with patch("api.revoke_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table

            # query returns two keys
            mock_table.query.return_value = {
                "Items": [
                    {"pk": "user_meta_fail", "sk": key_hash1, "key_hash": key_hash1},
                    {"pk": "user_meta_fail", "sk": key_hash2, "key_hash": key_hash2},
                ]
            }
            # get_item for USER_META raises an error
            mock_table.get_item.side_effect = Exception("DynamoDB timeout")

            result = original_handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_concurrent_user_meta_creation_race(self, mock_dynamodb, api_gateway_event):
        """Should handle ConditionalCheckFailedException when another request already created USER_META."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Two keys, NO USER_META
        key_hash1 = hashlib.sha256(b"pw_race_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_race_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_race",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                    "requests_this_month": 50,
                }
            )

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_race", "race@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Mock to simulate:
        # 1. query returns two keys (no USER_META)
        # 2. get_item for USER_META returns no item
        # 3. put_item raises ConditionalCheckFailedException (race condition)
        # 4. transact_write_items succeeds (since USER_META now exists from race winner)
        with (
            patch("api.revoke_api_key.dynamodb") as mock_ddb,
            patch("api.revoke_api_key.dynamodb_client") as mock_client,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table

            mock_table.query.return_value = {
                "Items": [
                    {"pk": "user_race", "sk": key_hash1, "key_hash": key_hash1, "requests_this_month": 50},
                    {"pk": "user_race", "sk": key_hash2, "key_hash": key_hash2, "requests_this_month": 50},
                ]
            }
            mock_table.get_item.return_value = {}
            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Already exists"}},
                "PutItem",
            )
            mock_client.transact_write_items.return_value = {}

            result = handler(api_gateway_event, {})

        # Should succeed despite the race condition on USER_META creation
        assert result["statusCode"] == 204

    @mock_aws
    def test_handles_non_conditional_client_error_in_meta_init(self, mock_dynamodb, api_gateway_event):
        """A non-ConditionalCheckFailedException ClientError during put_item should bubble up to 500."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash1 = hashlib.sha256(b"pw_non_cond_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_non_cond_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_non_cond",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_non_cond", "noncond@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.revoke_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table

            mock_table.query.return_value = {
                "Items": [
                    {"pk": "user_non_cond", "sk": key_hash1, "key_hash": key_hash1},
                    {"pk": "user_non_cond", "sk": key_hash2, "key_hash": key_hash2},
                ]
            }
            mock_table.get_item.return_value = {}
            # put_item raises a different ClientError (not ConditionalCheckFailedException)
            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "Throttled"}},
                "PutItem",
            )

            result = handler(api_gateway_event, {})

        # Should return 500 since the non-conditional error re-raises and gets caught by outer handler
        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: revoke_api_key.py lines 168-175 -- transaction errors
# ---------------------------------------------------------------------------
class TestRevokeApiKeyTransactionErrors:
    """Tests for transaction failures during revoke."""

    @mock_aws
    def test_returns_500_on_non_conditional_transaction_cancel(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when TransactionCanceledException has no ConditionalCheckFailed."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash1 = hashlib.sha256(b"pw_txn_rev_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_txn_rev_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_txn_rev",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )
        table.put_item(Item={"pk": "user_txn_rev", "sk": "USER_META", "key_count": 2})

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_txn_rev", "txnrev@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.revoke_api_key.dynamodb_client") as mock_client:
            error_response_obj = {
                "Error": {
                    "Code": "TransactionCanceledException",
                    "Message": "Transaction cancelled",
                },
                "CancellationReasons": [
                    {"Code": "None"},  # No ConditionalCheckFailed
                    {"Code": "None"},
                ],
            }
            mock_client.transact_write_items.side_effect = ClientError(error_response_obj, "TransactWriteItems")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_returns_500_on_generic_client_error_during_revoke(self, mock_dynamodb, api_gateway_event):
        """Should return 500 on non-TransactionCanceledException ClientError during revoke."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash1 = hashlib.sha256(b"pw_generic_rev_1").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_generic_rev_2").hexdigest()
        for kh in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_generic_rev",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )
        table.put_item(Item={"pk": "user_generic_rev", "sk": "USER_META", "key_count": 2})

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_generic_rev", "genericrev@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.revoke_api_key.dynamodb_client") as mock_client:
            mock_client.transact_write_items.side_effect = ClientError(
                {
                    "Error": {
                        "Code": "InternalServerError",
                        "Message": "Service unavailable",
                    }
                },
                "TransactWriteItems",
            )

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500

    @mock_aws
    def test_returns_500_on_outer_exception(self, mock_dynamodb, api_gateway_event):
        """Should return 500 on unexpected exception in the outer try block."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_outer_exc", "outerexc@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": "some_key_id"}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.revoke_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = RuntimeError("Unexpected failure")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: get_pending_key.py lines 82-83 -- delete_item failure
# ---------------------------------------------------------------------------
class TestGetPendingKeyDeleteFailure:
    """Tests for get_pending_key delete failure path."""

    @mock_aws
    def test_returns_key_even_if_delete_fails(self, mock_dynamodb, api_gateway_event):
        """Should still return the API key even if deleting the PENDING_DISPLAY record fails."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add PENDING_DISPLAY record
        table.put_item(
            Item={
                "pk": "user_delete_fail",
                "sk": "PENDING_DISPLAY",
                "api_key": "pw_secret_key_123",
            }
        )

        from api.get_pending_key import handler

        session_token = _create_test_session_token("user_delete_fail", "delfail@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Patch delete_item to fail but allow get_item to work normally

        with patch("api.get_pending_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table

            mock_table.get_item.return_value = {
                "Item": {
                    "pk": "user_delete_fail",
                    "sk": "PENDING_DISPLAY",
                    "api_key": "pw_secret_key_123",
                }
            }
            mock_table.delete_item.side_effect = Exception("Delete failed")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["api_key"] == "pw_secret_key_123"
        assert "only be shown once" in body["message"]


# ---------------------------------------------------------------------------
# Coverage gap: get_pending_key.py lines 104-106 -- general exception
# ---------------------------------------------------------------------------
class TestGetPendingKeyGeneralException:
    """Tests for general exception in get_pending_key."""

    @mock_aws
    def test_returns_500_on_unexpected_exception(self, mock_dynamodb, api_gateway_event):
        """Should return 500 when an unexpected error occurs."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_pending_key import handler

        session_token = _create_test_session_token("user_pend_exc", "pendexc@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        with patch("api.get_pending_key.dynamodb") as mock_ddb:
            mock_ddb.Table.side_effect = RuntimeError("Catastrophic failure")

            result = handler(api_gateway_event, {})

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"]["code"] == "internal_error"


# ---------------------------------------------------------------------------
# Coverage gap: get_pending_key.py -- expired session and 401
# ---------------------------------------------------------------------------
class TestGetPendingKeyAuth:
    """Tests for authentication on get_pending_key."""

    @mock_aws
    def test_returns_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when no session cookie is present."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.get_pending_key import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_returns_401_for_expired_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 when session is expired."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_pending_key import handler

        expired_token = _create_expired_session_token("user_pend_exp", "pendexp@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={expired_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_returns_404_when_no_pending_key(self, mock_dynamodb, api_gateway_event):
        """Should return 404 when there is no PENDING_DISPLAY record."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_pending_key import handler

        session_token = _create_test_session_token("user_no_pending", "nopending@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_pending_key"

    @mock_aws
    def test_returns_pending_key_and_deletes_record(self, mock_dynamodb, api_gateway_event):
        """Should return the pending key and delete it (one-time use)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_pending_ok",
                "sk": "PENDING_DISPLAY",
                "api_key": "pw_one_time_secret",
            }
        )

        from api.get_pending_key import handler

        session_token = _create_test_session_token("user_pending_ok", "pendingok@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["api_key"] == "pw_one_time_secret"

        # Verify the PENDING_DISPLAY record was deleted
        resp = table.get_item(Key={"pk": "user_pending_ok", "sk": "PENDING_DISPLAY"})
        assert "Item" not in resp

    @mock_aws
    def test_second_retrieval_returns_404(self, mock_dynamodb, api_gateway_event):
        """After retrieving a pending key, a second call should return 404."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        table.put_item(
            Item={
                "pk": "user_one_time",
                "sk": "PENDING_DISPLAY",
                "api_key": "pw_once_only",
            }
        )

        from api.get_pending_key import handler

        session_token = _create_test_session_token("user_one_time", "onetime@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # First retrieval
        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 200

        # Second retrieval
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 404


# ===========================================================================
# SECURITY-FOCUSED TESTS
# ===========================================================================


class TestCrossUserIsolation:
    """Security: user A cannot manage user B's keys."""

    @mock_aws
    def test_user_cannot_revoke_another_users_key(self, mock_dynamodb, api_gateway_event):
        """User A should not be able to revoke a key belonging to user B."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create key for user_b
        key_hash_b = hashlib.sha256(b"pw_user_b_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_b",
                "sk": key_hash_b,
                "key_hash": key_hash_b,
                "tier": "free",
                "email_verified": True,
            }
        )
        table.put_item(Item={"pk": "user_b", "sk": "USER_META", "key_count": 1})

        from api.revoke_api_key import handler

        # Authenticate as user_a
        session_token = _create_test_session_token("user_a", "a@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash_b[:16]}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # user_a has no keys, so key_hash_b should not be found
        assert result["statusCode"] == 404

        # Verify user_b's key is still intact
        resp = table.get_item(Key={"pk": "user_b", "sk": key_hash_b})
        assert "Item" in resp

    @mock_aws
    def test_user_cannot_list_another_users_keys(self, mock_dynamodb, api_gateway_event):
        """User A should only see their own keys, not user B's."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create key for user_b
        key_hash_b = hashlib.sha256(b"pw_user_b_list").hexdigest()
        table.put_item(
            Item={
                "pk": "user_b_list",
                "sk": key_hash_b,
                "key_hash": key_hash_b,
                "tier": "pro",
                "email_verified": True,
            }
        )

        # Create key for user_a
        key_hash_a = hashlib.sha256(b"pw_user_a_list").hexdigest()
        table.put_item(
            Item={
                "pk": "user_a_list",
                "sk": key_hash_a,
                "key_hash": key_hash_a,
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_a_list", "alist@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # User A should only see 1 key (their own)
        assert len(body["api_keys"]) == 1
        assert body["api_keys"][0]["tier"] == "free"


class TestKeyMaterialExposure:
    """Security: key material is never exposed after creation."""

    @mock_aws
    def test_key_not_exposed_in_list_response(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should never return the full API key or key_hash."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_secret_material").hexdigest()
        table.put_item(
            Item={
                "pk": "user_material",
                "sk": key_hash,
                "key_hash": key_hash,
                "key_suffix": "abcdefgh",
                "tier": "free",
                "email_verified": True,
                "requests_this_month": 50,
                "created_at": "2024-06-01T00:00:00Z",
            }
        )

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_material", "material@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        response_str = json.dumps(body)

        # The full key hash should NOT appear in the response
        assert key_hash not in response_str
        # Only the first 16 chars of the hash should appear as key_id
        assert body["api_keys"][0]["key_id"] == key_hash[:16]
        # key_prefix should only show the suffix with masking
        assert body["api_keys"][0]["key_prefix"] == "pw_....abcdefgh"
        # Should not have raw fields
        assert "key_hash" not in body["api_keys"][0]
        assert "sk" not in body["api_keys"][0]
        assert "pk" not in body["api_keys"][0]

    @mock_aws
    def test_created_key_shown_only_once(self, mock_dynamodb, api_gateway_event):
        """The full API key is returned only during creation, never in subsequent calls."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler as create_handler
        from api.get_api_keys import handler as list_handler

        session_token = _create_test_session_token("user_once", "once@example.com", "pro")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Create the key
        create_result = create_handler(api_gateway_event, {})
        assert create_result["statusCode"] == 201
        created_key = json.loads(create_result["body"])["api_key"]
        assert created_key.startswith("pw_")

        # List keys
        api_gateway_event["httpMethod"] = "GET"
        list_result = list_handler(api_gateway_event, {})
        assert list_result["statusCode"] == 200
        list_body = json.loads(list_result["body"])

        # The full created key should NOT appear in the list response
        list_str = json.dumps(list_body)
        assert created_key not in list_str


class TestKeyNameInjection:
    """Security: injection attacks in key names are handled safely."""

    @mock_aws
    def test_html_injection_in_key_name_rejected(self, mock_dynamodb, api_gateway_event):
        """HTML/script tags in key names should be rejected by allowlist validation."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_inject_html", "inject@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": '<script>alert("xss")</script>'})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_key_name"

    @mock_aws
    def test_dynamodb_injection_in_key_name_rejected(self, mock_dynamodb, api_gateway_event):
        """DynamoDB expression-like strings in key names should be rejected by allowlist."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_inject_ddb", "injectddb@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "SET key_count = key_count + :inc; DROP TABLE"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_key_name"

    @mock_aws
    def test_very_long_key_name_rejected(self, mock_dynamodb, api_gateway_event):
        """Key names over 100 characters should be rejected."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_longname", "longname@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "A" * 1000})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_key_name"

    @mock_aws
    def test_empty_string_key_name(self, mock_dynamodb, api_gateway_event):
        """Empty string key name should be treated as falsy and get default name."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_emptyname", "emptyname@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": ""})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify the key got a default name (empty string is falsy)
        response = table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq("user_emptyname"))
        key_items = [i for i in response["Items"] if i.get("sk") not in ("PENDING", "USER_META")]
        assert len(key_items) == 1
        # Empty string is falsy in Python, so it gets "Key 1"
        assert key_items[0].get("key_name") == "Key 1"


class TestMaxKeysEnforcement:
    """Security: max keys limit cannot be bypassed."""

    @mock_aws
    def test_cannot_create_beyond_max_even_with_pending_and_meta_records(self, mock_dynamodb, api_gateway_event):
        """Max key check should count only real keys, not PENDING/USER_META."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create exactly 5 real keys
        for i in range(5):
            kh = hashlib.sha256(f"pw_max_enforce_{i}".encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": "user_max_enforce",
                    "sk": kh,
                    "key_hash": kh,
                    "tier": "free",
                    "email_verified": True,
                }
            )

        # Also add PENDING and USER_META (should not affect counting)
        table.put_item(Item={"pk": "user_max_enforce", "sk": "PENDING", "email": "x@example.com"})
        table.put_item(Item={"pk": "user_max_enforce", "sk": "USER_META", "key_count": 5})

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_max_enforce", "maxenforce@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "max_keys_reached"


class TestFullLifecycle:
    """Integration-style test: create -> list -> revoke -> verify."""

    @mock_aws
    def test_full_key_lifecycle(self, mock_dynamodb, api_gateway_event):
        """Full lifecycle: create two keys, list them, revoke one, verify state."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler as create_handler
        from api.get_api_keys import handler as list_handler
        from api.revoke_api_key import handler as revoke_handler

        user_id = "user_lifecycle"
        session_token = _create_test_session_token(user_id, "lifecycle@example.com", "pro")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Step 1: Create first key
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"name": "Production"})
        result1 = create_handler(api_gateway_event, {})
        assert result1["statusCode"] == 201
        key1_body = json.loads(result1["body"])
        key1_full = key1_body["api_key"]
        key1_id = key1_body["key_id"]

        # Step 2: Create second key
        api_gateway_event["body"] = json.dumps({"name": "Staging"})
        result2 = create_handler(api_gateway_event, {})
        assert result2["statusCode"] == 201
        key2_body = json.loads(result2["body"])
        key2_full = key2_body["api_key"]
        key2_id = key2_body["key_id"]

        # Verify keys are different
        assert key1_full != key2_full
        assert key1_id != key2_id

        # Step 3: List keys - should see 2
        api_gateway_event["httpMethod"] = "GET"
        api_gateway_event["body"] = None
        list_result = list_handler(api_gateway_event, {})
        assert list_result["statusCode"] == 200
        listed = json.loads(list_result["body"])["api_keys"]
        assert len(listed) == 2

        # Verify full keys are NOT in list
        list_str = json.dumps(listed)
        assert key1_full not in list_str
        assert key2_full not in list_str

        # Step 4: Revoke key 1
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key1_id}
        revoke_result = revoke_handler(api_gateway_event, {})
        assert revoke_result["statusCode"] == 204

        # Step 5: List keys - should see 1
        api_gateway_event["httpMethod"] = "GET"
        api_gateway_event["pathParameters"] = {}
        list_result2 = list_handler(api_gateway_event, {})
        assert list_result2["statusCode"] == 200
        listed2 = json.loads(list_result2["body"])["api_keys"]
        assert len(listed2) == 1
        # The remaining key should be key 2
        assert listed2[0]["key_id"] == key2_id

        # Step 6: Try to revoke the same key again - should get 404
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key1_id}
        revoke_again = revoke_handler(api_gateway_event, {})
        assert revoke_again["statusCode"] == 404

    @mock_aws
    def test_revoke_last_key_prevented(self, mock_dynamodb, api_gateway_event):
        """Creating one key then trying to revoke it should fail (last key protection)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler as create_handler
        from api.revoke_api_key import handler as revoke_handler

        session_token = _create_test_session_token("user_last_key", "lastkey@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        # Create a key
        api_gateway_event["httpMethod"] = "POST"
        result = create_handler(api_gateway_event, {})
        assert result["statusCode"] == 201
        key_id = json.loads(result["body"])["key_id"]

        # Try to revoke the only key
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_id}
        revoke_result = revoke_handler(api_gateway_event, {})
        assert revoke_result["statusCode"] == 400
        body = json.loads(revoke_result["body"])
        assert body["error"]["code"] == "cannot_revoke_last_key"


class TestGetApiKeysFiltersPendingDisplay:
    """Tests that PENDING_DISPLAY and PENDING_RECOVERY_CODES are filtered."""

    @mock_aws
    def test_filters_out_pending_display_records(self, mock_dynamodb, api_gateway_event):
        """Should not include PENDING_DISPLAY in API key list."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Add PENDING_DISPLAY record
        table.put_item(
            Item={
                "pk": "user_pd_filter",
                "sk": "PENDING_DISPLAY",
                "api_key": "pw_secret",
            }
        )

        # Add PENDING_RECOVERY_CODES record
        table.put_item(
            Item={
                "pk": "user_pd_filter",
                "sk": "PENDING_RECOVERY_CODES",
                "codes": ["code1", "code2"],
            }
        )

        # Add real API key
        key_hash = hashlib.sha256(b"pw_real_pd_filter").hexdigest()
        table.put_item(
            Item={
                "pk": "user_pd_filter",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                "email_verified": True,
            }
        )

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_pd_filter", "pdfilter@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        # Only the real API key should appear
        assert len(body["api_keys"]) == 1

    @mock_aws
    def test_returns_empty_list_for_user_with_no_keys(self, mock_dynamodb, api_gateway_event):
        """Should return empty list for user who has no API keys."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_no_keys", "nokeys@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["api_keys"] == []


class TestGetApiKeysKeyFieldFormat:
    """Tests for proper key field formatting in list response."""

    @mock_aws
    def test_fallback_to_hash_suffix_for_old_keys(self, mock_dynamodb, api_gateway_event):
        """Keys without key_suffix should fall back to hash suffix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        key_hash = hashlib.sha256(b"pw_old_key_no_suffix").hexdigest()
        table.put_item(
            Item={
                "pk": "user_old_format",
                "sk": key_hash,
                "key_hash": key_hash,
                # No key_suffix field (legacy key)
                "tier": "free",
                "email_verified": True,
                "requests_this_month": 42,
                "created_at": "2024-01-01T00:00:00Z",
                "last_used": "2024-06-01T00:00:00Z",
            }
        )

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_old_format", "oldformat@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        key = body["api_keys"][0]
        # Should use last 8 of hash as fallback
        assert key["key_prefix"] == f"pw_....{key_hash[-8:]}"
        assert key["requests_this_month"] == 42
        assert key["created_at"] == "2024-01-01T00:00:00Z"
        assert key["last_used"] == "2024-06-01T00:00:00Z"


class TestRevokeNullPathParameters:
    """Tests for edge cases in path parameters."""

    @mock_aws
    def test_returns_400_when_path_parameters_is_none(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when pathParameters is None (not just empty dict)."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.revoke_api_key import handler

        session_token = _create_test_session_token("user_null_path", "nullpath@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["pathParameters"] = None  # API Gateway can send None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "missing_key_id"


class TestCreateApiKeyWithNullHeaders:
    """Edge cases for headers in get_pending_key."""

    @mock_aws
    def test_handles_null_headers(self, mock_dynamodb, api_gateway_event):
        """get_pending_key should handle None headers gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.get_pending_key import handler

        api_gateway_event["headers"] = None

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401


class TestKeyNameInGetResponse:
    """Tests for key_name being returned in GET /api-keys."""

    @mock_aws
    def test_key_name_returned_in_response(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should include key_name in response."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"
        _setup_secrets_manager()
        _reset_auth_cache()

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_namedkey").hexdigest()
        table.put_item(
            Item={
                "pk": "user_keyname_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "keyname@example.com",
                "tier": "pro",
                "key_name": "Production Server",
                "email_verified": True,
            }
        )

        from api.get_api_keys import handler

        session_token = _create_test_session_token("user_keyname_test", "keyname@example.com", "pro")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert len(body["api_keys"]) == 1
        assert body["api_keys"][0]["key_name"] == "Production Server"


class TestKeyNameValidation:
    """Tests for key_name allowlist validation in POST /api-keys."""

    @mock_aws
    def test_valid_key_name_accepted(self, mock_dynamodb, api_gateway_event):
        """Should accept key names with letters, numbers, spaces, hyphens, underscores, dots."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_valid_name", "valid@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "My-Key_1.prod"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

    @mock_aws
    def test_unicode_rtl_in_key_name_rejected(self, mock_dynamodb, api_gateway_event):
        """Should reject key names with Unicode RTL override characters."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        _setup_secrets_manager()
        _reset_auth_cache()

        from api.create_api_key import handler

        session_token = _create_test_session_token("user_unicode", "unicode@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "test\u202eevil"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_key_name"
