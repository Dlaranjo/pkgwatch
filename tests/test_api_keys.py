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
    def test_key_creation_aggregates_existing_usage(self, mock_dynamodb, api_gateway_event):
        """Creating a key for user without USER_META should aggregate existing per-key usage."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
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

    @mock_aws
    def test_listed_key_suffix_matches_created_key(self, mock_dynamodb, api_gateway_event):
        """The key suffix shown in the list should match the actual API key suffix."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.create_api_key import handler as create_handler
        from api.get_api_keys import handler as get_handler
        import api.auth_callback
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
        assert listed_key_prefix.endswith(actual_suffix), \
            f"Listed key suffix '{listed_key_prefix}' should end with actual key suffix '{actual_suffix}'"


class TestGetApiKeysFiltering:
    """Tests for filtering out non-API key records."""

    @mock_aws
    def test_filters_out_pending_records(self, mock_dynamodb, api_gateway_event):
        """Should not include PENDING records in API key list."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.get_api_keys import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.get_api_keys import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.get_api_keys import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_named_key", "named@example.com", "pro")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"
        api_gateway_event["body"] = json.dumps({"name": "Production Server"})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201

        # Verify the key was created with the custom name
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq("user_named_key")
        )
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.revoke_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.revoke_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.revoke_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.get_api_keys import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.get_api_keys import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
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
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
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

        from api.create_api_key import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_keyid", "keyid@example.com")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        body = json.loads(result["body"])
        assert "key_id" in body
        assert len(body["key_id"]) == 16  # First 16 chars of hash
