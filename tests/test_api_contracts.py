"""
API Contract Tests for PkgWatch.

These tests ensure all API endpoints return consistent, correct responses
that match documented contracts.

Contract Requirements:
1. All success responses have Content-Type: application/json
2. All error responses have {"error": {"code": "...", "message": "..."}}
3. Status codes match response types
4. Required fields are present and have correct types
5. Rate limit headers are present where expected
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
import pytest
from moto import mock_aws


# ============================================================================
# Contract Validation Helpers
# ============================================================================

def assert_json_content_type(response: dict) -> None:
    """Assert response has JSON content type."""
    headers = response.get("headers", {})
    content_type = headers.get("Content-Type") or headers.get("content-type")
    assert content_type == "application/json", (
        f"Expected Content-Type: application/json, got: {content_type}"
    )


def assert_error_response_format(response: dict) -> None:
    """Assert error response has correct format: {"error": {"code": ..., "message": ...}}"""
    assert_json_content_type(response)
    body = json.loads(response["body"])

    assert "error" in body, f"Error response missing 'error' key: {body}"
    assert isinstance(body["error"], dict), f"'error' should be dict, got: {type(body['error'])}"
    assert "code" in body["error"], f"Error missing 'code': {body['error']}"
    assert "message" in body["error"], f"Error missing 'message': {body['error']}"
    assert isinstance(body["error"]["code"], str), f"Error code should be string"
    assert isinstance(body["error"]["message"], str), f"Error message should be string"


def assert_rate_limit_headers(response: dict, check_remaining: bool = True) -> None:
    """Assert response includes rate limit headers."""
    headers = response.get("headers", {})
    assert "X-RateLimit-Limit" in headers, "Missing X-RateLimit-Limit header"

    if check_remaining:
        assert "X-RateLimit-Remaining" in headers, "Missing X-RateLimit-Remaining header"

    # Validate header values are numeric strings
    limit = headers.get("X-RateLimit-Limit")
    assert limit.isdigit(), f"X-RateLimit-Limit should be numeric, got: {limit}"


def assert_status_code_matches_response(response: dict) -> None:
    """Assert status code is appropriate for the response type."""
    status = response["statusCode"]
    body_str = response.get("body", "")

    if body_str:
        try:
            body = json.loads(body_str)
            is_error = "error" in body
        except json.JSONDecodeError:
            is_error = False
    else:
        is_error = False

    # Success codes
    if status in (200, 201):
        assert not is_error, f"Status {status} should not have error body"

    # Error codes should have error body
    if status >= 400:
        assert is_error, f"Status {status} should have error body"


# ============================================================================
# GET /v1/packages/{ecosystem}/{name} Contract Tests
# ============================================================================

class TestGetPackageContract:
    """Contract tests for GET /v1/packages/{ecosystem}/{name}."""

    @mock_aws
    def test_success_response_format(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Success response should have correct format and all required fields."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        # Status and content type
        assert result["statusCode"] == 200
        assert_json_content_type(result)
        assert_rate_limit_headers(result)

        # Parse and validate body structure
        body = json.loads(result["body"])

        # Required top-level fields
        required_fields = [
            "package", "ecosystem", "health_score", "risk_level",
            "components", "signals", "last_updated"
        ]
        for field in required_fields:
            assert field in body, f"Missing required field: {field}"

        # Package and ecosystem strings
        assert body["package"] == "lodash"
        assert body["ecosystem"] == "npm"

        # health_score: 0-100 integer or None
        if body["health_score"] is not None:
            assert isinstance(body["health_score"], (int, float))
            assert 0 <= body["health_score"] <= 100, (
                f"health_score out of range: {body['health_score']}"
            )

        # risk_level: one of LOW, MEDIUM, HIGH, CRITICAL or None
        valid_risk_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL", None]
        assert body["risk_level"] in valid_risk_levels, (
            f"Invalid risk_level: {body['risk_level']}"
        )

    @mock_aws
    def test_score_components_normalized(
        self, seeded_api_keys_table, mock_dynamodb, api_gateway_event
    ):
        """Score components should be normalized 0-100."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create package with score components
        packages_table = mock_dynamodb.Table("pkgwatch-packages")
        packages_table.put_item(
            Item={
                "pk": "npm#test-pkg",
                "sk": "LATEST",
                "ecosystem": "npm",
                "name": "test-pkg",
                "health_score": 75,
                "risk_level": "MEDIUM",
                "score_components": {
                    "activity": 80,
                    "community": 70,
                    "maintenance": 85,
                    "security": 60,
                },
                "last_updated": "2024-01-01T00:00:00Z",
            }
        )

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "test-pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})
        body = json.loads(result["body"])

        # Validate components exist and are in valid range
        if body.get("components"):
            for component, value in body["components"].items():
                if value is not None:
                    assert isinstance(value, (int, float)), (
                        f"Component {component} should be numeric"
                    )
                    assert 0 <= value <= 100, (
                        f"Component {component} out of range: {value}"
                    )

    @mock_aws
    def test_404_error_response_format(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """404 error response should have correct format."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "package_not_found"

    @mock_aws
    def test_400_invalid_ecosystem_format(
        self, seeded_api_keys_table, api_gateway_event
    ):
        """400 error for invalid ecosystem should have correct format."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table
        api_gateway_event["pathParameters"] = {"ecosystem": "invalid", "name": "pkg"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_ecosystem"

    @mock_aws
    def test_429_rate_limit_response_format(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """429 rate limit response should have correct format and headers."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create user at rate limit
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_ratelimited123456789"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_ratelimited",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "limited@example.com",
                "tier": "free",
                "requests_this_month": 5000,  # At limit (per-key, for analytics)
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        # Add USER_META with requests_this_month at limit (rate limiting is user-level)
        table.put_item(
            Item={
                "pk": "user_ratelimited",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 5000,  # At limit
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["x-api-key"] = test_key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        assert_error_response_format(result)
        assert_rate_limit_headers(result)

        # Rate limit specific headers
        headers = result["headers"]
        assert "Retry-After" in headers, "Missing Retry-After header"
        assert headers["X-RateLimit-Remaining"] == "0"

        # Body should contain upgrade info
        body = json.loads(result["body"])
        assert body["error"]["code"] == "rate_limit_exceeded"
        assert "upgrade_url" in body["error"]

    @mock_aws
    def test_demo_mode_rate_limit_response_format(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Demo mode 429 should have different error code and signup URL."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create demo rate limit entry
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%d-%H")
        client_ip = "127.0.0.1"

        table.put_item(
            Item={
                "pk": f"demo#{client_ip}",
                "sk": f"hour#{current_hour}",
                "requests": 25,  # Over demo limit
                "ttl": int(now.timestamp()) + 7200,
            }
        )

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key = demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 429
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "demo_rate_limit_exceeded"
        assert "signup_url" in body["error"]

    @mock_aws
    def test_demo_mode_includes_demo_header(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Demo mode success response should include X-Demo-Mode header."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        # No API key = demo mode

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert result["headers"].get("X-Demo-Mode") == "true"


# ============================================================================
# POST /v1/scan Contract Tests
# ============================================================================

class TestPostScanContract:
    """Contract tests for POST /v1/scan."""

    @mock_aws
    def test_success_response_format(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Success response should have correct format and all required fields."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"}
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert_json_content_type(result)
        assert_rate_limit_headers(result)

        body = json.loads(result["body"])

        # Required fields
        required_fields = ["total", "critical", "high", "medium", "low", "packages"]
        for field in required_fields:
            assert field in body, f"Missing required field: {field}"

        # Count fields should be integers
        for field in ["total", "critical", "high", "medium", "low"]:
            assert isinstance(body[field], int), f"{field} should be int"
            assert body[field] >= 0, f"{field} should be non-negative"

        # Packages should be a list
        assert isinstance(body["packages"], list)

        # Each package should have required fields
        for pkg in body["packages"]:
            assert "package" in pkg, "Package entry missing 'package'"
            assert "health_score" in pkg, "Package entry missing 'health_score'"
            assert "risk_level" in pkg, "Package entry missing 'risk_level'"

    @mock_aws
    def test_packages_sorted_by_risk(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Packages should be sorted by risk level (CRITICAL first)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21", "abandoned-pkg": "^1.0.0"}
        })

        result = handler(api_gateway_event, {})
        body = json.loads(result["body"])

        # abandoned-pkg is HIGH risk, lodash is LOW - HIGH should come first
        packages = body["packages"]
        if len(packages) >= 2:
            risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for i in range(len(packages) - 1):
                curr_risk = risk_order.get(packages[i]["risk_level"], 4)
                next_risk = risk_order.get(packages[i + 1]["risk_level"], 4)
                assert curr_risk <= next_risk, "Packages not sorted by risk"

    @mock_aws
    def test_401_without_api_key(self, mock_dynamodb, api_gateway_event):
        """Should return 401 without API key (no demo mode for scan)."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21"}
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"

    @mock_aws
    def test_400_invalid_json(self, seeded_api_keys_table, api_gateway_event):
        """Should return 400 for invalid JSON body."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = "not valid json"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_400_no_dependencies(self, seeded_api_keys_table, api_gateway_event):
        """Should return 400 when no dependencies provided."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({})

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "no_dependencies"

    @mock_aws
    def test_not_found_packages_list(
        self, seeded_api_keys_table, seeded_packages_table, api_gateway_event
    ):
        """Response should include list of packages not found."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["x-api-key"] = test_key
        api_gateway_event["body"] = json.dumps({
            "dependencies": {"lodash": "^4.17.21", "nonexistent": "^1.0.0"}
        })

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        assert "not_found" in body
        assert isinstance(body["not_found"], list)
        assert "nonexistent" in body["not_found"]


# ============================================================================
# API Keys Endpoints Contract Tests
# ============================================================================

def _create_test_session_token(user_id: str, email: str, tier: str = "free") -> str:
    """Create a test session token."""
    from api.auth_callback import _create_session_token

    data = {
        "user_id": user_id,
        "email": email,
        "tier": tier,
        "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
    }
    return _create_session_token(data, "test-secret-key-for-signing-sessions")


class TestGetApiKeysContract:
    """Contract tests for GET /api-keys."""

    @mock_aws
    def test_success_response_format(self, mock_dynamodb, api_gateway_event):
        """Success response should have correct format."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_testkey").hexdigest()
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "test@example.com",
                "tier": "free",
                "requests_this_month": 100,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.get_api_keys import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_test", "test@example.com")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert_json_content_type(result)

        body = json.loads(result["body"])
        assert "api_keys" in body
        assert isinstance(body["api_keys"], list)

        # Each key should have required fields
        for key in body["api_keys"]:
            assert "key_id" in key
            assert "key_prefix" in key
            assert "tier" in key
            assert "requests_this_month" in key
            # Should NOT expose full key hash
            assert "key_hash" not in key
            assert "sk" not in key

    @mock_aws
    def test_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 without session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.get_api_keys import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"


class TestCreateApiKeyContract:
    """Contract tests for POST /api-keys."""

    @mock_aws
    def test_success_response_format(self, mock_dynamodb, api_gateway_event):
        """Success response should include the new API key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_existing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_create",
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

        session_token = _create_test_session_token("user_create", "create@example.com", "pro")
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 201
        assert_json_content_type(result)

        body = json.loads(result["body"])
        assert "api_key" in body
        assert body["api_key"].startswith("pw_")
        assert "message" in body

    @mock_aws
    def test_400_max_keys_reached(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when max keys reached."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create 5 keys (max)
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
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "max_keys_reached"


class TestRevokeApiKeyContract:
    """Contract tests for DELETE /api-keys/{key_id}."""

    @mock_aws
    def test_success_response_format(self, mock_dynamodb, api_gateway_event):
        """Success response should have message."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create 2 keys (need 2 to revoke 1)
        key_hash1 = hashlib.sha256(b"pw_torevoke").hexdigest()
        key_hash2 = hashlib.sha256(b"pw_tokeep").hexdigest()

        for key_hash in [key_hash1, key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_revoke",
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

        session_token = _create_test_session_token("user_revoke", "revoke@example.com")
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": key_hash1}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        # 204 No Content is the correct status for successful DELETE
        assert result["statusCode"] == 204
        assert result["body"] == ""

    @mock_aws
    def test_404_key_not_found(self, mock_dynamodb, api_gateway_event):
        """Should return 404 for non-existent key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
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
        api_gateway_event["pathParameters"] = {"key_id": "nonexistent"}
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        assert_error_response_format(result)

    @mock_aws
    def test_400_cannot_revoke_last_key(self, mock_dynamodb, api_gateway_event):
        """Should return 400 when trying to revoke last key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
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
        assert_error_response_format(result)

        body = json.loads(result["body"])
        assert body["error"]["code"] == "cannot_revoke_last_key"


# ============================================================================
# Auth Endpoints Contract Tests
# ============================================================================

class TestAuthMeContract:
    """Contract tests for GET /auth/me."""

    @mock_aws
    def test_success_response_format(self, mock_dynamodb, api_gateway_event):
        """Success response should have user info."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        key_hash = hashlib.sha256(b"pw_testkey").hexdigest()
        table.put_item(
            Item={
                "pk": "user_me",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "me@example.com",
                "tier": "pro",
                "requests_this_month": 500,
                "created_at": "2024-01-01T00:00:00Z",
                "email_verified": True,
            }
        )

        from api.auth_me import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        session_token = _create_test_session_token("user_me", "me@example.com", "pro")
        api_gateway_event["headers"]["Cookie"] = f"session={session_token}"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        assert_json_content_type(result)

        body = json.loads(result["body"])

        # Required fields
        assert "user_id" in body
        assert "email" in body
        assert "tier" in body
        assert "requests_this_month" in body
        assert "monthly_limit" in body

        # Validate values
        assert body["email"] == "me@example.com"
        assert body["tier"] == "pro"
        assert isinstance(body["monthly_limit"], int)
        assert body["monthly_limit"] > 0

    @mock_aws
    def test_401_without_session(self, mock_dynamodb, api_gateway_event):
        """Should return 401 without session."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.auth_me import handler

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        assert_error_response_format(result)


class TestAuthCallbackContract:
    """Contract tests for GET /auth/callback."""

    @mock_aws
    def test_success_redirect_headers(self, mock_dynamodb, api_gateway_event):
        """Success should redirect with secure cookie."""
        import secrets

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        table = mock_dynamodb.Table("pkgwatch-api-keys")
        magic_token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        key_hash = hashlib.sha256(b"pw_existing").hexdigest()
        table.put_item(
            Item={
                "pk": "user_callback",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "callback@example.com",
                "tier": "free",
                "magic_token": magic_token,
                "magic_expires": expires,
                "email_verified": True,
            }
        )

        from api.auth_callback import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        api_gateway_event["queryStringParameters"] = {"token": magic_token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302

        headers = result["headers"]
        assert "Location" in headers
        assert "dashboard" in headers["Location"]

        # Cookie should be secure
        assert "Set-Cookie" in headers
        cookie = headers["Set-Cookie"]
        assert "session=" in cookie
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie

        # Cache control
        assert headers.get("Cache-Control") == "no-store"

    @mock_aws
    def test_error_redirect_format(self, mock_dynamodb, api_gateway_event):
        """Error should redirect to login with error params."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"
        os.environ["SESSION_SECRET_ARN"] = "test-secret"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-secret",
            SecretString='{"secret": "test-secret-key-for-signing-sessions"}'
        )

        from api.auth_callback import handler
        import api.auth_callback
        api.auth_callback._session_secret_cache = None

        api_gateway_event["queryStringParameters"] = {"token": "invalid"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302

        headers = result["headers"]
        location = headers["Location"]
        assert "login" in location
        assert "error=" in location


# ============================================================================
# Cross-Cutting Contract Tests
# ============================================================================

class TestCorsHeaders:
    """Tests for CORS header handling."""

    @mock_aws
    def test_cors_headers_for_allowed_origin(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """Should include CORS headers for allowed origins."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["ALLOW_DEV_CORS"] = "true"

        # Need to reload the module to pick up the env var change
        import importlib
        import api.get_package
        importlib.reload(api.get_package)
        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"]["origin"] = "http://localhost:4321"

        result = handler(api_gateway_event, {})

        headers = result["headers"]
        assert headers.get("Access-Control-Allow-Origin") == "http://localhost:4321"
        assert "Access-Control-Allow-Methods" in headers
        assert "Access-Control-Allow-Headers" in headers


class TestContentTypeConsistency:
    """Verify all endpoints return consistent Content-Type."""

    @mock_aws
    def test_all_json_responses_have_content_type(
        self, mock_dynamodb, seeded_packages_table, api_gateway_event
    ):
        """All JSON responses should have Content-Type: application/json."""
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.get_package import handler as get_package_handler
        from api.post_scan import handler as post_scan_handler

        # Test get_package 200
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        result = get_package_handler(api_gateway_event, {})
        assert_json_content_type(result)

        # Test get_package 404
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent"}
        result = get_package_handler(api_gateway_event, {})
        assert_json_content_type(result)

        # Test post_scan 401 - ensure no API key
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"dependencies": {}})
        api_gateway_event["headers"].pop("x-api-key", None)  # Safe removal
        result = post_scan_handler(api_gateway_event, {})
        assert_json_content_type(result)
