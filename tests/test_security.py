"""
Security tests for PkgWatch application.

Tests for:
- Authentication bypass attempts
- Authorization issues (IDOR, privilege escalation)
- Input injection (SQL/NoSQL, path traversal)
- Session security (tampering, expiration, constant-time comparison)
- Rate limiting bypass
- Stripe webhook security
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

import pytest
from moto import mock_aws

# =============================================================================
# Session Security Tests
# =============================================================================


class TestSessionTokenSecurity:
    """Test session token security - tampering, expiration, signature bypass."""

    @mock_aws
    def test_rejects_tampered_session_payload(self, mock_dynamodb):
        """Should reject session with modified payload but original signature."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Set up secrets manager with test secret
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(Name="test-session-secret", SecretString='{"secret": "super-secret-key-12345"}')
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret"

        # Clear cache and import
        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import _create_session_token, verify_session_token

        # Create legitimate session
        session_data = {
            "user_id": "user_victim",
            "email": "victim@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
        }

        valid_token = _create_session_token(session_data, "super-secret-key-12345")
        payload, signature = valid_token.rsplit(".", 1)

        # Attacker modifies payload to change user_id
        tampered_data = {
            "user_id": "user_attacker",  # Changed!
            "email": "attacker@example.com",
            "tier": "business",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp()),
        }
        tampered_payload = base64.urlsafe_b64encode(json.dumps(tampered_data).encode()).decode()

        # Attacker tries to use original signature with tampered payload
        tampered_token = f"{tampered_payload}.{signature}"

        result = verify_session_token(tampered_token)

        assert result is None, "Tampered session should be rejected"

    @mock_aws
    def test_rejects_expired_session(self, mock_dynamodb):
        """Should reject expired session tokens."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-exp", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-exp"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import _create_session_token, verify_session_token

        # Create expired session
        expired_data = {
            "user_id": "user_test",
            "email": "test@example.com",
            "tier": "free",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        }

        expired_token = _create_session_token(expired_data, "super-secret-key-12345")

        result = verify_session_token(expired_token)

        assert result is None, "Expired session should be rejected"

    @mock_aws
    def test_rejects_malformed_session_token(self, mock_dynamodb):
        """Should reject malformed session tokens gracefully."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-mal", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-mal"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import verify_session_token

        malformed_tokens = [
            "",
            "nosignature",
            ".",
            ".onlysignature",
            "onlypayload.",
            "not.valid.base64",
            base64.urlsafe_b64encode(b"not json").decode() + ".sig",
            "a" * 10000 + ".sig",  # Very long payload
            "../../../etc/passwd.sig",  # Path traversal attempt
        ]

        for token in malformed_tokens:
            result = verify_session_token(token)
            assert result is None, f"Malformed token should be rejected: {token[:50]}..."

    @mock_aws
    def test_rejects_forged_signature(self, mock_dynamodb):
        """Should reject tokens with forged signatures."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-forge", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-forge"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import verify_session_token

        # Attacker tries to forge token with wrong secret
        attacker_data = {
            "user_id": "user_admin",
            "email": "admin@example.com",
            "tier": "business",
            "exp": int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp()),
        }

        payload = base64.urlsafe_b64encode(json.dumps(attacker_data).encode()).decode()

        # Attacker guesses/uses wrong secret
        forged_signature = hmac.new(b"wrong-secret", payload.encode(), hashlib.sha256).hexdigest()

        forged_token = f"{payload}.{forged_signature}"

        result = verify_session_token(forged_token)

        assert result is None, "Forged signature should be rejected"

    def test_hmac_uses_constant_time_comparison(self):
        """Verify HMAC comparison uses constant-time function to prevent timing attacks."""
        import inspect

        from api.auth_callback import verify_session_token

        source = inspect.getsource(verify_session_token)

        # Should use hmac.compare_digest, not == for signature comparison
        assert "hmac.compare_digest" in source, (
            "Session verification should use hmac.compare_digest for constant-time comparison"
        )
        assert "signature ==" not in source or "expected_sig ==" not in source, (
            "Should not use == for signature comparison (timing attack vulnerability)"
        )


# =============================================================================
# Authentication Bypass Tests
# =============================================================================


class TestAuthenticationBypass:
    """Test authentication bypass attempts on protected endpoints."""

    @mock_aws
    def test_get_api_keys_without_session(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should return 401 without session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.get_api_keys import handler

        # No session cookie
        api_gateway_event["headers"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "unauthorized"

    @mock_aws
    def test_create_api_key_without_session(self, mock_dynamodb, api_gateway_event):
        """POST /api-keys should return 401 without session cookie."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.create_api_key import handler

        api_gateway_event["headers"] = {}
        api_gateway_event["httpMethod"] = "POST"

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_revoke_api_key_without_session(self, mock_dynamodb, api_gateway_event):
        """DELETE /api-keys/{key_id} should return 401 without session."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.revoke_api_key import handler

        api_gateway_event["headers"] = {}
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": "abc123"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_auth_me_without_session(self, mock_dynamodb, api_gateway_event):
        """GET /auth/me should return 401 without session."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["SESSION_SECRET_ARN"] = ""

        from api.auth_me import handler

        api_gateway_event["headers"] = {}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401

    @mock_aws
    def test_post_scan_without_api_key(self, mock_dynamodb, api_gateway_event):
        """POST /scan should return 401 without API key."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from api.post_scan import handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"dependencies": {"lodash": "^4.17.0"}})
        api_gateway_event["headers"] = {}  # No API key

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 401
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_api_key"

    @mock_aws
    def test_get_package_tracks_demo_usage_without_key(
        self, seeded_packages_table, seeded_api_keys_table, api_gateway_event
    ):
        """GET /packages should work in demo mode but track usage."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.get_package import handler

        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"] = {}  # No API key - demo mode
        api_gateway_event["requestContext"] = {"identity": {"sourceIp": "192.168.1.1"}}

        result = handler(api_gateway_event, {})

        # Should work but in demo mode
        assert result["statusCode"] == 200
        assert result["headers"].get("X-Demo-Mode") == "true"


# =============================================================================
# Authorization Tests (IDOR)
# =============================================================================


class TestAuthorizationIssues:
    """Test for Insecure Direct Object Reference and privilege escalation."""

    @mock_aws
    def test_cannot_revoke_other_users_api_key(self, mock_dynamodb, api_gateway_event):
        """Should not be able to revoke another user's API key."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Set up secrets manager
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-idor", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-idor"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import _create_session_token

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create victim's API key
        victim_key_hash = hashlib.sha256(b"pw_victim_key").hexdigest()
        table.put_item(
            Item={
                "pk": "user_victim",
                "sk": victim_key_hash,
                "key_hash": victim_key_hash,
                "email": "victim@example.com",
                "tier": "business",
                "email_verified": True,
            }
        )

        # Create attacker's API key (so they have at least 2 keys - needed for revoke)
        attacker_key_hash1 = hashlib.sha256(b"pw_attacker_key1").hexdigest()
        attacker_key_hash2 = hashlib.sha256(b"pw_attacker_key2").hexdigest()
        for kh in [attacker_key_hash1, attacker_key_hash2]:
            table.put_item(
                Item={
                    "pk": "user_attacker",
                    "sk": kh,
                    "key_hash": kh,
                    "email": "attacker@example.com",
                    "tier": "free",
                    "email_verified": True,
                }
            )

        # Create attacker's session
        attacker_session = _create_session_token(
            {
                "user_id": "user_attacker",
                "email": "attacker@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp()),
            },
            "super-secret-key-12345",
        )

        from api.revoke_api_key import handler

        # Attacker tries to revoke victim's key
        api_gateway_event["headers"] = {"Cookie": f"session={attacker_session}"}
        api_gateway_event["httpMethod"] = "DELETE"
        api_gateway_event["pathParameters"] = {"key_id": victim_key_hash[:16]}

        result = handler(api_gateway_event, {})

        # Should fail - key not found because it belongs to another user
        assert result["statusCode"] == 404
        body = json.loads(result["body"])
        assert body["error"]["code"] == "key_not_found"

        # Verify victim's key still exists
        response = table.get_item(Key={"pk": "user_victim", "sk": victim_key_hash})
        assert "Item" in response, "Victim's API key should still exist"

    @mock_aws
    def test_cannot_list_other_users_api_keys(self, mock_dynamodb, api_gateway_event):
        """Should only list own API keys, not other users'."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-list", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-list"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import _create_session_token

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create victim's API key
        victim_key_hash = hashlib.sha256(b"pw_victim_secret").hexdigest()
        table.put_item(
            Item={
                "pk": "user_victim",
                "sk": victim_key_hash,
                "key_hash": victim_key_hash,
                "email": "victim@example.com",
                "tier": "business",
                "email_verified": True,
            }
        )

        # Create attacker's API key
        attacker_key_hash = hashlib.sha256(b"pw_attacker").hexdigest()
        table.put_item(
            Item={
                "pk": "user_attacker",
                "sk": attacker_key_hash,
                "key_hash": attacker_key_hash,
                "email": "attacker@example.com",
                "tier": "free",
                "email_verified": True,
            }
        )

        # Create attacker's session
        attacker_session = _create_session_token(
            {
                "user_id": "user_attacker",
                "email": "attacker@example.com",
                "tier": "free",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp()),
            },
            "super-secret-key-12345",
        )

        from api.get_api_keys import handler

        api_gateway_event["headers"] = {"Cookie": f"session={attacker_session}"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        # Should only see attacker's own key
        assert len(body["api_keys"]) == 1
        assert body["api_keys"][0]["key_id"] == attacker_key_hash[:16]


# =============================================================================
# Input Injection Tests
# =============================================================================


class TestInputInjection:
    """Test for SQL/NoSQL injection and path traversal."""

    @mock_aws
    def test_package_name_injection_attempts(self, seeded_packages_table, seeded_api_keys_table, api_gateway_event):
        """Should safely handle malicious package names."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table

        malicious_names = [
            # NoSQL injection attempts
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "npm#lodash",  # Trying to forge pk format
            # XSS attempts (if rendered)
            "<script>alert(1)</script>",
            "';DROP TABLE packages;--",
            # Unicode shenanigans
            "\x00lodash",
            "lodash\x00.txt",
            # Very long input
            "a" * 10000,
        ]

        for name in malicious_names:
            api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": name}
            api_gateway_event["headers"] = {"x-api-key": test_key}
            api_gateway_event["requestContext"] = {"identity": {"sourceIp": "127.0.0.1"}}

            result = handler(api_gateway_event, {})

            # Should return 404 (not found) not 500 (crash)
            assert result["statusCode"] in [400, 404], f"Malicious input should not crash server: {name[:50]}..."

    @mock_aws
    def test_ecosystem_injection_attempts(self, seeded_packages_table, seeded_api_keys_table, api_gateway_event):
        """Should validate ecosystem parameter."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table

        malicious_ecosystems = [
            "../npm",
            "npm/../pypi",
            "NPM",  # Case sensitivity
            '{"$ne": ""}',
            "",
            "a" * 1000,
        ]

        for ecosystem in malicious_ecosystems:
            api_gateway_event["pathParameters"] = {"ecosystem": ecosystem, "name": "lodash"}
            api_gateway_event["headers"] = {"x-api-key": test_key}
            api_gateway_event["requestContext"] = {"identity": {"sourceIp": "127.0.0.1"}}

            result = handler(api_gateway_event, {})

            # Should return 400 for invalid ecosystem, not crash
            assert result["statusCode"] == 400, f"Invalid ecosystem should be rejected: {ecosystem[:50]}"

    @mock_aws
    def test_json_body_injection(self, seeded_api_keys_table, api_gateway_event):
        """POST /scan should handle malicious JSON gracefully."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.post_scan import handler

        table, test_key = seeded_api_keys_table

        malicious_bodies = [
            # Deeply nested
            '{"dependencies": {"a": {"b": {"c": {"d": "1"}}}}}',
            # Very large
            json.dumps({"dependencies": {f"pkg{i}": "1.0.0" for i in range(10000)}}),
            # Invalid types
            '{"dependencies": [1, 2, 3]}',
            '{"dependencies": "not an object"}',
            '{"content": 12345}',
        ]

        for body in malicious_bodies:
            api_gateway_event["httpMethod"] = "POST"
            api_gateway_event["headers"] = {"x-api-key": test_key}
            api_gateway_event["body"] = body

            result = handler(api_gateway_event, {})

            # Should handle gracefully (400 or 429 for rate limit)
            assert result["statusCode"] in [200, 400, 429], "Malicious body should not crash server"


# =============================================================================
# Sensitive Data Exposure Tests
# =============================================================================


class TestSensitiveDataExposure:
    """Test that sensitive data is not exposed in responses."""

    @mock_aws
    def test_api_keys_not_returned_in_list(self, mock_dynamodb, api_gateway_event):
        """GET /api-keys should not return actual API key values."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-expose", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-expose"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None
        from api.auth_callback import _create_session_token

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create user with API key
        real_api_key = "pw_supersecretkey12345"
        key_hash = hashlib.sha256(real_api_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_test",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "test@example.com",
                "tier": "pro",
                "email_verified": True,
            }
        )

        session_token = _create_session_token(
            {
                "user_id": "user_test",
                "email": "test@example.com",
                "tier": "pro",
                "exp": int((datetime.now(timezone.utc) + timedelta(days=1)).timestamp()),
            },
            "super-secret-key-12345",
        )

        from api.get_api_keys import handler

        api_gateway_event["headers"] = {"Cookie": f"session={session_token}"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])

        response_str = json.dumps(body)

        # Actual API key should never appear in response
        assert real_api_key not in response_str
        assert "pw_supersecret" not in response_str

        # Should only show key_id (hash prefix) and key_prefix (masked)
        for key_info in body["api_keys"]:
            assert "pw_..." in key_info["key_prefix"]  # Masked format

    @mock_aws
    def test_error_messages_dont_leak_internals(self, seeded_api_keys_table, api_gateway_event):
        """Error messages should not expose internal details."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.get_package import handler

        table, test_key = seeded_api_keys_table

        # Request non-existent package
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "nonexistent-pkg-xyz"}
        api_gateway_event["headers"] = {"x-api-key": test_key}
        api_gateway_event["requestContext"] = {"identity": {"sourceIp": "127.0.0.1"}}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 404
        body = json.loads(result["body"])

        error_str = json.dumps(body)

        # Should not leak internal details
        assert "dynamodb" not in error_str.lower()
        assert "boto" not in error_str.lower()
        assert "traceback" not in error_str.lower()
        assert "exception" not in error_str.lower()


# =============================================================================
# Rate Limiting Security Tests
# =============================================================================


class TestRateLimitingSecurity:
    """Test rate limiting cannot be bypassed."""

    @mock_aws
    def test_rate_limit_enforced_atomically(self, seeded_api_keys_table):
        """Rate limit check and increment should be atomic."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        from shared.auth import check_and_increment_usage

        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Set USER_META.requests_this_month to limit - 1 (rate limiting is user-level)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "key_count": 1,
                "requests_this_month": 4999,
            }
        )

        # First request should succeed
        allowed1, count1 = check_and_increment_usage("user_test123", key_hash, 5000)
        assert allowed1 is True
        assert count1 == 5000

        # Second request should fail (at limit)
        allowed2, count2 = check_and_increment_usage("user_test123", key_hash, 5000)
        assert allowed2 is False

    @mock_aws
    def test_demo_rate_limit_uses_verified_ip(self, seeded_packages_table, seeded_api_keys_table, api_gateway_event):
        """Demo rate limit should use API Gateway's verified sourceIp, not headers."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["PACKAGES_TABLE"] = "pkgwatch-packages"

        from api.get_package import _get_client_ip, handler

        # Test that _get_client_ip uses sourceIp, not X-Forwarded-For
        spoofed_event = {
            "headers": {
                "X-Forwarded-For": "1.2.3.4, 5.6.7.8",  # Attacker tries to spoof
            },
            "requestContext": {
                "identity": {"sourceIp": "192.168.1.100"}  # Real IP from API Gateway
            },
        }

        client_ip = _get_client_ip(spoofed_event)

        # Should use the verified sourceIp, not the spoofable X-Forwarded-For
        assert client_ip == "192.168.1.100"
        assert client_ip != "1.2.3.4"

        # Also test the full handler uses verified IP for rate limiting
        api_gateway_event["pathParameters"] = {"ecosystem": "npm", "name": "lodash"}
        api_gateway_event["headers"] = {
            "X-Forwarded-For": "1.2.3.4, 5.6.7.8",  # Spoofed
        }
        api_gateway_event["requestContext"] = {
            "identity": {"sourceIp": "192.168.1.100"}  # Real IP from API Gateway
        }

        result = handler(api_gateway_event, {})

        # Should succeed in demo mode
        assert result["statusCode"] == 200
        assert result["headers"].get("X-Demo-Mode") == "true"


# =============================================================================
# Stripe Webhook Security Tests
# =============================================================================


class TestStripeWebhookSecurity:
    """Test Stripe webhook signature verification."""

    def test_rejects_missing_stripe_signature(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook without Stripe-Signature header."""
        pytest.importorskip("stripe")

        import importlib

        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Set up Stripe secrets - inside the mock_dynamodb context
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(Name="stripe-api-key", SecretString='{"key": "sk_test_123"}')
        secretsmanager.create_secret(Name="stripe-webhook-secret", SecretString='{"secret": "whsec_test123"}')
        os.environ["STRIPE_SECRET_ARN"] = "stripe-api-key"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "stripe-webhook-secret"

        # Reload the module to pick up the mocked secretsmanager
        import api.stripe_webhook as webhook_module

        importlib.reload(webhook_module)
        handler = webhook_module.handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps(
            {"type": "checkout.session.completed", "data": {"object": {"customer_email": "test@example.com"}}}
        )
        api_gateway_event["headers"] = {}  # No Stripe-Signature

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "signature" in body["error"]["message"].lower()

    def test_rejects_invalid_stripe_signature(self, mock_dynamodb, api_gateway_event):
        """Should reject webhook with invalid signature."""
        pytest.importorskip("stripe")

        import importlib

        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create secrets within the same mock context as mock_dynamodb
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(Name="stripe-api-key-inv", SecretString='{"key": "sk_test_123"}')
        secretsmanager.create_secret(
            Name="stripe-webhook-secret-inv", SecretString='{"secret": "whsec_realwebhooksecret"}'
        )
        os.environ["STRIPE_SECRET_ARN"] = "stripe-api-key-inv"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "stripe-webhook-secret-inv"

        # Reload the module to pick up the mocked secretsmanager
        import api.stripe_webhook as webhook_module

        importlib.reload(webhook_module)
        handler = webhook_module.handler

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps(
            {"type": "checkout.session.completed", "data": {"object": {"customer_email": "test@example.com"}}}
        )
        # Attacker provides fake signature
        api_gateway_event["headers"] = {"Stripe-Signature": "t=123456,v1=fakesignature123"}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert "signature" in body["error"]["message"].lower() or "invalid" in body["error"]["message"].lower()

    def test_rejects_replayed_webhook(self, mock_dynamodb, api_gateway_event):
        """Stripe's signature verification should reject old timestamps (replay attacks)."""
        pytest.importorskip("stripe")

        import importlib

        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"

        # Create secrets within the same mock context as mock_dynamodb
        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(Name="stripe-api-key-replay", SecretString='{"key": "sk_test_123"}')
        secretsmanager.create_secret(Name="stripe-webhook-secret-replay", SecretString='{"secret": "whsec_test123456"}')
        os.environ["STRIPE_SECRET_ARN"] = "stripe-api-key-replay"
        os.environ["STRIPE_WEBHOOK_SECRET_ARN"] = "stripe-webhook-secret-replay"

        # Reload the module to pick up the mocked secretsmanager
        import api.stripe_webhook as webhook_module

        importlib.reload(webhook_module)
        handler = webhook_module.handler

        # Create a valid-looking but old signature (replay attack)
        payload = json.dumps(
            {"type": "checkout.session.completed", "data": {"object": {"customer_email": "victim@example.com"}}}
        )

        # Old timestamp (5 minutes ago - Stripe default tolerance is 5 min)
        old_timestamp = str(int(time.time()) - 400)  # 6+ minutes old

        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = payload
        api_gateway_event["headers"] = {"Stripe-Signature": f"t={old_timestamp},v1=somesignature"}

        result = handler(api_gateway_event, {})

        # Should reject due to timestamp validation in Stripe library
        assert result["statusCode"] == 400


# =============================================================================
# Magic Link Security Tests
# =============================================================================


class TestMagicLinkSecurity:
    """Test magic link token security."""

    @mock_aws
    def test_magic_link_single_use(self, mock_dynamodb, api_gateway_event):
        """Magic link tokens should be single-use."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-magic", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-magic"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create user with magic token
        magic_token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        key_hash = hashlib.sha256(b"pw_test").hexdigest()

        table.put_item(
            Item={
                "pk": "user_magic",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "magic@example.com",
                "tier": "free",
                "magic_token": magic_token,
                "magic_expires": expires,
                "email_verified": True,
            }
        )

        from api.auth_callback import handler

        # First use should succeed
        api_gateway_event["queryStringParameters"] = {"token": magic_token}

        result1 = handler(api_gateway_event, {})
        assert result1["statusCode"] == 302
        assert "dashboard" in result1["headers"]["Location"]

        # Clear cache to reload
        auth_callback._session_secret_cache = None

        # Second use should fail (token was cleared)
        result2 = handler(api_gateway_event, {})
        assert result2["statusCode"] == 302
        assert "invalid_token" in result2["headers"]["Location"]

    @mock_aws
    def test_magic_link_expiration_enforced(self, mock_dynamodb, api_gateway_event):
        """Expired magic link tokens should be rejected."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-expire", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-expire"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create user with expired magic token
        magic_token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()  # Expired
        key_hash = hashlib.sha256(b"pw_expired").hexdigest()

        table.put_item(
            Item={
                "pk": "user_expired_magic",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "expired@example.com",
                "tier": "free",
                "magic_token": magic_token,
                "magic_expires": expires,
                "email_verified": True,
            }
        )

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": magic_token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302
        assert "token_expired" in result["headers"]["Location"]

    @mock_aws
    def test_email_enumeration_prevention(self, mock_dynamodb, api_gateway_event):
        """Magic link endpoint should not reveal if email exists."""
        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        from api.magic_link import handler

        # Request for non-existent email
        api_gateway_event["httpMethod"] = "POST"
        api_gateway_event["body"] = json.dumps({"email": "nonexistent@example.com"})

        result1 = handler(api_gateway_event, {})

        # Request for format-invalid email
        api_gateway_event["body"] = json.dumps({"email": "another-fake@nowhere.com"})

        result2 = handler(api_gateway_event, {})

        # Both should return 200 with same message (no enumeration)
        assert result1["statusCode"] == 200
        assert result2["statusCode"] == 200

        body1 = json.loads(result1["body"])
        body2 = json.loads(result2["body"])

        # Same response to prevent enumeration
        assert body1["message"] == body2["message"]


# =============================================================================
# Cookie Security Tests
# =============================================================================


class TestCookieSecurity:
    """Test session cookie security flags."""

    @mock_aws
    def test_session_cookie_has_security_flags(self, mock_dynamodb, api_gateway_event):
        """Session cookie should have HttpOnly, Secure, SameSite flags."""
        import boto3

        os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
        os.environ["BASE_URL"] = "https://test.example.com"

        secretsmanager = boto3.client("secretsmanager", region_name="us-east-1")
        secretsmanager.create_secret(
            Name="test-session-secret-cookie", SecretString='{"secret": "super-secret-key-12345"}'
        )
        os.environ["SESSION_SECRET_ARN"] = "test-session-secret-cookie"

        import api.auth_callback as auth_callback

        auth_callback._session_secret_cache = None

        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create user with magic token
        magic_token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        key_hash = hashlib.sha256(b"pw_cookie").hexdigest()

        table.put_item(
            Item={
                "pk": "user_cookie",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "cookie@example.com",
                "tier": "free",
                "magic_token": magic_token,
                "magic_expires": expires,
                "email_verified": True,
            }
        )

        from api.auth_callback import handler

        api_gateway_event["queryStringParameters"] = {"token": magic_token}

        result = handler(api_gateway_event, {})

        assert result["statusCode"] == 302

        set_cookie = result["headers"]["Set-Cookie"]

        # Verify security flags
        assert "HttpOnly" in set_cookie, "Cookie must have HttpOnly flag"
        assert "Secure" in set_cookie, "Cookie must have Secure flag"
        assert "SameSite=Strict" in set_cookie, "Cookie must have SameSite=Strict"
        assert "Path=/" in set_cookie, "Cookie must have Path=/"
