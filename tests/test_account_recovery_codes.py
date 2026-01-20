"""
Tests for account recovery codes management.

Tests cover:
- Generate codes (first time, regenerate)
- Delete codes
- Status check
"""

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from moto import mock_aws

# Set environment variables before importing handlers
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"


def create_session_token(user_id: str, email: str, secret: str = "test-secret") -> str:
    """Create a test session token."""
    session_data = {
        "user_id": user_id,
        "email": email,
        "tier": "free",
        "exp": int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()),
    }
    payload = base64.urlsafe_b64encode(json.dumps(session_data).encode()).decode()
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


class TestGenerateRecoveryCodes:
    """Tests for POST /account/recovery-codes endpoint."""

    @mock_aws
    def test_generate_codes_first_time(self, mock_dynamodb, seeded_api_keys_table):
        """Should generate 4 recovery codes for first-time setup."""
        table, test_key = seeded_api_keys_table

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "POST",
            "body": "{}",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        assert "codes" in body
        assert len(body["codes"]) == 4
        assert body["codes_count"] == 4

        # Verify codes are in correct format (XXXX-XXXX-XXXX-XXXX)
        for code in body["codes"]:
            parts = code.split("-")
            assert len(parts) == 4
            assert all(len(p) == 4 and all(c in "0123456789ABCDEF" for c in p) for p in parts)

        # Verify hashes are stored in DynamoDB
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 4
        assert meta["recovery_codes_count"] == 4

    @mock_aws
    def test_regenerate_codes_replaces_existing(self, mock_dynamodb, seeded_api_keys_table):
        """Should replace existing codes when regenerating."""
        table, test_key = seeded_api_keys_table

        # First, set up existing codes
        from shared.recovery_utils import generate_recovery_codes
        old_codes, old_hashes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": old_hashes,
                "recovery_codes_count": 4,
            }
        )

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "POST",
            "body": "{}",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        # Verify new codes are returned
        assert body["codes"] != old_codes  # Codes should be different

        # Verify old codes are invalidated (can't use them)
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert meta["recovery_codes_hash"] != old_hashes

    @mock_aws
    def test_generate_codes_requires_auth(self, mock_dynamodb):
        """Should reject unauthenticated requests."""
        from api.account_recovery_codes import handler

        event = {
            "httpMethod": "POST",
            "body": "{}",
            "headers": {
                "origin": "https://pkgwatch.dev",
            },
        }

        response = handler(event, None)

        assert response["statusCode"] == 401


class TestDeleteRecoveryCodes:
    """Tests for DELETE /account/recovery-codes endpoint."""

    @mock_aws
    def test_delete_existing_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should delete existing recovery codes."""
        table, test_key = seeded_api_keys_table

        # Set up existing codes
        from shared.recovery_utils import generate_recovery_codes
        _, hashes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashes,
                "recovery_codes_count": 4,
            }
        )

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "DELETE",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200

        # Verify codes are removed
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert "recovery_codes_hash" not in meta

    @mock_aws
    def test_delete_nonexistent_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should succeed even when no codes exist."""
        table, test_key = seeded_api_keys_table

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "DELETE",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200


class TestRecoveryCodesStatus:
    """Tests for GET /account/recovery-codes/status endpoint."""

    @mock_aws
    def test_status_with_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should return correct status when codes exist."""
        table, test_key = seeded_api_keys_table

        # Set up existing codes (3 remaining)
        from shared.recovery_utils import generate_recovery_codes
        _, hashes = generate_recovery_codes(count=4)
        remaining_hashes = hashes[:3]  # Simulate 1 code used

        now = datetime.now(timezone.utc).isoformat()
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": remaining_hashes,
                "recovery_codes_count": 4,
                "recovery_codes_generated_at": now,
            }
        )

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "GET",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        assert body["has_codes"] is True
        assert body["codes_remaining"] == 3
        assert body["original_count"] == 4
        assert body["generated_at"] is not None

    @mock_aws
    def test_status_without_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should return correct status when no codes are set up."""
        table, test_key = seeded_api_keys_table

        from api.account_recovery_codes import handler

        session_token = create_session_token("user_test123", "test@example.com")

        event = {
            "httpMethod": "GET",
            "headers": {
                "cookie": f"session={session_token}",
                "origin": "https://pkgwatch.dev",
            },
        }

        with patch("api.auth_callback._get_session_secret", return_value="test-secret"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])

        assert body["has_codes"] is False
        assert body["codes_remaining"] == 0


class TestRecoveryUtils:
    """Tests for shared recovery utilities."""

    def test_generate_recovery_codes(self):
        """Should generate valid recovery codes."""
        from shared.recovery_utils import generate_recovery_codes

        codes, hashes = generate_recovery_codes(count=4)

        assert len(codes) == 4
        assert len(hashes) == 4

        # Verify format
        for code in codes:
            parts = code.split("-")
            assert len(parts) == 4
            assert all(len(p) == 4 for p in parts)

    def test_verify_recovery_code_valid(self):
        """Should verify valid recovery code."""
        from shared.recovery_utils import generate_recovery_codes, verify_recovery_code

        codes, hashes = generate_recovery_codes(count=4)

        # Verify each code
        for i, code in enumerate(codes):
            is_valid, index = verify_recovery_code(code, hashes)
            assert is_valid is True
            assert index == i

    def test_verify_recovery_code_invalid(self):
        """Should reject invalid recovery code."""
        from shared.recovery_utils import generate_recovery_codes, verify_recovery_code

        codes, hashes = generate_recovery_codes(count=4)

        # Try invalid code
        is_valid, index = verify_recovery_code("AAAA-BBBB-CCCC-DDDD", hashes)
        assert is_valid is False
        assert index == -1

    def test_verify_recovery_code_format_variations(self):
        """Should accept codes with or without dashes."""
        from shared.recovery_utils import generate_recovery_codes, verify_recovery_code

        codes, hashes = generate_recovery_codes(count=1)
        code = codes[0]

        # With dashes
        is_valid, _ = verify_recovery_code(code, hashes)
        assert is_valid is True

        # Without dashes
        code_no_dash = code.replace("-", "")
        is_valid, _ = verify_recovery_code(code_no_dash, hashes)
        assert is_valid is True

        # Lowercase
        is_valid, _ = verify_recovery_code(code.lower(), hashes)
        assert is_valid is True

    def test_mask_email(self):
        """Should mask email correctly."""
        from shared.recovery_utils import mask_email

        assert mask_email("john@example.com") == "j***@example.com"
        assert mask_email("ab@test.org") == "a***@test.org"
        assert mask_email("x@foo.com") == "x***@foo.com"
        assert mask_email("invalid") == "***@***.***"
        assert mask_email("") == "***@***.***"

    def test_validate_recovery_code_format(self):
        """Should validate recovery code format."""
        from shared.recovery_utils import validate_recovery_code_format

        # Valid formats
        assert validate_recovery_code_format("ABCD-1234-EF56-7890") is True
        assert validate_recovery_code_format("ABCD1234EF567890") is True  # No dashes
        assert validate_recovery_code_format("abcd-1234-ef56-7890") is True  # Lowercase

        # Invalid formats
        assert validate_recovery_code_format("") is False
        assert validate_recovery_code_format("ABCD") is False  # Too short
        assert validate_recovery_code_format("ABCD-1234-EF56-789G") is False  # Invalid char
        assert validate_recovery_code_format("ABCD-1234-EF56-78901") is False  # Too long
