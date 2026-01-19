"""
Tests for the account recovery flow.

Tests cover:
- Recovery initiation (timing normalization, session creation)
- API key verification (valid, invalid, revoked)
- Recovery code verification (valid, invalid, used, none set)
- Email update (valid token, expired, invalid)
"""

import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from moto import mock_aws

# Set environment variables before importing handlers
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["API_URL"] = "https://api.pkgwatch.laranjo.dev"
os.environ["BASE_URL"] = "https://pkgwatch.laranjo.dev"


class TestRecoveryInitiate:
    """Tests for POST /recovery/initiate endpoint."""

    @mock_aws
    def test_initiate_creates_session_for_valid_user(self, mock_dynamodb, seeded_api_keys_table):
        """Should create recovery session for existing user."""
        table, test_key = seeded_api_keys_table

        # Import handler after mocking
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        # Mock time.sleep to speed up test
        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body
        assert body["masked_email"] == "t***@example.com"

    @mock_aws
    def test_initiate_returns_fake_session_for_nonexistent_email(self, mock_dynamodb):
        """Should return consistent response for non-existent email (enumeration prevention)."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "nonexistent@example.com"}),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should still return 200 to prevent enumeration
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body

    @mock_aws
    def test_initiate_rejects_invalid_email(self, mock_dynamodb):
        """Should reject invalid email format."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "not-an-email"}),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"


class TestRecoveryVerifyApiKey:
    """Tests for POST /recovery/verify-api-key endpoint."""

    @mock_aws
    def test_verify_valid_api_key_sends_magic_link(self, mock_dynamodb, seeded_api_keys_table):
        """Should send magic link for valid API key."""
        table, test_key = seeded_api_keys_table

        # Create a recovery session first
        session_id = "test-session-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "api_key": test_key,
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_api_key.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["method"] == "api_key"
        mock_ses.send_email.assert_called_once()

    @mock_aws
    def test_verify_invalid_api_key(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid API key."""
        table, test_key = seeded_api_keys_table

        # Create a recovery session
        session_id = "test-session-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "api_key": "pw_invalid_key_12345",
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400


class TestRecoveryVerifyCode:
    """Tests for POST /recovery/verify-code endpoint."""

    @mock_aws
    def test_verify_valid_recovery_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should verify valid recovery code and consume it."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes
        plaintext_codes, hashed_codes = generate_recovery_codes(count=8)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 8,
            }
        )

        # Create a recovery session
        session_id = "test-session-456"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "recovery_code": plaintext_codes[0],  # Use first code
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_token" in body
        assert body["codes_remaining"] == 7  # One code consumed

        # Verify code was removed from USER_META
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 7

    @mock_aws
    def test_verify_invalid_recovery_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid recovery code."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes
        _, hashed_codes = generate_recovery_codes(count=8)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        # Create a recovery session
        session_id = "test-session-789"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "recovery_code": "AAAA-BBBB-CCCC-DDDD",  # Invalid code
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400

    @mock_aws
    def test_verify_code_no_codes_set(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject when no recovery codes are set up."""
        table, test_key = seeded_api_keys_table

        # Create USER_META without recovery codes
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
            }
        )

        # Create a recovery session
        session_id = "test-session-no-codes"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "recovery_code": "AAAA-BBBB-CCCC-DDDD",
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "no_recovery_codes"


class TestRecoveryUpdateEmail:
    """Tests for POST /recovery/update-email endpoint."""

    @mock_aws
    def test_update_email_with_valid_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should send verification email for valid recovery token."""
        table, test_key = seeded_api_keys_table

        # Create a verified recovery session with token
        session_id = "test-session-update"
        recovery_token = "valid-recovery-token-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "recovery_token": recovery_token,
                "recovery_method": "recovery_code",
                "verified": True,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps({
                "recovery_token": recovery_token,
                "new_email": "new@example.com",
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "n***@example.com" in body["masked_new_email"]
        # Should send both verification to new email and notification to old
        assert mock_ses.send_email.call_count == 2

    @mock_aws
    def test_update_email_rejects_api_key_verified_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject email update from API key verified session (not recovery code)."""
        table, test_key = seeded_api_keys_table

        # Create a session verified via API key (not recovery code)
        session_id = "test-session-api-key"
        recovery_token = "api-key-token-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "recovery_token": recovery_token,
                "recovery_method": "api_key",  # Not recovery_code
                "verified": True,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps({
                "recovery_token": recovery_token,
                "new_email": "new@example.com",
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should be rejected since API key verification can't change email
        assert response["statusCode"] == 400

    @mock_aws
    def test_update_email_rejects_invalid_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid recovery token."""
        from api.recovery_update_email import handler

        event = {
            "body": json.dumps({
                "recovery_token": "invalid-token-xyz",
                "new_email": "new@example.com",
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400


class TestRecoveryVerifyCodeRaceCondition:
    """Tests for race condition handling in recovery code verification."""

    @mock_aws
    def test_concurrent_code_use_is_rejected(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject concurrent attempts to use the same code (race condition prevention)."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes
        plaintext_codes, hashed_codes = generate_recovery_codes(count=8)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 8,
            }
        )

        # Create a recovery session
        session_id = "test-session-race"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps({
                "recovery_session_id": session_id,
                "recovery_code": plaintext_codes[0],
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        # First request should succeed
        with patch("time.sleep"):
            response1 = handler(event, None)
        assert response1["statusCode"] == 200

        # Simulate concurrent request by trying the same code again
        # Create another session
        session_id2 = "test-session-race-2"
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id2}",
                "email": "test@example.com",
                "recovery_session_id": session_id2,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        event2 = {
            "body": json.dumps({
                "recovery_session_id": session_id2,
                "recovery_code": plaintext_codes[0],  # Same code
            }),
            "headers": {"origin": "https://pkgwatch.laranjo.dev"},
        }

        # Second request with same code should fail (code already consumed)
        with patch("time.sleep"):
            response2 = handler(event2, None)
        assert response2["statusCode"] == 400

        # Verify only 7 codes remain (code was consumed once, not twice)
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 7


class TestRecoveryConfirmEmail:
    """Tests for GET /recovery/confirm-email endpoint."""

    @mock_aws
    def test_confirm_email_completes_change(self, mock_dynamodb, seeded_api_keys_table):
        """Should complete email change and create session."""
        table, test_key = seeded_api_keys_table

        # Create an EMAIL_CHANGE record
        change_token = "change-token-456"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )

        from api.recovery_confirm_email import handler

        # Mock session secret - need to patch both locations
        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), \
             patch("api.recovery_confirm_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()

            event = {
                "queryStringParameters": {"token": change_token},
            }
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "Set-Cookie" in response["headers"]
        assert "session=" in response["headers"]["Set-Cookie"]
        assert "email_changed=true" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_rejects_expired_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired change token."""
        table, test_key = seeded_api_keys_table

        # Create an expired EMAIL_CHANGE record
        change_token = "expired-token-789"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "ttl": int((now - timedelta(hours=1)).timestamp()),  # Expired
            }
        )

        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"):
            event = {
                "queryStringParameters": {"token": change_token},
            }
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=token_expired" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_rejects_invalid_token(self, mock_dynamodb):
        """Should reject invalid change token."""
        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), \
             patch("time.sleep"):
            event = {
                "queryStringParameters": {"token": "nonexistent-token"},
            }
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=invalid_token" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_rejects_double_use(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject second use of same email change token (race condition prevention)."""
        table, test_key = seeded_api_keys_table

        # Create an EMAIL_CHANGE record
        change_token = "change-token-double-use"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )

        from api.recovery_confirm_email import handler

        event = {
            "queryStringParameters": {"token": change_token},
        }

        # First request should succeed
        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), \
             patch("api.recovery_confirm_email.ses") as mock_ses, \
             patch("time.sleep"):
            mock_ses.send_email = MagicMock()
            response1 = handler(event, None)

        assert response1["statusCode"] == 302
        assert "email_changed=true" in response1["headers"]["Location"]

        # Second request with same token should fail
        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), \
             patch("time.sleep"):
            response2 = handler(event, None)

        assert response2["statusCode"] == 302
        assert "error=invalid_token" in response2["headers"]["Location"]
