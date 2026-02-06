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
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from moto import mock_aws

# Set environment variables before importing handlers
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["API_URL"] = "https://api.pkgwatch.dev"
os.environ["BASE_URL"] = "https://pkgwatch.dev"


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
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "api_key": "pw_invalid_key_12345",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 4,
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": plaintext_codes[0],  # Use first code
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_token" in body
        assert body["codes_remaining"] == 3  # One code consumed

        # Verify code was removed from USER_META
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 3

    @mock_aws
    def test_verify_invalid_recovery_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid recovery code."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes

        _, hashed_codes = generate_recovery_codes(count=4)

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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",  # Invalid code
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_token": "invalid-token-xyz",
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 4,
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": plaintext_codes[0],
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id2,
                    "recovery_code": plaintext_codes[0],  # Same code
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # Second request with same code should fail (code already consumed)
        with patch("time.sleep"):
            response2 = handler(event2, None)
        assert response2["statusCode"] == 400

        # Verify only 3 codes remain (code was consumed once, not twice)
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 3


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
        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
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

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
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
        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
            patch("time.sleep"),
        ):
            mock_ses.send_email = MagicMock()
            response1 = handler(event, None)

        assert response1["statusCode"] == 302
        assert "email_changed=true" in response1["headers"]["Location"]

        # Second request with same token should fail
        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
            response2 = handler(event, None)

        assert response2["statusCode"] == 302
        assert "error=invalid_token" in response2["headers"]["Location"]


class TestRecoveryVerifyCodeErrors:
    """Error path tests for POST /recovery/verify-code endpoint."""

    @mock_aws
    def test_verify_code_json_decode_error(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_verify_code import handler

        event = {
            "body": "invalid json{",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_verify_code_session_expired(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

        # Create an expired recovery session
        session_id = "expired-session-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now - timedelta(hours=1)).timestamp()),  # Expired
            }
        )

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_verify_code_dynamo_scan_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB scan error gracefully."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session-123",
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # Mock the table scan to raise an error
        with patch("time.sleep"), patch("api.recovery_verify_code.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_verify_code_dynamo_meta_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB get_item error for USER_META."""
        table, test_key = seeded_api_keys_table

        # Create a recovery session
        session_id = "test-session-meta-error"
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # Mock scan to work but get_item to fail
        with patch("time.sleep"), patch("api.recovery_verify_code.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"RECOVERY_{session_id}",
                        "email": "test@example.com",
                        "ttl": int((now + timedelta(hours=1)).timestamp()),
                        "verified": False,
                    }
                ]
            }
            mock_table.get_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "GetItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_verify_code_race_condition(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle race condition when consuming recovery code."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        # Store in USER_META
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 4,
            }
        )

        # Create a recovery session
        session_id = "test-session-race-condition"
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
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": plaintext_codes[0],
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # Mock update_item to raise ConditionalCheckFailedException
        with patch("time.sleep"), patch("api.recovery_verify_code.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"RECOVERY_{session_id}",
                        "email": "test@example.com",
                        "ttl": int((now + timedelta(hours=1)).timestamp()),
                        "verified": False,
                    }
                ]
            }
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": "user_test123",
                    "sk": "USER_META",
                    "recovery_codes_hash": hashed_codes,
                }
            }
            mock_table.update_item.side_effect = ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Condition failed"}}, "UpdateItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 409
        body = json.loads(response["body"])
        assert body["error"]["code"] == "concurrent_modification"


class TestRecoveryUpdateEmailErrors:
    """Error path tests for POST /recovery/update-email endpoint."""

    @mock_aws
    def test_update_email_json_decode_error(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_update_email import handler

        event = {
            "body": "not valid json",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_update_email_session_expired(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

        # Create an expired recovery session with token
        session_id = "test-session-expired"
        recovery_token = "expired-token-123"
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
                "ttl": int((now - timedelta(hours=1)).timestamp()),  # Expired
            }
        )

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_update_email_session_not_verified(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject unverified recovery session."""
        table, test_key = seeded_api_keys_table

        # Create an unverified recovery session with token
        session_id = "test-session-unverified"
        recovery_token = "unverified-token-123"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "recovery_token": recovery_token,
                "recovery_method": "recovery_code",
                "verified": False,  # Not verified
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "session_not_verified"

    @mock_aws
    def test_update_email_already_in_use(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject email that's already in use by another user."""
        table, test_key = seeded_api_keys_table

        # Create another user with the target email
        other_key = "pw_other_user_key_1234"
        other_key_hash = hashlib.sha256(other_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_other456",
                "sk": other_key_hash,
                "key_hash": other_key_hash,
                "email": "taken@example.com",
                "tier": "free",
            }
        )

        # Create a verified recovery session
        session_id = "test-session-email-in-use"
        recovery_token = "in-use-token-123"
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
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "taken@example.com",  # Already in use
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "email_in_use"

    @mock_aws
    def test_update_email_dynamo_scan_error(self, mock_dynamodb):
        """Should handle DynamoDB scan error gracefully."""
        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": "test-token-123",
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_update_email_verification_email_failure(self, mock_dynamodb, seeded_api_keys_table):
        """Should continue even if verification email fails."""
        table, test_key = seeded_api_keys_table

        # Create a verified recovery session
        session_id = "test-session-email-fail"
        recovery_token = "email-fail-token-123"
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
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # SES fails but operation should still succeed
        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email.side_effect = Exception("SES failure")
            response = handler(event, None)

        # Should still return 200 since the record is created
        assert response["statusCode"] == 200


class TestRecoveryVerifyApiKeyErrors:
    """Error path tests for POST /recovery/verify-api-key endpoint."""

    @mock_aws
    def test_verify_api_key_json_decode_error(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": "not valid json",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_verify_api_key_session_expired(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

        # Create an expired recovery session
        session_id = "expired-api-key-session"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now - timedelta(hours=1)).timestamp()),  # Expired
            }
        )

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "session_expired"

    @mock_aws
    def test_verify_api_key_dynamo_query_error(self, mock_dynamodb):
        """Should handle DynamoDB query error gracefully."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session-123",
                    "api_key": "pw_test_key_12345",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_verify_api_key_session_get_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB get_item error for session."""
        table, test_key = seeded_api_keys_table

        from api.recovery_verify_api_key import handler

        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session-123",
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        _now = datetime.now(timezone.utc)
        with patch("time.sleep"), patch("api.recovery_verify_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            # First query succeeds (API key lookup)
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                    }
                ]
            }
            # get_item fails
            mock_table.get_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "GetItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_verify_api_key_email_mismatch(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject API key for different email than recovery session."""
        table, test_key = seeded_api_keys_table

        # Create a recovery session with a different email
        session_id = "test-session-mismatch"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "different@example.com",  # Different from API key's email
                "recovery_session_id": session_id,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_credentials"

    @mock_aws
    def test_verify_api_key_update_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB update_item error gracefully."""
        table, test_key = seeded_api_keys_table

        # Create a valid recovery session
        session_id = "test-session-update-error"
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

        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                    }
                ]
            }
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": "user_test123",
                    "sk": f"RECOVERY_{session_id}",
                    "email": "test@example.com",
                    "ttl": int((now + timedelta(hours=1)).timestamp()),
                }
            }
            mock_table.update_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "UpdateItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryConfirmEmailErrors:
    """Error path tests for GET /recovery/confirm-email endpoint."""

    @mock_aws
    def test_confirm_email_dynamo_scan_error(self, mock_dynamodb):
        """Should handle DynamoDB scan error gracefully."""
        from api.recovery_confirm_email import handler

        event = {
            "queryStringParameters": {"token": "test-token-123"},
        }

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_user_query_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB query error for user records."""
        table, test_key = seeded_api_keys_table

        # Create an EMAIL_CHANGE record
        change_token = "change-token-query-error"
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

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"EMAIL_CHANGE_{change_token}",
                        "old_email": "test@example.com",
                        "new_email": "new@example.com",
                        "change_token": change_token,
                        "ttl": int((now + timedelta(hours=24)).timestamp()),
                    }
                ]
            }
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_token_consumed_race(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle race condition when token is consumed concurrently."""
        table, test_key = seeded_api_keys_table

        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Create an EMAIL_CHANGE record
        change_token = "change-token-race"
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

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"EMAIL_CHANGE_{change_token}",
                        "old_email": "test@example.com",
                        "new_email": "new@example.com",
                        "change_token": change_token,
                        "ttl": int((now + timedelta(hours=24)).timestamp()),
                    }
                ]
            }
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                    }
                ]
            }
            mock_table.delete_item.side_effect = ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Already deleted"}}, "DeleteItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=invalid_token" in response["headers"]["Location"]


class TestRecoveryInitiateErrors:
    """Error path tests for POST /recovery/initiate endpoint."""

    @mock_aws
    def test_initiate_json_decode_error(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_initiate import handler

        event = {
            "body": "not valid json",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_initiate_dynamo_query_error(self, mock_dynamodb):
        """Should handle DynamoDB query error gracefully."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_initiate_session_creation_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB put_item error when creating session."""
        table, test_key = seeded_api_keys_table

        from api.recovery_initiate import handler

        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "email": "test@example.com",
                        "email_verified": True,
                    }
                ]
            }
            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}}, "PutItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryConfirmEmailDeleteTokenError:
    """Tests for non-conditional ClientError on delete_item (lines 144-145 of recovery_confirm_email.py)."""

    @mock_aws
    def test_confirm_email_non_conditional_delete_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should return internal_error when delete_item fails with non-conditional error."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        change_token = "change-token-delete-error"
        now = datetime.now(timezone.utc)

        from api.recovery_confirm_email import handler

        event = {
            "queryStringParameters": {"token": change_token},
        }

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"EMAIL_CHANGE_{change_token}",
                        "old_email": "test@example.com",
                        "new_email": "new@example.com",
                        "change_token": change_token,
                        "ttl": int((now + timedelta(hours=24)).timestamp()),
                    }
                ]
            }
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                        "tier": "free",
                    }
                ]
            }
            # Non-conditional ClientError (not ConditionalCheckFailedException)
            mock_table.delete_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "DynamoDB failure"}}, "DeleteItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]


class TestRecoveryConfirmEmailUpdateErrors:
    """Tests for ClientError during email update operations (lines 180, 184-191)."""

    @mock_aws
    def test_confirm_email_update_records_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should return internal_error when updating user records fails (lines 189-191)."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        change_token = "change-token-update-err"
        now = datetime.now(timezone.utc)

        from api.recovery_confirm_email import handler

        event = {
            "queryStringParameters": {"token": change_token},
        }

        def always_fail_update(**kwargs):
            """All update_item calls fail."""
            raise ClientError({"Error": {"Code": "InternalServerError", "Message": "Update failed"}}, "UpdateItem")

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"EMAIL_CHANGE_{change_token}",
                        "old_email": "test@example.com",
                        "new_email": "new@example.com",
                        "change_token": change_token,
                        "ttl": int((now + timedelta(hours=24)).timestamp()),
                    }
                ]
            }
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                        "tier": "free",
                    }
                ]
            }
            # delete_item succeeds (token consumed)
            mock_table.delete_item.return_value = {}
            # update_item fails (user record updates)
            mock_table.update_item.side_effect = always_fail_update
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_confirm_email_deletes_recovery_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should delete the recovery session after email change completes (lines 183-186)."""
        table, test_key = seeded_api_keys_table

        change_token = "change-token-cleanup"
        recovery_session_sk = "RECOVERY_session-abc"
        now = datetime.now(timezone.utc)

        # Create email change record with recovery_session_sk
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "recovery_session_sk": recovery_session_sk,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )

        # Create the recovery session record
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": recovery_session_sk,
                "email": "test@example.com",
                "verified": True,
                "recovery_method": "recovery_code",
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_confirm_email import handler

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
            mock_ses.send_email = MagicMock()

            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "email_changed=true" in response["headers"]["Location"]

        # Verify recovery session was deleted
        session_resp = table.get_item(Key={"pk": "user_test123", "sk": recovery_session_sk})
        assert "Item" not in session_resp

    @mock_aws
    def test_confirm_email_user_meta_non_conditional_error_reraises(self, mock_dynamodb, seeded_api_keys_table):
        """Should re-raise non-conditional ClientError when updating USER_META (line 180)."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        change_token = "change-token-meta-error"
        now = datetime.now(timezone.utc)

        from api.recovery_confirm_email import handler

        event = {
            "queryStringParameters": {"token": change_token},
        }

        update_call_count = 0

        def selective_update(**kwargs):
            """First update (API key record) succeeds, second (USER_META) fails with non-conditional."""
            nonlocal update_call_count
            update_call_count += 1
            key = kwargs.get("Key", {})
            if key.get("sk") == "USER_META":
                raise ClientError(
                    {"Error": {"Code": "InternalServerError", "Message": "Meta update failed"}}, "UpdateItem"
                )
            return {}

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"EMAIL_CHANGE_{change_token}",
                        "old_email": "test@example.com",
                        "new_email": "new@example.com",
                        "change_token": change_token,
                        "ttl": int((now + timedelta(hours=24)).timestamp()),
                    }
                ]
            }
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "key_hash": key_hash,
                        "email": "test@example.com",
                        "tier": "free",
                    },
                    {
                        "pk": "user_test123",
                        "sk": "USER_META",
                    },
                ]
            }
            mock_table.delete_item.return_value = {}
            mock_table.update_item.side_effect = selective_update
            response = handler(event, None)

        # The non-conditional error on USER_META should be re-raised and
        # caught by the outer except, resulting in internal_error
        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]


class TestRecoveryVerifyCodeInternalError:
    """Tests for non-conditional ClientError during code consumption (lines 231-232)."""

    @mock_aws
    def test_verify_code_non_conditional_update_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should return 500 when update_item fails with a non-conditional error."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        session_id = "test-session-internal-err"
        now = datetime.now(timezone.utc)

        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": plaintext_codes[0],
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_code.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"RECOVERY_{session_id}",
                        "email": "test@example.com",
                        "ttl": int((now + timedelta(hours=1)).timestamp()),
                        "verified": False,
                    }
                ]
            }
            mock_table.get_item.return_value = {
                "Item": {
                    "pk": "user_test123",
                    "sk": "USER_META",
                    "recovery_codes_hash": hashed_codes,
                }
            }
            # Non-conditional error (InternalServerError, not ConditionalCheckFailedException)
            mock_table.update_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "DB error"}}, "UpdateItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"
        assert body["error"]["message"] == "Failed to process recovery code"


class TestRecoveryUpdateEmailInternalErrors:
    """Tests for ClientError paths in recovery_update_email.py (lines 184-186, 221-223)."""

    @mock_aws
    def test_update_email_email_check_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should return 500 when email availability check fails (lines 184-186)."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-email-check-err"
        recovery_token = "token-email-check-err"
        now = datetime.now(timezone.utc)

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        def selective_query(**kwargs):
            """email-index query fails."""
            index_name = kwargs.get("IndexName", "")
            if index_name == "email-index":
                raise ClientError({"Error": {"Code": "InternalServerError", "Message": "Query failed"}}, "Query")
            return {"Items": []}

        with patch("time.sleep"), patch("api.recovery_update_email.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"RECOVERY_{session_id}",
                        "email": "test@example.com",
                        "ttl": int((now + timedelta(hours=1)).timestamp()),
                        "verified": True,
                    }
                ]
            }
            mock_table.query.side_effect = selective_query
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_update_email_create_record_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should return 500 when creating EMAIL_CHANGE record fails (lines 221-223)."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-create-err"
        recovery_token = "token-create-err"
        now = datetime.now(timezone.utc)

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": f"RECOVERY_{session_id}",
                        "email": "test@example.com",
                        "ttl": int((now + timedelta(hours=1)).timestamp()),
                        "verified": True,
                    }
                ]
            }
            # Email check succeeds (no other user with this email)
            mock_table.query.return_value = {"Items": []}
            # Creating EMAIL_CHANGE record fails
            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Put failed"}}, "PutItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryInitiateUserMetaFetchError:
    """Test for line 119 of recovery_initiate.py: ClientError during USER_META fetch."""

    @mock_aws
    def test_initiate_user_meta_fetch_error_continues_gracefully(self, mock_dynamodb, seeded_api_keys_table):
        """Should continue without USER_META when fetch fails (line 119)."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        def get_item_fail(**kwargs):
            """Fail the get_item call for USER_META."""
            raise ClientError({"Error": {"Code": "InternalServerError", "Message": "Get failed"}}, "GetItem")

        with patch("time.sleep"), patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            # query returns the user (via email-index GSI)
            mock_table.query.return_value = {
                "Items": [
                    {
                        "pk": "user_test123",
                        "sk": key_hash,
                        "email": "test@example.com",
                    }
                ]
            }
            # get_item for USER_META fails
            mock_table.get_item.side_effect = get_item_fail
            # put_item for session succeeds
            mock_table.put_item.return_value = {}
            # update_item for rate limiting succeeds
            mock_table.update_item.return_value = {}
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        # Should still succeed with has_recovery_codes = False
        assert body["has_recovery_codes"] is False
        assert "recovery_session_id" in body


class TestRecoverySecurityEndToEnd:
    """End-to-end security tests for the recovery flow."""

    @mock_aws
    def test_full_recovery_flow_initiate_verify_update_confirm(self, mock_dynamodb, seeded_api_keys_table):
        """Should complete full recovery flow: initiate -> verify code -> update email -> confirm."""
        table, test_key = seeded_api_keys_table

        # Step 1: Generate recovery codes for the user
        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 4,
            }
        )

        # Step 2: Initiate recovery
        from api.recovery_initiate import handler as initiate_handler

        event_initiate = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = initiate_handler(event_initiate, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        session_id = body["recovery_session_id"]
        assert body["has_recovery_codes"] is True

        # Step 3: Verify with recovery code
        from api.recovery_verify_code import handler as verify_handler

        event_verify = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": plaintext_codes[0],
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = verify_handler(event_verify, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        recovery_token = body["recovery_token"]
        assert body["codes_remaining"] == 3

        # Verify the code was consumed (single-use)
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 3

        # Step 4: Update email
        from api.recovery_update_email import handler as update_handler

        event_update = {
            "body": json.dumps(
                {
                    "recovery_token": recovery_token,
                    "new_email": "newemail@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = update_handler(event_update, None)

        assert response["statusCode"] == 200

        # Step 5: Find the EMAIL_CHANGE record and confirm
        scan_result = table.scan(
            FilterExpression="begins_with(sk, :prefix)",
            ExpressionAttributeValues={":prefix": "EMAIL_CHANGE_"},
        )
        change_records = scan_result.get("Items", [])
        assert len(change_records) == 1
        change_token = change_records[0]["change_token"]

        from api.recovery_confirm_email import handler as confirm_handler

        event_confirm = {
            "queryStringParameters": {"token": change_token},
        }

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses2,
        ):
            mock_ses2.send_email = MagicMock()
            response = confirm_handler(event_confirm, None)

        assert response["statusCode"] == 302
        assert "email_changed=true" in response["headers"]["Location"]
        assert "Set-Cookie" in response["headers"]

        # Verify email was updated on API key record
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        updated_key = table.get_item(Key={"pk": "user_test123", "sk": key_hash})["Item"]
        assert updated_key["email"] == "newemail@example.com"
        assert updated_key["previous_email"] == "test@example.com"

    @mock_aws
    def test_api_key_verification_cannot_change_email(self, mock_dynamodb, seeded_api_keys_table):
        """Should prevent email change when verified via API key (not recovery code).

        API key verification only sends a magic link - it does NOT issue a recovery_token.
        Attempting to use an API key-verified session for email change should fail.
        """
        table, test_key = seeded_api_keys_table

        # Create a recovery session verified via API key
        session_id = "session-api-key-only"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "test@example.com",
                "recovery_session_id": session_id,
                "verified": True,
                "recovery_method": "api_key",
                # No recovery_token - API key method doesn't generate one
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": "fabricated-token-attempt",
                    "new_email": "attacker@evil.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should fail - no matching session with recovery_method=recovery_code and this token
        assert response["statusCode"] == 400

    @mock_aws
    def test_recovery_session_for_wrong_user_cannot_recover_account(self, mock_dynamodb, seeded_api_keys_table):
        """Should not allow recovery of someone else's account.

        Fake session IDs for non-existent emails are not stored in DynamoDB,
        so they cannot be used to progress the recovery flow.
        """
        table, test_key = seeded_api_keys_table

        # Initiate recovery for a non-existent email
        from api.recovery_initiate import handler as initiate_handler

        event = {
            "body": json.dumps({"email": "doesnotexist@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = initiate_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        fake_session_id = body["recovery_session_id"]

        # Now try to verify with recovery code - should fail because session was never stored
        from api.recovery_verify_code import handler as verify_handler

        event2 = {
            "body": json.dumps(
                {
                    "recovery_session_id": fake_session_id,
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response2 = verify_handler(event2, None)

        # Should fail with invalid_session since fake session was not stored
        assert response2["statusCode"] == 400
        body2 = json.loads(response2["body"])
        assert body2["error"]["code"] == "invalid_session"

    @mock_aws
    def test_confirm_email_null_query_string_params(self, mock_dynamodb):
        """Should handle null queryStringParameters gracefully."""
        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
            event = {"queryStringParameters": None}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=missing_token" in response["headers"]["Location"]
