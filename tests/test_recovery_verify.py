"""
Tests for recovery verification endpoints.

Tests cover:
- POST /recovery/verify-api-key - API key verification flow
- POST /recovery/verify-code - Recovery code verification flow

Security tests:
- Timing normalization
- Generic error messages to prevent enumeration
- Session validation
- Code consumption and race condition handling
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


class TestRecoveryVerifyApiKeyValidFlow:
    """Tests for valid API key verification flow."""

    @mock_aws
    def test_sends_magic_link_for_valid_api_key(self, mock_dynamodb, seeded_api_keys_table):
        """Should send magic link for valid API key."""
        table, test_key = seeded_api_keys_table

        # Create a recovery session first
        session_id = "test-session-valid"
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
    def test_marks_session_as_verified(self, mock_dynamodb, seeded_api_keys_table):
        """Should mark session as verified via API key."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-mark"
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

        # Verify session was updated
        session = table.get_item(Key={"pk": "user_test123", "sk": f"RECOVERY_{session_id}"})["Item"]
        assert session["verified"] is True
        assert session["recovery_method"] == "api_key"
        assert "verified_at" in session

    @mock_aws
    def test_stores_magic_token_on_api_key_record(self, mock_dynamodb, seeded_api_keys_table):
        """Should store magic token on API key record."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        session_id = "test-session-token"
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
            _response = handler(event, None)

        # Verify magic token was stored
        key_record = table.get_item(Key={"pk": "user_test123", "sk": key_hash})["Item"]
        assert "magic_token" in key_record
        assert "magic_expires" in key_record


class TestRecoveryVerifyApiKeyInputValidation:
    """Tests for input validation on API key verification."""

    @mock_aws
    def test_rejects_invalid_json(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": "not valid json{",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_rejects_missing_session_id(self, mock_dynamodb):
        """Should reject missing recovery_session_id."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "api_key": "pw_test_key",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_session"

    @mock_aws
    def test_rejects_missing_api_key(self, mock_dynamodb):
        """Should reject missing api_key."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_api_key"

    @mock_aws
    def test_rejects_invalid_api_key_format(self, mock_dynamodb):
        """Should reject API key not starting with pw_."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                    "api_key": "invalid_key_format",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_api_key"


class TestRecoveryVerifyApiKeySecurityChecks:
    """Tests for security validations."""

    @mock_aws
    def test_rejects_invalid_api_key(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid API key with generic error."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-invalid"
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
                    "api_key": "pw_invalid_key_12345678",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        # Should use generic error to prevent enumeration
        assert body["error"]["code"] == "invalid_credentials"

    @mock_aws
    def test_rejects_expired_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-expired"
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
    def test_rejects_nonexistent_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject non-existent recovery session."""
        table, test_key = seeded_api_keys_table

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "nonexistent-session",
                    "api_key": test_key,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_session"

    @mock_aws
    def test_rejects_email_mismatch(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject API key for different email than recovery session."""
        table, test_key = seeded_api_keys_table

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
    def test_handles_api_key_without_email(self, mock_dynamodb):
        """Should handle API key record missing email."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create API key without email field
        test_key = "pw_no_email_key_12345"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_no_email",
                "sk": key_hash,
                "key_hash": key_hash,
                "tier": "free",
                # No email field
            }
        )

        # Create recovery session
        session_id = "test-session-no-email"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_no_email",
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

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryVerifyApiKeyErrorHandling:
    """Tests for error handling."""

    @mock_aws
    def test_handles_dynamo_query_error(self, mock_dynamodb):
        """Should handle DynamoDB query error gracefully."""
        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                    "api_key": "pw_test_key_12345",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_api_key.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_session_get_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB get_item error for session."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        from api.recovery_verify_api_key import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
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
            mock_table.get_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "GetItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_update_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB update_item error gracefully."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        session_id = "test-session-update-error"
        now = datetime.now(timezone.utc)

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
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "UpdateItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_continues_on_email_send_failure(self, mock_dynamodb, seeded_api_keys_table):
        """Should return success even if email send fails."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-email-fail"
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
            mock_ses.send_email.side_effect = Exception("SES failure")
            response = handler(event, None)

        # Should still return success to prevent enumeration
        assert response["statusCode"] == 200


class TestRecoveryVerifyCodeValidFlow:
    """Tests for valid recovery code verification flow."""

    @mock_aws
    def test_verifies_valid_recovery_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should verify valid recovery code and return token."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=8)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-code"
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

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_token" in body
        assert body["codes_remaining"] == 7

    @mock_aws
    def test_consumes_recovery_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should remove used code from USER_META."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-consume"
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
                    "recovery_code": plaintext_codes[2],  # Use middle code
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200

        # Verify code was removed
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert len(meta["recovery_codes_hash"]) == 3

    @mock_aws
    def test_marks_session_as_verified_with_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should mark session as verified and store recovery token."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=2)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-token"
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

        with patch("time.sleep"):
            response = handler(event, None)

        body = json.loads(response["body"])

        # Verify session was updated
        session = table.get_item(Key={"pk": "user_test123", "sk": f"RECOVERY_{session_id}"})["Item"]
        assert session["verified"] is True
        assert session["recovery_method"] == "recovery_code"
        assert session["recovery_token"] == body["recovery_token"]


class TestRecoveryVerifyCodeInputValidation:
    """Tests for input validation on recovery code verification."""

    @mock_aws
    def test_rejects_invalid_json(self, mock_dynamodb):
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
    def test_rejects_missing_session_id(self, mock_dynamodb):
        """Should reject missing recovery_session_id."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_session"

    @mock_aws
    def test_rejects_missing_recovery_code(self, mock_dynamodb):
        """Should reject missing recovery_code."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_code"

    @mock_aws
    def test_rejects_invalid_code_format(self, mock_dynamodb):
        """Should reject invalid recovery code format."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                    "recovery_code": "invalid-format",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_code_format"


class TestRecoveryVerifyCodeSecurityChecks:
    """Tests for security validations."""

    @mock_aws
    def test_rejects_invalid_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject invalid recovery code with generic error."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        _, hashed_codes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-invalid"
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
                    "recovery_code": "1111-2222-3333-4444",  # Wrong code
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_code"

    @mock_aws
    def test_rejects_expired_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-expired"
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
                    "recovery_code": plaintext_codes[0],
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
    def test_rejects_nonexistent_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject non-existent recovery session."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "nonexistent-session",
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_session"

    @mock_aws
    def test_rejects_no_recovery_codes_set(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject when no recovery codes are set up."""
        table, test_key = seeded_api_keys_table

        # Create USER_META without recovery codes
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

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


class TestRecoveryVerifyCodeRaceConditions:
    """Tests for race condition handling."""

    @mock_aws
    def test_same_code_cannot_be_used_twice(self, mock_dynamodb, seeded_api_keys_table):
        """Should prevent the same code from being used twice."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        # Create first session
        session_id1 = "test-session-race-1"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id1}",
                "email": "test@example.com",
                "recovery_session_id": session_id1,
                "verified": False,
                "ttl": int((now + timedelta(hours=1)).timestamp()),
            }
        )

        from api.recovery_verify_code import handler

        event1 = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id1,
                    "recovery_code": plaintext_codes[0],
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # First use should succeed
        with patch("time.sleep"):
            response1 = handler(event1, None)
        assert response1["statusCode"] == 200

        # Create second session
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

        # Second use should fail
        with patch("time.sleep"):
            response2 = handler(event2, None)
        assert response2["statusCode"] == 400

    @mock_aws
    def test_handles_concurrent_modification_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle race condition when consuming recovery code."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=4)

        session_id = "test-session-race"
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

        # Mock update_item to raise ConditionalCheckFailedException
        with patch("time.sleep"), patch("api.recovery_verify_code.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.return_value.Table.return_value = mock_table
            mock_table.query.return_value = {
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


class TestRecoveryVerifyCodeErrorHandling:
    """Tests for error handling."""

    @mock_aws
    def test_handles_dynamo_scan_error(self, mock_dynamodb):
        """Should handle DynamoDB scan error gracefully."""
        from api.recovery_verify_code import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": "test-session",
                    "recovery_code": "AAAA-BBBB-CCCC-DDDD",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_verify_code.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.return_value.Table.return_value = mock_table
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_user_meta_fetch_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB get_item error for USER_META."""
        session_id = "test-session-error"
        now = datetime.now(timezone.utc)

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

        with patch("time.sleep"), patch("api.recovery_verify_code.get_dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.return_value.Table.return_value = mock_table
            mock_table.query.return_value = {
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
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "GetItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryCodeNormalization:
    """Tests for recovery code format handling."""

    @mock_aws
    def test_accepts_code_without_dashes(self, mock_dynamodb, seeded_api_keys_table):
        """Should accept recovery code without dashes."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=2)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-nodash"
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

        # Remove dashes from code
        code_without_dashes = plaintext_codes[0].replace("-", "")

        event = {
            "body": json.dumps(
                {
                    "recovery_session_id": session_id,
                    "recovery_code": code_without_dashes,
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200

    @mock_aws
    def test_accepts_lowercase_code(self, mock_dynamodb, seeded_api_keys_table):
        """Should accept lowercase recovery code."""
        table, test_key = seeded_api_keys_table

        from shared.recovery_utils import generate_recovery_codes

        plaintext_codes, hashed_codes = generate_recovery_codes(count=2)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
            }
        )

        session_id = "test-session-lowercase"
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
                    "recovery_code": plaintext_codes[0].lower(),
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
