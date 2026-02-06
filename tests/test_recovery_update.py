"""
Tests for email update flow in account recovery.

Tests cover:
- POST /recovery/update-email - Initiating email change
- GET /recovery/confirm-email - Completing email change

Security tests:
- Only recovery code verification allows email change (not API key)
- Email verification required before change takes effect
- Old email receives notification
- Token single-use and expiration
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


class TestRecoveryUpdateEmailValidFlow:
    """Tests for valid email update flow."""

    @mock_aws
    def test_sends_verification_email_for_valid_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should send verification email for valid recovery token."""
        table, test_key = seeded_api_keys_table

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
        assert "masked_new_email" in body
        # Should send both verification to new email and notification to old
        assert mock_ses.send_email.call_count == 2

    @mock_aws
    def test_creates_email_change_record(self, mock_dynamodb, seeded_api_keys_table):
        """Should create EMAIL_CHANGE record in database."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-record"
        recovery_token = "valid-token-456"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"RECOVERY_{session_id}",
                "email": "old@example.com",
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

        # Verify EMAIL_CHANGE record was created
        scan_result = table.scan(
            FilterExpression="begins_with(sk, :prefix)",
            ExpressionAttributeValues={":prefix": "EMAIL_CHANGE_"},
        )
        change_records = scan_result.get("Items", [])
        assert len(change_records) == 1

        change = change_records[0]
        assert change["old_email"] == "old@example.com"
        assert change["new_email"] == "new@example.com"
        assert "change_token" in change


class TestRecoveryUpdateEmailInputValidation:
    """Tests for input validation on email update."""

    @mock_aws
    def test_rejects_invalid_json(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_update_email import handler

        event = {
            "body": "invalid json{",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_rejects_missing_token(self, mock_dynamodb):
        """Should reject missing recovery_token."""
        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "new_email": "new@example.com",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_token"

    @mock_aws
    def test_rejects_missing_email(self, mock_dynamodb):
        """Should reject missing new_email."""
        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": "some-token",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "missing_email"

    @mock_aws
    def test_rejects_invalid_email_format(self, mock_dynamodb):
        """Should reject invalid email format."""
        from api.recovery_update_email import handler

        event = {
            "body": json.dumps(
                {
                    "recovery_token": "some-token",
                    "new_email": "not-an-email",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"


class TestRecoveryUpdateEmailSecurityChecks:
    """Tests for security validations."""

    @mock_aws
    def test_rejects_api_key_verified_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject email update from API key verified session."""
        table, test_key = seeded_api_keys_table

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
    def test_rejects_invalid_token(self, mock_dynamodb, seeded_api_keys_table):
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
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_token"

    @mock_aws
    def test_rejects_expired_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired recovery session."""
        table, test_key = seeded_api_keys_table

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
    def test_rejects_unverified_session(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject unverified recovery session."""
        table, test_key = seeded_api_keys_table

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
    def test_rejects_email_already_in_use(self, mock_dynamodb, seeded_api_keys_table):
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

        session_id = "test-session-in-use"
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
                    "new_email": "taken@example.com",
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
    def test_allows_changing_to_own_email(self, mock_dynamodb, seeded_api_keys_table):
        """Should allow changing to email already owned by same user (no-op)."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-same"
        recovery_token = "same-email-token-123"
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
                    "new_email": "test@example.com",  # Same as current
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = handler(event, None)

        # Should succeed - user owns this email
        assert response["statusCode"] == 200


class TestRecoveryUpdateEmailErrorHandling:
    """Tests for error handling."""

    @mock_aws
    def test_handles_dynamo_scan_error(self, mock_dynamodb):
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
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_continues_on_email_send_failure(self, mock_dynamodb, seeded_api_keys_table):
        """Should continue even if email send fails."""
        table, test_key = seeded_api_keys_table

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

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email.side_effect = Exception("SES failure")
            response = handler(event, None)

        # Should still return 200 since the record is created
        assert response["statusCode"] == 200


class TestRecoveryConfirmEmailValidFlow:
    """Tests for valid email confirmation flow."""

    @mock_aws
    def test_completes_email_change(self, mock_dynamodb, seeded_api_keys_table):
        """Should complete email change and create session."""
        table, test_key = seeded_api_keys_table

        change_token = "change-token-valid"
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

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
            mock_ses.send_email = MagicMock()

            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "Set-Cookie" in response["headers"]
        assert "session=" in response["headers"]["Set-Cookie"]
        assert "email_changed=true" in response["headers"]["Location"]

    @mock_aws
    def test_updates_all_user_records(self, mock_dynamodb, seeded_api_keys_table):
        """Should update email on all user API key records."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Add another API key for the same user
        second_key = "pw_second_key_12345"
        second_hash = hashlib.sha256(second_key.encode()).hexdigest()
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": second_hash,
                "key_hash": second_hash,
                "email": "test@example.com",
                "tier": "free",
            }
        )

        change_token = "change-token-multi"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "updated@example.com",
                "change_token": change_token,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
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

        # Verify both API key records were updated
        key1 = table.get_item(Key={"pk": "user_test123", "sk": key_hash})["Item"]
        key2 = table.get_item(Key={"pk": "user_test123", "sk": second_hash})["Item"]

        assert key1["email"] == "updated@example.com"
        assert key2["email"] == "updated@example.com"
        assert "email_changed_at" in key1
        assert key1["previous_email"] == "test@example.com"

    @mock_aws
    def test_sends_notification_to_old_email(self, mock_dynamodb, seeded_api_keys_table):
        """Should send notification to old email about the change."""
        table, test_key = seeded_api_keys_table

        change_token = "change-token-notify"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "old@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )

        from api.recovery_confirm_email import handler

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
            mock_ses.send_email = MagicMock()

            event = {"queryStringParameters": {"token": change_token}}
            handler(event, None)

        # Should send notification to old email
        mock_ses.send_email.assert_called_once()
        call_args = mock_ses.send_email.call_args
        assert "old@example.com" in call_args.kwargs["Destination"]["ToAddresses"]


class TestRecoveryConfirmEmailSecurityChecks:
    """Tests for security validations."""

    @mock_aws
    def test_rejects_missing_token(self, mock_dynamodb):
        """Should reject missing token parameter."""
        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
            event = {"queryStringParameters": {}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=missing_token" in response["headers"]["Location"]

    @mock_aws
    def test_rejects_invalid_token(self, mock_dynamodb):
        """Should reject invalid change token."""
        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
            event = {"queryStringParameters": {"token": "nonexistent-token"}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=invalid_token" in response["headers"]["Location"]

    @mock_aws
    def test_rejects_expired_token(self, mock_dynamodb, seeded_api_keys_table):
        """Should reject expired change token."""
        table, test_key = seeded_api_keys_table

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
            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=token_expired" in response["headers"]["Location"]

    @mock_aws
    def test_token_single_use(self, mock_dynamodb, seeded_api_keys_table):
        """Should prevent token reuse (single-use)."""
        table, test_key = seeded_api_keys_table

        change_token = "single-use-token"
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

        event = {"queryStringParameters": {"token": change_token}}

        # First use should succeed
        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
            patch("time.sleep"),
        ):
            mock_ses.send_email = MagicMock()
            response1 = handler(event, None)

        assert response1["statusCode"] == 302
        assert "email_changed=true" in response1["headers"]["Location"]

        # Second use should fail
        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"), patch("time.sleep"):
            response2 = handler(event, None)

        assert response2["statusCode"] == 302
        assert "error=invalid_token" in response2["headers"]["Location"]


class TestRecoveryConfirmEmailRaceConditions:
    """Tests for race condition handling in email confirmation."""

    @mock_aws
    def test_handles_concurrent_token_use(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle race condition when token is consumed concurrently."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        change_token = "race-condition-token"
        now = datetime.now(timezone.utc)

        from api.recovery_confirm_email import handler

        event = {"queryStringParameters": {"token": change_token}}

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
            # delete_item fails with ConditionalCheckFailed (already deleted)
            mock_table.delete_item.side_effect = ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "Already deleted"}}, "DeleteItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=invalid_token" in response["headers"]["Location"]


class TestRecoveryConfirmEmailErrorHandling:
    """Tests for error handling in email confirmation."""

    @mock_aws
    def test_handles_missing_session_secret(self, mock_dynamodb):
        """Should handle missing session secret."""
        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value=None):
            event = {"queryStringParameters": {"token": "some-token"}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_handles_dynamo_scan_error(self, mock_dynamodb):
        """Should handle DynamoDB scan error gracefully."""
        from api.recovery_confirm_email import handler

        event = {"queryStringParameters": {"token": "test-token"}}

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.dynamodb") as mock_ddb,
        ):
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.scan.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "Scan"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_handles_user_query_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB query error for user records."""
        table, test_key = seeded_api_keys_table

        change_token = "query-error-token"
        now = datetime.now(timezone.utc)

        from api.recovery_confirm_email import handler

        event = {"queryStringParameters": {"token": change_token}}

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
                {"Error": {"Code": "InternalServerError", "Message": "Test"}}, "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_handles_no_api_key_records(self, mock_dynamodb):
        """Should handle case where no API key records exist."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        change_token = "no-records-token"
        now = datetime.now(timezone.utc)
        table.put_item(
            Item={
                "pk": "user_orphan",
                "sk": f"EMAIL_CHANGE_{change_token}",
                "old_email": "test@example.com",
                "new_email": "new@example.com",
                "change_token": change_token,
                "ttl": int((now + timedelta(hours=24)).timestamp()),
            }
        )

        from api.recovery_confirm_email import handler

        with patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"):
            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "error=internal_error" in response["headers"]["Location"]

    @mock_aws
    def test_continues_on_notification_email_failure(self, mock_dynamodb, seeded_api_keys_table):
        """Should continue even if notification email fails."""
        table, test_key = seeded_api_keys_table

        change_token = "notify-fail-token"
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

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
            mock_ses.send_email.side_effect = Exception("SES failure")

            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        # Should still succeed despite email failure
        assert response["statusCode"] == 302
        assert "email_changed=true" in response["headers"]["Location"]


class TestRecoveryConfirmEmailSessionCreation:
    """Tests for session creation after email change."""

    @mock_aws
    def test_creates_session_with_correct_data(self, mock_dynamodb, seeded_api_keys_table):
        """Should create session with correct user data."""
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        # Update user to pro tier
        table.update_item(
            Key={"pk": "user_test123", "sk": key_hash},
            UpdateExpression="SET tier = :tier",
            ExpressionAttributeValues={":tier": "pro"},
        )

        change_token = "session-data-token"
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

        with (
            patch("api.recovery_confirm_email._get_session_secret", return_value="test-secret"),
            patch("api.recovery_confirm_email.ses") as mock_ses,
        ):
            mock_ses.send_email = MagicMock()

            event = {"queryStringParameters": {"token": change_token}}
            response = handler(event, None)

        assert response["statusCode"] == 302
        assert "Set-Cookie" in response["headers"]
        # Session cookie should be HttpOnly and Secure
        cookie = response["headers"]["Set-Cookie"]
        assert "HttpOnly" in cookie
        assert "Secure" in cookie
        assert "SameSite=Strict" in cookie


class TestRecoveryUpdateEmailNormalization:
    """Tests for email normalization."""

    @mock_aws
    def test_normalizes_email_to_lowercase(self, mock_dynamodb, seeded_api_keys_table):
        """Should normalize new email to lowercase."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-norm"
        recovery_token = "norm-token-123"
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
                    "new_email": "NEW@EXAMPLE.COM",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = handler(event, None)

        assert response["statusCode"] == 200

        # Check EMAIL_CHANGE record has lowercase email
        scan_result = table.scan(
            FilterExpression="begins_with(sk, :prefix)",
            ExpressionAttributeValues={":prefix": "EMAIL_CHANGE_"},
        )
        change = scan_result["Items"][0]
        assert change["new_email"] == "new@example.com"

    @mock_aws
    def test_strips_whitespace_from_email(self, mock_dynamodb, seeded_api_keys_table):
        """Should strip whitespace from new email."""
        table, test_key = seeded_api_keys_table

        session_id = "test-session-strip"
        recovery_token = "strip-token-123"
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
                    "new_email": "  new@example.com  ",
                }
            ),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), patch("api.recovery_update_email.ses") as mock_ses:
            mock_ses.send_email = MagicMock()
            response = handler(event, None)

        assert response["statusCode"] == 200

        # Check EMAIL_CHANGE record has trimmed email
        scan_result = table.scan(
            FilterExpression="begins_with(sk, :prefix)",
            ExpressionAttributeValues={":prefix": "EMAIL_CHANGE_"},
        )
        change = scan_result["Items"][0]
        assert change["new_email"] == "new@example.com"
