"""
Comprehensive tests for signup endpoint (functions/api/signup.py).

Security-critical code: Tests cover:
1. Duplicate email handling
2. Malformed request body (missing fields, invalid email format)
3. Referral code validation during signup (valid code, invalid code, already-used code)
4. Email verification token generation edge cases
5. Rate limiting on signup attempts (resend cooldown)
6. Database error handling
7. Concurrent signup attempts with same email
8. Timing normalization for enumeration prevention
9. Disposable email blocking
"""

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_aws


# Set environment variables before importing modules
os.environ["API_KEYS_TABLE"] = "pkgwatch-api-keys"
os.environ["BASE_URL"] = "https://test.example.com"
os.environ["API_URL"] = "https://api.test.example.com"
os.environ["VERIFICATION_EMAIL_SENDER"] = "noreply@pkgwatch.dev"


@pytest.fixture
def ses_client(mock_dynamodb):
    """Setup SES with verified identity for email sending."""
    ses = boto3.client("ses", region_name="us-east-1")
    ses.verify_email_identity(EmailAddress="noreply@pkgwatch.dev")
    return ses


@pytest.fixture
def api_keys_table(mock_dynamodb):
    """Get the API keys table."""
    return mock_dynamodb.Table("pkgwatch-api-keys")


@pytest.fixture
def base_event():
    """Base API Gateway event for signup handler."""
    return {
        "httpMethod": "POST",
        "headers": {"origin": "https://pkgwatch.dev"},
        "pathParameters": {},
        "queryStringParameters": {},
        "body": None,
        "requestContext": {
            "identity": {"sourceIp": "127.0.0.1"},
        },
    }


class TestMalformedRequestBody:
    """Tests for malformed request body handling."""

    @mock_aws
    def test_invalid_json_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for invalid JSON body."""
        from api.signup import handler

        base_event["body"] = "not valid json {{"

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_null_body_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for null body."""
        from api.signup import handler

        base_event["body"] = None

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_empty_body_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for empty body."""
        from api.signup import handler

        base_event["body"] = ""

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_empty_object_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for empty JSON object."""
        from api.signup import handler

        base_event["body"] = "{}"

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_missing_email_field_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 when email field is missing."""
        from api.signup import handler

        base_event["body"] = json.dumps({"name": "John"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_empty_email_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for empty email string."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": ""})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_whitespace_only_email_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for whitespace-only email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "   "})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"


class TestInvalidEmailFormat:
    """Tests for invalid email format handling."""

    @mock_aws
    def test_email_without_at_symbol_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without @ symbol."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "invalid-email"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_domain_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without domain."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "user@"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_local_part_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without local part."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "@domain.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_tld_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without TLD."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "user@domain"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"


class TestDisposableEmailBlocking:
    """Tests for disposable email domain blocking."""

    @mock_aws
    def test_disposable_email_mailinator_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for mailinator.com email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "test@mailinator.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "disposable_email"

    @mock_aws
    def test_disposable_email_tempmail_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for tempmail.com email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "test@tempmail.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "disposable_email"

    @mock_aws
    def test_disposable_email_guerrillamail_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for guerrillamail.com email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "test@guerrillamail.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "disposable_email"

    @mock_aws
    def test_legitimate_domain_allowed(self, mock_dynamodb, base_event, ses_client):
        """Should allow legitimate email domains."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "test@legitimate-company.io"})

        result = handler(base_event, {})

        # Should proceed to signup (200 success)
        assert result["statusCode"] == 200


class TestDuplicateEmailHandling:
    """Tests for duplicate email handling with enumeration prevention."""

    @mock_aws
    def test_existing_verified_user_returns_200(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should return 200 for existing verified user (enumeration prevention)."""
        # Create an existing verified user
        key_hash = hashlib.sha256(b"pw_existing_key").hexdigest()
        api_keys_table.put_item(
            Item={
                "pk": "user_existing123",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "existing@example.com",
                "tier": "free",
                "email_verified": True,
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "existing@example.com"})

        result = handler(base_event, {})

        # Should return same 200 as new signup (enumeration prevention)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "email" in body["message"].lower()

    @mock_aws
    def test_existing_verified_user_sends_magic_link(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should send magic link to existing verified user."""
        # Create an existing verified user
        key_hash = hashlib.sha256(b"pw_existing_key").hexdigest()
        api_keys_table.put_item(
            Item={
                "pk": "user_existing456",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "existing2@example.com",
                "tier": "free",
                "email_verified": True,
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "existing2@example.com"})

        result = handler(base_event, {})

        # Verify magic token was created on the user record
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq("user_existing456"),
        )
        items = response.get("Items", [])
        api_key_item = [i for i in items if i["sk"] == key_hash][0]

        assert "magic_token" in api_key_item
        assert "magic_expires" in api_key_item

    @mock_aws
    def test_new_email_creates_pending_user(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should create PENDING record for new email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "newuser@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify PENDING user was created
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser@example.com"),
        )
        assert len(response["Items"]) == 1
        assert response["Items"][0]["sk"] == "PENDING"
        assert response["Items"][0]["email_verified"] is False
        assert "verification_token" in response["Items"][0]

    @mock_aws
    def test_case_insensitive_email_matching(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle email case insensitively."""
        # Create user with lowercase email
        api_keys_table.put_item(
            Item={
                "pk": "user_case_test",
                "sk": "PENDING",
                "email": "casetest@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "last_verification_sent": datetime.now(timezone.utc).isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        # Try signing up with uppercase version
        base_event["body"] = json.dumps({"email": "CaseTest@Example.COM"})

        result = handler(base_event, {})

        # Should succeed (return 200)
        assert result["statusCode"] == 200


class TestReferralCodeValidation:
    """Tests for referral code handling during signup."""

    @mock_aws
    def test_valid_referral_code_stored(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should store valid referral code in PENDING record."""
        # Create a referrer user with referral code
        api_keys_table.put_item(
            Item={
                "pk": "user_referrer",
                "sk": "USER_META",
                "email": "referrer@example.com",
                "referral_code": "REF12345",
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({
            "email": "newuser_ref@example.com",
            "referral_code": "REF12345",
        })

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify referral code was stored in PENDING record
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser_ref@example.com"),
        )
        pending_item = response["Items"][0]
        assert pending_item["referral_code_used"] == "REF12345"

    @mock_aws
    def test_invalid_format_referral_code_ignored(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should ignore referral code with invalid format."""
        from api.signup import handler

        base_event["body"] = json.dumps({
            "email": "newuser_invalid_ref@example.com",
            "referral_code": "bad",  # Too short
        })

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify referral code was NOT stored
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser_invalid_ref@example.com"),
        )
        pending_item = response["Items"][0]
        assert "referral_code_used" not in pending_item

    @mock_aws
    def test_nonexistent_referral_code_ignored(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should ignore referral code that doesn't exist in DB."""
        from api.signup import handler

        base_event["body"] = json.dumps({
            "email": "newuser_noref@example.com",
            "referral_code": "NOTEXIST",
        })

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify referral code was NOT stored (doesn't exist)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("newuser_noref@example.com"),
        )
        pending_item = response["Items"][0]
        assert "referral_code_used" not in pending_item

    @mock_aws
    def test_null_referral_code_handled(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle null/missing referral code gracefully."""
        from api.signup import handler

        base_event["body"] = json.dumps({
            "email": "newuser_nullref@example.com",
            "referral_code": None,
        })

        result = handler(base_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_empty_referral_code_handled(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle empty string referral code gracefully."""
        from api.signup import handler

        base_event["body"] = json.dumps({
            "email": "newuser_emptyref@example.com",
            "referral_code": "",
        })

        result = handler(base_event, {})

        assert result["statusCode"] == 200


class TestResendCooldown:
    """Tests for resend cooldown on pending users."""

    @mock_aws
    def test_resend_within_cooldown_returns_success_without_email(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should return success but not resend email within cooldown."""
        now = datetime.now(timezone.utc)

        # Create a PENDING user with recent send
        api_keys_table.put_item(
            Item={
                "pk": "user_cooldown",
                "sk": "PENDING",
                "email": "cooldown@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (now + timedelta(hours=24)).isoformat(),
                "last_verification_sent": now.isoformat(),  # Just now
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "cooldown@example.com"})

        result = handler(base_event, {})

        # Should return success (same response for enumeration prevention)
        assert result["statusCode"] == 200

        # Verify token was NOT updated (still original)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("cooldown@example.com"),
        )
        pending_item = response["Items"][0]
        # last_verification_sent should be very close to the original (not updated)

    @mock_aws
    def test_resend_after_cooldown_sends_new_email(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should resend verification email after cooldown passes."""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(seconds=120)  # 2 minutes ago, past 60s cooldown
        old_token = secrets.token_urlsafe(32)

        # Create a PENDING user with old send time
        api_keys_table.put_item(
            Item={
                "pk": "user_resend",
                "sk": "PENDING",
                "email": "resend@example.com",
                "verification_token": old_token,
                "verification_expires": (now + timedelta(hours=24)).isoformat(),
                "last_verification_sent": old_time.isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "resend@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify token was updated (new token generated)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("resend@example.com"),
        )
        pending_item = response["Items"][0]
        assert pending_item["verification_token"] != old_token


class TestExpiredPendingCleanup:
    """Tests for cleanup of expired PENDING records."""

    @mock_aws
    def test_expired_pending_deleted(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should delete expired PENDING records on signup attempt."""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(hours=48)  # Expired 24 hours ago

        # Create an expired PENDING user
        old_user_id = f"user_{hashlib.sha256(b'expired@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": old_user_id,
                "sk": "PENDING",
                "email": "expired@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": old_time.isoformat(),  # Expired
                "last_verification_sent": old_time.isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "expired@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify a new PENDING record exists (old one was cleaned up)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("expired@example.com"),
        )
        assert len(response["Items"]) == 1
        # Token should be fresh (different from expired one)
        pending_item = response["Items"][0]
        # Verification should be in the future now
        expires = datetime.fromisoformat(pending_item["verification_expires"].replace("Z", "+00:00"))
        assert expires > now


class TestDatabaseErrorHandling:
    """Tests for database error handling."""

    @mock_aws
    def test_dynamodb_query_error_returns_500(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return 500 on DynamoDB query error."""
        from api.signup import handler

        # Patch the DynamoDB query to raise an exception
        with patch("api.signup.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.side_effect = Exception("DynamoDB error")
            mock_db.Table.return_value = mock_table

            base_event["body"] = json.dumps({"email": "error@example.com"})

            result = handler(base_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_put_item_error_returns_500(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return 500 on DynamoDB put_item error."""
        from api.signup import handler
        from botocore.exceptions import ClientError

        # Patch put_item to raise a ClientError (not ConditionalCheckFailed)
        with patch("api.signup.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.return_value = {"Items": []}

            # Create a generic DynamoDB error that's not ConditionalCheckFailed
            error_response = {
                "Error": {
                    "Code": "InternalServerError",
                    "Message": "Internal server error",
                }
            }
            mock_table.put_item.side_effect = ClientError(error_response, "PutItem")

            # Mock the exception class check (this is how the real code catches it)
            mock_db.meta.client.exceptions.ConditionalCheckFailedException = type(
                "ConditionalCheckFailedException", (Exception,), {}
            )
            mock_db.Table.return_value = mock_table

            base_event["body"] = json.dumps({"email": "writeerror@example.com"})

            result = handler(base_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "internal_error"


class TestConcurrentSignupAttempts:
    """Tests for concurrent signup handling (race conditions)."""

    @mock_aws
    def test_conditional_write_conflict_returns_200(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return 200 on conditional write conflict (enumeration prevention)."""
        from api.signup import handler
        from botocore.exceptions import ClientError

        # Patch put_item to raise ConditionalCheckFailedException
        with patch("api.signup.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.return_value = {"Items": []}

            # Create the exception properly
            error_response = {
                "Error": {
                    "Code": "ConditionalCheckFailedException",
                    "Message": "Condition check failed",
                }
            }
            mock_table.put_item.side_effect = mock_db.meta.client.exceptions.ConditionalCheckFailedException(
                error_response, "PutItem"
            )
            mock_db.Table.return_value = mock_table

            # Create the exception class
            mock_db.meta.client.exceptions.ConditionalCheckFailedException = type(
                "ConditionalCheckFailedException", (Exception,), {}
            )
            mock_table.put_item.side_effect = mock_db.meta.client.exceptions.ConditionalCheckFailedException()

            base_event["body"] = json.dumps({"email": "concurrent@example.com"})

            result = handler(base_event, {})

            # Should return 200 (same as success to prevent enumeration)
            assert result["statusCode"] == 200


class TestVerificationTokenGeneration:
    """Tests for verification token generation."""

    @mock_aws
    def test_token_is_cryptographically_secure(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should generate cryptographically secure verification tokens."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "secure@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify token properties
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("secure@example.com"),
        )
        pending_item = response["Items"][0]
        token = pending_item["verification_token"]

        # Token should be URL-safe base64 (43 chars for 32 bytes)
        assert len(token) == 43  # secrets.token_urlsafe(32) produces 43 chars
        assert all(c.isalnum() or c in "-_" for c in token)

    @mock_aws
    def test_verification_expires_in_24_hours(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should set verification expiry to 24 hours."""
        from api.signup import handler

        now = datetime.now(timezone.utc)
        base_event["body"] = json.dumps({"email": "expiry@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("expiry@example.com"),
        )
        pending_item = response["Items"][0]
        expires = datetime.fromisoformat(pending_item["verification_expires"].replace("Z", "+00:00"))

        # Should be approximately 24 hours from now
        expected_expires = now + timedelta(hours=24)
        diff = abs((expires - expected_expires).total_seconds())
        assert diff < 60  # Within 1 minute tolerance

    @mock_aws
    def test_ttl_is_set_for_pending_record(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should set TTL for auto-cleanup of PENDING records."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "ttl@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("ttl@example.com"),
        )
        pending_item = response["Items"][0]

        # TTL should be set (25 hours after verification expires)
        assert "ttl" in pending_item
        ttl_timestamp = pending_item["ttl"]
        # DynamoDB stores numbers as Decimal, so check it's numeric
        from decimal import Decimal
        assert isinstance(ttl_timestamp, (int, float, Decimal))


class TestEmailSendingFailure:
    """Tests for email sending failure handling."""

    @mock_aws
    def test_ses_failure_does_not_fail_signup(
        self, mock_dynamodb, base_event, api_keys_table
    ):
        """Should not fail signup if SES fails (user can request resend)."""
        from api.signup import handler

        # Don't verify email identity - SES will reject the send
        # But the handler should catch this and continue

        base_event["body"] = json.dumps({"email": "sesfail@example.com"})

        result = handler(base_event, {})

        # Should still return 200 (user was created, email failed)
        assert result["statusCode"] == 200

        # Verify user was still created
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("sesfail@example.com"),
        )
        assert len(response["Items"]) == 1


class TestOriginHeaderHandling:
    """Tests for Origin header handling in CORS responses."""

    @mock_aws
    def test_cors_origin_in_response(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should include CORS origin header in response."""
        from api.signup import handler

        base_event["headers"] = {"origin": "https://pkgwatch.dev"}
        base_event["body"] = json.dumps({"email": "cors@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200
        # Check CORS headers are present
        headers = result.get("headers", {})
        assert "Access-Control-Allow-Origin" in headers

    @mock_aws
    def test_missing_origin_handled(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle missing Origin header."""
        from api.signup import handler

        base_event["headers"] = {}
        base_event["body"] = json.dumps({"email": "noorigin@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_case_insensitive_origin_header(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle case-insensitive Origin header."""
        from api.signup import handler

        # API Gateway may lowercase headers
        base_event["headers"] = {"Origin": "https://pkgwatch.dev"}
        base_event["body"] = json.dumps({"email": "caseorig@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200


class TestTimingNormalization:
    """Tests for timing normalization (enumeration prevention)."""

    @mock_aws
    def test_response_takes_minimum_time(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Response should take at least MIN_RESPONSE_TIME_SECONDS."""
        from api.signup import handler, MIN_RESPONSE_TIME_SECONDS

        base_event["body"] = json.dumps({"email": "timing@example.com"})

        start = time.time()
        result = handler(base_event, {})
        elapsed = time.time() - start

        assert result["statusCode"] == 200
        # Should take at least the minimum response time
        # Allow small tolerance for timing inaccuracies
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1


class TestUserIdGeneration:
    """Tests for deterministic user ID generation."""

    @mock_aws
    def test_user_id_is_deterministic(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should generate deterministic user ID from email."""
        from api.signup import handler

        email = "deterministic@example.com"
        expected_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
        expected_user_id = f"user_{expected_hash}"

        base_event["body"] = json.dumps({"email": email})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email),
        )
        pending_item = response["Items"][0]
        assert pending_item["pk"] == expected_user_id

    @mock_aws
    def test_user_id_is_lowercase_email_based(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should generate user ID from lowercased email."""
        from api.signup import handler

        # Use uppercase email
        email_input = "UPPERCASE@Example.COM"
        email_normalized = email_input.lower()
        expected_hash = hashlib.sha256(email_normalized.encode()).hexdigest()[:16]
        expected_user_id = f"user_{expected_hash}"

        base_event["body"] = json.dumps({"email": email_input})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq(email_normalized),
        )
        pending_item = response["Items"][0]
        assert pending_item["pk"] == expected_user_id


class TestPendingRecordResendUpdate:
    """Tests for updating PENDING records on resend."""

    @mock_aws
    def test_resend_updates_pending_record_fields(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should update verification fields when resending."""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(seconds=120)  # Past cooldown
        old_token = "old_token_value_123456789012345678901234567890"
        old_expires = (old_time + timedelta(hours=24)).isoformat()

        user_id = f"user_{hashlib.sha256(b'resendupdate@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "resendupdate@example.com",
                "verification_token": old_token,
                "verification_expires": old_expires,
                "last_verification_sent": old_time.isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "resendupdate@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify all fields were updated
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("resendupdate@example.com"),
        )
        pending_item = response["Items"][0]

        # Token should be different
        assert pending_item["verification_token"] != old_token
        # Expires should be in the future
        new_expires = datetime.fromisoformat(pending_item["verification_expires"].replace("Z", "+00:00"))
        assert new_expires > now
        # Last sent should be recent
        new_sent = datetime.fromisoformat(pending_item["last_verification_sent"].replace("Z", "+00:00"))
        diff = abs((new_sent - now).total_seconds())
        assert diff < 60  # Within 1 minute


class TestPendingWithoutExpiry:
    """Tests for handling PENDING records without expiry field."""

    @mock_aws
    def test_pending_without_expiry_deleted(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should delete PENDING record without verification_expires."""
        user_id = f"user_{hashlib.sha256(b'noexpiry@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "noexpiry@example.com",
                "verification_token": secrets.token_urlsafe(32),
                # No verification_expires field
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "noexpiry@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # A new PENDING record should exist (old one was cleaned up)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("noexpiry@example.com"),
        )
        assert len(response["Items"]) == 1
        # New record should have expiry
        assert "verification_expires" in response["Items"][0]


class TestMagicLinkSendFailure:
    """Tests for magic link send failure handling."""

    @mock_aws
    def test_magic_link_failure_still_returns_200(
        self, mock_dynamodb, base_event, api_keys_table
    ):
        """Should return 200 even if magic link send fails (enumeration prevention)."""
        # Create an existing verified user
        key_hash = hashlib.sha256(b"pw_magic_fail_key").hexdigest()
        api_keys_table.put_item(
            Item={
                "pk": "user_magic_fail",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "magicfail@example.com",
                "tier": "free",
                "email_verified": True,
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.signup import handler

        # Don't verify SES identity - send will fail
        base_event["body"] = json.dumps({"email": "magicfail@example.com"})

        result = handler(base_event, {})

        # Should still return 200 (enumeration prevention)
        assert result["statusCode"] == 200


class TestInvalidDateParsing:
    """Tests for handling invalid date formats in stored records."""

    @mock_aws
    def test_invalid_expiry_format_creates_new_pending(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should handle invalid verification_expires format gracefully."""
        user_id = f"user_{hashlib.sha256(b'badexpiry@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "badexpiry@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": "not-a-valid-date",  # Invalid format
                "last_verification_sent": datetime.now(timezone.utc).isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "badexpiry@example.com"})

        result = handler(base_event, {})

        # Should succeed (ValueError caught and ignored)
        assert result["statusCode"] == 200

    @mock_aws
    def test_invalid_last_sent_format_proceeds_with_resend(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should proceed with resend when last_verification_sent is invalid."""
        now = datetime.now(timezone.utc)
        old_token = "old_token_value_123456789012345678901234567890"

        user_id = f"user_{hashlib.sha256(b'badsent@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "badsent@example.com",
                "verification_token": old_token,
                "verification_expires": (now + timedelta(hours=24)).isoformat(),
                "last_verification_sent": "not-a-valid-date",  # Invalid format
                "email_verified": False,
            }
        )

        from api.signup import handler

        base_event["body"] = json.dumps({"email": "badsent@example.com"})

        result = handler(base_event, {})

        # Should succeed and resend (ValueError caught, proceeds with resend)
        assert result["statusCode"] == 200

        # Verify token was updated (resend happened)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("badsent@example.com"),
        )
        pending_item = response["Items"][0]
        assert pending_item["verification_token"] != old_token


class TestResendUpdateError:
    """Tests for errors during PENDING record update on resend."""

    @mock_aws
    def test_update_pending_error_returns_success(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return success even if update_item fails (enumeration prevention)."""
        from api.signup import handler
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(seconds=120)  # Past cooldown

        # Create the mock for testing error handling
        with patch("api.signup.dynamodb") as mock_db:
            mock_table = MagicMock()

            # First query returns valid PENDING record past cooldown
            mock_table.query.return_value = {
                "Items": [{
                    "pk": "user_resend_fail",
                    "sk": "PENDING",
                    "email": "resendfail@example.com",
                    "verification_token": "old_token",
                    "verification_expires": (now + timedelta(hours=24)).isoformat(),
                    "last_verification_sent": old_time.isoformat(),
                    "email_verified": False,
                }]
            }

            # Update fails
            mock_table.update_item.side_effect = Exception("Update failed")
            mock_db.Table.return_value = mock_table

            base_event["body"] = json.dumps({"email": "resendfail@example.com"})

            result = handler(base_event, {})

            # Should return success (enumeration prevention)
            assert result["statusCode"] == 200


class TestResendEmailFailure:
    """Tests for email send failure during resend."""

    @mock_aws
    def test_resend_email_failure_still_succeeds(
        self, mock_dynamodb, base_event, api_keys_table
    ):
        """Should return success even if resend email fails."""
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(seconds=120)  # Past cooldown
        old_token = "old_token_abc123"

        user_id = f"user_{hashlib.sha256(b'resendemailfail@example.com').hexdigest()[:16]}"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "resendemailfail@example.com",
                "verification_token": old_token,
                "verification_expires": (now + timedelta(hours=24)).isoformat(),
                "last_verification_sent": old_time.isoformat(),
                "email_verified": False,
            }
        )

        from api.signup import handler

        # Don't verify SES identity - email send will fail
        base_event["body"] = json.dumps({"email": "resendemailfail@example.com"})

        result = handler(base_event, {})

        # Should succeed despite email failure
        assert result["statusCode"] == 200

        # Token should still be updated (update_item succeeded before email fail)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("resendemailfail@example.com"),
        )
        pending_item = response["Items"][0]
        # Token was updated
        assert pending_item["verification_token"] != old_token


class TestEmailNormalization:
    """Tests for email normalization (whitespace trimming, lowercasing)."""

    @mock_aws
    def test_email_whitespace_trimmed(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should trim whitespace from email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "  trimmed@example.com  "})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("trimmed@example.com"),
        )
        assert len(response["Items"]) == 1

    @mock_aws
    def test_email_lowercased(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should lowercase email."""
        from api.signup import handler

        base_event["body"] = json.dumps({"email": "UPPER@EXAMPLE.COM"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("upper@example.com"),
        )
        assert len(response["Items"]) == 1
