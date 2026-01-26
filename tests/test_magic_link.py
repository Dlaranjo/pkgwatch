"""
Comprehensive tests for magic link endpoint (functions/api/magic_link.py).

Security-critical code: Tests cover:
1. Valid magic link generation for verified users
2. Invalid/missing email handling
3. Timing normalization to prevent email enumeration attacks
4. Non-existent email handling (same response as existing for enumeration prevention)
5. Unverified/PENDING user handling
6. Email validation (format, missing @ symbol, etc.)
7. Database error handling
8. SES email send failure handling (silent, for enumeration prevention)
9. Origin header and CORS handling
10. Magic token storage and expiration
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
os.environ["LOGIN_EMAIL_SENDER"] = "noreply@pkgwatch.dev"


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
    """Base API Gateway event for magic link handler."""
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


@pytest.fixture
def verified_user(api_keys_table):
    """Create a verified user in the database."""
    key_hash = hashlib.sha256(b"pw_verified_user_key").hexdigest()
    user_id = "user_verified123"
    api_keys_table.put_item(
        Item={
            "pk": user_id,
            "sk": key_hash,
            "key_hash": key_hash,
            "email": "verified@example.com",
            "tier": "free",
            "email_verified": True,
            "created_at": "2024-01-01T00:00:00Z",
        }
    )
    return {"user_id": user_id, "key_hash": key_hash, "email": "verified@example.com"}


class TestValidMagicLinkGeneration:
    """Tests for valid magic link generation."""

    @mock_aws
    def test_generates_magic_link_for_verified_user(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should generate and store magic link for verified user."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "message" in body
        assert "email" in body["message"].lower()

        # Verify magic token was stored on user record
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        items = response.get("Items", [])
        api_key_item = [i for i in items if i["sk"] == verified_user["key_hash"]][0]

        assert "magic_token" in api_key_item
        assert "magic_expires" in api_key_item

        # Token should be URL-safe
        token = api_key_item["magic_token"]
        assert len(token) == 43  # secrets.token_urlsafe(32) produces 43 chars
        assert all(c.isalnum() or c in "-_" for c in token)

    @mock_aws
    def test_magic_token_expires_in_15_minutes(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should set magic link expiry to 15 minutes."""
        from api.magic_link import handler

        now = datetime.now(timezone.utc)
        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]
        expires = datetime.fromisoformat(api_key_item["magic_expires"].replace("Z", "+00:00"))

        # Should be approximately 15 minutes from now
        expected_expires = now + timedelta(minutes=15)
        diff = abs((expires - expected_expires).total_seconds())
        assert diff < 60  # Within 1 minute tolerance

    @mock_aws
    def test_email_case_insensitive_lookup(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should handle email lookup case insensitively."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "VERIFIED@EXAMPLE.COM"})

        result = handler(base_event, {})

        # Should succeed - email normalized to lowercase
        assert result["statusCode"] == 200

        # Verify magic token was stored
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]
        assert "magic_token" in api_key_item


class TestInvalidEmailHandling:
    """Tests for invalid/missing email handling."""

    @mock_aws
    def test_missing_email_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 when email is missing."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_empty_email_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for empty email string."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": ""})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_whitespace_only_email_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for whitespace-only email."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "   "})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_at_symbol_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without @ symbol."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "invalid-email"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_domain_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without domain."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "user@"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_email_without_tld_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for email without TLD."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "user@domain"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_invalid_json_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for invalid JSON body."""
        from api.magic_link import handler

        base_event["body"] = "not valid json {{"

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_null_body_returns_400(self, mock_dynamodb, base_event):
        """Should return 400 for null body."""
        from api.magic_link import handler

        base_event["body"] = None

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        body = json.loads(result["body"])
        assert body["error"]["code"] == "invalid_email"


class TestTimingNormalization:
    """Tests for timing normalization (enumeration prevention)."""

    @mock_aws
    def test_response_takes_minimum_time_for_existing_user(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Response should take at least MIN_RESPONSE_TIME_SECONDS for existing user."""
        from api.magic_link import handler, MIN_RESPONSE_TIME_SECONDS

        base_event["body"] = json.dumps({"email": "verified@example.com"})

        start = time.time()
        result = handler(base_event, {})
        elapsed = time.time() - start

        assert result["statusCode"] == 200
        # Should take at least the minimum response time (with tolerance for timing inaccuracies)
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1

    @mock_aws
    def test_response_takes_minimum_time_for_nonexistent_user(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Response should take at least MIN_RESPONSE_TIME_SECONDS for non-existent user."""
        from api.magic_link import handler, MIN_RESPONSE_TIME_SECONDS

        base_event["body"] = json.dumps({"email": "nonexistent@example.com"})

        start = time.time()
        result = handler(base_event, {})
        elapsed = time.time() - start

        assert result["statusCode"] == 200
        # Should take at least the minimum response time
        assert elapsed >= MIN_RESPONSE_TIME_SECONDS - 0.1

    @mock_aws
    def test_same_response_for_existing_and_nonexistent_emails(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should return identical response structure for existing and non-existing emails."""
        from api.magic_link import handler

        # Existing user
        base_event["body"] = json.dumps({"email": "verified@example.com"})
        result_existing = handler(base_event, {})

        # Non-existing user
        base_event["body"] = json.dumps({"email": "doesnotexist@example.com"})
        result_nonexistent = handler(base_event, {})

        # Both should be 200 with same message structure
        assert result_existing["statusCode"] == 200
        assert result_nonexistent["statusCode"] == 200

        body_existing = json.loads(result_existing["body"])
        body_nonexistent = json.loads(result_nonexistent["body"])

        # Same message structure (preventing enumeration)
        assert body_existing["message"] == body_nonexistent["message"]


class TestNonExistentUserHandling:
    """Tests for non-existent user handling (enumeration prevention)."""

    @mock_aws
    def test_nonexistent_email_returns_success(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return 200 for non-existent email (enumeration prevention)."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "unknown@example.com"})

        result = handler(base_event, {})

        # Should return success to prevent enumeration
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "message" in body

    @mock_aws
    def test_nonexistent_email_does_not_store_token(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should not create any database records for non-existent email."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "unknown@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify no records were created
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            IndexName="email-index",
            KeyConditionExpression=Key("email").eq("unknown@example.com"),
        )
        assert len(response.get("Items", [])) == 0


class TestUnverifiedUserHandling:
    """Tests for unverified/PENDING user handling."""

    @mock_aws
    def test_pending_user_returns_success_without_magic_link(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should return 200 for PENDING user but not send magic link."""
        # Create a PENDING user (not yet verified)
        user_id = "user_pending123"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "PENDING",
                "email": "pending@example.com",
                "verification_token": secrets.token_urlsafe(32),
                "verification_expires": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(),
                "email_verified": False,
            }
        )

        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "pending@example.com"})

        result = handler(base_event, {})

        # Should return success (same response for enumeration prevention)
        assert result["statusCode"] == 200

        # Verify no magic token was stored (user not verified)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        pending_item = [i for i in response["Items"] if i["sk"] == "PENDING"][0]
        assert "magic_token" not in pending_item

    @mock_aws
    def test_user_with_email_verified_false_returns_success_without_magic_link(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should not send magic link to user with email_verified=False."""
        key_hash = hashlib.sha256(b"pw_unverified_key").hexdigest()
        user_id = "user_unverified"
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unverified@example.com",
                "tier": "free",
                "email_verified": False,  # Not verified
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "unverified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify no magic token was stored
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == key_hash][0]
        assert "magic_token" not in api_key_item


class TestDatabaseErrorHandling:
    """Tests for database error handling."""

    @mock_aws
    def test_dynamodb_query_error_returns_500(
        self, mock_dynamodb, base_event, ses_client
    ):
        """Should return 500 on DynamoDB query error."""
        from api.magic_link import handler

        with patch("api.magic_link.dynamodb") as mock_db:
            mock_table = MagicMock()
            mock_table.query.side_effect = Exception("DynamoDB error")
            mock_db.Table.return_value = mock_table

            base_event["body"] = json.dumps({"email": "error@example.com"})

            result = handler(base_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_update_item_error_returns_500(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should return 500 on DynamoDB update_item error."""
        from api.magic_link import handler

        with patch("api.magic_link.dynamodb") as mock_db:
            mock_table = MagicMock()
            # Query succeeds
            mock_table.query.return_value = {
                "Items": [{
                    "pk": verified_user["user_id"],
                    "sk": verified_user["key_hash"],
                    "email": "verified@example.com",
                    "email_verified": True,
                }]
            }
            # Update fails
            mock_table.update_item.side_effect = Exception("Update failed")
            mock_db.Table.return_value = mock_table

            base_event["body"] = json.dumps({"email": "verified@example.com"})

            result = handler(base_event, {})

            assert result["statusCode"] == 500
            body = json.loads(result["body"])
            assert body["error"]["code"] == "internal_error"


class TestSESEmailFailureHandling:
    """Tests for SES email send failure handling."""

    @mock_aws
    def test_ses_failure_still_returns_success(
        self, mock_dynamodb, base_event, api_keys_table, verified_user
    ):
        """Should return 200 even if SES fails (enumeration prevention)."""
        from api.magic_link import handler

        # Don't verify SES identity - email send will fail
        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        # Should still return success (enumeration prevention)
        assert result["statusCode"] == 200

        # Magic token should still be stored
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]
        assert "magic_token" in api_key_item

    @mock_aws
    def test_ses_exception_caught_and_logged(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should catch SES exceptions and log them without failing."""
        from api.magic_link import handler

        with patch("api.magic_link.ses") as mock_ses:
            mock_ses.send_email.side_effect = Exception("SES error")

            base_event["body"] = json.dumps({"email": "verified@example.com"})

            result = handler(base_event, {})

            # Should still return success
            assert result["statusCode"] == 200


class TestOriginHeaderHandling:
    """Tests for Origin header and CORS handling."""

    @mock_aws
    def test_cors_origin_in_response(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should include CORS origin header in response."""
        from api.magic_link import handler

        base_event["headers"] = {"origin": "https://pkgwatch.dev"}
        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200
        headers = result.get("headers", {})
        assert "Access-Control-Allow-Origin" in headers

    @mock_aws
    def test_missing_origin_handled(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should handle missing Origin header."""
        from api.magic_link import handler

        base_event["headers"] = {}
        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_case_insensitive_origin_header(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should handle case-insensitive Origin header."""
        from api.magic_link import handler

        base_event["headers"] = {"Origin": "https://pkgwatch.dev"}
        base_event["body"] = json.dumps({"email": "verified@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

    @mock_aws
    def test_cors_in_error_response(self, mock_dynamodb, base_event):
        """Should include CORS headers in error responses."""
        from api.magic_link import handler

        base_event["headers"] = {"origin": "https://pkgwatch.dev"}
        base_event["body"] = json.dumps({"email": "invalid"})

        result = handler(base_event, {})

        assert result["statusCode"] == 400
        headers = result.get("headers", {})
        assert "Access-Control-Allow-Origin" in headers


class TestMagicTokenStorage:
    """Tests for magic token storage and overwrite behavior."""

    @mock_aws
    def test_new_magic_link_overwrites_existing(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Requesting new magic link should overwrite existing token."""
        from api.magic_link import handler

        # First request
        base_event["body"] = json.dumps({"email": "verified@example.com"})
        handler(base_event, {})

        # Get first token
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        first_token = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]["magic_token"]

        # Second request
        result = handler(base_event, {})
        assert result["statusCode"] == 200

        # Get second token
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        second_token = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]["magic_token"]

        # Tokens should be different (new token generated)
        assert first_token != second_token

    @mock_aws
    def test_magic_token_is_cryptographically_secure(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should generate cryptographically secure magic tokens."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "verified@example.com"})

        # Generate multiple tokens
        tokens = []
        for _ in range(5):
            handler(base_event, {})
            from boto3.dynamodb.conditions import Key
            response = api_keys_table.query(
                KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
            )
            token = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]["magic_token"]
            tokens.append(token)

        # All tokens should be unique
        assert len(set(tokens)) == 5

        # All tokens should be URL-safe (secrets.token_urlsafe format)
        for token in tokens:
            assert len(token) == 43
            assert all(c.isalnum() or c in "-_" for c in token)


class TestMultipleApiKeysUser:
    """Tests for users with multiple API keys."""

    @mock_aws
    def test_magic_link_uses_first_verified_record(
        self, mock_dynamodb, base_event, ses_client, api_keys_table
    ):
        """Should use first verified record found for user with multiple keys."""
        user_id = "user_multikey"

        # Create USER_META
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": "USER_META",
                "email": "multikey@example.com",
                "key_count": 2,
            }
        )

        # Create first API key (verified)
        key_hash_1 = hashlib.sha256(b"pw_key_1").hexdigest()
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash_1,
                "key_hash": key_hash_1,
                "email": "multikey@example.com",
                "tier": "free",
                "email_verified": True,
                "created_at": "2024-01-01T00:00:00Z",
            }
        )

        # Create second API key (also verified)
        key_hash_2 = hashlib.sha256(b"pw_key_2").hexdigest()
        api_keys_table.put_item(
            Item={
                "pk": user_id,
                "sk": key_hash_2,
                "key_hash": key_hash_2,
                "email": "multikey@example.com",
                "tier": "pro",
                "email_verified": True,
                "created_at": "2024-01-02T00:00:00Z",
            }
        )

        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "multikey@example.com"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify magic token was stored on one of the verified records
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(user_id),
        )

        # At least one record should have magic_token
        has_magic_token = any(
            "magic_token" in item
            for item in response["Items"]
            if item["sk"] not in ["USER_META", "PENDING"]
        )
        assert has_magic_token


class TestEmailNormalization:
    """Tests for email normalization."""

    @mock_aws
    def test_email_whitespace_trimmed(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should trim whitespace from email."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "  verified@example.com  "})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify magic token was stored (email matched after trimming)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]
        assert "magic_token" in api_key_item

    @mock_aws
    def test_email_lowercased(
        self, mock_dynamodb, base_event, ses_client, api_keys_table, verified_user
    ):
        """Should lowercase email for lookup."""
        from api.magic_link import handler

        base_event["body"] = json.dumps({"email": "VERIFIED@EXAMPLE.COM"})

        result = handler(base_event, {})

        assert result["statusCode"] == 200

        # Verify magic token was stored (email matched after lowercasing)
        from boto3.dynamodb.conditions import Key
        response = api_keys_table.query(
            KeyConditionExpression=Key("pk").eq(verified_user["user_id"]),
        )
        api_key_item = [i for i in response["Items"] if i["sk"] == verified_user["key_hash"]][0]
        assert "magic_token" in api_key_item


class TestNullHeadersHandling:
    """Tests for null headers edge case."""

    @mock_aws
    def test_null_headers_handled(self, mock_dynamodb, base_event):
        """Should handle null headers dict gracefully."""
        from api.magic_link import handler

        base_event["headers"] = None
        base_event["body"] = json.dumps({"email": "test@example.com"})

        # Should not crash
        result = handler(base_event, {})

        # Returns success (enumeration prevention for non-existent user)
        assert result["statusCode"] == 200
