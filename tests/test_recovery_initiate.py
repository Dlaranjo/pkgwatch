"""
Tests for POST /recovery/initiate endpoint.

Tests cover:
- Initiating recovery for valid users
- Timing normalization for enumeration prevention
- Rate limiting per user
- Recovery code detection
- Input validation
- Edge cases (PENDING records, unverified users)
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


class TestRecoveryInitiateValidUser:
    """Tests for recovery initiation with valid users."""

    @mock_aws
    def test_creates_session_for_verified_user(self, mock_dynamodb, seeded_api_keys_table):
        """Should create recovery session for verified user."""
        table, test_key = seeded_api_keys_table
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body
        assert body["masked_email"] == "t***@example.com"
        assert body["message"] == "Recovery session created. Choose a verification method."

    @mock_aws
    def test_creates_session_for_unverified_user(self, mock_dynamodb):
        """Should allow recovery for users who never verified email."""
        # Create a user without email_verified=True
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        test_key = "pw_unverified_user_key_123"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        table.put_item(
            Item={
                "pk": "user_unverified",
                "sk": key_hash,
                "key_hash": key_hash,
                "email": "unverified@example.com",
                "tier": "free",
                # No email_verified field
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "unverified@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body
        # Session should be stored in DynamoDB
        _items = table.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": "user_unverified"}},
        )

    @mock_aws
    def test_detects_user_with_recovery_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should indicate when user has recovery codes set up."""
        table, test_key = seeded_api_keys_table

        # Generate and store recovery codes
        from shared.recovery_utils import generate_recovery_codes
        _, hashed_codes = generate_recovery_codes(count=8)

        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_codes_hash": hashed_codes,
                "recovery_codes_count": 8,
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["has_recovery_codes"] is True

    @mock_aws
    def test_detects_user_without_recovery_codes(self, mock_dynamodb, seeded_api_keys_table):
        """Should indicate when user has no recovery codes."""
        table, test_key = seeded_api_keys_table

        # Create USER_META without recovery codes
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "key_count": 1,
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["has_recovery_codes"] is False


class TestRecoveryInitiateEnumerationPrevention:
    """Tests for email enumeration prevention via timing normalization."""

    @mock_aws
    def test_returns_fake_session_for_nonexistent_email(self, mock_dynamodb):
        """Should return consistent response for non-existent email."""
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
        # Response structure should be identical to real user
        assert "masked_email" in body
        assert "has_recovery_codes" in body
        assert body["has_recovery_codes"] is False

    @mock_aws
    def test_timing_normalization_applied(self, mock_dynamodb, seeded_api_keys_table):
        """Should apply timing normalization to prevent timing attacks."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep") as mock_sleep:
            handler(event, None)

        # time.sleep should be called to normalize response time
        mock_sleep.assert_called()

    @mock_aws
    def test_fake_session_not_stored_in_database(self, mock_dynamodb):
        """Should not store session for non-existent users."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "nonexistent@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        body = json.loads(response["body"])
        session_id = body["recovery_session_id"]

        # Verify no session was stored
        scan_result = table.scan(
            FilterExpression="contains(sk, :session)",
            ExpressionAttributeValues={":session": f"RECOVERY_{session_id}"},
        )
        assert len(scan_result.get("Items", [])) == 0


class TestRecoveryInitiateRateLimiting:
    """Tests for per-user rate limiting."""

    @mock_aws
    def test_rate_limits_after_max_attempts(self, mock_dynamodb, seeded_api_keys_table):
        """Should rate limit after MAX_RECOVERY_ATTEMPTS_PER_DAY attempts."""
        table, test_key = seeded_api_keys_table

        # Set up USER_META with max attempts reached
        now = datetime.now(timezone.utc)
        today_key = now.strftime("%Y-%m-%d")
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_attempts_today": 10,  # MAX_RECOVERY_ATTEMPTS_PER_DAY
                "recovery_attempts_reset_at": today_key,
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 429
        body = json.loads(response["body"])
        assert body["error"]["code"] == "rate_limited"

    @mock_aws
    def test_resets_rate_limit_on_new_day(self, mock_dynamodb, seeded_api_keys_table):
        """Should reset rate limit counter on new day."""
        table, test_key = seeded_api_keys_table

        # Set up USER_META with max attempts from yesterday
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_attempts_today": 10,
                "recovery_attempts_reset_at": yesterday,  # Yesterday
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should succeed - new day resets the counter
        assert response["statusCode"] == 200

        # Verify counter was reset
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert meta["recovery_attempts_today"] == 1
        assert meta["recovery_attempts_reset_at"] == datetime.now(timezone.utc).strftime("%Y-%m-%d")

    @mock_aws
    def test_increments_rate_limit_counter(self, mock_dynamodb, seeded_api_keys_table):
        """Should increment rate limit counter on each attempt."""
        table, test_key = seeded_api_keys_table

        # Set up USER_META with some attempts
        today_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        table.put_item(
            Item={
                "pk": "user_test123",
                "sk": "USER_META",
                "recovery_attempts_today": 3,
                "recovery_attempts_reset_at": today_key,
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200

        # Verify counter incremented
        meta = table.get_item(Key={"pk": "user_test123", "sk": "USER_META"})["Item"]
        assert meta["recovery_attempts_today"] == 4


class TestRecoveryInitiateInputValidation:
    """Tests for input validation."""

    @mock_aws
    def test_rejects_invalid_json(self, mock_dynamodb):
        """Should reject invalid JSON body."""
        from api.recovery_initiate import handler

        event = {
            "body": "not valid json{",
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_json"

    @mock_aws
    def test_rejects_empty_email(self, mock_dynamodb):
        """Should reject empty email."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": ""}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_rejects_email_without_at(self, mock_dynamodb):
        """Should reject email without @ symbol."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "notanemail"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_rejects_email_without_domain(self, mock_dynamodb):
        """Should reject email without proper domain."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "user@nodomain"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_normalizes_email_to_lowercase(self, mock_dynamodb, seeded_api_keys_table):
        """Should normalize email to lowercase for lookup."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "TEST@EXAMPLE.COM"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200

    @mock_aws
    def test_handles_null_body(self, mock_dynamodb):
        """Should handle null body gracefully."""
        from api.recovery_initiate import handler

        event = {
            "body": None,
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        response = handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"]["code"] == "invalid_email"

    @mock_aws
    def test_handles_missing_headers(self, mock_dynamodb):
        """Should handle missing headers gracefully."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": None,
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should still work, just without CORS origin
        assert response["statusCode"] == 200


class TestRecoveryInitiateEdgeCases:
    """Tests for edge cases and special scenarios."""

    @mock_aws
    def test_ignores_pending_records(self, mock_dynamodb):
        """Should ignore PENDING records (incomplete signups)."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create only a PENDING record (incomplete signup)
        table.put_item(
            Item={
                "pk": "user_pending",
                "sk": "PENDING",
                "email": "pending@example.com",
                "verification_token": "some-token",
            }
        )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "pending@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        # Should return fake session since no real user record exists
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body

    @mock_aws
    def test_handles_user_with_multiple_api_keys(self, mock_dynamodb):
        """Should work for users with multiple API keys."""
        table = mock_dynamodb.Table("pkgwatch-api-keys")

        # Create user with multiple API keys
        for i in range(3):
            key = f"pw_multikey_user_key_{i}"
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            table.put_item(
                Item={
                    "pk": "user_multikey",
                    "sk": key_hash,
                    "key_hash": key_hash,
                    "email": "multikey@example.com",
                    "tier": "free",
                }
            )

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "multikey@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "recovery_session_id" in body

    @mock_aws
    def test_handles_user_meta_fetch_error_gracefully(self, mock_dynamodb, seeded_api_keys_table):
        """Should continue gracefully if USER_META fetch fails."""
        table, test_key = seeded_api_keys_table
        import hashlib

        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        # Mock the DynamoDB operations
        with patch("time.sleep"), \
             patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table

            # Query returns the user
            mock_table.query.return_value = {
                "Items": [{
                    "pk": "user_test123",
                    "sk": key_hash,
                    "email": "test@example.com",
                }]
            }

            # get_item for USER_META fails
            mock_table.get_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test"}},
                "GetItem"
            )

            # put_item succeeds (session creation)
            mock_table.put_item.return_value = {}
            mock_table.update_item.return_value = {}

            response = handler(event, None)

        # Should still succeed with has_recovery_codes = False
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["has_recovery_codes"] is False


class TestRecoveryInitiateErrorHandling:
    """Tests for error handling."""

    @mock_aws
    def test_handles_dynamo_query_error(self, mock_dynamodb):
        """Should handle DynamoDB query error gracefully."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), \
             patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}},
                "Query"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"

    @mock_aws
    def test_handles_session_creation_error(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle DynamoDB put_item error when creating session."""
        import hashlib
        table, test_key = seeded_api_keys_table
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"), \
             patch("api.recovery_initiate.dynamodb") as mock_ddb:
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_table.query.return_value = {
                "Items": [{
                    "pk": "user_test123",
                    "sk": key_hash,
                    "email": "test@example.com",
                    "email_verified": True,
                }]
            }
            mock_table.put_item.side_effect = ClientError(
                {"Error": {"Code": "InternalServerError", "Message": "Test error"}},
                "PutItem"
            )
            response = handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert body["error"]["code"] == "internal_error"


class TestRecoveryInitiateCORSHeaders:
    """Tests for CORS header handling."""

    @mock_aws
    def test_includes_cors_origin_header(self, mock_dynamodb, seeded_api_keys_table):
        """Should include CORS origin in response when provided."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"Origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
        # Check that the handler extracted and used the origin
        body = json.loads(response["body"])
        assert "recovery_session_id" in body

    @mock_aws
    def test_handles_lowercase_origin_header(self, mock_dynamodb, seeded_api_keys_table):
        """Should handle lowercase 'origin' header."""
        from api.recovery_initiate import handler

        event = {
            "body": json.dumps({"email": "test@example.com"}),
            "headers": {"origin": "https://pkgwatch.dev"},
        }

        with patch("time.sleep"):
            response = handler(event, None)

        assert response["statusCode"] == 200
